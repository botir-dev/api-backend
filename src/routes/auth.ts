import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createHash, randomBytes } from 'crypto';
import { v4 as uuid } from 'uuid';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { query, withTransaction } from '../db/pool';
import { ok, created, AppError, Errors } from '../utils/response';
import { requireAuth } from '../middleware/index';
import rateLimit from 'express-rate-limit';

const router = Router();

const ACCESS_SECRET  = () => process.env.JWT_ACCESS_SECRET!;
const REFRESH_SECRET = () => process.env.JWT_REFRESH_SECRET!;
const BCRYPT_ROUNDS  = 12;

// Rate limiters
const loginLimiter = rateLimit({
  windowMs: 60_000, max: 10,
  message: { success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many login attempts' } },
  standardHeaders: true, legacyHeaders: false,
});

const magicLimiter = rateLimit({
  windowMs: 5 * 60_000, max: 5,
  message: { success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' } },
});

// ── Helpers ────────────────────────────────────────────────
function signAccess(payload: object): string {
  return jwt.sign(payload, ACCESS_SECRET(), { expiresIn: '15m' });
}

function signRefresh(userId: string, sessionId: string): string {
  return jwt.sign({ sub: userId, sid: sessionId }, REFRESH_SECRET(), { expiresIn: '30d' });
}

async function saveSession(
  userId: string, tenantId: string, refreshToken: string,
  ip: string, userAgent: string
): Promise<string> {
  const sessionId  = uuid();
  const tokenHash  = createHash('sha256').update(refreshToken).digest('hex');
  const expiresAt  = new Date(Date.now() + 30 * 24 * 3600 * 1000);
  await query(
    `INSERT INTO sessions(id,user_id,tenant_id,refresh_token_hash,ip_address,device_info,expires_at)
     VALUES($1,$2,$3,$4,$5,$6,$7)`,
    [sessionId, userId, tenantId, tokenHash, ip, JSON.stringify({ userAgent }), expiresAt]
  );
  return sessionId;
}

async function buildTokenPair(userId: string, tenantId: string, email: string, ip: string, ua: string) {
  const { rows: roleRows } = await query(
    `SELECT r.name FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = $1`, [userId]
  );
  const roles = roleRows.map((r: any) => r.name);
  const sessionId    = uuid();
  const accessToken  = signAccess({ sub: userId, tid: tenantId, email, roles, sessionId });
  const refreshToken = signRefresh(userId, sessionId);
  await saveSession(userId, tenantId, refreshToken, ip, ua);
  return { accessToken, refreshToken, expiresIn: 900 };
}

// ── POST /auth/register ────────────────────────────────────
router.post('/register', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, name, tenantSlug } = req.body;
    if (!email || !password || !tenantSlug)
      throw Errors.validation('email, password, tenantSlug are required');
    if (password.length < 8)
      throw Errors.validation('Password must be at least 8 characters');

    const { rows: tenantRows } = await query(
      `SELECT id FROM tenants WHERE slug=$1 AND is_active=true`, [tenantSlug]
    );
    if (!tenantRows.length) throw Errors.notFound('Tenant');
    const tenantId = (tenantRows[0] as any).id;

    const { rows: existing } = await query(
      `SELECT id FROM users WHERE tenant_id=$1 AND email=$2`, [tenantId, email.toLowerCase()]
    );
    if (existing.length) throw Errors.conflict('Email already registered');

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const userId = uuid();

    await withTransaction(async (client) => {
      await client.query(
        `INSERT INTO users(id,tenant_id,email,password_hash,full_name,provider)
         VALUES($1,$2,$3,$4,$5,'email')`,
        [userId, tenantId, email.toLowerCase(), passwordHash, name || null]
      );
      await client.query(
        `INSERT INTO user_roles(user_id,role_id)
         SELECT $1, id FROM roles WHERE tenant_id=$2 AND name='user'`,
        [userId, tenantId]
      );
    });

    return created(res, { id: userId, email: email.toLowerCase(), message: 'Registration successful' });
  } catch (err) { next(err); }
});

// ── POST /auth/login ───────────────────────────────────────
router.post('/login', loginLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, tenantSlug } = req.body;
    if (!email || !password || !tenantSlug)
      throw Errors.validation('email, password, tenantSlug are required');

    const { rows } = await query(
      `SELECT u.id, u.tenant_id, u.email, u.password_hash, u.is_active, u.metadata
       FROM users u JOIN tenants t ON t.id=u.tenant_id
       WHERE t.slug=$1 AND u.email=$2`,
      [tenantSlug, email.toLowerCase()]
    );

    const user: any = rows[0];
    // Constant-time: always hash even if user not found
    const hashToCheck = user?.password_hash || '$2b$12$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const valid = await bcrypt.compare(password, hashToCheck);

    if (!user || !valid || !user.is_active)
      throw new AppError('Invalid credentials', 401, 'UNAUTHORIZED');

    // 2FA check
    if (user.metadata?.totp_enabled) {
      const tempToken = randomBytes(32).toString('hex');
      await query(
        `INSERT INTO sessions(id,user_id,tenant_id,refresh_token_hash,expires_at)
         VALUES($1,$2,$3,$4,now()+interval'5 minutes')`,
        [uuid(), user.id, user.tenant_id, createHash('sha256').update(`2fa:${tempToken}`).digest('hex')]
      );
      return ok(res, { requires2FA: true, tempToken });
    }

    const tokens = await buildTokenPair(
      user.id, user.tenant_id, user.email,
      req.ip || '', req.headers['user-agent'] || ''
    );
    query(`UPDATE users SET last_login_at=now() WHERE id=$1`, [user.id]).catch(() => {});

    return ok(res, {
      ...tokens,
      user: { id: user.id, email: user.email },
    });
  } catch (err) { next(err); }
});

// ── POST /auth/refresh ─────────────────────────────────────
router.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) throw Errors.unauthorized('Refresh token required');

    let payload: any;
    try { payload = jwt.verify(refreshToken, REFRESH_SECRET()); }
    catch { throw new AppError('Refresh token expired or invalid', 401, 'UNAUTHORIZED'); }

    const tokenHash = createHash('sha256').update(refreshToken).digest('hex');
    const { rows } = await query(
      `SELECT user_id, tenant_id FROM sessions
       WHERE refresh_token_hash=$1 AND expires_at>now() AND revoked_at IS NULL`,
      [tokenHash]
    );
    if (!rows.length) throw new AppError('Session expired', 401, 'UNAUTHORIZED');

    const { user_id, tenant_id } = rows[0] as any;
    const { rows: userRows } = await query(
      `SELECT email FROM users WHERE id=$1 AND is_active=true`, [user_id]
    );
    if (!userRows.length) throw Errors.unauthorized();

    const { rows: roleRows } = await query(
      `SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=$1`,
      [user_id]
    );
    const roles = roleRows.map((r: any) => r.name);
    const sessionId = payload.sid || uuid();
    const accessToken = signAccess({ sub: user_id, tid: tenant_id, email: (userRows[0] as any).email, roles, sessionId });

    return ok(res, { accessToken, expiresIn: 900 });
  } catch (err) { next(err); }
});

// ── POST /auth/logout ──────────────────────────────────────
router.post('/logout', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      const tokenHash = createHash('sha256').update(refreshToken).digest('hex');
      await query(`UPDATE sessions SET revoked_at=now() WHERE refresh_token_hash=$1`, [tokenHash]);
    }
    return ok(res, { message: 'Logged out successfully' });
  } catch (err) { next(err); }
});

// ── POST /auth/magic-link ──────────────────────────────────
router.post('/magic-link', magicLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, tenantSlug } = req.body;
    if (!email || !tenantSlug) throw Errors.validation('email and tenantSlug required');

    const { rows } = await query(
      `SELECT u.id, u.tenant_id FROM users u JOIN tenants t ON t.id=u.tenant_id
       WHERE t.slug=$1 AND u.email=$2 AND u.is_active=true`,
      [tenantSlug, email.toLowerCase()]
    );

    if (rows.length) {
      const user: any = rows[0];
      const token = randomBytes(32).toString('hex');
      const tokenHash = createHash('sha256').update(token).digest('hex');
      await query(
        `INSERT INTO sessions(id,user_id,tenant_id,refresh_token_hash,expires_at)
         VALUES($1,$2,$3,$4,now()+interval'15 minutes')`,
        [uuid(), user.id, user.tenant_id, `magic:${tokenHash}`]
      );
      // In production: send email via notification service
      console.log(`Magic link token for ${email}: ${token}`);
    }

    // Always return success (prevent user enumeration)
    return ok(res, { message: 'If that email exists, a magic link has been sent' });
  } catch (err) { next(err); }
});

// ── GET /auth/magic-link/verify ────────────────────────────
router.get('/magic-link/verify', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.query as { token: string };
    if (!token) throw Errors.validation('Token required');

    const tokenHash = createHash('sha256').update(token).digest('hex');
    const { rows } = await query(
      `SELECT user_id, tenant_id FROM sessions
       WHERE refresh_token_hash=$1 AND expires_at>now() AND revoked_at IS NULL`,
      [`magic:${tokenHash}`]
    );
    if (!rows.length) throw new AppError('Magic link invalid or expired', 401, 'UNAUTHORIZED');

    const { user_id, tenant_id } = rows[0] as any;
    // Revoke magic link session
    await query(
      `UPDATE sessions SET revoked_at=now() WHERE refresh_token_hash=$1`,
      [`magic:${tokenHash}`]
    );

    const { rows: userRows } = await query(`SELECT email FROM users WHERE id=$1`, [user_id]);
    const tokens = await buildTokenPair(
      user_id, tenant_id, (userRows[0] as any).email,
      req.ip || '', req.headers['user-agent'] || ''
    );
    return ok(res, tokens);
  } catch (err) { next(err); }
});

// ── POST /auth/totp/setup ──────────────────────────────────
router.post('/totp/setup', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = res.locals.user;
    const secret = speakeasy.generateSecret({ name: `json-api.uz:${user.email}`, length: 20 });

    // Temporarily store in DB metadata (pending confirmation)
    await query(
      `UPDATE users SET metadata=metadata||$1::jsonb WHERE id=$2`,
      [JSON.stringify({ totp_pending: secret.base32 }), user.sub]
    );

    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url!);
    return ok(res, { secret: secret.base32, qrCode: qrDataUrl });
  } catch (err) { next(err); }
});

// ── POST /auth/totp/confirm ────────────────────────────────
router.post('/totp/confirm', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { code } = req.body;
    const user = res.locals.user;

    const { rows } = await query(`SELECT metadata FROM users WHERE id=$1`, [user.sub]);
    const meta: any = (rows[0] as any)?.metadata || {};
    if (!meta.totp_pending) throw Errors.validation('TOTP setup not initiated');

    const valid = speakeasy.totp.verify({
      secret: meta.totp_pending, encoding: 'base32', token: code, window: 2,
    });
    if (!valid) throw new AppError('Invalid TOTP code', 401, 'UNAUTHORIZED');

    await query(
      `UPDATE users SET metadata=metadata||$1::jsonb WHERE id=$2`,
      [JSON.stringify({ totp_enabled: true, totp_secret: meta.totp_pending, totp_pending: null }), user.sub]
    );
    return ok(res, { message: '2FA enabled successfully' });
  } catch (err) { next(err); }
});

// ── POST /auth/totp/verify (for 2FA login) ────────────────
router.post('/totp/verify', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { code, tempToken } = req.body;
    if (!code || !tempToken) throw Errors.validation('code and tempToken required');

    const tempHash = createHash('sha256').update(`2fa:${tempToken}`).digest('hex');
    const { rows } = await query(
      `SELECT user_id, tenant_id FROM sessions
       WHERE refresh_token_hash=$1 AND expires_at>now() AND revoked_at IS NULL`,
      [tempHash]
    );
    if (!rows.length) throw new AppError('2FA session expired', 401, 'UNAUTHORIZED');

    const { user_id, tenant_id } = rows[0] as any;
    const { rows: userRows } = await query(
      `SELECT email, metadata FROM users WHERE id=$1`, [user_id]
    );
    const user: any = userRows[0];

    const valid = speakeasy.totp.verify({
      secret: user.metadata.totp_secret,
      encoding: 'base32', token: code, window: 2,
    });
    if (!valid) throw new AppError('Invalid TOTP code', 401, 'UNAUTHORIZED');

    // Revoke temp session
    await query(`UPDATE sessions SET revoked_at=now() WHERE refresh_token_hash=$1`, [tempHash]);

    const tokens = await buildTokenPair(
      user_id, tenant_id, user.email,
      req.ip || '', req.headers['user-agent'] || ''
    );
    return ok(res, tokens);
  } catch (err) { next(err); }
});

// ── GET /auth/me ───────────────────────────────────────────
router.get('/me', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { sub } = res.locals.user;
    const { rows } = await query(
      `SELECT u.id, u.email, u.full_name, u.avatar_url, u.email_verified, u.created_at,
              array_agg(r.name) FILTER (WHERE r.name IS NOT NULL) AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id=u.id
       LEFT JOIN roles r ON r.id=ur.role_id
       WHERE u.id=$1 GROUP BY u.id`,
      [sub]
    );
    if (!rows.length) throw Errors.notFound('User');
    return ok(res, rows[0]);
  } catch (err) { next(err); }
});

export default router;
