"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = require("crypto");
const uuid_1 = require("uuid");
const speakeasy_1 = __importDefault(require("speakeasy"));
const qrcode_1 = __importDefault(require("qrcode"));
const pool_1 = require("../db/pool");
const response_1 = require("../utils/response");
const index_1 = require("../middleware/index");
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const router = (0, express_1.Router)();
const ACCESS_SECRET = () => process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = () => process.env.JWT_REFRESH_SECRET;
const BCRYPT_ROUNDS = 12;
// Rate limiters
const loginLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60_000, max: 10,
    message: { success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many login attempts' } },
    standardHeaders: true, legacyHeaders: false,
});
const magicLimiter = (0, express_rate_limit_1.default)({
    windowMs: 5 * 60_000, max: 5,
    message: { success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' } },
});
// ── Helpers ────────────────────────────────────────────────
function signAccess(payload) {
    return jsonwebtoken_1.default.sign(payload, ACCESS_SECRET(), { expiresIn: '15m' });
}
function signRefresh(userId, sessionId) {
    return jsonwebtoken_1.default.sign({ sub: userId, sid: sessionId }, REFRESH_SECRET(), { expiresIn: '30d' });
}
async function saveSession(userId, tenantId, refreshToken, ip, userAgent) {
    const sessionId = (0, uuid_1.v4)();
    const tokenHash = (0, crypto_1.createHash)('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + 30 * 24 * 3600 * 1000);
    await (0, pool_1.query)(`INSERT INTO sessions(id,user_id,tenant_id,refresh_token_hash,ip_address,device_info,expires_at)
     VALUES($1,$2,$3,$4,$5,$6,$7)`, [sessionId, userId, tenantId, tokenHash, ip, JSON.stringify({ userAgent }), expiresAt]);
    return sessionId;
}
async function buildTokenPair(userId, tenantId, email, ip, ua) {
    const { rows: roleRows } = await (0, pool_1.query)(`SELECT r.name FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = $1`, [userId]);
    const roles = roleRows.map((r) => r.name);
    const sessionId = (0, uuid_1.v4)();
    const accessToken = signAccess({ sub: userId, tid: tenantId, email, roles, sessionId });
    const refreshToken = signRefresh(userId, sessionId);
    await saveSession(userId, tenantId, refreshToken, ip, ua);
    return { accessToken, refreshToken, expiresIn: 900 };
}
// ── POST /auth/register ────────────────────────────────────
router.post('/register', async (req, res, next) => {
    try {
        const { email, password, name, tenantSlug } = req.body;
        if (!email || !password || !tenantSlug)
            throw response_1.Errors.validation('email, password, tenantSlug are required');
        if (password.length < 8)
            throw response_1.Errors.validation('Password must be at least 8 characters');
        const { rows: tenantRows } = await (0, pool_1.query)(`SELECT id FROM tenants WHERE slug=$1 AND is_active=true`, [tenantSlug]);
        if (!tenantRows.length)
            throw response_1.Errors.notFound('Tenant');
        const tenantId = tenantRows[0].id;
        const { rows: existing } = await (0, pool_1.query)(`SELECT id FROM users WHERE tenant_id=$1 AND email=$2`, [tenantId, email.toLowerCase()]);
        if (existing.length)
            throw response_1.Errors.conflict('Email already registered');
        const passwordHash = await bcryptjs_1.default.hash(password, BCRYPT_ROUNDS);
        const userId = (0, uuid_1.v4)();
        await (0, pool_1.withTransaction)(async (client) => {
            await client.query(`INSERT INTO users(id,tenant_id,email,password_hash,full_name,provider)
         VALUES($1,$2,$3,$4,$5,'email')`, [userId, tenantId, email.toLowerCase(), passwordHash, name || null]);
            await client.query(`INSERT INTO user_roles(user_id,role_id)
         SELECT $1, id FROM roles WHERE tenant_id=$2 AND name='user'`, [userId, tenantId]);
        });
        return (0, response_1.created)(res, { id: userId, email: email.toLowerCase(), message: 'Registration successful' });
    }
    catch (err) {
        next(err);
    }
});
// ── POST /auth/login ───────────────────────────────────────
router.post('/login', loginLimiter, async (req, res, next) => {
    try {
        const { email, password, tenantSlug } = req.body;
        if (!email || !password || !tenantSlug)
            throw response_1.Errors.validation('email, password, tenantSlug are required');
        const { rows } = await (0, pool_1.query)(`SELECT u.id, u.tenant_id, u.email, u.password_hash, u.is_active, u.metadata
       FROM users u JOIN tenants t ON t.id=u.tenant_id
       WHERE t.slug=$1 AND u.email=$2`, [tenantSlug, email.toLowerCase()]);
        const user = rows[0];
        // Constant-time: always hash even if user not found
        const hashToCheck = user?.password_hash || '$2b$12$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
        const valid = await bcryptjs_1.default.compare(password, hashToCheck);
        if (!user || !valid || !user.is_active)
            throw new response_1.AppError('Invalid credentials', 401, 'UNAUTHORIZED');
        // 2FA check
        if (user.metadata?.totp_enabled) {
            const tempToken = (0, crypto_1.randomBytes)(32).toString('hex');
            await (0, pool_1.query)(`INSERT INTO sessions(id,user_id,tenant_id,refresh_token_hash,expires_at)
         VALUES($1,$2,$3,$4,now()+interval'5 minutes')`, [(0, uuid_1.v4)(), user.id, user.tenant_id, (0, crypto_1.createHash)('sha256').update(`2fa:${tempToken}`).digest('hex')]);
            return (0, response_1.ok)(res, { requires2FA: true, tempToken });
        }
        const tokens = await buildTokenPair(user.id, user.tenant_id, user.email, req.ip || '', req.headers['user-agent'] || '');
        (0, pool_1.query)(`UPDATE users SET last_login_at=now() WHERE id=$1`, [user.id]).catch(() => { });
        return (0, response_1.ok)(res, {
            ...tokens,
            user: { id: user.id, email: user.email },
        });
    }
    catch (err) {
        next(err);
    }
});
// ── POST /auth/refresh ─────────────────────────────────────
router.post('/refresh', async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken)
            throw response_1.Errors.unauthorized('Refresh token required');
        let payload;
        try {
            payload = jsonwebtoken_1.default.verify(refreshToken, REFRESH_SECRET());
        }
        catch {
            throw new response_1.AppError('Refresh token expired or invalid', 401, 'UNAUTHORIZED');
        }
        const tokenHash = (0, crypto_1.createHash)('sha256').update(refreshToken).digest('hex');
        const { rows } = await (0, pool_1.query)(`SELECT user_id, tenant_id FROM sessions
       WHERE refresh_token_hash=$1 AND expires_at>now() AND revoked_at IS NULL`, [tokenHash]);
        if (!rows.length)
            throw new response_1.AppError('Session expired', 401, 'UNAUTHORIZED');
        const { user_id, tenant_id } = rows[0];
        const { rows: userRows } = await (0, pool_1.query)(`SELECT email FROM users WHERE id=$1 AND is_active=true`, [user_id]);
        if (!userRows.length)
            throw response_1.Errors.unauthorized();
        const { rows: roleRows } = await (0, pool_1.query)(`SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=$1`, [user_id]);
        const roles = roleRows.map((r) => r.name);
        const sessionId = payload.sid || (0, uuid_1.v4)();
        const accessToken = signAccess({ sub: user_id, tid: tenant_id, email: userRows[0].email, roles, sessionId });
        return (0, response_1.ok)(res, { accessToken, expiresIn: 900 });
    }
    catch (err) {
        next(err);
    }
});
// ── POST /auth/logout ──────────────────────────────────────
router.post('/logout', index_1.requireAuth, async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        if (refreshToken) {
            const tokenHash = (0, crypto_1.createHash)('sha256').update(refreshToken).digest('hex');
            await (0, pool_1.query)(`UPDATE sessions SET revoked_at=now() WHERE refresh_token_hash=$1`, [tokenHash]);
        }
        return (0, response_1.ok)(res, { message: 'Logged out successfully' });
    }
    catch (err) {
        next(err);
    }
});
// ── POST /auth/magic-link ──────────────────────────────────
router.post('/magic-link', magicLimiter, async (req, res, next) => {
    try {
        const { email, tenantSlug } = req.body;
        if (!email || !tenantSlug)
            throw response_1.Errors.validation('email and tenantSlug required');
        const { rows } = await (0, pool_1.query)(`SELECT u.id, u.tenant_id FROM users u JOIN tenants t ON t.id=u.tenant_id
       WHERE t.slug=$1 AND u.email=$2 AND u.is_active=true`, [tenantSlug, email.toLowerCase()]);
        if (rows.length) {
            const user = rows[0];
            const token = (0, crypto_1.randomBytes)(32).toString('hex');
            const tokenHash = (0, crypto_1.createHash)('sha256').update(token).digest('hex');
            await (0, pool_1.query)(`INSERT INTO sessions(id,user_id,tenant_id,refresh_token_hash,expires_at)
         VALUES($1,$2,$3,$4,now()+interval'15 minutes')`, [(0, uuid_1.v4)(), user.id, user.tenant_id, `magic:${tokenHash}`]);
            // In production: send email via notification service
            console.log(`Magic link token for ${email}: ${token}`);
        }
        // Always return success (prevent user enumeration)
        return (0, response_1.ok)(res, { message: 'If that email exists, a magic link has been sent' });
    }
    catch (err) {
        next(err);
    }
});
// ── GET /auth/magic-link/verify ────────────────────────────
router.get('/magic-link/verify', async (req, res, next) => {
    try {
        const { token } = req.query;
        if (!token)
            throw response_1.Errors.validation('Token required');
        const tokenHash = (0, crypto_1.createHash)('sha256').update(token).digest('hex');
        const { rows } = await (0, pool_1.query)(`SELECT user_id, tenant_id FROM sessions
       WHERE refresh_token_hash=$1 AND expires_at>now() AND revoked_at IS NULL`, [`magic:${tokenHash}`]);
        if (!rows.length)
            throw new response_1.AppError('Magic link invalid or expired', 401, 'UNAUTHORIZED');
        const { user_id, tenant_id } = rows[0];
        // Revoke magic link session
        await (0, pool_1.query)(`UPDATE sessions SET revoked_at=now() WHERE refresh_token_hash=$1`, [`magic:${tokenHash}`]);
        const { rows: userRows } = await (0, pool_1.query)(`SELECT email FROM users WHERE id=$1`, [user_id]);
        const tokens = await buildTokenPair(user_id, tenant_id, userRows[0].email, req.ip || '', req.headers['user-agent'] || '');
        return (0, response_1.ok)(res, tokens);
    }
    catch (err) {
        next(err);
    }
});
// ── POST /auth/totp/setup ──────────────────────────────────
router.post('/totp/setup', index_1.requireAuth, async (req, res, next) => {
    try {
        const user = res.locals.user;
        const secret = speakeasy_1.default.generateSecret({ name: `json-api.uz:${user.email}`, length: 20 });
        // Temporarily store in DB metadata (pending confirmation)
        await (0, pool_1.query)(`UPDATE users SET metadata=metadata||$1::jsonb WHERE id=$2`, [JSON.stringify({ totp_pending: secret.base32 }), user.sub]);
        const qrDataUrl = await qrcode_1.default.toDataURL(secret.otpauth_url);
        return (0, response_1.ok)(res, { secret: secret.base32, qrCode: qrDataUrl });
    }
    catch (err) {
        next(err);
    }
});
// ── POST /auth/totp/confirm ────────────────────────────────
router.post('/totp/confirm', index_1.requireAuth, async (req, res, next) => {
    try {
        const { code } = req.body;
        const user = res.locals.user;
        const { rows } = await (0, pool_1.query)(`SELECT metadata FROM users WHERE id=$1`, [user.sub]);
        const meta = rows[0]?.metadata || {};
        if (!meta.totp_pending)
            throw response_1.Errors.validation('TOTP setup not initiated');
        const valid = speakeasy_1.default.totp.verify({
            secret: meta.totp_pending, encoding: 'base32', token: code, window: 2,
        });
        if (!valid)
            throw new response_1.AppError('Invalid TOTP code', 401, 'UNAUTHORIZED');
        await (0, pool_1.query)(`UPDATE users SET metadata=metadata||$1::jsonb WHERE id=$2`, [JSON.stringify({ totp_enabled: true, totp_secret: meta.totp_pending, totp_pending: null }), user.sub]);
        return (0, response_1.ok)(res, { message: '2FA enabled successfully' });
    }
    catch (err) {
        next(err);
    }
});
// ── POST /auth/totp/verify (for 2FA login) ────────────────
router.post('/totp/verify', async (req, res, next) => {
    try {
        const { code, tempToken } = req.body;
        if (!code || !tempToken)
            throw response_1.Errors.validation('code and tempToken required');
        const tempHash = (0, crypto_1.createHash)('sha256').update(`2fa:${tempToken}`).digest('hex');
        const { rows } = await (0, pool_1.query)(`SELECT user_id, tenant_id FROM sessions
       WHERE refresh_token_hash=$1 AND expires_at>now() AND revoked_at IS NULL`, [tempHash]);
        if (!rows.length)
            throw new response_1.AppError('2FA session expired', 401, 'UNAUTHORIZED');
        const { user_id, tenant_id } = rows[0];
        const { rows: userRows } = await (0, pool_1.query)(`SELECT email, metadata FROM users WHERE id=$1`, [user_id]);
        const user = userRows[0];
        const valid = speakeasy_1.default.totp.verify({
            secret: user.metadata.totp_secret,
            encoding: 'base32', token: code, window: 2,
        });
        if (!valid)
            throw new response_1.AppError('Invalid TOTP code', 401, 'UNAUTHORIZED');
        // Revoke temp session
        await (0, pool_1.query)(`UPDATE sessions SET revoked_at=now() WHERE refresh_token_hash=$1`, [tempHash]);
        const tokens = await buildTokenPair(user_id, tenant_id, user.email, req.ip || '', req.headers['user-agent'] || '');
        return (0, response_1.ok)(res, tokens);
    }
    catch (err) {
        next(err);
    }
});
// ── GET /auth/me ───────────────────────────────────────────
router.get('/me', index_1.requireAuth, async (req, res, next) => {
    try {
        const { sub } = res.locals.user;
        const { rows } = await (0, pool_1.query)(`SELECT u.id, u.email, u.full_name, u.avatar_url, u.email_verified, u.created_at,
              array_agg(r.name) FILTER (WHERE r.name IS NOT NULL) AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id=u.id
       LEFT JOIN roles r ON r.id=ur.role_id
       WHERE u.id=$1 GROUP BY u.id`, [sub]);
        if (!rows.length)
            throw response_1.Errors.notFound('User');
        return (0, response_1.ok)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
exports.default = router;
