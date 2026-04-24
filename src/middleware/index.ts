import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { createHash } from 'crypto';
import { v4 as uuid } from 'uuid';
import { query } from '../db/pool';
import { AppError } from '../utils/response';
import { logger } from '../utils/logger';

// ── Trace ID ──────────────────────────────────────────────
export function traceMiddleware(req: Request, res: Response, next: NextFunction) {
  res.locals.traceId = uuid();
  res.setHeader('X-Trace-Id', res.locals.traceId);
  next();
}

// ── Request Logger ────────────────────────────────────────
export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`, {
      traceId: res.locals.traceId,
      ip: req.ip,
    });
    // Async log to DB — non-blocking
    if (res.locals.tenantId) {
      query(
        `INSERT INTO request_logs(tenant_id,trace_id,method,path,status_code,duration_ms,ip_address,user_agent)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          res.locals.tenantId,
          res.locals.traceId,
          req.method,
          req.path,
          res.statusCode,
          duration,
          req.ip || null,
          req.headers['user-agent'] || null,
        ]
      ).catch(() => {});
    }
  });
  next();
}

// ── JWT Auth ──────────────────────────────────────────────
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return next(new AppError('Authentication required', 401, 'UNAUTHORIZED'));
  }
  try {
    const payload = jwt.verify(header.slice(7), process.env.JWT_ACCESS_SECRET!) as any;
    res.locals.user = payload;
    res.locals.tenantId = payload.tid;
    next();
  } catch (err: any) {
    next(new AppError('Token invalid or expired', 401, 'UNAUTHORIZED'));
  }
}

export function optionalAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(header.slice(7), process.env.JWT_ACCESS_SECRET!) as any;
      res.locals.user = payload;
      res.locals.tenantId = payload.tid;
    } catch {}
  }
  next();
}

// ── API Key Auth ──────────────────────────────────────────
export async function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const apiKey = req.headers['x-api-key'] as string;
  if (!apiKey) return next();

  try {
    const keyHash = createHash('sha256').update(apiKey).digest('hex');
    const { rows } = await query(
      `SELECT ak.id, ak.tenant_id, ak.permissions, t.slug
       FROM api_keys ak
       JOIN tenants t ON t.id = ak.tenant_id
       WHERE ak.key_hash = $1
         AND t.is_active = true
         AND (ak.expires_at IS NULL OR ak.expires_at > now())`,
      [keyHash]
    );
    if (rows.length) {
      const row = rows[0] as any;
      res.locals.apiKey = row;
      res.locals.tenantId = row.tenant_id;
      res.locals.tenantSlug = row.slug;
      // update last_used async
      query(
        `UPDATE api_keys SET last_used_at=now(), usage_count=usage_count+1 WHERE id=$1`,
        [row.id]
      ).catch(() => {});
    }
    next();
  } catch (err) {
    next(err);
  }
}

// ── Require Tenant ────────────────────────────────────────
export async function requireTenant(req: Request, res: Response, next: NextFunction) {
  const slug = req.params.tenantSlug || res.locals.tenantSlug;
  if (!slug) return next(new AppError('Tenant not found', 404, 'NOT_FOUND'));

  try {
    const { rows } = await query(
      `SELECT id, slug, plan, settings FROM tenants WHERE slug=$1 AND is_active=true`,
      [slug]
    );
    if (!rows.length) return next(new AppError('Tenant not found', 404, 'NOT_FOUND'));
    res.locals.tenant = rows[0];
    res.locals.tenantId = (rows[0] as any).id;
    next();
  } catch (err) {
    next(err);
  }
}

// ── Global Error Handler ──────────────────────────────────
export function errorHandler(err: any, req: Request, res: Response, _next: NextFunction) {
  const statusCode = err.statusCode || err.status || 500;
  const code = err.code || 'INTERNAL_ERROR';
  const message =
    statusCode === 500 && process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message;

  if (statusCode === 500) {
    logger.error('Unhandled error:', { error: err.message, stack: err.stack, traceId: res.locals.traceId });
  }

  res.status(statusCode).json({
    success: false,
    error: { code, message, ...(err.details ? { details: err.details } : {}) },
    traceId: res.locals.traceId || uuid(),
    timestamp: new Date().toISOString(),
  });
}

// ── 404 Handler ───────────────────────────────────────────
export function notFoundHandler(req: Request, res: Response) {
  res.status(404).json({
    success: false,
    error: { code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` },
    traceId: res.locals.traceId || uuid(),
    timestamp: new Date().toISOString(),
  });
}
