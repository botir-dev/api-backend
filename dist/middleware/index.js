"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.traceMiddleware = traceMiddleware;
exports.requestLogger = requestLogger;
exports.requireAuth = requireAuth;
exports.optionalAuth = optionalAuth;
exports.apiKeyAuth = apiKeyAuth;
exports.requireTenant = requireTenant;
exports.errorHandler = errorHandler;
exports.notFoundHandler = notFoundHandler;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = require("crypto");
const uuid_1 = require("uuid");
const pool_1 = require("../db/pool");
const response_1 = require("../utils/response");
const logger_1 = require("../utils/logger");
// ── Trace ID ──────────────────────────────────────────────
function traceMiddleware(req, res, next) {
    res.locals.traceId = (0, uuid_1.v4)();
    res.setHeader('X-Trace-Id', res.locals.traceId);
    next();
}
// ── Request Logger ────────────────────────────────────────
function requestLogger(req, res, next) {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        logger_1.logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`, {
            traceId: res.locals.traceId,
            ip: req.ip,
        });
        // Async log to DB — non-blocking
        if (res.locals.tenantId) {
            (0, pool_1.query)(`INSERT INTO request_logs(tenant_id,trace_id,method,path,status_code,duration_ms,ip_address,user_agent)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [
                res.locals.tenantId,
                res.locals.traceId,
                req.method,
                req.path,
                res.statusCode,
                duration,
                req.ip || null,
                req.headers['user-agent'] || null,
            ]).catch(() => { });
        }
    });
    next();
}
// ── JWT Auth ──────────────────────────────────────────────
function requireAuth(req, res, next) {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
        return next(new response_1.AppError('Authentication required', 401, 'UNAUTHORIZED'));
    }
    try {
        const payload = jsonwebtoken_1.default.verify(header.slice(7), process.env.JWT_ACCESS_SECRET);
        res.locals.user = payload;
        res.locals.tenantId = payload.tid;
        next();
    }
    catch (err) {
        next(new response_1.AppError('Token invalid or expired', 401, 'UNAUTHORIZED'));
    }
}
function optionalAuth(req, res, next) {
    const header = req.headers.authorization;
    if (header?.startsWith('Bearer ')) {
        try {
            const payload = jsonwebtoken_1.default.verify(header.slice(7), process.env.JWT_ACCESS_SECRET);
            res.locals.user = payload;
            res.locals.tenantId = payload.tid;
        }
        catch { }
    }
    next();
}
// ── API Key Auth ──────────────────────────────────────────
async function apiKeyAuth(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey)
        return next();
    try {
        const keyHash = (0, crypto_1.createHash)('sha256').update(apiKey).digest('hex');
        const { rows } = await (0, pool_1.query)(`SELECT ak.id, ak.tenant_id, ak.permissions, t.slug
       FROM api_keys ak
       JOIN tenants t ON t.id = ak.tenant_id
       WHERE ak.key_hash = $1
         AND t.is_active = true
         AND (ak.expires_at IS NULL OR ak.expires_at > now())`, [keyHash]);
        if (rows.length) {
            const row = rows[0];
            res.locals.apiKey = row;
            res.locals.tenantId = row.tenant_id;
            res.locals.tenantSlug = row.slug;
            // update last_used async
            (0, pool_1.query)(`UPDATE api_keys SET last_used_at=now(), usage_count=usage_count+1 WHERE id=$1`, [row.id]).catch(() => { });
        }
        next();
    }
    catch (err) {
        next(err);
    }
}
// ── Require Tenant ────────────────────────────────────────
async function requireTenant(req, res, next) {
    const slug = req.params.tenantSlug || res.locals.tenantSlug;
    if (!slug)
        return next(new response_1.AppError('Tenant not found', 404, 'NOT_FOUND'));
    try {
        const { rows } = await (0, pool_1.query)(`SELECT id, slug, plan, settings FROM tenants WHERE slug=$1 AND is_active=true`, [slug]);
        if (!rows.length)
            return next(new response_1.AppError('Tenant not found', 404, 'NOT_FOUND'));
        res.locals.tenant = rows[0];
        res.locals.tenantId = rows[0].id;
        next();
    }
    catch (err) {
        next(err);
    }
}
// ── Global Error Handler ──────────────────────────────────
function errorHandler(err, req, res, _next) {
    const statusCode = err.statusCode || err.status || 500;
    const code = err.code || 'INTERNAL_ERROR';
    const message = statusCode === 500 && process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : err.message;
    if (statusCode === 500) {
        logger_1.logger.error('Unhandled error:', { error: err.message, stack: err.stack, traceId: res.locals.traceId });
    }
    res.status(statusCode).json({
        success: false,
        error: { code, message, ...(err.details ? { details: err.details } : {}) },
        traceId: res.locals.traceId || (0, uuid_1.v4)(),
        timestamp: new Date().toISOString(),
    });
}
// ── 404 Handler ───────────────────────────────────────────
function notFoundHandler(req, res) {
    res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` },
        traceId: res.locals.traceId || (0, uuid_1.v4)(),
        timestamp: new Date().toISOString(),
    });
}
