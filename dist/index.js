"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
const compression_1 = __importDefault(require("compression"));
const morgan_1 = __importDefault(require("morgan"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const pool_1 = require("./db/pool");
const logger_1 = require("./utils/logger");
const index_1 = require("./middleware/index");
const auth_1 = __importDefault(require("./routes/auth"));
const tenants_1 = __importDefault(require("./routes/tenants"));
const collections_1 = __importDefault(require("./routes/collections"));
const extras_1 = require("./routes/extras");
const app = (0, express_1.default)();
const PORT = parseInt(process.env.PORT || '10000');
// ── Security ──────────────────────────────────────────────
app.set('trust proxy', 1);
app.use((0, helmet_1.default)({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use((0, cors_1.default)({
    origin: true, // allow all origins; restrict per-tenant in production
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Api-Key', 'X-Tenant-Id'],
    exposedHeaders: ['X-Trace-Id'],
}));
// ── Global rate limit ─────────────────────────────────────
app.use((0, express_rate_limit_1.default)({
    windowMs: 60_000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/health',
    message: { success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' } },
}));
// ── Parsing ───────────────────────────────────────────────
app.use((0, compression_1.default)());
app.use(express_1.default.json({ limit: '10mb' }));
app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' }));
// ── Observability ─────────────────────────────────────────
app.use(index_1.traceMiddleware);
app.use(index_1.requestLogger);
if (process.env.NODE_ENV !== 'test') {
    app.use((0, morgan_1.default)('combined', {
        stream: { write: (msg) => logger_1.logger.info(msg.trim()) },
        skip: (req) => req.path === '/health',
    }));
}
// ── Auth (attaches user/apiKey to res.locals) ─────────────
app.use(index_1.optionalAuth);
app.use(index_1.apiKeyAuth);
// ── Health ────────────────────────────────────────────────
app.get('/health', async (req, res) => {
    try {
        await (0, pool_1.testConnection)();
        res.json({ status: 'ok', version: process.env.npm_package_version || '2.0.0', timestamp: new Date().toISOString() });
    }
    catch {
        res.status(503).json({ status: 'degraded', timestamp: new Date().toISOString() });
    }
});
// ── API Routes ────────────────────────────────────────────
// Auth
app.use('/v1/auth', auth_1.default);
// Tenant management
app.use('/v1/tenants', tenants_1.default);
// Per-tenant resources
app.use('/v1/:tenantSlug/collections', collections_1.default);
app.use('/v1/:tenantSlug/api-keys', extras_1.apiKeysRouter);
app.use('/v1/:tenantSlug/webhooks', extras_1.webhooksRouter);
app.use('/v1/:tenantSlug/functions', extras_1.edgeFunctionsRouter);
app.use('/v1/:tenantSlug/notifications', extras_1.notificationsRouter);
app.use('/v1/:tenantSlug/analytics', extras_1.analyticsRouter);
// Root
app.get('/', (req, res) => {
    res.json({
        name: 'json-api.uz Enterprise BaaS',
        version: '2.0.0',
        docs: '/v1/docs',
        health: '/health',
        timestamp: new Date().toISOString(),
    });
});
// ── Error Handling ────────────────────────────────────────
app.use(index_1.notFoundHandler);
app.use(index_1.errorHandler);
// ── Start ─────────────────────────────────────────────────
async function start() {
    try {
        await (0, pool_1.testConnection)();
        logger_1.logger.info('✅ Database connected');
    }
    catch (err) {
        logger_1.logger.error('❌ Database connection failed:', err.message);
        logger_1.logger.warn('⚠️  Starting server without confirmed DB connection — will retry on requests');
    }
    app.listen(PORT, '0.0.0.0', () => {
        logger_1.logger.info(`🚀 json-api.uz running on port ${PORT}`);
        logger_1.logger.info(`   ENV: ${process.env.NODE_ENV}`);
        logger_1.logger.info(`   Health: http://localhost:${PORT}/health`);
    });
}
start();
exports.default = app;
