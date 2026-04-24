import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

import { testConnection } from './db/pool';
import { logger } from './utils/logger';
import {
  traceMiddleware,
  requestLogger,
  optionalAuth,
  apiKeyAuth,
  errorHandler,
  notFoundHandler,
} from './middleware/index';

import authRouter from './routes/auth';
import tenantsRouter from './routes/tenants';
import collectionsRouter from './routes/collections';
import {
  apiKeysRouter,
  webhooksRouter,
  edgeFunctionsRouter,
  notificationsRouter,
  analyticsRouter,
} from './routes/extras';

const app = express();
const PORT = parseInt(process.env.PORT || '10000');

// ── Security ──────────────────────────────────────────────
app.set('trust proxy', 1);

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

app.use(cors({
  origin: true,          // allow all origins; restrict per-tenant in production
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Api-Key', 'X-Tenant-Id'],
  exposedHeaders: ['X-Trace-Id'],
}));

// ── Global rate limit ─────────────────────────────────────
app.use(rateLimit({
  windowMs: 60_000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health',
  message: { success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' } },
}));

// ── Parsing ───────────────────────────────────────────────
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── Observability ─────────────────────────────────────────
app.use(traceMiddleware);
app.use(requestLogger);
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined', {
    stream: { write: (msg) => logger.info(msg.trim()) },
    skip: (req) => req.path === '/health',
  }));
}

// ── Auth (attaches user/apiKey to res.locals) ─────────────
app.use(optionalAuth);
app.use(apiKeyAuth);

// ── Health ────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    await testConnection();
    res.json({ status: 'ok', version: process.env.npm_package_version || '2.0.0', timestamp: new Date().toISOString() });
  } catch {
    res.status(503).json({ status: 'degraded', timestamp: new Date().toISOString() });
  }
});

// ── API Routes ────────────────────────────────────────────
// Auth
app.use('/v1/auth', authRouter);

// Tenant management
app.use('/v1/tenants', tenantsRouter);

// Per-tenant resources
app.use('/v1/:tenantSlug/collections', collectionsRouter);
app.use('/v1/:tenantSlug/api-keys',    apiKeysRouter);
app.use('/v1/:tenantSlug/webhooks',    webhooksRouter);
app.use('/v1/:tenantSlug/functions',   edgeFunctionsRouter);
app.use('/v1/:tenantSlug/notifications', notificationsRouter);
app.use('/v1/:tenantSlug/analytics',   analyticsRouter);

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
app.use(notFoundHandler);
app.use(errorHandler);

// ── Start ─────────────────────────────────────────────────
async function start(): Promise<void> {
  try {
    await testConnection();
    logger.info('✅ Database connected');
  } catch (err: any) {
    logger.error('❌ Database connection failed:', err.message);
    logger.warn('⚠️  Starting server without confirmed DB connection — will retry on requests');
  }

  app.listen(PORT, '0.0.0.0', () => {
    logger.info(`🚀 json-api.uz running on port ${PORT}`);
    logger.info(`   ENV: ${process.env.NODE_ENV}`);
    logger.info(`   Health: http://localhost:${PORT}/health`);
  });
}

start();

export default app;
