"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyticsRouter = exports.notificationsRouter = exports.edgeFunctionsRouter = exports.webhooksRouter = exports.apiKeysRouter = void 0;
exports.fireWebhook = fireWebhook;
const express_1 = require("express");
const crypto_1 = require("crypto");
const nodemailer_1 = __importDefault(require("nodemailer"));
const handlebars_1 = __importDefault(require("handlebars"));
const pool_1 = require("../db/pool");
const response_1 = require("../utils/response");
const index_1 = require("../middleware/index");
const logger_1 = require("../utils/logger");
// ══════════════════════════════════════════════════════════
// API KEYS ROUTER
// ══════════════════════════════════════════════════════════
exports.apiKeysRouter = (0, express_1.Router)({ mergeParams: true });
exports.apiKeysRouter.use(index_1.requireTenant, index_1.requireAuth);
exports.apiKeysRouter.post('/', async (req, res, next) => {
    try {
        const { name, permissions = [], expiresAt, rateLimitPerMin = 100 } = req.body;
        if (!name)
            throw response_1.Errors.validation('name is required');
        const rawKey = `bk_${(0, crypto_1.randomBytes)(24).toString('hex')}`;
        const keyHash = (0, crypto_1.createHash)('sha256').update(rawKey).digest('hex');
        const keyPrefix = rawKey.slice(0, 12);
        const { rows } = await (0, pool_1.query)(`INSERT INTO api_keys(tenant_id,name,key_hash,key_prefix,permissions,rate_limit_per_min,expires_at)
       VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)
       RETURNING id,name,key_prefix,created_at`, [res.locals.tenantId, name, keyHash, keyPrefix,
            JSON.stringify(permissions), rateLimitPerMin, expiresAt || null]);
        // Return raw key ONCE — never stored
        return (0, response_1.created)(res, { ...rows[0], key: rawKey, warning: 'Save this key — it will not be shown again' });
    }
    catch (err) {
        next(err);
    }
});
exports.apiKeysRouter.get('/', async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`SELECT id,name,key_prefix,permissions,rate_limit_per_min,expires_at,last_used_at,usage_count,created_at
       FROM api_keys WHERE tenant_id=$1 ORDER BY created_at DESC`, [res.locals.tenantId]);
        return (0, response_1.ok)(res, rows);
    }
    catch (err) {
        next(err);
    }
});
exports.apiKeysRouter.delete('/:keyId', async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`DELETE FROM api_keys WHERE id=$1 AND tenant_id=$2 RETURNING id`, [req.params.keyId, res.locals.tenantId]);
        if (!rows.length)
            throw response_1.Errors.notFound('API Key');
        return (0, response_1.noContent)(res);
    }
    catch (err) {
        next(err);
    }
});
// ══════════════════════════════════════════════════════════
// WEBHOOKS ROUTER
// ══════════════════════════════════════════════════════════
exports.webhooksRouter = (0, express_1.Router)({ mergeParams: true });
exports.webhooksRouter.use(index_1.requireTenant, index_1.requireAuth);
exports.webhooksRouter.post('/', async (req, res, next) => {
    try {
        const { name, url, events, headers = {} } = req.body;
        if (!name || !url || !events?.length)
            throw response_1.Errors.validation('name, url, events[] required');
        try {
            new URL(url);
        }
        catch {
            throw response_1.Errors.validation('Invalid URL');
        }
        const secret = (0, crypto_1.randomBytes)(32).toString('hex');
        const secretHash = (0, crypto_1.createHash)('sha256').update(secret).digest('hex');
        const { rows } = await (0, pool_1.query)(`INSERT INTO webhooks(tenant_id,name,url,events,secret_hash,headers)
       VALUES($1,$2,$3,$4,$5,$6::jsonb)
       RETURNING id,name,url,events,enabled,created_at`, [res.locals.tenantId, name, url, events, secretHash, JSON.stringify(headers)]);
        return (0, response_1.created)(res, { ...rows[0], secret, warning: 'Save this secret — it will not be shown again' });
    }
    catch (err) {
        next(err);
    }
});
exports.webhooksRouter.get('/', async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`SELECT id,name,url,events,enabled,failure_count,last_triggered,created_at
       FROM webhooks WHERE tenant_id=$1 ORDER BY created_at DESC`, [res.locals.tenantId]);
        return (0, response_1.ok)(res, rows);
    }
    catch (err) {
        next(err);
    }
});
exports.webhooksRouter.patch('/:webhookId', async (req, res, next) => {
    try {
        const { enabled } = req.body;
        const { rows } = await (0, pool_1.query)(`UPDATE webhooks SET enabled=$1 WHERE id=$2 AND tenant_id=$3 RETURNING id,name,enabled`, [enabled, req.params.webhookId, res.locals.tenantId]);
        if (!rows.length)
            throw response_1.Errors.notFound('Webhook');
        return (0, response_1.ok)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
exports.webhooksRouter.delete('/:webhookId', async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`DELETE FROM webhooks WHERE id=$1 AND tenant_id=$2 RETURNING id`, [req.params.webhookId, res.locals.tenantId]);
        if (!rows.length)
            throw response_1.Errors.notFound('Webhook');
        return (0, response_1.noContent)(res);
    }
    catch (err) {
        next(err);
    }
});
// Internal: fire webhook event
async function fireWebhook(tenantId, event, payload) {
    const { rows } = await (0, pool_1.query)(`SELECT id,url,secret_hash,headers FROM webhooks
     WHERE tenant_id=$1 AND enabled=true AND $2=ANY(events)`, [tenantId, event]);
    for (const wh of rows) {
        const body = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
        const sig = (0, crypto_1.createHash)('sha256').update(`${wh.secret_hash}${body}`).digest('hex');
        fetch(wh.url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Webhook-Signature': sig,
                'X-Webhook-Event': event,
                ...(wh.headers || {}),
            },
            body,
            signal: AbortSignal.timeout(10000),
        }).then(async (r) => {
            await (0, pool_1.query)(`INSERT INTO webhook_deliveries(webhook_id,event_type,payload,response_status,delivered_at)
         VALUES($1,$2,$3::jsonb,$4,now())`, [wh.id, event, JSON.stringify(payload), r.status]);
            if (!r.ok) {
                await (0, pool_1.query)(`UPDATE webhooks SET failure_count=failure_count+1 WHERE id=$1`, [wh.id]);
            }
            else {
                await (0, pool_1.query)(`UPDATE webhooks SET failure_count=0,last_triggered=now() WHERE id=$1`, [wh.id]);
            }
        }).catch(async (err) => {
            await (0, pool_1.query)(`INSERT INTO webhook_deliveries(webhook_id,event_type,payload,failed_at)
         VALUES($1,$2,$3::jsonb,now())`, [wh.id, event, JSON.stringify(payload)]);
            await (0, pool_1.query)(`UPDATE webhooks SET failure_count=failure_count+1 WHERE id=$1`, [wh.id]);
        });
    }
}
// ══════════════════════════════════════════════════════════
// EDGE FUNCTIONS ROUTER
// ══════════════════════════════════════════════════════════
exports.edgeFunctionsRouter = (0, express_1.Router)({ mergeParams: true });
exports.edgeFunctionsRouter.use(index_1.requireTenant);
exports.edgeFunctionsRouter.post('/', index_1.requireAuth, async (req, res, next) => {
    try {
        const { name, slug, sourceCode, memoryMb = 128, timeoutMs = 5000, envVars = {}, triggerType = 'http' } = req.body;
        if (!name || !slug || !sourceCode)
            throw response_1.Errors.validation('name, slug, sourceCode required');
        if (!/^[a-z0-9-]+$/.test(slug))
            throw response_1.Errors.validation('slug must be lowercase alphanumeric and hyphens');
        // Syntax check (basic)
        try {
            new Function(sourceCode);
        }
        catch (e) {
            throw response_1.Errors.validation(`Syntax error: ${e.message}`);
        }
        const { rows } = await (0, pool_1.query)(`INSERT INTO edge_functions(tenant_id,name,slug,source_code,memory_mb,timeout_ms,env_vars,trigger_type)
       VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
       ON CONFLICT(tenant_id,slug)
       DO UPDATE SET source_code=EXCLUDED.source_code,
                     version=edge_functions.version+1,
                     updated_at=now()
       RETURNING id,name,slug,version,trigger_type,created_at`, [res.locals.tenantId, name, slug, sourceCode, memoryMb, timeoutMs,
            JSON.stringify(envVars), triggerType]);
        return (0, response_1.created)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
exports.edgeFunctionsRouter.get('/', index_1.requireAuth, async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`SELECT id,name,slug,version,memory_mb,timeout_ms,trigger_type,is_active,created_at,updated_at
       FROM edge_functions WHERE tenant_id=$1 AND is_active=true ORDER BY created_at DESC`, [res.locals.tenantId]);
        return (0, response_1.ok)(res, rows);
    }
    catch (err) {
        next(err);
    }
});
exports.edgeFunctionsRouter.post('/:slug/invoke', async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`SELECT id,source_code,memory_mb,timeout_ms,env_vars FROM edge_functions
       WHERE tenant_id=$1 AND slug=$2 AND is_active=true`, [res.locals.tenantId, req.params.slug]);
        if (!rows.length)
            throw response_1.Errors.notFound('Edge Function');
        const fn = rows[0];
        const start = Date.now();
        // Safe sandbox using Function constructor (basic VM)
        // For production: use isolated-vm or a Worker thread
        let result;
        const sandboxEnv = fn.env_vars || {};
        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Function timed out')), fn.timeout_ms);
            try {
                const handlerFn = new Function('payload', 'env', 'console', `
          ${fn.source_code}
          if (typeof handler === 'function') return handler(payload, { env });
          return undefined;
        `);
                const sandboxConsole = {
                    log: (...a) => logger_1.logger.info('[edge] ' + a.join(' ')),
                    error: (...a) => logger_1.logger.error('[edge] ' + a.join(' ')),
                };
                result = handlerFn(req.body, sandboxEnv, sandboxConsole);
                clearTimeout(timeout);
                resolve();
            }
            catch (err) {
                clearTimeout(timeout);
                reject(err);
            }
        });
        // If result is a Promise, await it
        if (result && typeof result.then === 'function') {
            result = await Promise.race([
                result,
                new Promise((_, reject) => setTimeout(() => reject(new Error('Async function timed out')), fn.timeout_ms)),
            ]);
        }
        (0, pool_1.query)(`UPDATE edge_functions SET deploy_count=COALESCE(deploy_count,0)+1 WHERE id=$1`, [fn.id]).catch(() => { });
        return (0, response_1.ok)(res, { result, durationMs: Date.now() - start });
    }
    catch (err) {
        if (err.message?.includes('timed out')) {
            return next({ statusCode: 504, code: 'TIMEOUT', message: err.message });
        }
        next(err);
    }
});
exports.edgeFunctionsRouter.delete('/:slug', index_1.requireAuth, async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`UPDATE edge_functions SET is_active=false WHERE tenant_id=$1 AND slug=$2 RETURNING id`, [res.locals.tenantId, req.params.slug]);
        if (!rows.length)
            throw response_1.Errors.notFound('Edge Function');
        return (0, response_1.noContent)(res);
    }
    catch (err) {
        next(err);
    }
});
// ══════════════════════════════════════════════════════════
// NOTIFICATIONS ROUTER
// ══════════════════════════════════════════════════════════
exports.notificationsRouter = (0, express_1.Router)({ mergeParams: true });
exports.notificationsRouter.use(index_1.requireTenant, index_1.requireAuth);
// Lazy email transport
let emailTransport = null;
function getTransport() {
    if (!emailTransport) {
        emailTransport = nodemailer_1.default.createTransport({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT || '587'),
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
            pool: true,
        });
    }
    return emailTransport;
}
exports.notificationsRouter.post('/send', async (req, res, next) => {
    try {
        const { to, channel, template: templateName, subject, body, variables = {}, priority = 'normal' } = req.body;
        if (!to || !channel)
            throw response_1.Errors.validation('to and channel required');
        const recipients = Array.isArray(to) ? to : [to];
        let finalSubject = subject || '(no subject)';
        let finalHtml = body || '';
        let finalText = body || '';
        // Load template if specified
        if (templateName) {
            const { rows } = await (0, pool_1.query)(`SELECT subject,body_html,body_text FROM notification_templates
         WHERE tenant_id=$1 AND name=$2 AND channel=$3 AND is_active=true`, [res.locals.tenantId, templateName, channel]);
            if (rows.length) {
                const tmpl = rows[0];
                const render = (src) => src ? handlebars_1.default.compile(src)(variables) : '';
                finalSubject = render(tmpl.subject) || finalSubject;
                finalHtml = render(tmpl.body_html) || finalHtml;
                finalText = render(tmpl.body_text) || finalText;
            }
        }
        const logIds = [];
        for (const recipient of recipients) {
            const { rows } = await (0, pool_1.query)(`INSERT INTO notification_logs(tenant_id,channel,recipient,status)
         VALUES($1,$2,$3,'pending') RETURNING id`, [res.locals.tenantId, channel, recipient]);
            logIds.push(rows[0].id);
        }
        // Send async (fire-and-forget)
        setImmediate(async () => {
            for (let i = 0; i < recipients.length; i++) {
                try {
                    if (channel === 'email' && process.env.SMTP_HOST) {
                        const info = await getTransport().sendMail({
                            from: process.env.EMAIL_FROM || 'noreply@example.com',
                            to: recipients[i],
                            subject: finalSubject,
                            html: finalHtml || undefined,
                            text: finalText || undefined,
                        });
                        await (0, pool_1.query)(`UPDATE notification_logs SET status='sent',provider_id=$1 WHERE id=$2`, [info.messageId, logIds[i]]);
                    }
                    else {
                        // Log as sent if no transport configured
                        logger_1.logger.info(`[notify] Would send ${channel} to ${recipients[i]}: ${finalSubject}`);
                        await (0, pool_1.query)(`UPDATE notification_logs SET status='sent' WHERE id=$1`, [logIds[i]]);
                    }
                }
                catch (err) {
                    logger_1.logger.error(`[notify] Failed to send to ${recipients[i]}:`, err.message);
                    await (0, pool_1.query)(`UPDATE notification_logs SET status='failed' WHERE id=$1`, [logIds[i]]);
                }
            }
        });
        return (0, response_1.ok)(res, { queued: true, logIds, recipients: recipients.length }, undefined, 202);
    }
    catch (err) {
        next(err);
    }
});
exports.notificationsRouter.post('/templates', async (req, res, next) => {
    try {
        const { name, channel, subject, bodyHtml, bodyText, variables = [] } = req.body;
        if (!name || !channel)
            throw response_1.Errors.validation('name and channel required');
        const { rows } = await (0, pool_1.query)(`INSERT INTO notification_templates(tenant_id,name,channel,subject,body_html,body_text,variables)
       VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)
       ON CONFLICT(tenant_id,name,channel)
       DO UPDATE SET subject=EXCLUDED.subject,body_html=EXCLUDED.body_html,
                     body_text=EXCLUDED.body_text,version=notification_templates.version+1
       RETURNING id,name,channel,version`, [res.locals.tenantId, name, channel, subject || null, bodyHtml || null, bodyText || null, JSON.stringify(variables)]);
        return (0, response_1.created)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
exports.notificationsRouter.get('/templates', async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`SELECT id,name,channel,subject,variables,version,created_at FROM notification_templates
       WHERE tenant_id=$1 AND is_active=true ORDER BY name`, [res.locals.tenantId]);
        return (0, response_1.ok)(res, rows);
    }
    catch (err) {
        next(err);
    }
});
exports.notificationsRouter.get('/logs', async (req, res, next) => {
    try {
        const page = Math.max(1, parseInt(req.query.page || '1'));
        const limit = Math.min(100, parseInt(req.query.limit || '20'));
        const offset = (page - 1) * limit;
        const { rows } = await (0, pool_1.query)(`SELECT id,channel,recipient,status,provider_id,opened_at,clicked_at,created_at
       FROM notification_logs WHERE tenant_id=$1
       ORDER BY created_at DESC LIMIT $2 OFFSET $3`, [res.locals.tenantId, limit, offset]);
        const { rows: countRows } = await (0, pool_1.query)(`SELECT COUNT(*) FROM notification_logs WHERE tenant_id=$1`, [res.locals.tenantId]);
        return (0, response_1.paginate)(res, rows, parseInt(countRows[0].count), page, limit);
    }
    catch (err) {
        next(err);
    }
});
// Open pixel tracking
exports.notificationsRouter.get('/tracking/:logId/open', async (req, res, next) => {
    try {
        (0, pool_1.query)(`UPDATE notification_logs SET status='delivered',opened_at=now() WHERE id=$1`, [req.params.logId]).catch(() => { });
        const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
        res.setHeader('Content-Type', 'image/gif');
        res.setHeader('Cache-Control', 'no-store');
        res.end(pixel);
    }
    catch (err) {
        next(err);
    }
});
// ══════════════════════════════════════════════════════════
// ANALYTICS ROUTER
// ══════════════════════════════════════════════════════════
exports.analyticsRouter = (0, express_1.Router)({ mergeParams: true });
exports.analyticsRouter.use(index_1.requireTenant, index_1.requireAuth);
exports.analyticsRouter.get('/overview', async (req, res, next) => {
    try {
        const period = req.query.period || '24h';
        const intervalMap = {
            '1h': '1 hour', '24h': '24 hours', '7d': '7 days', '30d': '30 days',
        };
        const interval = intervalMap[period] || '24 hours';
        const tenantId = res.locals.tenantId;
        const [stats, errors, timeline] = await Promise.all([
            (0, pool_1.query)(`SELECT
           COUNT(*) AS total_requests,
           COUNT(*) FILTER(WHERE status_code < 400) AS successful,
           COUNT(*) FILTER(WHERE status_code >= 400) AS client_errors,
           COUNT(*) FILTER(WHERE status_code >= 500) AS server_errors,
           COALESCE(AVG(duration_ms),0)::int AS avg_duration_ms,
           COALESCE(MAX(duration_ms),0)::int AS max_duration_ms
         FROM request_logs
         WHERE tenant_id=$1 AND created_at > now()-$2::interval`, [tenantId, interval]),
            (0, pool_1.query)(`SELECT status_code, COUNT(*) as count FROM request_logs
         WHERE tenant_id=$1 AND created_at > now()-$2::interval AND status_code >= 400
         GROUP BY status_code ORDER BY count DESC LIMIT 10`, [tenantId, interval]),
            (0, pool_1.query)(`SELECT date_trunc('hour', created_at) AS hour,
                COUNT(*) AS requests,
                COALESCE(AVG(duration_ms),0)::int AS avg_ms
         FROM request_logs
         WHERE tenant_id=$1 AND created_at > now()-$2::interval
         GROUP BY hour ORDER BY hour`, [tenantId, interval]),
        ]);
        return (0, response_1.ok)(res, { period, stats: stats.rows[0], errors: errors.rows, timeline: timeline.rows });
    }
    catch (err) {
        next(err);
    }
});
exports.analyticsRouter.get('/requests', async (req, res, next) => {
    try {
        const page = Math.max(1, parseInt(req.query.page || '1'));
        const limit = Math.min(100, parseInt(req.query.limit || '50'));
        const offset = (page - 1) * limit;
        const tenantId = res.locals.tenantId;
        const conds = ['tenant_id=$1'];
        const params = [tenantId];
        let pi = 2;
        if (req.query.status) {
            conds.push(`status_code=$${pi++}`);
            params.push(parseInt(req.query.status));
        }
        if (req.query.method) {
            conds.push(`method=$${pi++}`);
            params.push(req.query.method.toUpperCase());
        }
        if (req.query.traceId) {
            conds.push(`trace_id=$${pi++}`);
            params.push(req.query.traceId);
        }
        const { rows } = await (0, pool_1.query)(`SELECT id,trace_id,method,path,status_code,duration_ms,ip_address,created_at
       FROM request_logs WHERE ${conds.join(' AND ')}
       ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`, params);
        const { rows: countRows } = await (0, pool_1.query)(`SELECT COUNT(*) FROM request_logs WHERE ${conds.join(' AND ')}`, params);
        return (0, response_1.paginate)(res, rows, parseInt(countRows[0].count), page, limit);
    }
    catch (err) {
        next(err);
    }
});
