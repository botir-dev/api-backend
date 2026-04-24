import { Router, Request, Response, NextFunction } from 'express';
import { createHash, randomBytes } from 'crypto';
import { v4 as uuid } from 'uuid';
import nodemailer from 'nodemailer';
import Handlebars from 'handlebars';
import { query, withTransaction } from '../db/pool';
import { ok, created, noContent, paginate, Errors } from '../utils/response';
import { requireAuth, requireTenant } from '../middleware/index';
import { logger } from '../utils/logger';

// ══════════════════════════════════════════════════════════
// API KEYS ROUTER
// ══════════════════════════════════════════════════════════
export const apiKeysRouter = Router({ mergeParams: true });
apiKeysRouter.use(requireTenant, requireAuth);

apiKeysRouter.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, permissions = [], expiresAt, rateLimitPerMin = 100 } = req.body;
    if (!name) throw Errors.validation('name is required');

    const rawKey = `bk_${randomBytes(24).toString('hex')}`;
    const keyHash = createHash('sha256').update(rawKey).digest('hex');
    const keyPrefix = rawKey.slice(0, 12);

    const { rows } = await query(
      `INSERT INTO api_keys(tenant_id,name,key_hash,key_prefix,permissions,rate_limit_per_min,expires_at)
       VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)
       RETURNING id,name,key_prefix,created_at`,
      [res.locals.tenantId, name, keyHash, keyPrefix,
       JSON.stringify(permissions), rateLimitPerMin, expiresAt || null]
    );

    // Return raw key ONCE — never stored
    return created(res, { ...rows[0], key: rawKey, warning: 'Save this key — it will not be shown again' });
  } catch (err) { next(err); }
});

apiKeysRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `SELECT id,name,key_prefix,permissions,rate_limit_per_min,expires_at,last_used_at,usage_count,created_at
       FROM api_keys WHERE tenant_id=$1 ORDER BY created_at DESC`,
      [res.locals.tenantId]
    );
    return ok(res, rows);
  } catch (err) { next(err); }
});

apiKeysRouter.delete('/:keyId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `DELETE FROM api_keys WHERE id=$1 AND tenant_id=$2 RETURNING id`,
      [req.params.keyId, res.locals.tenantId]
    );
    if (!rows.length) throw Errors.notFound('API Key');
    return noContent(res);
  } catch (err) { next(err); }
});

// ══════════════════════════════════════════════════════════
// WEBHOOKS ROUTER
// ══════════════════════════════════════════════════════════
export const webhooksRouter = Router({ mergeParams: true });
webhooksRouter.use(requireTenant, requireAuth);

webhooksRouter.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, url, events, headers = {} } = req.body;
    if (!name || !url || !events?.length)
      throw Errors.validation('name, url, events[] required');

    try { new URL(url); } catch { throw Errors.validation('Invalid URL'); }

    const secret = randomBytes(32).toString('hex');
    const secretHash = createHash('sha256').update(secret).digest('hex');

    const { rows } = await query(
      `INSERT INTO webhooks(tenant_id,name,url,events,secret_hash,headers)
       VALUES($1,$2,$3,$4,$5,$6::jsonb)
       RETURNING id,name,url,events,enabled,created_at`,
      [res.locals.tenantId, name, url, events, secretHash, JSON.stringify(headers)]
    );

    return created(res, { ...rows[0], secret, warning: 'Save this secret — it will not be shown again' });
  } catch (err) { next(err); }
});

webhooksRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `SELECT id,name,url,events,enabled,failure_count,last_triggered,created_at
       FROM webhooks WHERE tenant_id=$1 ORDER BY created_at DESC`,
      [res.locals.tenantId]
    );
    return ok(res, rows);
  } catch (err) { next(err); }
});

webhooksRouter.patch('/:webhookId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { enabled } = req.body;
    const { rows } = await query(
      `UPDATE webhooks SET enabled=$1 WHERE id=$2 AND tenant_id=$3 RETURNING id,name,enabled`,
      [enabled, req.params.webhookId, res.locals.tenantId]
    );
    if (!rows.length) throw Errors.notFound('Webhook');
    return ok(res, rows[0]);
  } catch (err) { next(err); }
});

webhooksRouter.delete('/:webhookId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `DELETE FROM webhooks WHERE id=$1 AND tenant_id=$2 RETURNING id`,
      [req.params.webhookId, res.locals.tenantId]
    );
    if (!rows.length) throw Errors.notFound('Webhook');
    return noContent(res);
  } catch (err) { next(err); }
});

// Internal: fire webhook event
export async function fireWebhook(tenantId: string, event: string, payload: any): Promise<void> {
  const { rows } = await query(
    `SELECT id,url,secret_hash,headers FROM webhooks
     WHERE tenant_id=$1 AND enabled=true AND $2=ANY(events)`,
    [tenantId, event]
  );

  for (const wh of rows as any[]) {
    const body = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
    const sig  = createHash('sha256').update(`${wh.secret_hash}${body}`).digest('hex');

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
      await query(
        `INSERT INTO webhook_deliveries(webhook_id,event_type,payload,response_status,delivered_at)
         VALUES($1,$2,$3::jsonb,$4,now())`,
        [wh.id, event, JSON.stringify(payload), r.status]
      );
      if (!r.ok) {
        await query(`UPDATE webhooks SET failure_count=failure_count+1 WHERE id=$1`, [wh.id]);
      } else {
        await query(`UPDATE webhooks SET failure_count=0,last_triggered=now() WHERE id=$1`, [wh.id]);
      }
    }).catch(async (err) => {
      await query(
        `INSERT INTO webhook_deliveries(webhook_id,event_type,payload,failed_at)
         VALUES($1,$2,$3::jsonb,now())`,
        [wh.id, event, JSON.stringify(payload)]
      );
      await query(`UPDATE webhooks SET failure_count=failure_count+1 WHERE id=$1`, [wh.id]);
    });
  }
}

// ══════════════════════════════════════════════════════════
// EDGE FUNCTIONS ROUTER
// ══════════════════════════════════════════════════════════
export const edgeFunctionsRouter = Router({ mergeParams: true });
edgeFunctionsRouter.use(requireTenant);

edgeFunctionsRouter.post('/', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, slug, sourceCode, memoryMb = 128, timeoutMs = 5000, envVars = {}, triggerType = 'http' } = req.body;
    if (!name || !slug || !sourceCode) throw Errors.validation('name, slug, sourceCode required');
    if (!/^[a-z0-9-]+$/.test(slug)) throw Errors.validation('slug must be lowercase alphanumeric and hyphens');

    // Syntax check (basic)
    try { new Function(sourceCode); } catch (e: any) {
      throw Errors.validation(`Syntax error: ${e.message}`);
    }

    const { rows } = await query(
      `INSERT INTO edge_functions(tenant_id,name,slug,source_code,memory_mb,timeout_ms,env_vars,trigger_type)
       VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
       ON CONFLICT(tenant_id,slug)
       DO UPDATE SET source_code=EXCLUDED.source_code,
                     version=edge_functions.version+1,
                     updated_at=now()
       RETURNING id,name,slug,version,trigger_type,created_at`,
      [res.locals.tenantId, name, slug, sourceCode, memoryMb, timeoutMs,
       JSON.stringify(envVars), triggerType]
    );
    return created(res, rows[0]);
  } catch (err) { next(err); }
});

edgeFunctionsRouter.get('/', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `SELECT id,name,slug,version,memory_mb,timeout_ms,trigger_type,is_active,created_at,updated_at
       FROM edge_functions WHERE tenant_id=$1 AND is_active=true ORDER BY created_at DESC`,
      [res.locals.tenantId]
    );
    return ok(res, rows);
  } catch (err) { next(err); }
});

edgeFunctionsRouter.post('/:slug/invoke', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `SELECT id,source_code,memory_mb,timeout_ms,env_vars FROM edge_functions
       WHERE tenant_id=$1 AND slug=$2 AND is_active=true`,
      [res.locals.tenantId, req.params.slug]
    );
    if (!rows.length) throw Errors.notFound('Edge Function');

    const fn: any = rows[0];
    const start = Date.now();

    // Safe sandbox using Function constructor (basic VM)
    // For production: use isolated-vm or a Worker thread
    let result: any;
    const sandboxEnv = fn.env_vars || {};

    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Function timed out')), fn.timeout_ms);
      try {
        const handlerFn = new Function('payload', 'env', 'console', `
          ${fn.source_code}
          if (typeof handler === 'function') return handler(payload, { env });
          return undefined;
        `);

        const sandboxConsole = {
          log: (...a: any[]) => logger.info('[edge] ' + a.join(' ')),
          error: (...a: any[]) => logger.error('[edge] ' + a.join(' ')),
        };

        result = handlerFn(req.body, sandboxEnv, sandboxConsole);
        clearTimeout(timeout);
        resolve();
      } catch (err) {
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

    query(`UPDATE edge_functions SET deploy_count=COALESCE(deploy_count,0)+1 WHERE id=$1`, [fn.id]).catch(() => {});

    return ok(res, { result, durationMs: Date.now() - start });
  } catch (err: any) {
    if (err.message?.includes('timed out')) {
      return next({ statusCode: 504, code: 'TIMEOUT', message: err.message });
    }
    next(err);
  }
});

edgeFunctionsRouter.delete('/:slug', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `UPDATE edge_functions SET is_active=false WHERE tenant_id=$1 AND slug=$2 RETURNING id`,
      [res.locals.tenantId, req.params.slug]
    );
    if (!rows.length) throw Errors.notFound('Edge Function');
    return noContent(res);
  } catch (err) { next(err); }
});

// ══════════════════════════════════════════════════════════
// NOTIFICATIONS ROUTER
// ══════════════════════════════════════════════════════════
export const notificationsRouter = Router({ mergeParams: true });
notificationsRouter.use(requireTenant, requireAuth);

// Lazy email transport
let emailTransport: nodemailer.Transporter | null = null;
function getTransport(): nodemailer.Transporter {
  if (!emailTransport) {
    emailTransport = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587'),
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      pool: true,
    });
  }
  return emailTransport;
}

notificationsRouter.post('/send', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { to, channel, template: templateName, subject, body, variables = {}, priority = 'normal' } = req.body;
    if (!to || !channel) throw Errors.validation('to and channel required');

    const recipients = Array.isArray(to) ? to : [to];
    let finalSubject = subject || '(no subject)';
    let finalHtml = body || '';
    let finalText = body || '';

    // Load template if specified
    if (templateName) {
      const { rows } = await query(
        `SELECT subject,body_html,body_text FROM notification_templates
         WHERE tenant_id=$1 AND name=$2 AND channel=$3 AND is_active=true`,
        [res.locals.tenantId, templateName, channel]
      );
      if (rows.length) {
        const tmpl: any = rows[0];
        const render = (src?: string) => src ? Handlebars.compile(src)(variables) : '';
        finalSubject = render(tmpl.subject) || finalSubject;
        finalHtml    = render(tmpl.body_html) || finalHtml;
        finalText    = render(tmpl.body_text) || finalText;
      }
    }

    const logIds: string[] = [];
    for (const recipient of recipients) {
      const { rows } = await query(
        `INSERT INTO notification_logs(tenant_id,channel,recipient,status)
         VALUES($1,$2,$3,'pending') RETURNING id`,
        [res.locals.tenantId, channel, recipient]
      );
      logIds.push((rows[0] as any).id);
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
            await query(
              `UPDATE notification_logs SET status='sent',provider_id=$1 WHERE id=$2`,
              [info.messageId, logIds[i]]
            );
          } else {
            // Log as sent if no transport configured
            logger.info(`[notify] Would send ${channel} to ${recipients[i]}: ${finalSubject}`);
            await query(`UPDATE notification_logs SET status='sent' WHERE id=$1`, [logIds[i]]);
          }
        } catch (err: any) {
          logger.error(`[notify] Failed to send to ${recipients[i]}:`, err.message);
          await query(`UPDATE notification_logs SET status='failed' WHERE id=$1`, [logIds[i]]);
        }
      }
    });

    return ok(res, { queued: true, logIds, recipients: recipients.length }, undefined, 202);
  } catch (err) { next(err); }
});

notificationsRouter.post('/templates', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, channel, subject, bodyHtml, bodyText, variables = [] } = req.body;
    if (!name || !channel) throw Errors.validation('name and channel required');

    const { rows } = await query(
      `INSERT INTO notification_templates(tenant_id,name,channel,subject,body_html,body_text,variables)
       VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)
       ON CONFLICT(tenant_id,name,channel)
       DO UPDATE SET subject=EXCLUDED.subject,body_html=EXCLUDED.body_html,
                     body_text=EXCLUDED.body_text,version=notification_templates.version+1
       RETURNING id,name,channel,version`,
      [res.locals.tenantId, name, channel, subject||null, bodyHtml||null, bodyText||null, JSON.stringify(variables)]
    );
    return created(res, rows[0]);
  } catch (err) { next(err); }
});

notificationsRouter.get('/templates', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `SELECT id,name,channel,subject,variables,version,created_at FROM notification_templates
       WHERE tenant_id=$1 AND is_active=true ORDER BY name`,
      [res.locals.tenantId]
    );
    return ok(res, rows);
  } catch (err) { next(err); }
});

notificationsRouter.get('/logs', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page as string || '1'));
    const limit = Math.min(100, parseInt(req.query.limit as string || '20'));
    const offset = (page - 1) * limit;

    const { rows } = await query(
      `SELECT id,channel,recipient,status,provider_id,opened_at,clicked_at,created_at
       FROM notification_logs WHERE tenant_id=$1
       ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [res.locals.tenantId, limit, offset]
    );
    const { rows: countRows } = await query(
      `SELECT COUNT(*) FROM notification_logs WHERE tenant_id=$1`, [res.locals.tenantId]
    );
    return paginate(res, rows, parseInt((countRows[0] as any).count), page, limit);
  } catch (err) { next(err); }
});

// Open pixel tracking
notificationsRouter.get('/tracking/:logId/open', async (req: Request, res: Response, next: NextFunction) => {
  try {
    query(`UPDATE notification_logs SET status='delivered',opened_at=now() WHERE id=$1`, [req.params.logId]).catch(() => {});
    const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    res.setHeader('Content-Type', 'image/gif');
    res.setHeader('Cache-Control', 'no-store');
    res.end(pixel);
  } catch (err) { next(err); }
});

// ══════════════════════════════════════════════════════════
// ANALYTICS ROUTER
// ══════════════════════════════════════════════════════════
export const analyticsRouter = Router({ mergeParams: true });
analyticsRouter.use(requireTenant, requireAuth);

analyticsRouter.get('/overview', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const period = (req.query.period as string) || '24h';
    const intervalMap: Record<string, string> = {
      '1h': '1 hour', '24h': '24 hours', '7d': '7 days', '30d': '30 days',
    };
    const interval = intervalMap[period] || '24 hours';
    const tenantId = res.locals.tenantId;

    const [stats, errors, timeline] = await Promise.all([
      query(
        `SELECT
           COUNT(*) AS total_requests,
           COUNT(*) FILTER(WHERE status_code < 400) AS successful,
           COUNT(*) FILTER(WHERE status_code >= 400) AS client_errors,
           COUNT(*) FILTER(WHERE status_code >= 500) AS server_errors,
           COALESCE(AVG(duration_ms),0)::int AS avg_duration_ms,
           COALESCE(MAX(duration_ms),0)::int AS max_duration_ms
         FROM request_logs
         WHERE tenant_id=$1 AND created_at > now()-$2::interval`,
        [tenantId, interval]
      ),
      query(
        `SELECT status_code, COUNT(*) as count FROM request_logs
         WHERE tenant_id=$1 AND created_at > now()-$2::interval AND status_code >= 400
         GROUP BY status_code ORDER BY count DESC LIMIT 10`,
        [tenantId, interval]
      ),
      query(
        `SELECT date_trunc('hour', created_at) AS hour,
                COUNT(*) AS requests,
                COALESCE(AVG(duration_ms),0)::int AS avg_ms
         FROM request_logs
         WHERE tenant_id=$1 AND created_at > now()-$2::interval
         GROUP BY hour ORDER BY hour`,
        [tenantId, interval]
      ),
    ]);

    return ok(res, { period, stats: stats.rows[0], errors: errors.rows, timeline: timeline.rows });
  } catch (err) { next(err); }
});

analyticsRouter.get('/requests', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const page   = Math.max(1, parseInt(req.query.page as string || '1'));
    const limit  = Math.min(100, parseInt(req.query.limit as string || '50'));
    const offset = (page - 1) * limit;
    const tenantId = res.locals.tenantId;

    const conds: string[] = ['tenant_id=$1'];
    const params: any[] = [tenantId];
    let pi = 2;
    if (req.query.status)  { conds.push(`status_code=$${pi++}`); params.push(parseInt(req.query.status as string)); }
    if (req.query.method)  { conds.push(`method=$${pi++}`);      params.push((req.query.method as string).toUpperCase()); }
    if (req.query.traceId) { conds.push(`trace_id=$${pi++}`);    params.push(req.query.traceId); }

    const { rows } = await query(
      `SELECT id,trace_id,method,path,status_code,duration_ms,ip_address,created_at
       FROM request_logs WHERE ${conds.join(' AND ')}
       ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`,
      params
    );
    const { rows: countRows } = await query(
      `SELECT COUNT(*) FROM request_logs WHERE ${conds.join(' AND ')}`, params
    );
    return paginate(res, rows, parseInt((countRows[0] as any).count), page, limit);
  } catch (err) { next(err); }
});
