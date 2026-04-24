import { Router, Request, Response, NextFunction } from 'express';
import { v4 as uuid } from 'uuid';
import { query, withTransaction } from '../db/pool';
import { ok, created, noContent, AppError, Errors } from '../utils/response';
import { requireAuth } from '../middleware/index';

const router = Router();

function slugify(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function schemaName(slug: string): string {
  return `t_${slug.replace(/-/g, '_')}`;
}

// ── POST /tenants ─ Create a new tenant ───────────────────
router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, plan = 'free' } = req.body;
    if (!name) throw Errors.validation('name is required');

    const slug = slugify(name);
    const schema = schemaName(slug);

    const { rows: existing } = await query(
      `SELECT id FROM tenants WHERE slug=$1`, [slug]
    );
    if (existing.length) throw Errors.conflict(`Tenant '${slug}' already exists`);

    const tenantId = uuid();

    await withTransaction(async (client) => {
      // Create tenant record
      await client.query(
        `INSERT INTO tenants(id,name,slug,plan,schema_name,settings)
         VALUES($1,$2,$3,$4,$5,$6::jsonb)`,
        [tenantId, name, slug, plan, schema, JSON.stringify({
          maxApiKeys: 10,
          maxCollections: plan === 'free' ? 10 : 100,
          maxStorageMB: plan === 'free' ? 100 : 10000,
          maxRequestsPerMonth: plan === 'free' ? 10000 : 1000000,
        })]
      );

      // Default roles
      await client.query(
        `INSERT INTO roles(tenant_id,name,description,is_system) VALUES
         ($1,'admin','Full access',true),
         ($1,'user','Standard user',true)`,
        [tenantId]
      );
    });

    return created(res, { id: tenantId, name, slug, plan });
  } catch (err) { next(err); }
});

// ── GET /tenants/:slug ────────────────────────────────────
router.get('/:slug', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `SELECT id, name, slug, plan, settings, created_at FROM tenants WHERE slug=$1`,
      [req.params.slug]
    );
    if (!rows.length) throw Errors.notFound('Tenant');
    return ok(res, rows[0]);
  } catch (err) { next(err); }
});

// ── GET /tenants/:slug/stats ──────────────────────────────
router.get('/:slug/stats', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows: tenantRows } = await query(
      `SELECT id FROM tenants WHERE slug=$1 AND is_active=true`, [req.params.slug]
    );
    if (!tenantRows.length) throw Errors.notFound('Tenant');
    const tenantId = (tenantRows[0] as any).id;

    const [usersResult, collectionsResult, requestsResult] = await Promise.all([
      query(`SELECT COUNT(*) FROM users WHERE tenant_id=$1`, [tenantId]),
      query(`SELECT COUNT(*) FROM collections WHERE tenant_id=$1`, [tenantId]),
      query(
        `SELECT COUNT(*) FROM request_logs WHERE tenant_id=$1 AND created_at > now()-interval'30 days'`,
        [tenantId]
      ),
    ]);

    return ok(res, {
      users:        parseInt((usersResult.rows[0] as any).count),
      collections:  parseInt((collectionsResult.rows[0] as any).count),
      requests30d:  parseInt((requestsResult.rows[0] as any).count),
    });
  } catch (err) { next(err); }
});

export default router;
