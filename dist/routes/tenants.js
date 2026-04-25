"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const uuid_1 = require("uuid");
const pool_1 = require("../db/pool");
const response_1 = require("../utils/response");
const index_1 = require("../middleware/index");
const router = (0, express_1.Router)();
function slugify(text) {
    return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
function schemaName(slug) {
    return `t_${slug.replace(/-/g, '_')}`;
}
// ── POST /tenants ─ Create a new tenant ───────────────────
router.post('/', async (req, res, next) => {
    try {
        const { name, plan = 'free' } = req.body;
        if (!name)
            throw response_1.Errors.validation('name is required');
        const slug = slugify(name);
        const schema = schemaName(slug);
        const { rows: existing } = await (0, pool_1.query)(`SELECT id FROM tenants WHERE slug=$1`, [slug]);
        if (existing.length)
            throw response_1.Errors.conflict(`Tenant '${slug}' already exists`);
        const tenantId = (0, uuid_1.v4)();
        await (0, pool_1.withTransaction)(async (client) => {
            // Create tenant record
            await client.query(`INSERT INTO tenants(id,name,slug,plan,schema_name,settings)
         VALUES($1,$2,$3,$4,$5,$6::jsonb)`, [tenantId, name, slug, plan, schema, JSON.stringify({
                    maxApiKeys: 10,
                    maxCollections: plan === 'free' ? 10 : 100,
                    maxStorageMB: plan === 'free' ? 100 : 10000,
                    maxRequestsPerMonth: plan === 'free' ? 10000 : 1000000,
                })]);
            // Default roles
            await client.query(`INSERT INTO roles(tenant_id,name,description,is_system) VALUES
         ($1,'admin','Full access',true),
         ($1,'user','Standard user',true)`, [tenantId]);
        });
        return (0, response_1.created)(res, { id: tenantId, name, slug, plan });
    }
    catch (err) {
        next(err);
    }
});
// ── GET /tenants/:slug ────────────────────────────────────
router.get('/:slug', index_1.requireAuth, async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`SELECT id, name, slug, plan, settings, created_at FROM tenants WHERE slug=$1`, [req.params.slug]);
        if (!rows.length)
            throw response_1.Errors.notFound('Tenant');
        return (0, response_1.ok)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
// ── GET /tenants/:slug/stats ──────────────────────────────
router.get('/:slug/stats', index_1.requireAuth, async (req, res, next) => {
    try {
        const { rows: tenantRows } = await (0, pool_1.query)(`SELECT id FROM tenants WHERE slug=$1 AND is_active=true`, [req.params.slug]);
        if (!tenantRows.length)
            throw response_1.Errors.notFound('Tenant');
        const tenantId = tenantRows[0].id;
        const [usersResult, collectionsResult, requestsResult] = await Promise.all([
            (0, pool_1.query)(`SELECT COUNT(*) FROM users WHERE tenant_id=$1`, [tenantId]),
            (0, pool_1.query)(`SELECT COUNT(*) FROM collections WHERE tenant_id=$1`, [tenantId]),
            (0, pool_1.query)(`SELECT COUNT(*) FROM request_logs WHERE tenant_id=$1 AND created_at > now()-interval'30 days'`, [tenantId]),
        ]);
        return (0, response_1.ok)(res, {
            users: parseInt(usersResult.rows[0].count),
            collections: parseInt(collectionsResult.rows[0].count),
            requests30d: parseInt(requestsResult.rows[0].count),
        });
    }
    catch (err) {
        next(err);
    }
});
exports.default = router;
