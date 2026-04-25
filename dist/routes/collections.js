"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const pool_1 = require("../db/pool");
const response_1 = require("../utils/response");
const index_1 = require("../middleware/index");
const router = (0, express_1.Router)({ mergeParams: true });
// All routes require tenant
router.use(index_1.requireTenant);
function safeName(name) {
    return name.replace(/[^a-z0-9_]/gi, '_').toLowerCase();
}
function pgType(type) {
    const map = {
        string: 'TEXT', number: 'NUMERIC', boolean: 'BOOLEAN',
        date: 'DATE', datetime: 'TIMESTAMPTZ',
        json: 'JSONB', array: 'JSONB', relation: 'UUID', file: 'TEXT',
    };
    return map[type] ?? 'TEXT';
}
// ── POST /schema — Create collection ──────────────────────
router.post('/schema', index_1.requireAuth, async (req, res, next) => {
    try {
        const { name, displayName, fields = [] } = req.body;
        if (!name || !/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name))
            throw response_1.Errors.validation('name must start with a letter, alphanumeric/underscore only');
        if (!displayName)
            throw response_1.Errors.validation('displayName is required');
        const tenantId = res.locals.tenantId;
        const tableName = safeName(name);
        const { rows: existing } = await (0, pool_1.query)(`SELECT id FROM collections WHERE tenant_id=$1 AND name=$2`, [tenantId, name]);
        if (existing.length)
            throw response_1.Errors.conflict(`Collection '${name}' already exists`);
        // Build column definitions
        const colDefs = fields.map((f) => {
            const t = pgType(f.type);
            const nn = f.required ? 'NOT NULL' : '';
            const uq = f.unique ? 'UNIQUE' : '';
            return `  ${safeName(f.name)} ${t} ${nn} ${uq}`.trim();
        }).join(',\n');
        const createTableSQL = `
      CREATE TABLE IF NOT EXISTS ${tableName} (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        ${colDefs ? colDefs + ',' : ''}
        created_by  UUID,
        created_at  TIMESTAMPTZ DEFAULT now(),
        updated_at  TIMESTAMPTZ DEFAULT now()
      )
    `;
        await (0, pool_1.withTransaction)(async (client) => {
            // Create physical table in the shared public schema (namespaced by tenant prefix)
            await client.query(createTableSQL);
            // GIN indexes for JSONB fields
            for (const f of fields) {
                if (f.type === 'json' || f.type === 'array') {
                    await client.query(`CREATE INDEX IF NOT EXISTS idx_${tableName}_${safeName(f.name)}_gin
             ON ${tableName} USING GIN (${safeName(f.name)})`);
                }
                if (f.type === 'string') {
                    await client.query(`CREATE INDEX IF NOT EXISTS idx_${tableName}_${safeName(f.name)}_trgm
             ON ${tableName} USING GIN (${safeName(f.name)} gin_trgm_ops)`);
                }
            }
            // Register collection metadata
            await client.query(`INSERT INTO collections(tenant_id,name,display_name,schema_def)
         VALUES($1,$2,$3,$4::jsonb)`, [tenantId, name, displayName, JSON.stringify({ fields })]);
        });
        return (0, response_1.created)(res, { name, displayName, fields, tableName });
    }
    catch (err) {
        next(err);
    }
});
// ── GET /schema — List collections ───────────────────────
router.get('/schema', index_1.requireAuth, async (req, res, next) => {
    try {
        const { rows } = await (0, pool_1.query)(`SELECT id, name, display_name, schema_def, created_at FROM collections
       WHERE tenant_id=$1 ORDER BY created_at`, [res.locals.tenantId]);
        return (0, response_1.ok)(res, rows);
    }
    catch (err) {
        next(err);
    }
});
// ── DELETE /schema/:name ──────────────────────────────────
router.delete('/schema/:collectionName', index_1.requireAuth, async (req, res, next) => {
    try {
        const { collectionName } = req.params;
        const tableName = safeName(collectionName);
        await (0, pool_1.withTransaction)(async (client) => {
            await client.query(`DROP TABLE IF EXISTS ${tableName}`);
            await client.query(`DELETE FROM collections WHERE tenant_id=$1 AND name=$2`, [res.locals.tenantId, collectionName]);
        });
        return (0, response_1.noContent)(res);
    }
    catch (err) {
        next(err);
    }
});
// ── Collection CRUD ───────────────────────────────────────
async function getCollection(tenantId, name) {
    const { rows } = await (0, pool_1.query)(`SELECT schema_def FROM collections WHERE tenant_id=$1 AND name=$2`, [tenantId, name]);
    if (!rows.length)
        throw response_1.Errors.notFound('Collection');
    return rows[0];
}
function buildWhere(filter, startIdx = 1) {
    if (!filter)
        return { clause: '', params: [] };
    const params = [];
    let idx = startIdx;
    function processGroup(group) {
        const parts = (group.conditions || []).map((cond) => {
            if (cond.conditions)
                return `(${processGroup(cond)})`;
            return processCondition(cond);
        });
        return parts.filter(Boolean).join(` ${group.operator || 'AND'} `);
    }
    function processCondition(c) {
        if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(c.field))
            return '';
        switch (c.operator) {
            case 'eq':
                params.push(c.value);
                return `${c.field} = $${idx++}`;
            case 'neq':
                params.push(c.value);
                return `${c.field} != $${idx++}`;
            case 'gt':
                params.push(c.value);
                return `${c.field} > $${idx++}`;
            case 'gte':
                params.push(c.value);
                return `${c.field} >= $${idx++}`;
            case 'lt':
                params.push(c.value);
                return `${c.field} < $${idx++}`;
            case 'lte':
                params.push(c.value);
                return `${c.field} <= $${idx++}`;
            case 'like':
                params.push(`%${c.value}%`);
                return `${c.field} ILIKE $${idx++}`;
            case 'in':
                params.push(c.value);
                return `${c.field} = ANY($${idx++})`;
            case 'is_null': return `${c.field} IS NULL`;
            case 'is_not_null': return `${c.field} IS NOT NULL`;
            default: return '';
        }
    }
    const clause = processGroup(filter);
    return { clause: clause ? `WHERE ${clause}` : '', params };
}
// GET /collections/:name
router.get('/:collectionName', async (req, res, next) => {
    try {
        const { collectionName } = req.params;
        await getCollection(res.locals.tenantId, collectionName);
        const tableName = safeName(collectionName);
        const page = Math.max(1, parseInt(req.query.page || '1'));
        const limit = Math.min(1000, parseInt(req.query.limit || '20'));
        const offset = (page - 1) * limit;
        let filter = undefined;
        try {
            if (req.query.filter)
                filter = JSON.parse(req.query.filter);
        }
        catch { }
        const search = req.query.search;
        const sort = req.query.sort || 'created_at';
        const order = req.query.order === 'asc' ? 'ASC' : 'DESC';
        const safeSort = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(sort) ? sort : 'created_at';
        const { clause, params } = buildWhere(filter, 1);
        // Full-text search
        let whereStr = clause;
        const extraParams = [...params];
        if (search) {
            const searchParam = `%${search}%`;
            extraParams.push(searchParam);
            const searchCond = `id::text ILIKE $${extraParams.length}`;
            whereStr = whereStr ? `${whereStr} AND (${searchCond})` : `WHERE (${searchCond})`;
        }
        const [dataRes, countRes] = await Promise.all([
            (0, pool_1.query)(`SELECT * FROM ${tableName} ${whereStr} ORDER BY ${safeSort} ${order} LIMIT ${limit} OFFSET ${offset}`, extraParams),
            (0, pool_1.query)(`SELECT COUNT(*) FROM ${tableName} ${whereStr}`, extraParams),
        ]);
        return (0, response_1.paginate)(res, dataRes.rows, parseInt(countRes.rows[0].count), page, limit);
    }
    catch (err) {
        next(err);
    }
});
// GET /collections/:name/:id
router.get('/:collectionName/:id', async (req, res, next) => {
    try {
        const { collectionName, id } = req.params;
        await getCollection(res.locals.tenantId, collectionName);
        const { rows } = await (0, pool_1.query)(`SELECT * FROM ${safeName(collectionName)} WHERE id=$1`, [id]);
        if (!rows.length)
            throw response_1.Errors.notFound(collectionName);
        return (0, response_1.ok)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
// POST /collections/:name
router.post('/:collectionName', async (req, res, next) => {
    try {
        const { collectionName } = req.params;
        const col = await getCollection(res.locals.tenantId, collectionName);
        const fields = col.schema_def?.fields || [];
        const tableName = safeName(collectionName);
        const data = req.body;
        // Validate required fields
        for (const f of fields) {
            if (f.required && (data[f.name] === undefined || data[f.name] === null)) {
                throw response_1.Errors.validation(`Field '${f.name}' is required`);
            }
        }
        // Only insert known fields
        const allowedFields = new Set(fields.map((f) => f.name));
        const insertData = {};
        for (const key of Object.keys(data)) {
            if (allowedFields.has(key))
                insertData[key] = data[key];
        }
        if (res.locals.user?.sub)
            insertData.created_by = res.locals.user.sub;
        const cols = Object.keys(insertData);
        const vals = Object.values(insertData);
        const phs = vals.map((_, i) => `$${i + 1}`).join(', ');
        if (!cols.length)
            throw response_1.Errors.validation('No valid fields provided');
        const { rows } = await (0, pool_1.query)(`INSERT INTO ${tableName} (${cols.join(', ')}) VALUES (${phs}) RETURNING *`, vals);
        return (0, response_1.created)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
// PUT /collections/:name/:id
router.put('/:collectionName/:id', async (req, res, next) => {
    try {
        const { collectionName, id } = req.params;
        const col = await getCollection(res.locals.tenantId, collectionName);
        const fields = col.schema_def?.fields || [];
        const tableName = safeName(collectionName);
        const allowedFields = new Set(fields.map((f) => f.name));
        const updateData = {};
        for (const key of Object.keys(req.body)) {
            if (allowedFields.has(key))
                updateData[key] = req.body[key];
        }
        if (!Object.keys(updateData).length)
            throw response_1.Errors.validation('No valid fields to update');
        const setClauses = Object.keys(updateData).map((k, i) => `${k}=$${i + 2}`).join(', ');
        const { rows } = await (0, pool_1.query)(`UPDATE ${tableName} SET ${setClauses}, updated_at=now() WHERE id=$1 RETURNING *`, [id, ...Object.values(updateData)]);
        if (!rows.length)
            throw response_1.Errors.notFound(collectionName);
        return (0, response_1.ok)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
// PATCH /collections/:name/:id
router.patch('/:collectionName/:id', async (req, res, next) => {
    try {
        const { collectionName, id } = req.params;
        await getCollection(res.locals.tenantId, collectionName);
        const tableName = safeName(collectionName);
        const patch = req.body;
        const safe = {};
        for (const k of Object.keys(patch)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(k) && k !== 'id')
                safe[k] = patch[k];
        }
        if (!Object.keys(safe).length)
            throw response_1.Errors.validation('No valid fields to patch');
        const setClauses = Object.keys(safe).map((k, i) => `${k}=$${i + 2}`).join(', ');
        const { rows } = await (0, pool_1.query)(`UPDATE ${tableName} SET ${setClauses}, updated_at=now() WHERE id=$1 RETURNING *`, [id, ...Object.values(safe)]);
        if (!rows.length)
            throw response_1.Errors.notFound(collectionName);
        return (0, response_1.ok)(res, rows[0]);
    }
    catch (err) {
        next(err);
    }
});
// DELETE /collections/:name/:id
router.delete('/:collectionName/:id', async (req, res, next) => {
    try {
        const { collectionName, id } = req.params;
        await getCollection(res.locals.tenantId, collectionName);
        const { rows } = await (0, pool_1.query)(`DELETE FROM ${safeName(collectionName)} WHERE id=$1 RETURNING id`, [id]);
        if (!rows.length)
            throw response_1.Errors.notFound(collectionName);
        return (0, response_1.noContent)(res);
    }
    catch (err) {
        next(err);
    }
});
// POST /collections/:name/bulk
router.post('/:collectionName/bulk', index_1.requireAuth, async (req, res, next) => {
    try {
        const { collectionName } = req.params;
        const { operation, records } = req.body;
        if (!records?.length)
            throw response_1.Errors.validation('records array required');
        if (records.length > 500)
            throw response_1.Errors.validation('Max 500 records per bulk operation');
        const col = await getCollection(res.locals.tenantId, collectionName);
        const fields = col.schema_def?.fields || [];
        const allowedFields = new Set(fields.map((f) => f.name));
        const tableName = safeName(collectionName);
        let results = [];
        await (0, pool_1.withTransaction)(async (client) => {
            if (operation === 'insert') {
                for (const record of records) {
                    const d = {};
                    for (const k of Object.keys(record)) {
                        if (allowedFields.has(k))
                            d[k] = record[k];
                    }
                    const cols = Object.keys(d);
                    const vals = Object.values(d);
                    const phs = vals.map((_, i) => `$${i + 1}`).join(', ');
                    const { rows } = await client.query(`INSERT INTO ${tableName} (${cols.join(', ')}) VALUES (${phs}) RETURNING *`, vals);
                    results.push(rows[0]);
                }
            }
            else if (operation === 'delete') {
                const ids = records.map((r) => r.id).filter(Boolean);
                const { rows } = await client.query(`DELETE FROM ${tableName} WHERE id = ANY($1::uuid[]) RETURNING id`, [ids]);
                results = rows;
            }
        });
        return (0, response_1.ok)(res, { affected: results.length, records: results });
    }
    catch (err) {
        next(err);
    }
});
exports.default = router;
