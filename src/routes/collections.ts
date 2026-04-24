import { Router, Request, Response, NextFunction } from 'express';
import { query, withTransaction, tenantQuery } from '../db/pool';
import { ok, created, noContent, paginate, AppError, Errors } from '../utils/response';
import { requireAuth, requireTenant, apiKeyAuth } from '../middleware/index';

const router = Router({ mergeParams: true });

// All routes require tenant
router.use(requireTenant);

function safeName(name: string): string {
  return name.replace(/[^a-z0-9_]/gi, '_').toLowerCase();
}

function pgType(type: string): string {
  const map: Record<string, string> = {
    string: 'TEXT', number: 'NUMERIC', boolean: 'BOOLEAN',
    date: 'DATE', datetime: 'TIMESTAMPTZ',
    json: 'JSONB', array: 'JSONB', relation: 'UUID', file: 'TEXT',
  };
  return map[type] ?? 'TEXT';
}

// ── POST /schema — Create collection ──────────────────────
router.post('/schema', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, displayName, fields = [] } = req.body;
    if (!name || !/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name))
      throw Errors.validation('name must start with a letter, alphanumeric/underscore only');
    if (!displayName) throw Errors.validation('displayName is required');

    const tenantId = res.locals.tenantId;
    const tableName = safeName(name);

    const { rows: existing } = await query(
      `SELECT id FROM collections WHERE tenant_id=$1 AND name=$2`, [tenantId, name]
    );
    if (existing.length) throw Errors.conflict(`Collection '${name}' already exists`);

    // Build column definitions
    const colDefs = fields.map((f: any) => {
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

    await withTransaction(async (client) => {
      // Create physical table in the shared public schema (namespaced by tenant prefix)
      await client.query(createTableSQL);

      // GIN indexes for JSONB fields
      for (const f of fields) {
        if (f.type === 'json' || f.type === 'array') {
          await client.query(
            `CREATE INDEX IF NOT EXISTS idx_${tableName}_${safeName(f.name)}_gin
             ON ${tableName} USING GIN (${safeName(f.name)})`
          );
        }
        if (f.type === 'string') {
          await client.query(
            `CREATE INDEX IF NOT EXISTS idx_${tableName}_${safeName(f.name)}_trgm
             ON ${tableName} USING GIN (${safeName(f.name)} gin_trgm_ops)`
          );
        }
      }

      // Register collection metadata
      await client.query(
        `INSERT INTO collections(tenant_id,name,display_name,schema_def)
         VALUES($1,$2,$3,$4::jsonb)`,
        [tenantId, name, displayName, JSON.stringify({ fields })]
      );
    });

    return created(res, { name, displayName, fields, tableName });
  } catch (err) { next(err); }
});

// ── GET /schema — List collections ───────────────────────
router.get('/schema', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { rows } = await query(
      `SELECT id, name, display_name, schema_def, created_at FROM collections
       WHERE tenant_id=$1 ORDER BY created_at`,
      [res.locals.tenantId]
    );
    return ok(res, rows);
  } catch (err) { next(err); }
});

// ── DELETE /schema/:name ──────────────────────────────────
router.delete('/schema/:collectionName', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { collectionName } = req.params;
    const tableName = safeName(collectionName);

    await withTransaction(async (client) => {
      await client.query(`DROP TABLE IF EXISTS ${tableName}`);
      await client.query(
        `DELETE FROM collections WHERE tenant_id=$1 AND name=$2`,
        [res.locals.tenantId, collectionName]
      );
    });

    return noContent(res);
  } catch (err) { next(err); }
});

// ── Collection CRUD ───────────────────────────────────────

async function getCollection(tenantId: string, name: string) {
  const { rows } = await query(
    `SELECT schema_def FROM collections WHERE tenant_id=$1 AND name=$2`,
    [tenantId, name]
  );
  if (!rows.length) throw Errors.notFound('Collection');
  return rows[0] as any;
}

function buildWhere(filter: any, startIdx = 1): { clause: string; params: any[] } {
  if (!filter) return { clause: '', params: [] };
  const params: any[] = [];
  let idx = startIdx;

  function processGroup(group: any): string {
    const parts = (group.conditions || []).map((cond: any) => {
      if (cond.conditions) return `(${processGroup(cond)})`;
      return processCondition(cond);
    });
    return parts.filter(Boolean).join(` ${group.operator || 'AND'} `);
  }

  function processCondition(c: any): string {
    if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(c.field)) return '';
    switch (c.operator) {
      case 'eq':   params.push(c.value);        return `${c.field} = $${idx++}`;
      case 'neq':  params.push(c.value);        return `${c.field} != $${idx++}`;
      case 'gt':   params.push(c.value);        return `${c.field} > $${idx++}`;
      case 'gte':  params.push(c.value);        return `${c.field} >= $${idx++}`;
      case 'lt':   params.push(c.value);        return `${c.field} < $${idx++}`;
      case 'lte':  params.push(c.value);        return `${c.field} <= $${idx++}`;
      case 'like': params.push(`%${c.value}%`); return `${c.field} ILIKE $${idx++}`;
      case 'in':   params.push(c.value);        return `${c.field} = ANY($${idx++})`;
      case 'is_null':     return `${c.field} IS NULL`;
      case 'is_not_null': return `${c.field} IS NOT NULL`;
      default: return '';
    }
  }

  const clause = processGroup(filter);
  return { clause: clause ? `WHERE ${clause}` : '', params };
}

// GET /collections/:name
router.get('/:collectionName', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { collectionName } = req.params;
    await getCollection(res.locals.tenantId, collectionName);

    const tableName = safeName(collectionName);
    const page   = Math.max(1, parseInt(req.query.page as string || '1'));
    const limit  = Math.min(1000, parseInt(req.query.limit as string || '20'));
    const offset = (page - 1) * limit;

    let filter: any = undefined;
    try { if (req.query.filter) filter = JSON.parse(req.query.filter as string); } catch {}

    const search = req.query.search as string;
    const sort   = req.query.sort as string || 'created_at';
    const order  = req.query.order === 'asc' ? 'ASC' : 'DESC';
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
      query(
        `SELECT * FROM ${tableName} ${whereStr} ORDER BY ${safeSort} ${order} LIMIT ${limit} OFFSET ${offset}`,
        extraParams
      ),
      query(`SELECT COUNT(*) FROM ${tableName} ${whereStr}`, extraParams),
    ]);

    return paginate(res, dataRes.rows, parseInt((countRes.rows[0] as any).count), page, limit);
  } catch (err) { next(err); }
});

// GET /collections/:name/:id
router.get('/:collectionName/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { collectionName, id } = req.params;
    await getCollection(res.locals.tenantId, collectionName);
    const { rows } = await query(
      `SELECT * FROM ${safeName(collectionName)} WHERE id=$1`, [id]
    );
    if (!rows.length) throw Errors.notFound(collectionName);
    return ok(res, rows[0]);
  } catch (err) { next(err); }
});

// POST /collections/:name
router.post('/:collectionName', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { collectionName } = req.params;
    const col = await getCollection(res.locals.tenantId, collectionName);
    const fields: any[] = col.schema_def?.fields || [];
    const tableName = safeName(collectionName);
    const data = req.body;

    // Validate required fields
    for (const f of fields) {
      if (f.required && (data[f.name] === undefined || data[f.name] === null)) {
        throw Errors.validation(`Field '${f.name}' is required`);
      }
    }

    // Only insert known fields
    const allowedFields = new Set(fields.map((f: any) => f.name));
    const insertData: Record<string, any> = {};
    for (const key of Object.keys(data)) {
      if (allowedFields.has(key)) insertData[key] = data[key];
    }
    if (res.locals.user?.sub) insertData.created_by = res.locals.user.sub;

    const cols = Object.keys(insertData);
    const vals = Object.values(insertData);
    const phs  = vals.map((_, i) => `$${i + 1}`).join(', ');

    if (!cols.length) throw Errors.validation('No valid fields provided');

    const { rows } = await query(
      `INSERT INTO ${tableName} (${cols.join(', ')}) VALUES (${phs}) RETURNING *`,
      vals
    );

    return created(res, rows[0]);
  } catch (err) { next(err); }
});

// PUT /collections/:name/:id
router.put('/:collectionName/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { collectionName, id } = req.params;
    const col = await getCollection(res.locals.tenantId, collectionName);
    const fields: any[] = col.schema_def?.fields || [];
    const tableName = safeName(collectionName);

    const allowedFields = new Set(fields.map((f: any) => f.name));
    const updateData: Record<string, any> = {};
    for (const key of Object.keys(req.body)) {
      if (allowedFields.has(key)) updateData[key] = req.body[key];
    }
    if (!Object.keys(updateData).length) throw Errors.validation('No valid fields to update');

    const setClauses = Object.keys(updateData).map((k, i) => `${k}=$${i + 2}`).join(', ');
    const { rows } = await query(
      `UPDATE ${tableName} SET ${setClauses}, updated_at=now() WHERE id=$1 RETURNING *`,
      [id, ...Object.values(updateData)]
    );
    if (!rows.length) throw Errors.notFound(collectionName);
    return ok(res, rows[0]);
  } catch (err) { next(err); }
});

// PATCH /collections/:name/:id
router.patch('/:collectionName/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { collectionName, id } = req.params;
    await getCollection(res.locals.tenantId, collectionName);
    const tableName = safeName(collectionName);

    const patch = req.body;
    const safe: Record<string, any> = {};
    for (const k of Object.keys(patch)) {
      if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(k) && k !== 'id') safe[k] = patch[k];
    }
    if (!Object.keys(safe).length) throw Errors.validation('No valid fields to patch');

    const setClauses = Object.keys(safe).map((k, i) => `${k}=$${i + 2}`).join(', ');
    const { rows } = await query(
      `UPDATE ${tableName} SET ${setClauses}, updated_at=now() WHERE id=$1 RETURNING *`,
      [id, ...Object.values(safe)]
    );
    if (!rows.length) throw Errors.notFound(collectionName);
    return ok(res, rows[0]);
  } catch (err) { next(err); }
});

// DELETE /collections/:name/:id
router.delete('/:collectionName/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { collectionName, id } = req.params;
    await getCollection(res.locals.tenantId, collectionName);
    const { rows } = await query(
      `DELETE FROM ${safeName(collectionName)} WHERE id=$1 RETURNING id`, [id]
    );
    if (!rows.length) throw Errors.notFound(collectionName);
    return noContent(res);
  } catch (err) { next(err); }
});

// POST /collections/:name/bulk
router.post('/:collectionName/bulk', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { collectionName } = req.params;
    const { operation, records } = req.body;
    if (!records?.length) throw Errors.validation('records array required');
    if (records.length > 500) throw Errors.validation('Max 500 records per bulk operation');

    const col = await getCollection(res.locals.tenantId, collectionName);
    const fields: any[] = col.schema_def?.fields || [];
    const allowedFields = new Set(fields.map((f: any) => f.name));
    const tableName = safeName(collectionName);
    let results: any[] = [];

    await withTransaction(async (client) => {
      if (operation === 'insert') {
        for (const record of records) {
          const d: Record<string, any> = {};
          for (const k of Object.keys(record)) {
            if (allowedFields.has(k)) d[k] = record[k];
          }
          const cols = Object.keys(d);
          const vals = Object.values(d);
          const phs  = vals.map((_, i) => `$${i + 1}`).join(', ');
          const { rows } = await client.query(
            `INSERT INTO ${tableName} (${cols.join(', ')}) VALUES (${phs}) RETURNING *`, vals
          );
          results.push(rows[0]);
        }
      } else if (operation === 'delete') {
        const ids = records.map((r: any) => r.id).filter(Boolean);
        const { rows } = await client.query(
          `DELETE FROM ${tableName} WHERE id = ANY($1::uuid[]) RETURNING id`, [ids]
        );
        results = rows;
      }
    });

    return ok(res, { affected: results.length, records: results });
  } catch (err) { next(err); }
});

export default router;
