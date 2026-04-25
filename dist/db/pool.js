"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pool = void 0;
exports.query = query;
exports.withTransaction = withTransaction;
exports.schemaName = schemaName;
exports.tenantQuery = tenantQuery;
exports.testConnection = testConnection;
const pg_1 = require("pg");
// Render provides DATABASE_URL with SSL required
exports.pool = new pg_1.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false } // Render self-signed cert
        : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
});
exports.pool.on('error', (err) => {
    console.error('DB pool error:', err.message);
});
async function query(sql, params = []) {
    const client = await exports.pool.connect();
    try {
        return await client.query(sql, params);
    }
    finally {
        client.release();
    }
}
async function withTransaction(fn) {
    const client = await exports.pool.connect();
    try {
        await client.query('BEGIN');
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
    }
    catch (err) {
        await client.query('ROLLBACK');
        throw err;
    }
    finally {
        client.release();
    }
}
// Tenant schema helpers
function schemaName(tenantSlug) {
    return `t_${tenantSlug.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`;
}
async function tenantQuery(tenantSlug, sql, params = []) {
    const schema = schemaName(tenantSlug);
    const client = await exports.pool.connect();
    try {
        await client.query(`SET search_path TO "${schema}", public`);
        return await client.query(sql, params);
    }
    finally {
        await client.query(`SET search_path TO public`).catch(() => { });
        client.release();
    }
}
async function testConnection() {
    const res = await query('SELECT NOW() as now');
    console.log('✅ Database connected:', res.rows[0].now);
}
