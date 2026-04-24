import { Pool, PoolClient, QueryResult } from 'pg';

// Render provides DATABASE_URL with SSL required
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }  // Render self-signed cert
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('DB pool error:', err.message);
});

export async function query<T = any>(
  sql: string,
  params: any[] = []
): Promise<QueryResult<T>> {
  const client = await pool.connect();
  try {
    return await client.query<T>(sql, params);
  } finally {
    client.release();
  }
}

export async function withTransaction<T>(
  fn: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// Tenant schema helpers
export function schemaName(tenantSlug: string): string {
  return `t_${tenantSlug.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`;
}

export async function tenantQuery<T = any>(
  tenantSlug: string,
  sql: string,
  params: any[] = []
): Promise<QueryResult<T>> {
  const schema = schemaName(tenantSlug);
  const client = await pool.connect();
  try {
    await client.query(`SET search_path TO "${schema}", public`);
    return await client.query<T>(sql, params);
  } finally {
    await client.query(`SET search_path TO public`).catch(() => {});
    client.release();
  }
}

export async function testConnection(): Promise<void> {
  const res = await query('SELECT NOW() as now');
  console.log('✅ Database connected:', res.rows[0].now);
}
