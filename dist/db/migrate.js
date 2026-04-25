"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const pool_1 = require("./pool");
const MIGRATION = `
-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  slug        TEXT UNIQUE NOT NULL,
  plan        TEXT NOT NULL DEFAULT 'free',
  schema_name TEXT UNIQUE NOT NULL,
  settings    JSONB NOT NULL DEFAULT '{}',
  is_active   BOOLEAN DEFAULT true,
  created_at  TIMESTAMPTZ DEFAULT now(),
  updated_at  TIMESTAMPTZ DEFAULT now()
);

-- Users
CREATE TABLE IF NOT EXISTS users (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email            TEXT NOT NULL,
  email_verified   BOOLEAN DEFAULT false,
  password_hash    TEXT,
  full_name        TEXT,
  avatar_url       TEXT,
  provider         TEXT DEFAULT 'email',
  provider_id      TEXT,
  metadata         JSONB DEFAULT '{}',
  last_login_at    TIMESTAMPTZ,
  is_active        BOOLEAN DEFAULT true,
  created_at       TIMESTAMPTZ DEFAULT now(),
  updated_at       TIMESTAMPTZ DEFAULT now(),
  UNIQUE(tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  refresh_token_hash  TEXT UNIQUE NOT NULL,
  device_info         JSONB DEFAULT '{}',
  ip_address          TEXT,
  expires_at          TIMESTAMPTZ NOT NULL,
  revoked_at          TIMESTAMPTZ,
  created_at          TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(refresh_token_hash);

-- Roles
CREATE TABLE IF NOT EXISTS roles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  description TEXT,
  is_system   BOOLEAN DEFAULT false,
  created_at  TIMESTAMPTZ DEFAULT now(),
  UNIQUE(tenant_id, name)
);

-- Permissions
CREATE TABLE IF NOT EXISTS permissions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  resource    TEXT NOT NULL,
  action      TEXT NOT NULL,
  conditions  JSONB DEFAULT '{}',
  UNIQUE(tenant_id, resource, action)
);

-- Role ↔ Permission
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       UUID REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

-- User ↔ Role
CREATE TABLE IF NOT EXISTS user_roles (
  user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  role_id    UUID REFERENCES roles(id) ON DELETE CASCADE,
  granted_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

-- API Keys
CREATE TABLE IF NOT EXISTS api_keys (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name                 TEXT NOT NULL,
  key_hash             TEXT UNIQUE NOT NULL,
  key_prefix           TEXT NOT NULL,
  permissions          JSONB DEFAULT '[]',
  rate_limit_per_min   INT DEFAULT 100,
  expires_at           TIMESTAMPTZ,
  last_used_at         TIMESTAMPTZ,
  usage_count          BIGINT DEFAULT 0,
  created_at           TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

-- Webhooks
CREATE TABLE IF NOT EXISTS webhooks (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  url              TEXT NOT NULL,
  events           TEXT[] NOT NULL,
  secret_hash      TEXT NOT NULL,
  headers          JSONB DEFAULT '{}',
  enabled          BOOLEAN DEFAULT true,
  failure_count    INT DEFAULT 0,
  last_triggered   TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT now()
);

-- Webhook Deliveries
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id      UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_type      TEXT NOT NULL,
  payload         JSONB NOT NULL,
  response_status INT,
  attempt_count   INT DEFAULT 1,
  delivered_at    TIMESTAMPTZ,
  failed_at       TIMESTAMPTZ,
  next_retry_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT now()
);

-- Edge Functions
CREATE TABLE IF NOT EXISTS edge_functions (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name           TEXT NOT NULL,
  slug           TEXT NOT NULL,
  source_code    TEXT NOT NULL,
  env_vars       JSONB DEFAULT '{}',
  memory_mb      INT DEFAULT 128,
  timeout_ms     INT DEFAULT 5000,
  trigger_type   TEXT DEFAULT 'http',
  trigger_config JSONB DEFAULT '{}',
  version        INT DEFAULT 1,
  is_active      BOOLEAN DEFAULT true,
  created_at     TIMESTAMPTZ DEFAULT now(),
  updated_at     TIMESTAMPTZ DEFAULT now(),
  UNIQUE(tenant_id, slug)
);

-- Notification Templates
CREATE TABLE IF NOT EXISTS notification_templates (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  channel     TEXT NOT NULL,
  subject     TEXT,
  body_html   TEXT,
  body_text   TEXT,
  variables   JSONB DEFAULT '[]',
  version     INT DEFAULT 1,
  is_active   BOOLEAN DEFAULT true,
  created_at  TIMESTAMPTZ DEFAULT now(),
  UNIQUE(tenant_id, name, channel)
);

-- Notification Logs
CREATE TABLE IF NOT EXISTS notification_logs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  channel      TEXT NOT NULL,
  template_id  UUID REFERENCES notification_templates(id),
  recipient    TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  provider_id  TEXT,
  opened_at    TIMESTAMPTZ,
  clicked_at   TIMESTAMPTZ,
  metadata     JSONB DEFAULT '{}',
  created_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notif_logs_tenant ON notification_logs(tenant_id, created_at DESC);

-- Request Logs (analytics)
CREATE TABLE IF NOT EXISTS request_logs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID REFERENCES tenants(id) ON DELETE SET NULL,
  trace_id     TEXT NOT NULL,
  method       TEXT NOT NULL,
  path         TEXT NOT NULL,
  status_code  INT NOT NULL,
  duration_ms  INT NOT NULL,
  ip_address   TEXT,
  user_agent   TEXT,
  user_id      UUID,
  error_code   TEXT,
  created_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_req_logs_tenant ON request_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_req_logs_trace  ON request_logs(trace_id);

-- Storage Objects
CREATE TABLE IF NOT EXISTS storage_objects (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  bucket       TEXT NOT NULL,
  path         TEXT NOT NULL,
  filename     TEXT NOT NULL,
  mime_type    TEXT,
  size_bytes   BIGINT NOT NULL,
  provider_url TEXT NOT NULL,
  is_public    BOOLEAN DEFAULT false,
  metadata     JSONB DEFAULT '{}',
  created_at   TIMESTAMPTZ DEFAULT now(),
  UNIQUE(tenant_id, bucket, path)
);

-- Collections metadata (per tenant, platform-level)
CREATE TABLE IF NOT EXISTS collections (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  display_name TEXT NOT NULL,
  schema_def   JSONB NOT NULL DEFAULT '{"fields":[]}',
  hooks        JSONB NOT NULL DEFAULT '[]',
  created_at   TIMESTAMPTZ DEFAULT now(),
  updated_at   TIMESTAMPTZ DEFAULT now(),
  UNIQUE(tenant_id, name)
);

-- Migration tracking
CREATE TABLE IF NOT EXISTS _migrations (
  id         SERIAL PRIMARY KEY,
  name       TEXT UNIQUE NOT NULL,
  applied_at TIMESTAMPTZ DEFAULT now()
);
`;
async function migrate() {
    console.log('🔄 Running migrations...');
    const client = await pool_1.pool.connect();
    try {
        await client.query(MIGRATION);
        await client.query(`INSERT INTO _migrations (name) VALUES ($1) ON CONFLICT DO NOTHING`, ['001_initial']);
        console.log('✅ Migrations complete');
    }
    catch (err) {
        console.error('❌ Migration failed:', err);
        throw err;
    }
    finally {
        client.release();
        await pool_1.pool.end();
    }
}
migrate().catch((err) => {
    console.error(err);
    process.exit(1);
});
