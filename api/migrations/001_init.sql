CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  display_name text NOT NULL,
  role text NOT NULL DEFAULT 'user',
  attributes jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS files (
  id uuid PRIMARY KEY,
  original_filename text NOT NULL,
  size_bytes bigint NOT NULL,
  mime_type text NOT NULL,
  object_key text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  sender_id uuid NOT NULL REFERENCES users(id),
  status text NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS transfers (
  id uuid PRIMARY KEY,
  file_id uuid NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  sender_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_email text NOT NULL,
  access_mode text NOT NULL,
  access_policy jsonb NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  download_limit integer,
  download_count integer NOT NULL DEFAULT 0,
  destroy_after_first boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active',
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_transfers_sender ON transfers(sender_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfers_expiry ON transfers(expires_at);

CREATE TABLE IF NOT EXISTS recipients (
  id uuid PRIMARY KEY,
  transfer_id uuid NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
  email text NOT NULL,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_policies (
  id uuid PRIMARY KEY,
  transfer_id uuid NOT NULL UNIQUE REFERENCES transfers(id) ON DELETE CASCADE,
  expression text NOT NULL,
  requirements jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS download_attempts (
  id uuid PRIMARY KEY,
  transfer_id uuid NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
  recipient_email text NOT NULL,
  success boolean NOT NULL,
  ip_hash text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  transfer_id uuid REFERENCES transfers(id) ON DELETE SET NULL,
  event text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_transfer ON audit_events(transfer_id, created_at DESC);

CREATE TABLE IF NOT EXISTS otp_challenges (
  id uuid PRIMARY KEY,
  transfer_id uuid NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  consumed boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_otp_transfer ON otp_challenges(transfer_id, created_at DESC);

CREATE TABLE IF NOT EXISTS download_sessions (
  id uuid PRIMARY KEY,
  transfer_id uuid NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
