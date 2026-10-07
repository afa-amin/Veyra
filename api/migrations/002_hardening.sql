ALTER TABLE files ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email));
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_files_status ON files (status);
CREATE INDEX IF NOT EXISTS idx_transfers_status_expiry ON transfers (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_transfers_file ON transfers (file_id);
CREATE INDEX IF NOT EXISTS idx_download_attempts_transfer ON download_attempts (transfer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_download_sessions_expiry ON download_sessions (expires_at);
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin'));
ALTER TABLE transfers DROP CONSTRAINT IF EXISTS transfers_status_check;
ALTER TABLE transfers ADD CONSTRAINT transfers_status_check CHECK (status IN ('active', 'revoked', 'expired', 'downloaded'));
ALTER TABLE transfers DROP CONSTRAINT IF EXISTS transfers_access_mode_check;
ALTER TABLE transfers ADD CONSTRAINT transfers_access_mode_check CHECK (access_mode IN ('simple', 'restricted'));
ALTER TABLE files DROP CONSTRAINT IF EXISTS files_status_check;
ALTER TABLE files ADD CONSTRAINT files_status_check CHECK (status IN ('active', 'deleted'))
