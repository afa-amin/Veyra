# Configuration

See `.env.example`.

Required:

- `DATABASE_URL`
- `VEYRA_MASTER_ENCRYPTION_KEY`

Storage:

- `STORAGE_DRIVER=local` for development.
- `STORAGE_DRIVER=s3` for S3-compatible object storage.

Never commit production secrets. Use a secret manager or protected environment injection for the master encryption key and database credentials.
