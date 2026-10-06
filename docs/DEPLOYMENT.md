# Deployment

## Docker Compose

Development:

```bash
docker compose up
```

## Linux production

Recommended layout:

```text
nginx → Veyra API systemd service → PostgreSQL
                             └────→ S3/MinIO
```

Run the API as a dedicated unprivileged service account. Keep its data directory inaccessible to other users. Terminate TLS at Nginx and enable HSTS after confirming the domain is HTTPS-only.

The current repository's Compose setup is intentionally a development environment. Production secrets, TLS certificates, SMTP credentials, PostgreSQL credentials, and the master encryption key must be replaced before deployment.
