# Deployment

## Docker Compose

```bash
cp .env.docker.example .env      # set POSTGRES_PASSWORD and VEYRA_MASTER_ENCRYPTION_KEY
docker compose up --build
```

The compose file builds a release image that runs as an unprivileged user and only exposes nginx. It is suitable for evaluation. For production put a TLS terminator in front of nginx, set `VEYRA_ENV=production`, `VEYRA_PUBLIC_BASE_URL=https://...`, SMTP settings and `VEYRA_ADMIN_EMAIL`.

## Bare metal (Ubuntu/Debian)

```bash
sudo ./installer/install.sh --domain veyra.example.com --admin-email you@example.com \
     --tls-cert /etc/ssl/veyra/fullchain.pem --tls-key /etc/ssl/veyra/privkey.pem
```

The installer builds the project, creates a sandboxed systemd unit (no capabilities, private /tmp and devices, read-only filesystem except the data directory) and an Nginx site with security headers, HSTS (with TLS), per-endpoint rate limits and access-log redaction of link tokens. Production mode requires SMTP.

## Operations

- Back up PostgreSQL, `master.v2.enc` and the master secret together. Losing the master key makes every stored transfer unreadable.
- The API refuses to start if `master.v2.enc` is missing while encrypted transfers exist.
- Rate limits are per API instance. Multi-instance setups should rate limit at the proxy as well.
- Upgrading from 0.1: objects created by 0.1 used an insecure CP-ABE attribute mapping and cannot be read by 0.2. See `RELEASE_NOTES.md`.
