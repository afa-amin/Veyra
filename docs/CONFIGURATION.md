# Configuration

All settings are environment variables; see `.env.example` (bare metal) and `.env.docker.example` (Compose). Invalid or unsafe values stop the process at startup.

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | required | PostgreSQL URL |
| `VEYRA_MASTER_ENCRYPTION_KEY` | required | At least 32 characters. Published placeholder values are rejected in production. Argon2id turns it into the key that protects `master.v2.enc`. |
| `VEYRA_ENV` | `production` | `production` or `development`. Development prints verification codes to the log when SMTP is not configured. |
| `VEYRA_BIND` | `127.0.0.1:4000` | Listen address |
| `VEYRA_PUBLIC_BASE_URL` | `http://localhost` | Used for secure links. Cookies are `Secure` when this starts with `https://`. |
| `VEYRA_TRUST_PROXY` | `false` | Trust `X-Real-IP` from the reverse proxy for rate limiting. Enable only behind a proxy that overwrites it. |
| `VEYRA_ADMIN_EMAIL` | empty | Only this address can become the first administrator. |
| `VEYRA_ALLOW_NEW_MASTER` | `false` | Allow creating a new master key although encrypted transfers exist (makes them unreadable). |
| `VEYRA_DATA_DIR` | `./data` | Holds `master.v2.enc`, `objects/` and `tmp/` (mode 0700) |
| `STORAGE_DRIVER` | `local` | `local` or `s3` (`S3_BUCKET` required; uploads limited to 4 GiB because objects are written with a single PUT) |
| `MAX_UPLOAD_BYTES` | 5 GiB | 1 byte to 64 GiB |
| `OTP_TTL_MINUTES` | 10 | 1 to 60 |
| `SESSION_TTL_HOURS` | 24 | 1 to 720 |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | | Mandatory in production |
| `SMTP_TLS` | by port | `tls` (implicit, port 465), `starttls` (port 587) or `none` (development only) |

Never commit `.env` files or `data/`. Back up `master.v2.enc` together with the master secret: without both, stored transfers cannot be decrypted.
