# API

Base path: `/api/v1`. All state-changing authenticated requests need the `X-CSRF-Token` header (value of the `veyra_csrf` cookie).

## Authentication

```text
POST /auth/register     {email, password (>= 12 chars), display_name}
POST /auth/login
POST /auth/logout
GET  /me
```

## Transfers (sender)

```text
GET  /transfers
POST /transfers                 multipart
POST /transfers/:id/revoke      deletes the encrypted object immediately
```

`POST /transfers` fields: `file`, `recipient_email`, `access_mode` (`simple` | `restricted`), `expires_hours` (1-720), `download_limit` (1-1000 or `unlimited`), `destroy_after_first`, and for restricted mode `policy_expression`. Requirements are always derived server-side from the validated expression. Policies accept at most 1024 characters, 32 distinct attributes and 8 nesting levels.

Allowed attributes: `clearance>=N` (1-10), `department=x`, `role=x`, `project=x`, `organization=x` (values `[a-z0-9._-]`, max 64).

## Recipient

```text
GET  /download/:token                           file name, size, expiry (no recipient address)
POST /download/:token/request-verification      {email}   always answers identically
POST /download/:token/verify                    {email, code (8 digits)}
GET  /download/:token/status                    remaining downloads
GET  /download/:token/file                      streaming download
```

`verify` sets an HttpOnly, SameSite=Strict cookie scoped to the link and also returns `access_token` for API clients (`Authorization: Bearer`). A recipient who does not satisfy the policy gets `403` without consuming a download.

## Administration

```text
GET  /admin/users
POST /admin/users/:id/attributes    {attributes: ["clearance>=3", "department=ops"]}
```

## Health

```text
GET /health
GET /ready
```

Rate-limited endpoints answer `429` with `Retry-After`.
