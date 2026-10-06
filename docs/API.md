# API

Base path: `/api/v1`

## Authentication

```text
POST /auth/register
POST /auth/login
POST /auth/logout
GET  /me
```

## Transfers

```text
GET  /transfers
POST /transfers
POST /transfers/:id/revoke
```

`POST /transfers` is multipart and accepts `file`, `recipient_email`, `access_mode`, `expires_hours`, `download_limit`, `destroy_after_first`, `policy_requirements`, and `policy_expression`.

## Recipient

```text
GET  /download/:token
POST /download/:token/request-verification
POST /download/:token/verify
GET  /download/:token/file
```

The file endpoint requires a short-lived verification access token in the `Authorization: Bearer ...` header.

## Health

```text
GET /health
GET /ready
```
