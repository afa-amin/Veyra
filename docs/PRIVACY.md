# Privacy

Veyra stores the minimum metadata needed to operate transfers:

- account email and display name
- transfer recipient email
- filename, size, MIME type, status, and timestamps
- access policy requirements
- download counts and audit events

File contents are not stored in plaintext in persistent object storage. Audit records must never contain file contents, passwords, session tokens, OTP values, private keys, or DEKs.

Deployments should define retention periods for expired transfers, audit events, and account records according to their legal and operational requirements.
