# Testing

## Unit

The crypto core covers:

- Policy parsing/evaluation.
- Streaming encryption/decryption.
- Large chunked payloads.
- Ciphertext tampering failure.

## Integration targets

The API should be exercised for:

- Registration/login/logout.
- Upload and transfer creation.
- OTP request/verification.
- Successful download.
- Expiration.
- Revocation.
- Download limits.
- One-time download.
- Unauthorized transfer access.
- Restricted recipient attribute mismatch.
- IDOR attempts.

## Security regression targets

- Path traversal filenames.
- Token guessing.
- OTP brute force.
- Session fixation.
- CSRF.
- Oversized uploads.
- Concurrent last-slot downloads.
- Invalid package headers.
- Modified ciphertext.
- Policy tampering.
