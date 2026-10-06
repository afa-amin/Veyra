# Threat Model

## Assets

- File contents
- DEKs and ABE master material
- User credentials and sessions
- Transfer bearer tokens
- Recipient identity
- Access policy metadata
- Audit integrity

## Threats

### Malicious recipient

A recipient must pass verification and policy authorization before decryption. Restricted transfers additionally require an existing account with matching attributes.

### Compromised object storage

Persistent objects are ciphertext. Object keys are random and contain no filename or sequential identifier.

### Compromised database

Database compromise exposes metadata and hashed session/transfer/OTP values, but not plaintext objects. It can still expose sensitive metadata, so database encryption and access control remain necessary.

### Stolen transfer link

The link is a high-entropy bearer capability. Recipient verification and expiration reduce misuse, but a stolen link remains sensitive. Revoke is provided to the sender.

### Replay

OTP challenges are single-use. Download sessions are short-lived. Transfer download limits are enforced transactionally.

### Concurrent downloads

Transfer rows are locked before a download slot is reserved, preventing two requests from both consuming the last available slot.

### Malicious filename

Filenames never become filesystem paths. Object keys are server generated.

### Malicious policy

Policy strings are parsed by the policy parser and never executed as code.

### Compromised application server

A fully compromised API host can access plaintext during upload/decryption and can access the master key if it is available to the process. This is an explicit trust-model limitation and is why the product is not called E2EE.
