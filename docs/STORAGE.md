# Storage

The API depends on the `ObjectStore` abstraction.

## Local

Encrypted objects live under:

```text
data/objects/<user-id>/<transfer-id>.vobj
```

Only encrypted objects are persistent. During multipart upload, the current API must temporarily stage plaintext because the encrypted object header authenticates the final plaintext size before the stream can be encrypted.

The plaintext staging file is deliberately constrained: it uses a cryptographically random filename, is created with mode `0600`, lives only under Veyra's private `0700` temporary directory, is removed by an RAII guard on normal/error/panic paths, is purged completely at service startup after a crash, and stale leftovers are removed by the maintenance sweep after six hours. Plaintext contents are never logged and are never copied into the persistent object store. This does **not** claim secure/forensic erasure from SSDs or other storage media.

## S3-compatible

Set:

```text
STORAGE_DRIVER=s3
S3_ENDPOINT=
S3_BUCKET=
S3_REGION=
S3_ACCESS_KEY=
S3_SECRET_KEY=
```

The implementation is compatible with AWS S3 and S3-compatible endpoints such as MinIO.
