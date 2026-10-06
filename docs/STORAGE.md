# Storage

The API depends on the `ObjectStore` abstraction.

## Local

Encrypted objects live under:

```text
data/objects/<user-id>/<transfer-id>.vobj
```

Only encrypted objects are persistent. Temporary plaintext files are removed after encryption.

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
