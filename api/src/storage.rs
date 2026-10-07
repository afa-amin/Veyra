//! Object storage backends. Objects are always Veyra ciphertext.

use crate::{config::Config, error::AppError};
use async_trait::async_trait;
use aws_sdk_s3::{primitives::ByteStream, Client};
use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::{fs, io::AsyncWriteExt};

#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Store the file at `path` under `key`. The source file may be consumed.
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), AppError>;
    async fn get_file(&self, key: &str, destination: &Path) -> Result<(), AppError>;
    async fn delete(&self, key: &str) -> Result<(), AppError>;
    async fn exists(&self, key: &str) -> Result<bool, AppError>;
    /// Path to read the object directly without copying, if the backend is local.
    async fn local_path(&self, _key: &str) -> Option<PathBuf> {
        None
    }
}

/// Resolve `key` below `root`, rejecting anything that could escape it.
fn safe_join(root: &Path, key: &str) -> Result<PathBuf, AppError> {
    let rel = Path::new(key);
    if key.is_empty() || rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(AppError::Internal(anyhow::anyhow!("invalid object key")));
    }
    Ok(root.join(rel))
}

pub struct LocalStore {
    root: PathBuf,
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

#[async_trait]
impl ObjectStore for LocalStore {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), AppError> {
        let dst = safe_join(&self.root, key)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).await?;
            restrict_dir(parent);
        }
        if fs::rename(path, &dst).await.is_err() {
            // Different filesystems: copy then remove the source.
            fs::copy(path, &dst).await?;
            fs::remove_file(path).await?;
        }
        restrict_file(&dst);
        Ok(())
    }

    async fn get_file(&self, key: &str, destination: &Path) -> Result<(), AppError> {
        fs::copy(safe_join(&self.root, key)?, destination).await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        let p = safe_join(&self.root, key)?;
        match fs::remove_file(p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, AppError> {
        Ok(fs::try_exists(safe_join(&self.root, key)?).await?)
    }

    async fn local_path(&self, key: &str) -> Option<PathBuf> {
        safe_join(&self.root, key).ok()
    }
}

pub struct S3Store {
    client: Client,
    bucket: String,
}

fn internal<E: std::error::Error + Send + Sync + 'static>(e: E) -> AppError {
    AppError::Internal(e.into())
}

#[async_trait]
impl ObjectStore for S3Store {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), AppError> {
        let body = ByteStream::from_path(path).await.map_err(internal)?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .map_err(internal)?;
        Ok(())
    }

    async fn get_file(&self, key: &str, destination: &Path) -> Result<(), AppError> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(internal)?;
        let mut body = out.body;
        let mut f = fs::File::create(destination).await?;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(internal)?;
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(internal)?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, AppError> {
        Ok(self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .is_ok())
    }
}

pub async fn build_store(cfg: &Config) -> Result<Arc<dyn ObjectStore>, AppError> {
    match cfg.storage_driver.as_str() {
        "local" => {
            let root = cfg.data_dir.join("objects");
            fs::create_dir_all(&root).await?;
            restrict_dir(&root);
            Ok(Arc::new(LocalStore { root }))
        }
        "s3" => {
            let region = aws_config::Region::new(cfg.s3_region.clone());
            let mut loader = aws_config::from_env().region(region);
            if let (Some(a), Some(s)) = (cfg.s3_access_key.clone(), cfg.s3_secret_key.clone()) {
                loader = loader.credentials_provider(aws_sdk_s3::config::Credentials::new(
                    a, s, None, None, "veyra",
                ));
            }
            let shared = loader.load().await;
            let mut b = aws_sdk_s3::config::Builder::from(&shared);
            if let Some(e) = &cfg.s3_endpoint {
                b = b.endpoint_url(e).force_path_style(true);
            }
            let client = Client::from_conf(b.build());
            let bucket = cfg
                .s3_bucket
                .clone()
                .ok_or_else(|| AppError::bad("S3_BUCKET is required"))?;
            Ok(Arc::new(S3Store { client, bucket }))
        }
        _ => Err(AppError::bad("Unsupported storage driver")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_escapes() {
        let root = Path::new("/data/objects");
        assert!(safe_join(root, "user/abc.vobj").is_ok());
        assert!(safe_join(root, "../etc/passwd").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "a/../../b").is_err());
        assert!(safe_join(root, "").is_err());
    }
}
