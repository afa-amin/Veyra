use crate::{config::Config, error::AppError};
use async_trait::async_trait;
use std::{path::{Path, PathBuf}, sync::Arc};
use tokio::{fs, io::AsyncWriteExt};
use aws_sdk_s3::{primitives::ByteStream, Client};

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), AppError>;
    async fn get_file(&self, key: &str, destination: &Path) -> Result<(), AppError>;
    async fn delete(&self, key: &str) -> Result<(), AppError>;
    async fn exists(&self, key: &str) -> Result<bool, AppError>;
}

pub struct LocalStore { root: PathBuf }
#[async_trait]
impl ObjectStore for LocalStore {
    async fn put_file(&self,key:&str,path:&Path)->Result<(),AppError>{ let dst=self.root.join(key); if let Some(p)=dst.parent(){fs::create_dir_all(p).await?;} match fs::rename(path,&dst).await { Ok(_) => {}, Err(_) => {fs::copy(path,&dst).await?; fs::remove_file(path).await?;} } Ok(()) }
    async fn get_file(&self,key:&str,destination:&Path)->Result<(),AppError>{ fs::copy(self.root.join(key),destination).await?; Ok(()) }
    async fn delete(&self,key:&str)->Result<(),AppError>{ let p=self.root.join(key); if fs::try_exists(&p).await? { fs::remove_file(p).await?; } Ok(()) }
    async fn exists(&self,key:&str)->Result<bool,AppError>{ Ok(fs::try_exists(self.root.join(key)).await?) }
}

pub struct S3Store { client: Client, bucket: String }
#[async_trait]
impl ObjectStore for S3Store {
    async fn put_file(&self,key:&str,path:&Path)->Result<(),AppError>{ self.client.put_object().bucket(&self.bucket).key(key).body(ByteStream::from_path(path).await.map_err(|e|AppError::Internal(e.into()))?).send().await.map_err(|e|AppError::Internal(e.into()))?; Ok(()) }
    async fn get_file(&self,key:&str,destination:&Path)->Result<(),AppError>{ let out=self.client.get_object().bucket(&self.bucket).key(key).send().await.map_err(|e|AppError::Internal(e.into()))?; let mut body=out.body; let mut f=fs::File::create(destination).await?; while let Some(chunk)=body.next().await { let chunk=chunk.map_err(|e|AppError::Internal(e.into()))?; f.write_all(&chunk).await?; } f.flush().await?; Ok(()) }
    async fn delete(&self,key:&str)->Result<(),AppError>{ self.client.delete_object().bucket(&self.bucket).key(key).send().await.map_err(|e|AppError::Internal(e.into()))?; Ok(()) }
    async fn exists(&self,key:&str)->Result<bool,AppError>{ Ok(self.client.head_object().bucket(&self.bucket).key(key).send().await.is_ok()) }
}

pub async fn build_store(cfg:&Config)->Result<Arc<dyn ObjectStore>,AppError>{
    match cfg.storage_driver.as_str(){
        "local"=>{fs::create_dir_all(cfg.data_dir.join("objects")).await?; Ok(Arc::new(LocalStore{root:cfg.data_dir.join("objects")}))},
        "s3"=>{let region=aws_config::Region::new(cfg.s3_region.clone()); let mut loader=aws_config::from_env().region(region); if let (Some(a),Some(s))=(cfg.s3_access_key.clone(),cfg.s3_secret_key.clone()){loader=loader.credentials_provider(aws_sdk_s3::config::Credentials::new(a,s,None,None,"veyra"));} let shared=loader.load().await; let mut b=aws_sdk_s3::config::Builder::from(&shared); if let Some(e)=&cfg.s3_endpoint{b=b.endpoint_url(e);} let client=Client::from_conf(b.build()); let bucket=cfg.s3_bucket.clone().ok_or_else(||AppError::BadRequest("S3_BUCKET is required".into()))?; Ok(Arc::new(S3Store{client,bucket}))},
        _=>Err(AppError::BadRequest("Unsupported storage driver".into()))
    }
}
