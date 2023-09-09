use std::result::Result as StdResult;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceAccountError {
    #[error("failed to read key file: {0}")]
    ReadKey(String),

    #[error("failed to de/serialize to json")]
    SerdeJson(#[from] serde_json::Error),

    #[error("failed to decode base64")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("failed to create rsa key pair: {0}")]
    RsaKeyPair(String),

    #[error("failed to rsa sign: {0}")]
    RsaSign(String),

    #[error("failed to send request")]
    HttpReqwest(#[from] reqwest::Error),
}

pub type Result<T> = StdResult<T, ServiceAccountError>;
