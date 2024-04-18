use reqwest::StatusCode;
use ring::error::{KeyRejected, Unspecified};
use std::{io, path::PathBuf, result::Result as StdResult};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceAccountError {
    #[error("failed to read key file: {0}: {1}")]
    ReadKey(PathBuf, io::Error),

    #[error("failed to de/serialize to json")]
    SerdeJson(#[from] serde_json::Error),

    #[error("failed to decode base64")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("failed to create rsa key pair: {0}")]
    RsaKeyPair(KeyRejected),

    #[error("failed to rsa sign: {0}")]
    RsaSign(Unspecified),

    #[error("failed to send request")]
    HttpRequest(reqwest::Error),

    #[error("failed to send request")]
    HttpRequestUnsuccessful(StatusCode, std::result::Result<String, reqwest::Error>),

    #[error("failed to get response JSON")]
    HttpJson(reqwest::Error),

    #[error("response returned non-Bearer auth access token: {0}")]
    AccessTokenNotBeaarer(String),
}

pub type Result<T> = StdResult<T, ServiceAccountError>;
