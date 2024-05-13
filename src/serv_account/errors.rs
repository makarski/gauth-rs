use reqwest::StatusCode;
use ring::error::{KeyRejected, Unspecified};
use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceAccountFromFileError {
    #[error("failed to read key file: {0}: {1}")]
    ReadFile(PathBuf, io::Error),

    #[error("failed to de/serialize to json")]
    DeserializeFile(#[from] serde_json::Error),

    #[error("Failed to initialize service account: {0}")]
    ServiceAccountInitialization(ServiceAccountBuildError),

    #[error("Failed to get access token: {0}")]
    GetAccessToken(GetAccessTokenError),
}

#[derive(Debug, Error)]
pub enum ServiceAccountBuildError {
    #[error("RSA private key didn't start with PEM prefix: -----BEGIN PRIVATE KEY-----")]
    RsaPrivateKeyNoPrefix,

    #[error("RSA private key didn't end with PEM suffix: -----END PRIVATE KEY-----")]
    RsaPrivateKeyNoSuffix,

    #[error("RSA private key could not be decoded as base64: {0}")]
    RsaPrivateKeyDecode(base64::DecodeError),

    #[error("RSA private key could not be parsed: {0}")]
    RsaPrivateKeyParse(KeyRejected),
}

#[derive(Debug, Error)]
pub enum GetAccessTokenError {
    #[error("failed to serialize JSON: {0}")]
    JsonSerialization(serde_json::Error),

    #[error("failed to RSA sign: {0}")]
    RsaSign(Unspecified),

    #[error("failed to send request")]
    HttpRequest(reqwest::Error),

    #[error("failed to send request")]
    HttpRequestUnsuccessful(StatusCode, std::result::Result<String, reqwest::Error>),

    #[error("failed to get response JSON")]
    HttpJson(reqwest::Error),

    #[error("response returned non-Bearer auth access token: {0}")]
    AccessTokenNotBearer(String),

    // TODO error variant for invalid authentication
}
