use serde_json::error as serde_err;
use std::{error, io, result};
use thiserror::Error;

pub type Result<T> = result::Result<T, AuthError>;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("failed to identify home directory")]
    HomeDirError,

    #[error("failed to read key file: {0}")]
    IOError(#[from] io::Error),

    #[error("failed to de/serialize to json: {0}")]
    JSONError(#[from] serde_err::Error),

    #[error("failed to make an HttpRequest: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("failed to parse url: {0}")]
    UrlError(#[from] url::ParseError),

    #[error("failed to retrieve redirect_uri from credentials")]
    RedirectUriCfgError,

    #[error("AuthHandler error:{0}")]
    UserError(Box<dyn error::Error>),

    #[error("expected a refresh token string value, got None")]
    RefreshTokenValue,
}
