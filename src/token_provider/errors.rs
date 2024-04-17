use std::result::Result as StdResult;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::TryLockError;

use crate::serv_account::errors::ServiceAccountError;

#[derive(Debug, Error)]
pub enum TokenProviderError {
    #[error("failed to get access token: {0}")]
    AccessToken(#[from] TryLockError),

    #[error("service account error: {0}")]
    ServiceAccountError(#[from] ServiceAccountError),

    #[error("failed to send token: {0}")]
    SendError(#[from] SendError<String>),
}

pub type Result<T> = StdResult<T, TokenProviderError>;
