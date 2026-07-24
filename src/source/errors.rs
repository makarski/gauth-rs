//! Error types for the v2 token source API.

use std::result::Result as StdResult;
use thiserror::Error;

use crate::serv_account::errors::ServiceAccountError;

/// Failures while fetching a token from a [`crate::source::TokenSource`].
#[derive(Debug, Error)]
pub enum SourceError {
    /// Service-account JWT exchange failed.
    #[error("service account error: {0}")]
    ServiceAccount(#[from] ServiceAccountError),

    /// Metadata-server fetch failed.
    #[error("metadata server error: {0}")]
    Metadata(#[from] crate::metadata::errors::MetadataError),

    /// Failure from a source implemented outside this crate.
    #[error("token fetch failed: {0}")]
    Custom(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Convenience alias for token source results.
pub type Result<T> = StdResult<T, SourceError>;
