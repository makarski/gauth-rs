//! Error types for the metadata-server token source.

use std::result::Result as StdResult;
use thiserror::Error;

/// Failures while obtaining a token from the metadata server.
#[derive(Debug, Error)]
pub enum MetadataError {
    /// The metadata server was unreachable or answered with an error
    /// status (e.g. the workload has no attached service account).
    #[error("metadata server request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The response body was not the expected token JSON.
    #[error("malformed metadata token response: {0}")]
    Malformed(String),
}

/// Convenience alias for metadata token results.
pub type Result<T> = StdResult<T, MetadataError>;
