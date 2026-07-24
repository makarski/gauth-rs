//! GCE/GKE metadata-server token source — keyless authentication.
//!
//! On Google compute platforms (GCE, GKE with Workload Identity, Cloud
//! Run), the metadata server issues access tokens for the workload's
//! service account with no key file involved. [`MetadataTokenSource`]
//! implements [`crate::source::TokenSource`]; wrap it in a
//! [`crate::source::CachingTokenSource`] for expiry-aware caching:
//!
//! ```no_run
//! use gauth::metadata::MetadataTokenSource;
//! use gauth::source::CachingTokenSource;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let source = CachingTokenSource::new(
//!     MetadataTokenSource::new()
//!         .with_scopes(["https://www.googleapis.com/auth/pubsub"]),
//! );
//!
//! let token = source.token().await?;
//! let header = token.authorization_header(); // "Bearer …"
//! # Ok(())
//! # }
//! ```

use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::source::{Token, TokenSource};
use errors::MetadataError;

/// Error types for this module.
pub mod errors;

const DEFAULT_METADATA_HOST: &str = "metadata.google.internal";

/// Standard override honored by Google client libraries; useful for
/// emulators and tests.
const METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";

/// Uncached token source backed by the GCE/GKE metadata server. Caching,
/// expiry handling, and single-flight refresh belong to
/// [`crate::source::CachingTokenSource`].
#[derive(Debug, Clone)]
pub struct MetadataTokenSource {
    http_client: reqwest::Client,
    token_url: String,
    scopes: Vec<String>,
}

#[derive(serde_derive::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

impl Default for MetadataTokenSource {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataTokenSource {
    /// Token source for the workload's default service account. The
    /// metadata host honors the `GCE_METADATA_HOST` environment variable.
    pub fn new() -> Self {
        Self::for_account("default")
    }

    /// Token source for a specific service account known to the metadata
    /// server (an email, or `"default"`).
    pub fn for_account(account: &str) -> Self {
        let host =
            std::env::var(METADATA_HOST_ENV).unwrap_or_else(|_| DEFAULT_METADATA_HOST.to_string());
        Self::with_base_url(format!("http://{host}"), account)
    }

    /// Explicit metadata base URL — for emulators and tests.
    pub fn with_base_url(base_url: impl Into<String>, account: &str) -> Self {
        let base_url = base_url.into();
        Self {
            http_client: reqwest::Client::new(),
            token_url: format!(
                "{}/computeMetadata/v1/instance/service-accounts/{account}/token",
                base_url.trim_end_matches('/')
            ),
            scopes: Vec::new(),
        }
    }

    /// Restrict the token to specific OAuth scopes. Without this the
    /// metadata server issues the account's configured default scopes.
    pub fn with_scopes<S: Into<String>>(mut self, scopes: impl IntoIterator<Item = S>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    async fn fetch_token(&self) -> errors::Result<Token> {
        // Scope values (URLs) and commas are query-safe per RFC 3986, so a
        // plain append avoids needing reqwest's query feature.
        let url = if self.scopes.is_empty() {
            self.token_url.clone()
        } else {
            format!("{}?scopes={}", self.token_url, self.scopes.join(","))
        };

        let response = self
            .http_client
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?;
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|e| MetadataError::Malformed(e.to_string()))?;

        Ok(Token {
            value: token.access_token,
            expires_at: Instant::now() + Duration::from_secs(token.expires_in),
            token_type: token.token_type,
        })
    }
}

#[async_trait]
impl TokenSource for MetadataTokenSource {
    async fn fetch(&self) -> crate::source::Result<Token> {
        Ok(self.fetch_token().await?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::source::CachingTokenSource;

    use super::*;

    /// Minimal fake metadata server: records each request head and
    /// answers with the given JSON body.
    async fn spawn_fake_metadata(body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len(),
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{addr}"), requests)
    }

    #[tokio::test]
    async fn fetch_returns_raw_token_with_expiry() {
        let (base, _requests) = spawn_fake_metadata(
            r#"{"access_token":"md-token","expires_in":3600,"token_type":"Bearer"}"#,
        )
        .await;
        let source = MetadataTokenSource::with_base_url(&base, "default");

        let token = source.fetch_token().await.unwrap();
        assert_eq!(token.value, "md-token");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.authorization_header(), "Bearer md-token");
        assert!(token.is_fresh(std::time::Duration::from_secs(300)));
    }

    /// The intended composition: caching, expiry, and single-flight come
    /// from `CachingTokenSource`, not from this source.
    #[tokio::test]
    async fn caching_wrapper_serves_repeat_reads_from_one_fetch() {
        let (base, requests) = spawn_fake_metadata(
            r#"{"access_token":"md-token","expires_in":3600,"token_type":"Bearer"}"#,
        )
        .await;
        let source = CachingTokenSource::new(MetadataTokenSource::with_base_url(&base, "default"));

        assert_eq!(source.token().await.unwrap().value, "md-token");
        assert_eq!(source.token().await.unwrap().value, "md-token");
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn sends_flavor_header_account_path_and_scopes() {
        let (base, requests) =
            spawn_fake_metadata(r#"{"access_token":"t","expires_in":3600,"token_type":"Bearer"}"#)
                .await;
        let source =
            MetadataTokenSource::with_base_url(&base, "publisher@p.iam.gserviceaccount.com")
                .with_scopes(["https://www.googleapis.com/auth/pubsub"]);
        source.fetch_token().await.unwrap();

        let request = requests.lock().unwrap()[0].clone();
        // reqwest lowercases header names on the wire.
        assert!(
            request.to_lowercase().contains("metadata-flavor: google"),
            "{request}"
        );
        assert!(
            request.contains(
                "/computeMetadata/v1/instance/service-accounts/publisher@p.iam.gserviceaccount.com/token"
            ),
            "{request}"
        );
        assert!(
            request.contains("?scopes=https://www.googleapis.com/auth/pubsub"),
            "{request}"
        );
    }
}
