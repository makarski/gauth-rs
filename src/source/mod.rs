//! Fetch-on-demand token sources with expiry-aware caching — the
//! recommended API for obtaining access tokens.
//!
//! A [`TokenSource`] knows how to fetch one fresh [`Token`]; wrap it in a
//! [`CachingTokenSource`] to get expiry-aware caching with single-flight
//! refresh and no background task:
//!
//! ```no_run
//! use gauth::serv_account::ServiceAccount;
//! use gauth::source::CachingTokenSource;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let account = ServiceAccount::from_file(
//!     "/path/to/key.json",
//!     vec!["https://www.googleapis.com/auth/pubsub"],
//! );
//! let source = CachingTokenSource::new(account);
//!
//! let token = source.token().await?;
//! let header = token.authorization_header(); // "Bearer …"
//! # Ok(())
//! # }
//! ```
//!
//! Compared to the deprecated [`crate::token_provider`] shape: the first
//! call either returns a valid token or a real error (never an empty
//! string), refresh happens when a token approaches expiry (not on a
//! wall-clock interval), and nothing needs `tokio` — the module is
//! runtime-agnostic.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;

pub use errors::{Result, SourceError};

/// Error types for this module.
pub mod errors;

/// Default freshness margin: tokens are refreshed when they are within
/// this window of expiring.
const DEFAULT_REFRESH_MARGIN: Duration = Duration::from_secs(300);

/// An access token together with its expiry and type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The raw token value (no `Bearer ` prefix).
    pub value: String,
    /// Monotonic expiry instant.
    pub expires_at: Instant,
    /// Token type as reported by the issuer, normally `Bearer`.
    pub token_type: String,
}

impl Token {
    /// Full `authorization` header value, e.g. `Bearer ya29…`.
    pub fn authorization_header(&self) -> String {
        format!("{} {}", self.token_type, self.value)
    }

    /// Whether the token remains valid for at least `margin` from now.
    pub fn is_fresh(&self, margin: Duration) -> bool {
        Instant::now() + margin < self.expires_at
    }
}

/// Anything that can fetch one fresh token. Implementations should not
/// cache — wrap the source in a [`CachingTokenSource`] instead.
#[async_trait]
pub trait TokenSource: Send + Sync {
    /// Fetch a fresh token from the underlying credential mechanism.
    async fn fetch(&self) -> Result<Token>;
}

/// Expiry-aware cache around a [`TokenSource`]: [`CachingTokenSource::token`]
/// returns the cached token while it is fresh and refreshes it inline —
/// with single-flight semantics — when it is missing, expired, or within
/// the refresh margin of expiring.
pub struct CachingTokenSource<T> {
    inner: T,
    cache: RwLock<Option<Token>>,
    refresh_margin: Duration,
    refresh_lock: futures::lock::Mutex<()>,
}

impl<T: TokenSource> CachingTokenSource<T> {
    /// Wrap a source with the default refresh margin (5 minutes).
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            cache: RwLock::new(None),
            refresh_margin: DEFAULT_REFRESH_MARGIN,
            refresh_lock: futures::lock::Mutex::new(()),
        }
    }

    /// Refresh when a token is within `margin` of expiring.
    pub fn with_refresh_margin(mut self, margin: Duration) -> Self {
        self.refresh_margin = margin;
        self
    }

    /// A valid token: cached while fresh, refreshed inline otherwise.
    /// Concurrent callers share one in-flight refresh; the first call
    /// either returns a valid token or the underlying fetch error.
    pub async fn token(&self) -> Result<Token> {
        if let Some(token) = self.cached_fresh() {
            return Ok(token);
        }

        let _refreshing = self.refresh_lock.lock().await;
        // Another caller may have refreshed while we waited on the lock.
        if let Some(token) = self.cached_fresh() {
            return Ok(token);
        }

        let fresh = self.inner.fetch().await?;
        *self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fresh.clone());
        Ok(fresh)
    }

    /// Warm the cache ahead of time, for callers that want zero
    /// tail-latency on their first request.
    pub async fn prefetch(&self) -> Result<()> {
        self.token().await.map(|_| ())
    }

    fn cached_fresh(&self) -> Option<Token> {
        self.cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|token| token.is_fresh(self.refresh_margin))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    struct CountingSource {
        fetches: Arc<AtomicU32>,
        expires_in: Duration,
        fail: bool,
    }

    #[async_trait]
    impl TokenSource for CountingSource {
        async fn fetch(&self) -> Result<Token> {
            // Yield so concurrent callers genuinely overlap in the
            // single-flight test.
            tokio::task::yield_now().await;
            let n = self.fetches.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail {
                return Err(SourceError::Custom("issuer unavailable".into()));
            }
            Ok(Token {
                value: format!("token-{n}"),
                expires_at: Instant::now() + self.expires_in,
                token_type: "Bearer".to_string(),
            })
        }
    }

    fn counting(expires_in: Duration) -> (CachingTokenSource<CountingSource>, Arc<AtomicU32>) {
        let fetches = Arc::new(AtomicU32::new(0));
        let source = CachingTokenSource::new(CountingSource {
            fetches: fetches.clone(),
            expires_in,
            fail: false,
        });
        (source, fetches)
    }

    /// Acceptance: 100 concurrent `token()` calls cause exactly one
    /// underlying fetch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_share_one_fetch() {
        let (source, fetches) = counting(Duration::from_secs(3600));
        let source = Arc::new(source);

        let calls = (0..100).map(|_| {
            let source = source.clone();
            tokio::spawn(async move { source.token().await.unwrap().value })
        });
        for call in calls {
            assert_eq!(call.await.unwrap(), "token-1");
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    /// Acceptance: refresh fires when the token is within the margin of
    /// expiry — and not before.
    #[tokio::test]
    async fn refresh_is_expiry_driven() {
        // Fresh well beyond the margin: cached.
        let (source, fetches) = counting(Duration::from_secs(3600));
        source.token().await.unwrap();
        source.token().await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        // Expiring within the margin: every call refreshes.
        let (source, fetches) = counting(Duration::from_secs(10));
        source.token().await.unwrap();
        source.token().await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);

        // Same expiry, but a caller-tightened margin accepts it.
        let (source, fetches) = counting(Duration::from_secs(10));
        let source = source.with_refresh_margin(Duration::from_secs(1));
        source.token().await.unwrap();
        source.token().await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    /// Acceptance: no empty-string cold state — the first call surfaces
    /// the fetch error.
    #[tokio::test]
    async fn cold_read_surfaces_fetch_errors() {
        let source = CachingTokenSource::new(CountingSource {
            fetches: Arc::new(AtomicU32::new(0)),
            expires_in: Duration::from_secs(3600),
            fail: true,
        });
        let err = source
            .token()
            .await
            .expect_err("must not fabricate a token");
        assert!(err.to_string().contains("issuer unavailable"));
    }

    #[test]
    fn authorization_header_joins_type_and_value() {
        let token = Token {
            value: "abc".into(),
            expires_at: Instant::now() + Duration::from_secs(60),
            token_type: "Bearer".into(),
        };
        assert_eq!(token.authorization_header(), "Bearer abc");
    }
}
