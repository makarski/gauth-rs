//! Background token refresher with a synchronous read accessor.
//!
//! Wrap any [`TokenProvider`] in an [`AsyncTokenProvider`] to spawn a daemon
//! that calls `access_token` on the given interval, retries with
//! exponential backoff on failure, and caches the latest value behind a
//! [`tokio::sync::Mutex`]. Synchronous consumers (e.g. tonic interceptors)
//! can read the cached token via [`AsyncTokenProvider::access_token`]
//! without `.await`.
//!
//! `TokenProvider` is implemented for [`crate::serv_account::ServiceAccount`]
//! and [`crate::app::Auth`] out of the box; downstream types can add their
//! own impls.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, interval, sleep};

use self::errors::Result;

mod errors;

/// Background-refreshing token cache. See the [module-level docs](self) for
/// the design and usage.
#[derive(Debug, Clone)]
pub struct AsyncTokenProvider<T> {
    inner: T,
    cached_token: Arc<Mutex<String>>,
    interval: u64,
}

/// Anything that can produce a fresh access token. The blanket
/// [`Watcher`] impl turns any `TokenProvider` into something that can drive
/// the [`AsyncTokenProvider`] refresh loop.
#[async_trait]
pub trait TokenProvider: Send {
    /// Produce a fresh access token, refreshing the underlying credential
    /// state as needed. Called once per refresh interval by [`Watcher`].
    async fn access_token(&mut self) -> Result<String>;
}

#[async_trait]
impl TokenProvider for crate::serv_account::ServiceAccount {
    async fn access_token(&mut self) -> Result<String> {
        Ok(self.access_token().await?)
    }
}

#[async_trait]
impl TokenProvider for crate::app::Auth {
    async fn access_token(&mut self) -> Result<String> {
        Ok(self.access_token().await?)
    }
}

/// Drives a token-refresh loop and forwards each fresh value over a channel.
/// A blanket impl is provided for every [`TokenProvider`], so consumers
/// implement `TokenProvider` and get `Watcher` for free.
#[async_trait]
pub trait Watcher {
    /// Refresh the token every `interval_sec` seconds, sending each value
    /// down `tx`. On error the call is retried up to three times with
    /// exponential backoff (2, 4, 8 seconds) before the loop exits.
    async fn watch_updates(&mut self, tx: Sender<String>, interval_sec: u64);
}

#[async_trait]
impl<T: TokenProvider> Watcher for T {
    async fn watch_updates(&mut self, tx: Sender<String>, interval_sec: u64) {
        let mut interval = interval(Duration::from_secs(interval_sec));
        let retries = 3;
        let mut attempt = 0;

        loop {
            let res = self.access_token().await;
            match send_token(res, &tx).await {
                Ok(_) => {}
                Err(err) => {
                    if attempt == retries {
                        log::error!("{}", err);
                        break;
                    }

                    attempt += 1;
                    let backoff = 1 << attempt;
                    let delay = Duration::from_secs(backoff);

                    log::error!("{}. retry in: {}s", err, backoff);
                    sleep(delay).await;
                    continue;
                }
            }

            attempt = 0;
            interval.tick().await;
        }
    }
}

async fn send_token(access_token_res: Result<String>, tx: &Sender<String>) -> Result<()> {
    Ok(tx.send(access_token_res?).await?)
}

impl<T> AsyncTokenProvider<T>
where
    T: Watcher + Clone + Send + 'static,
{
    /// Create a new provider wrapping `inner`. Defaults to a 60-second
    /// refresh interval; override with [`Self::with_interval`].
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            cached_token: Arc::new(Mutex::new(String::new())),
            interval: 60,
        }
    }

    /// Override the refresh interval (in seconds) before starting
    /// [`Self::watch_updates`].
    pub fn with_interval(mut self, interval: u64) -> Self {
        self.interval = interval;
        self
    }

    /// Synchronous read of the cached token. Returns the empty string until
    /// the first refresh completes. Fails with an `AccessToken` error if the
    /// cache mutex is currently held by the refresh task — retry, or `await`
    /// on a clone of the inner [`TokenProvider`] for guaranteed availability.
    pub fn access_token(&self) -> Result<String> {
        Ok(self.cached_token.try_lock()?.clone())
    }

    /// Spawn the background refresh loop. Returns immediately; the spawned
    /// tasks live until the inner [`Watcher`] gives up (after three
    /// consecutive failed attempts) or the runtime shuts down.
    pub async fn watch_updates(&self) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        let mut watcher = self.inner.clone();
        let cached_token = Arc::clone(&self.cached_token);
        let interval = self.interval;

        tokio::spawn(async move {
            watcher.watch_updates(tx, interval).await;
        });

        tokio::spawn(async move {
            while let Some(token) = rx.recv().await {
                log::debug!("access token refreshed");
                let mut cached_token = cached_token.lock().await;
                *cached_token = token;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fake `TokenProvider` that returns deterministic, counted tokens and
    /// can be configured to fail a fixed number of initial calls so we can
    /// exercise the retry path without touching the network.
    #[derive(Clone)]
    struct FakeProvider {
        calls: Arc<AtomicU32>,
        fail_first_n: u32,
    }

    impl FakeProvider {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicU32::new(0)),
                fail_first_n: 0,
            }
        }

        fn with_initial_failures(n: u32) -> Self {
            Self {
                calls: Arc::new(AtomicU32::new(0)),
                fail_first_n: n,
            }
        }
    }

    #[async_trait]
    impl TokenProvider for FakeProvider {
        async fn access_token(&mut self) -> Result<String> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call < self.fail_first_n {
                Err(errors::TokenProviderError::SendError(
                    tokio::sync::mpsc::error::SendError("simulated".to_string()),
                ))
            } else {
                Ok(format!("tok-{}", call))
            }
        }
    }

    #[test]
    fn new_defaults_to_sixty_second_interval() {
        let provider = AsyncTokenProvider::new(FakeProvider::new());
        assert_eq!(provider.interval, 60);
    }

    #[test]
    fn with_interval_overrides_default() {
        let provider = AsyncTokenProvider::new(FakeProvider::new()).with_interval(5);
        assert_eq!(provider.interval, 5);
    }

    #[test]
    fn access_token_returns_empty_string_initially() {
        let provider = AsyncTokenProvider::new(FakeProvider::new());
        assert_eq!(provider.access_token().unwrap(), "");
    }

    /// `watch_updates` populates the cache from the inner provider on the
    /// first tick. Time is paused so the test doesn't sleep for real. We
    /// only assert the cache is *some* `tok-N` value — under paused time
    /// `interval.tick()` fires immediately, so multiple iterations can race
    /// before we observe; the meaningful property is that the cache moves
    /// from empty to populated.
    #[tokio::test(start_paused = true)]
    async fn watch_updates_populates_cache_from_provider() {
        let provider = AsyncTokenProvider::new(FakeProvider::new()).with_interval(60);
        provider.watch_updates().await;

        for _ in 0..32 {
            tokio::task::yield_now().await;
            if let Ok(t) = provider.access_token()
                && !t.is_empty()
            {
                assert!(t.starts_with("tok-"), "unexpected cached value: {t}");
                return;
            }
        }
        panic!("cache never populated within 32 yields");
    }

    /// The watcher retries on failure with exponential backoff and recovers
    /// once the underlying provider starts succeeding. With
    /// `fail_first_n = 2`, the third call onwards succeeds — the cache must
    /// eventually populate. We don't pin the exact value for the same
    /// paused-clock reason as the test above.
    #[tokio::test(start_paused = true)]
    async fn watch_updates_recovers_after_transient_failures() {
        let provider = AsyncTokenProvider::new(FakeProvider::with_initial_failures(2));
        provider.watch_updates().await;

        // attempt 1 fails -> sleep 1<<1 = 2s
        // attempt 2 fails -> sleep 1<<2 = 4s
        // attempt 3 succeeds. 16 simulated seconds is generous headroom.
        for _ in 0..16 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            if let Ok(t) = provider.access_token()
                && !t.is_empty()
            {
                assert!(t.starts_with("tok-"), "unexpected cached value: {t}");
                return;
            }
        }
        panic!("cache never populated after 16 simulated seconds");
    }
}
