use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::time::{interval, sleep, Duration};

use self::errors::Result;

mod errors;

#[derive(Debug, Clone)]
pub struct AsyncTokenProvider<T> {
    inner: T,
    cached_token: Arc<Mutex<String>>,
    interval: u64,
}

#[async_trait]
pub trait TokenProvider: Send {
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

#[async_trait]
pub trait Watcher {
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
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            cached_token: Arc::new(Mutex::new(String::new())),
            interval: 60,
        }
    }

    pub fn with_interval(mut self, interval: u64) -> Self {
        self.interval = interval;
        self
    }

    pub fn access_token(&self) -> Result<String> {
        Ok(self.cached_token.try_lock()?.clone())
    }

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
                log::debug!("received new access token: {}", &token);
                let mut cached_token = cached_token.lock().await;
                *cached_token = token;
            }
        });
    }
}
