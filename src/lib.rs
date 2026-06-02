//! HTTP client for Google OAuth2.
//!
//! This crate covers two Google auth flows:
//!
//!   * [`app`] — **OAuth2 for installed apps**. Three-legged flow with a
//!     consent URI, auth code exchange, and a refresh-token loop. Tokens are
//!     cached on disk so subsequent calls reuse them until they expire.
//!   * [`serv_account`] — **Service accounts**. JWT-bearer flow for
//!     server-to-server auth using a Google-issued JSON key. Tokens are
//!     cached in-memory on the [`ServiceAccount`] instance.
//!
//! ## Optional features
//!
//!   * `app-blocking` — adds [`app::Auth::access_token_blocking`], a
//!     synchronous wrapper around the async access-token call. Useful when
//!     plugging gauth into a synchronous integration point (e.g. a tonic
//!     interceptor).
//!   * `token-watcher` — adds [`token_provider::AsyncTokenProvider`], a
//!     daemon that periodically refreshes a token in the background and
//!     exposes a synchronous read accessor over a shared cache.
//!
//! See the crate README for usage examples.
//!
//! [`ServiceAccount`]: serv_account::ServiceAccount

#![deny(missing_docs)]

pub mod app;
pub mod serv_account;

#[cfg(feature = "token-watcher")]
pub mod token_provider;
