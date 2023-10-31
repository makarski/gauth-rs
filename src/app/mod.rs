use std::error::Error as StdError;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::{env, path};

use chrono::Utc;
use reqwest::Client as HttpClient;
use serde_derive::{Deserialize, Serialize};

mod credentials;
mod errors;

use errors::{AuthError, Result};

const GRANT_TYPE: &str = "authorization_code";
const DEFAULT_APP_NAME: &str = "gauth_app";
const TOKEN_DIR: &str = "GAUTH_TOKEN_DIR";
const GOOGLE_VALIDATE_HOST: &str = "https://www.googleapis.com";

type AuthHandler = Box<dyn Fn(String) -> StdResult<String, Box<dyn StdError>>>;

/// Auth struct represents an auth instance
pub struct Auth {
    app_name: String,

    auth_handler: Option<AuthHandler>,
    oauth_creds: credentials::OauthCredentials,
    consent_uri: String,

    token_validate_host: String,
    http_client: HttpClient,
}

/// Access token
#[derive(Debug, Deserialize, Serialize)]
struct Token {
    access_token: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: Option<String>,
    token_type: String,

    expires_at: Option<u64>,
}

impl Token {
    fn bearer_token(&self) -> String {
        format!("{} {}", self.token_type, self.access_token)
    }

    fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => expires_at < Utc::now().timestamp() as u64,
            None => true,
        }
    }

    fn set_expires_at(&mut self) {
        self.expires_at = Some(Utc::now().timestamp() as u64 + self.expires_in);
    }
}

impl Auth {
    /// Creates a new auth instance from a key file and scopes
    pub fn from_file(key_path: &str, scopes: Vec<&str>) -> Result<Self> {
        let kp = path::Path::new(key_path);
        let oauth_creds = credentials::read_oauth_config(kp)?.installed;

        let scope = scopes.join(" ");
        let consent_uri = credentials::auth_code_uri_str(&oauth_creds, &scope)?;

        Ok(Self {
            app_name: DEFAULT_APP_NAME.to_owned(),
            auth_handler: None,
            oauth_creds,
            consent_uri,
            token_validate_host: GOOGLE_VALIDATE_HOST.to_owned(),
            http_client: HttpClient::new(),
        })
    }

    /// App_name can be used to override the default app name
    pub fn app_name(mut self, app_name: &str) -> Self {
        self.app_name = app_name.to_owned();
        self
    }

    /// Handler can be used to override the default auth handler
    pub fn handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(String) -> StdResult<String, Box<dyn StdError>> + 'static,
    {
        self.auth_handler = Some(Box::new(handler));
        self
    }

    async fn generate_new_token(&self) -> Result<Token> {
        let auth_code = match self.auth_handler.as_ref() {
            Some(h) => (h)(self.consent_uri.clone()),
            None => default_auth_handler(self.consent_uri.clone()),
        }
        .map_err(|err| AuthError::UserError(err))?;

        self.exchange_auth_code(auth_code)
            .await
            .and_then(|token| self.cache_token(token))
    }

    /// Returns an access token
    /// If the access token is not expired, it will return the cached access token
    /// Otherwise, it will exchange the auth code for an access token
    pub async fn access_token(&self) -> Result<String> {
        let token = match self.cached_token() {
            Ok(token) => token,
            Err(_) => self.generate_new_token().await?,
        };

        if self.is_token_valid(&token).await {
            return Ok(token.bearer_token());
        }

        self.refresh_token(token)
            .await
            .and_then(|token| self.cache_token(token))
            .map(|token| token.bearer_token())
    }

    async fn exchange_auth_code(&self, auth_code: String) -> Result<Token> {
        let req_builder = self
            .http_client
            .post(self.oauth_creds.token_uri.as_str())
            .form(&[
                ("code", auth_code.as_str()),
                ("client_id", self.oauth_creds.client_id.as_str()),
                ("client_secret", self.oauth_creds.client_secret.as_str()),
                ("redirect_uri", self.oauth_creds.redirect_uri()?.as_str()),
                ("grant_type", GRANT_TYPE),
            ]);

        let res = match req_builder.send().await {
            Ok(resp) => resp,
            Err(err) => return Err(AuthError::ReqwestError(err)),
        };

        let token = match res.json::<Token>().await {
            Ok(token) => token,
            Err(err) => return Err(AuthError::ReqwestError(err)),
        };

        Ok(token)
    }

    async fn refresh_token(&self, token: Token) -> Result<Token> {
        let refresh_token_str = token
            .refresh_token
            .as_ref()
            .ok_or(AuthError::RefreshTokenValue)?
            .as_str();

        let req_builder = self
            .http_client
            .post(self.oauth_creds.token_uri.as_str())
            .form(&[
                ("refresh_token", refresh_token_str),
                ("client_id", self.oauth_creds.client_id.as_str()),
                ("client_secret", self.oauth_creds.client_secret.as_str()),
                ("grant_type", "refresh_token"),
            ]);

        let res = match req_builder.send().await {
            Ok(resp) => resp,
            Err(err) => return Err(AuthError::ReqwestError(err)),
        };

        let mut token = match res.json::<Token>().await {
            Ok(token) => token,
            Err(err) => return Err(AuthError::ReqwestError(err)),
        };

        // refresh token is not returned on refresh
        token.refresh_token = Some(refresh_token_str.to_owned());
        Ok(token)
    }

    fn cached_token(&self) -> Result<Token> {
        let token_dir = self.token_dir()?;
        let b = std::fs::read(token_dir.join("access_token.json"))?;
        Ok(serde_json::from_slice::<Token>(&b)?)
    }

    fn cache_token(&self, token: Token) -> Result<Token> {
        let token_dir = self.token_dir()?;

        if !token_dir.exists() {
            std::fs::create_dir_all(&token_dir)?;
        }

        let mut token = token;
        token.set_expires_at();

        let token_path = token_dir.join("access_token.json");
        let b = serde_json::to_vec(&token)?;
        std::fs::write(token_path, b)?;

        Ok(token)
    }

    fn token_dir(&self) -> Result<PathBuf> {
        if let Ok(token_dir) = env::var(TOKEN_DIR) {
            Ok(PathBuf::from(token_dir))
        } else {
            match dirs::home_dir() {
                Some(d) => Ok(d.join(format!(".{}", self.app_name))),
                None => Err(AuthError::HomeDirError),
            }
        }
    }

    async fn is_token_valid(&self, token: &Token) -> bool {
        if token.is_expired() {
            return false;
        }

        let url = format!(
            "{}/oauth2/v3/tokeninfo?access_token={}",
            self.token_validate_host, token.access_token
        );

        match self.http_client.get(url.as_str()).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

fn default_auth_handler(consent_uri: String) -> StdResult<String, Box<dyn StdError>> {
    println!("> open the link in browser\n\n{}\n", consent_uri);
    println!("> enter the auth. code\n");

    let mut auth_code = String::new();
    std::io::stdin().read_line(&mut auth_code)?;

    Ok(auth_code)
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::env;

//     #[test]
//     fn test_access_token_success() {
//         let mut google = mockito::Server::new();
//         let google_host = google.url();

//         google
//             .mock("POST", "/token")
//             .with_status(200)
//             .with_body(r#"{"access_token":"access_token","expires_in":3599,"refresh_token":"refresh_token","scope":"https://www.googleapis.com/auth/drive","token_type":"Bearer"}"#)
//             .create();

//         let consent_uri = format!("{}/o/oauth2/auth?client_id=client_id&response_type=code&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&include_granted_scopes=true&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive&access_type=offline&state=pass-through+value", google_host);

//         let expected_consent_uri = consent_uri.clone();
//         let auth_handler = move |auth_consent_uri: String| -> StdResult<String, Box<dyn StdError>> {
//             assert_eq!(auth_consent_uri, expected_consent_uri);
//             Ok("auth_code".to_owned())
//         };

//         env::set_var(TOKEN_DIR, "./tmp/gauth_app");

//         let auth = Auth {
//             app_name: "gauth_app".to_owned(),
//             auth_handler: None,
//             consent_uri,
//             oauth_creds: credentials::OauthCredentials {
//                 client_id: "client_id".to_owned(),
//                 project_id: "project_id".to_owned(),
//                 auth_uri: format!("{}/o/oauth2/auth", google_host),
//                 token_uri: format!("{}/token", google_host),
//                 auth_provider_x509_cert_url: "auth_provider_x509_cert_url".to_owned(),
//                 client_secret: "client_secret".to_owned(),
//                 redirect_uris: vec!["urn:ietf:wg:oauth:2.0:oob".to_owned()],
//             },
//             token_validate_host: google_host.to_owned(),
//             http_client: HttpClient::new(),
//         };

//         let auth = auth.handler(auth_handler);

//         let token = auth.access_token().unwrap();
//         assert_eq!(token, "Bearer access_token");
//         env::remove_var(TOKEN_DIR);
//     }
// }
