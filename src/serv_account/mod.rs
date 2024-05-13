use self::{
    errors::{
        GetAccessTokenError, ServiceAccountBuildError as ServiceAccountBuilderError,
        ServiceAccountFromFileError,
    },
    jwt::JwtTokenSigner,
};
use chrono::{DateTime, Duration, Utc};
use reqwest::Client as HttpClient;
use serde_derive::Deserialize;
use std::{path::Path, sync::Arc};
use tokio::sync::RwLock;

pub use self::jwt::ServiceAccountKey;

pub mod errors;
mod jwt;

#[derive(Debug, Clone)]
pub struct ServiceAccount {
    http_client: HttpClient,
    jwt_token: JwtTokenSigner,
    access_token: Arc<RwLock<Option<AccessToken>>>,
}

#[derive(Debug, Clone)]
pub struct AccessToken {
    pub bearer_token: String,
    pub expires_at: DateTime<Utc>,
}

impl ServiceAccount {
    pub fn builder() -> ServiceAccountBuilder {
        ServiceAccountBuilder::new()
    }

    /// Creates a new `ServiceAccountBuilder` from a key file
    pub fn from_file<P: AsRef<Path>>(
        key_path: P,
    ) -> Result<ServiceAccountBuilder, ServiceAccountFromFileError> {
        let bytes = std::fs::read(&key_path).map_err(|e| {
            ServiceAccountFromFileError::ReadFile(key_path.as_ref().to_path_buf(), e)
        })?;
        let key = serde_json::from_slice::<ServiceAccountKey>(&bytes)
            .map_err(ServiceAccountFromFileError::DeserializeFile)?;
        Ok(Self::builder().key(key))
    }

    /// Returns an access token
    /// If the access token is not expired, it will return the cached access token
    /// Otherwise, it will exchange the JWT token for an access token
    pub async fn access_token(&self) -> Result<AccessToken, GetAccessTokenError> {
        let access_token = self.access_token.read().await.clone();
        match access_token {
            Some(access_token) if access_token.expires_at > Utc::now() => Ok(access_token),
            _ => {
                let new_token = self.get_fresh_access_token().await?;
                *self.access_token.write().await = Some(new_token.clone());
                Ok(new_token)
            }
        }
    }

    async fn get_fresh_access_token(&self) -> Result<AccessToken, GetAccessTokenError> {
        #[derive(Debug, Deserialize)]
        pub struct TokenResponse {
            token_type: String,
            access_token: String,
            expires_in: i64,
        }

        let response = self
            .http_client
            .post(self.jwt_token.token_uri())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &self.jwt_token.sign()?),
            ])
            .send()
            .await
            .map_err(GetAccessTokenError::HttpRequest)?;

        if !response.status().is_success() {
            return Err(GetAccessTokenError::HttpRequestUnsuccessful(
                response.status(),
                response.text().await,
            ));
        }

        let json = response
            .json::<TokenResponse>()
            .await
            .map_err(GetAccessTokenError::HttpJson)?;

        if json.token_type != "Bearer" {
            return Err(GetAccessTokenError::AccessTokenNotBearer(json.token_type));
        }

        // Account for clock skew or time to receive or process the response
        const LEEWAY: Duration = Duration::seconds(30);

        let expires_at = Utc::now() + Duration::seconds(json.expires_in) - LEEWAY;

        Ok(AccessToken {
            bearer_token: json.access_token,
            expires_at,
        })
    }
}

pub struct ServiceAccountBuilder {
    http_client: Option<HttpClient>,
    key: Option<ServiceAccountKey>,
    scopes: Option<String>,
    user_email: Option<String>,
}

impl ServiceAccountBuilder {
    pub fn new() -> Self {
        Self {
            http_client: None,
            key: None,
            scopes: None,
            user_email: None,
        }
    }

    /// Panics if key is not provided
    pub fn build(self) -> Result<ServiceAccount, ServiceAccountBuilderError> {
        let key = self.key.expect("Key required");
        let jwt_token =
            jwt::JwtTokenSigner::from_key(key, self.scopes.unwrap_or_default(), self.user_email)?;
        Ok(ServiceAccount {
            http_client: self.http_client.unwrap_or_default(),
            jwt_token,
            access_token: Arc::new(RwLock::new(None)),
        })
    }

    pub fn http_client(mut self, http_client: HttpClient) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub fn key(mut self, key: ServiceAccountKey) -> Self {
        self.key = Some(key);
        self
    }

    pub fn scopes(mut self, scopes: Vec<&str>) -> Self {
        self.scopes = Some(scopes.join(" "));
        self
    }

    pub fn user_email<S: Into<String>>(mut self, user_email: S) -> Self {
        self.user_email = Some(user_email.into());
        self
    }
}

impl Default for ServiceAccountBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_access_token_cache() {
        let scopes = vec!["https://www.googleapis.com/auth/drive"];
        let key_path = "test_fixtures/service-account-key.json";
        let service_account = ServiceAccount::from_file(key_path)
            .unwrap()
            .scopes(scopes)
            .build()
            .unwrap();

        let expires_at = Utc::now() + Duration::seconds(3600);
        *service_account.access_token.write().await = Some(AccessToken {
            bearer_token: "test_access_token".to_string(),
            expires_at,
        });

        assert_eq!(
            service_account.access_token().await.unwrap().bearer_token,
            "test_access_token"
        );
        assert_eq!(
            service_account.access_token().await.unwrap().expires_at,
            expires_at
        );
    }
}
