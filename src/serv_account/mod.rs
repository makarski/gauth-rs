use chrono::Utc;
use errors::Result;
use reqwest::Client as HttpClient;

use self::errors::ServiceAccountError;

pub(crate) mod errors;
mod jwt;

#[derive(Debug, Clone)]
pub struct ServiceAccount {
    scopes: String,
    key_path: String,
    user_email: Option<String>,

    access_token: Option<String>,
    expires_at: Option<u64>,

    http_client: HttpClient,
}

#[derive(Debug, serde_derive::Deserialize)]
struct Token {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

impl Token {
    fn bearer_token(&self) -> String {
        format!("{} {}", self.token_type, self.access_token)
    }
}

impl ServiceAccount {
    /// Creates a new service account from a key file and scopes
    pub fn from_file(key_path: &str, scopes: Vec<&str>) -> Self {
        Self {
            scopes: scopes.join(" "),
            key_path: key_path.to_string(),
            user_email: None,

            access_token: None,
            expires_at: None,

            http_client: HttpClient::new(),
        }
    }

    /// Sets the user email
    pub fn user_email(mut self, user_email: &str) -> Self {
        self.user_email = Some(user_email.to_string());
        self
    }

    /// Returns an access token
    /// If the access token is not expired, it will return the cached access token
    /// Otherwise, it will exchange the JWT token for an access token
    pub async fn access_token(&mut self) -> Result<String> {
        match (self.access_token.as_ref(), self.expires_at) {
            (Some(access_token), Some(expires_at))
                if expires_at > Utc::now().timestamp() as u64 =>
            {
                Ok(access_token.to_string())
            }
            _ => {
                let jwt_token = self.jwt_token()?;
                let token = match self.exchange_jwt_token_for_access_token(jwt_token).await {
                    Ok(token) => token,
                    Err(err) => return Err(err),
                };

                let expires_at = Utc::now().timestamp() as u64 + token.expires_in - 30;

                self.access_token = Some(token.bearer_token());
                self.expires_at = Some(expires_at);

                Ok(token.bearer_token())
            }
        }
    }

    async fn exchange_jwt_token_for_access_token(
        &mut self,
        jwt_token: jwt::JwtToken,
    ) -> Result<Token> {
        let req_builder = self.http_client.post(jwt_token.token_uri()).form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt_token.to_string()?),
        ]);

        let res = match req_builder.send().await {
            Ok(resp) => resp,
            Err(err) => return Err(ServiceAccountError::HttpReqwest(err)),
        };

        let token = match res.json::<Token>().await {
            Ok(token) => token,
            Err(err) => return Err(ServiceAccountError::HttpReqwest(err)),
        };

        Ok(token)
    }

    fn jwt_token(&self) -> Result<jwt::JwtToken> {
        let token = jwt::JwtToken::from_file(&self.key_path)?;

        Ok(match self.user_email {
            Some(ref user_email) => token.sub(user_email.to_string()),
            None => token,
        }
        .scope(self.scopes.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_access_token() {
        let scopes = vec!["https://www.googleapis.com/auth/drive"];
        let key_path = "test_fixtures/service-account-key.json";
        let mut service_account = ServiceAccount::from_file(key_path, scopes);

        // TODO: fix this test - make sure we can run an integration test
        // let access_token = service_account.access_token();
        // assert!(access_token.is_ok());
        // assert!(!access_token.unwrap().is_empty());

        service_account.access_token = Some("test_access_token".to_string());

        let expires_at = Utc::now().timestamp() as u64 + 3600;
        service_account.expires_at = Some(expires_at);

        assert_eq!(
            service_account.access_token().await.unwrap(),
            "test_access_token"
        );
        assert_eq!(service_account.expires_at.unwrap(), expires_at);
    }
}
