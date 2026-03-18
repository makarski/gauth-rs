use chrono::Utc;
use errors::Result;
use reqwest::Client as HttpClient;

use self::errors::ServiceAccountError;

pub(crate) mod errors;
mod jwt;

#[derive(Debug, Clone)]
enum KeySource {
    File(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct ServiceAccount {
    scopes: String,
    key_source: KeySource,
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
    fn new(key_source: KeySource, scopes: Vec<&str>) -> Self {
        Self {
            scopes: scopes.join(" "),
            key_source,
            user_email: None,
            access_token: None,
            expires_at: None,
            http_client: HttpClient::new(),
        }
    }

    /// Creates a new service account from a key file and scopes
    pub fn from_file(key_path: &str, scopes: Vec<&str>) -> Self {
        Self::new(KeySource::File(key_path.to_string()), scopes)
    }

    /// Creates a new service account from raw JSON key bytes and scopes
    pub fn from_bytes(key_json: &[u8], scopes: Vec<&str>) -> Self {
        Self::new(KeySource::Bytes(key_json.to_vec()), scopes)
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
        let token = match &self.key_source {
            KeySource::File(path) => jwt::JwtToken::from_file(path)?,
            KeySource::Bytes(bytes) => jwt::JwtToken::from_bytes(bytes)?,
        };

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
    use base64::Engine as _;

    const KEY_PATH: &str = "test_fixtures/service-account-key.json";

    async fn assert_cached_token_returned(mut sa: ServiceAccount) {
        sa.access_token = Some("test_access_token".to_string());
        let expires_at = Utc::now().timestamp() as u64 + 3600;
        sa.expires_at = Some(expires_at);

        assert_eq!(sa.access_token().await.unwrap(), "test_access_token");
        assert_eq!(sa.expires_at.unwrap(), expires_at);
    }

    #[tokio::test]
    async fn test_access_token_from_file() {
        let sa = ServiceAccount::from_file(KEY_PATH, vec!["https://www.googleapis.com/auth/drive"]);
        assert_cached_token_returned(sa).await;
    }

    #[tokio::test]
    async fn test_access_token_from_bytes() {
        let key_json = std::fs::read(KEY_PATH).unwrap();
        let sa =
            ServiceAccount::from_bytes(&key_json, vec!["https://www.googleapis.com/auth/drive"]);
        assert_cached_token_returned(sa).await;
    }

    #[test]
    fn jwt_token_from_file_and_bytes_produce_same_fields() {
        let scopes = vec!["https://www.googleapis.com/auth/pubsub"];

        let from_file = ServiceAccount::from_file(KEY_PATH, scopes.clone());
        let jwt_file = from_file.jwt_token().unwrap();

        let key_json = std::fs::read(KEY_PATH).unwrap();
        let from_bytes = ServiceAccount::from_bytes(&key_json, scopes);
        let jwt_bytes = from_bytes.jwt_token().unwrap();

        assert_eq!(jwt_file.token_uri(), jwt_bytes.token_uri());
        assert_eq!(
            jwt_file.to_string().unwrap(),
            jwt_bytes.to_string().unwrap()
        );
    }

    #[test]
    fn from_file_nonexistent_path_errors_on_jwt() {
        let sa = ServiceAccount::from_file("/no/such/file.json", vec!["scope"]);
        let err = sa.jwt_token().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("/no/such/file.json"),
            "error should mention the path: {msg}"
        );
    }

    #[test]
    fn from_bytes_invalid_json_errors_on_jwt() {
        let sa = ServiceAccount::from_bytes(b"not json", vec!["scope"]);
        let err = sa.jwt_token().unwrap_err();
        assert!(matches!(err, errors::ServiceAccountError::SerdeJson(_)));
    }

    fn decode_jwt_payload(sa: &ServiceAccount) -> serde_json::Value {
        let jwt = sa.jwt_token().unwrap();
        let token_str = jwt.to_string().unwrap();
        let payload_b64 = token_str.split('.').nth(1).unwrap();
        let payload_bytes = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .unwrap();
        serde_json::from_slice(&payload_bytes).unwrap()
    }

    #[test]
    fn user_email_sets_sub_in_jwt() {
        let sa = ServiceAccount::from_file(KEY_PATH, vec!["scope"]).user_email("user@example.com");
        let payload = decode_jwt_payload(&sa);
        assert_eq!(payload["sub"], "user@example.com");
    }

    #[test]
    fn user_email_absent_means_no_sub_in_jwt() {
        let sa = ServiceAccount::from_file(KEY_PATH, vec!["scope"]);
        let payload = decode_jwt_payload(&sa);
        assert!(payload["sub"].is_null());
    }

    #[tokio::test]
    async fn expired_token_triggers_refresh_attempt() {
        let scopes = vec!["https://www.googleapis.com/auth/drive"];
        let mut sa = ServiceAccount::from_file(KEY_PATH, scopes);

        sa.access_token = Some("stale_token".to_string());
        sa.expires_at = Some(0); // expired in 1970

        // access_token() should try to exchange a new JWT, which fails
        // because there's no real Google endpoint — but it proves the
        // cached token was NOT returned.
        let result = sa.access_token().await;
        assert!(
            result.is_err(),
            "expired token should not be returned as-is"
        );
    }

    #[tokio::test]
    async fn cached_token_returned_when_not_expired() {
        let scopes = vec!["https://www.googleapis.com/auth/drive"];
        let mut sa = ServiceAccount::from_file(KEY_PATH, scopes);

        sa.access_token = Some("cached_value".to_string());
        sa.expires_at = Some(Utc::now().timestamp() as u64 + 3600);

        assert_eq!(sa.access_token().await.unwrap(), "cached_value");
    }

    #[test]
    fn scopes_are_joined_with_space() {
        let sa =
            ServiceAccount::from_file(KEY_PATH, vec!["https://scope.one", "https://scope.two"]);
        assert_eq!(sa.scopes, "https://scope.one https://scope.two");
    }

    #[test]
    fn empty_scopes_produce_empty_string() {
        let sa = ServiceAccount::from_file(KEY_PATH, vec![]);
        assert_eq!(sa.scopes, "");
    }
}
