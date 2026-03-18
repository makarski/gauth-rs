use super::errors::{Result, ServiceAccountError};
use serde_derive::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct JwtToken {
    private_key: String,
    header: JwtHeader,
    payload: JwtPayload,
}

#[derive(Clone, Debug, Default, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct JwtPayload {
    iss: String,
    sub: Option<String>,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

use base64::{Engine as _, engine::general_purpose};
use ring::{rand, signature};
use serde_derive::Deserialize;

impl JwtToken {
    /// Creates a new JWT token from a service account key file
    pub fn from_file(key_path: &str) -> Result<Self> {
        let bytes = std::fs::read(key_path)
            .map_err(|err| ServiceAccountError::ReadKey(format!("{}: {}", err, key_path)))?;

        Self::from_bytes(&bytes)
    }

    /// Creates a new JWT token from raw service account key JSON bytes
    pub fn from_bytes(key_json: &[u8]) -> Result<Self> {
        let key_data = serde_json::from_slice::<ServiceAccountKey>(key_json)?;

        let iat = chrono::Utc::now().timestamp() as u64;
        let exp = iat + 3600;

        let private_key = key_data
            .private_key
            .replace('\n', "")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "");

        Ok(Self {
            header: JwtHeader {
                alg: String::from("RS256"),
                typ: String::from("JWT"),
            },
            payload: JwtPayload {
                iss: key_data.client_email,
                sub: None,
                scope: String::new(),
                aud: key_data.token_uri,
                exp,
                iat,
            },
            private_key,
        })
    }

    /// Returns a JWT token string
    pub fn to_string(&self) -> Result<String> {
        let header = serde_json::to_vec(&self.header)?;
        let payload = serde_json::to_vec(&self.payload)?;

        let base64_header = general_purpose::STANDARD.encode(header);
        let base64_payload = general_purpose::STANDARD.encode(payload);

        let raw_signature = format!("{}.{}", base64_header, base64_payload);
        let signature = self.sign_rsa(raw_signature)?;

        let base64_signature = general_purpose::STANDARD.encode(signature);

        Ok(format!(
            "{}.{}.{}",
            base64_header, base64_payload, base64_signature
        ))
    }

    /// Returns the token uri
    pub fn token_uri(&self) -> &str {
        &self.payload.aud
    }

    /// Sets the sub field in the payload
    pub fn sub(mut self, sub: String) -> Self {
        self.payload.sub = Some(sub);
        self
    }

    /// Sets the scope field in the payload
    pub fn scope(mut self, scope: String) -> Self {
        self.payload.scope = scope;
        self
    }

    /// Signs a message with the private key
    fn sign_rsa(&self, message: String) -> Result<Vec<u8>> {
        let private_key = self.private_key.as_bytes();
        let decoded = general_purpose::STANDARD.decode(private_key)?;

        let key_pair = signature::RsaKeyPair::from_pkcs8(&decoded).map_err(|err| {
            ServiceAccountError::RsaKeyPair(format!("failed tp create key pair: {}", err))
        })?;

        // Sign the message, using PKCS#1 v1.5 padding and the SHA256 digest algorithm.
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; key_pair.public_modulus_len()];
        key_pair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &rng,
                message.as_bytes(),
                &mut signature,
            )
            .map_err(|err| ServiceAccountError::RsaSign(format!("{}", err)))?;

        Ok(signature)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    r#type: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
    universe_domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_ACCOUNT_KEY_PATH: &str = "test_fixtures/service-account-key.json";

    fn assert_jwt_fields(token: &JwtToken) {
        assert_eq!(token.header.alg, "RS256");
        assert_eq!(token.header.typ, "JWT");
        assert!(token.payload.iss.contains("iam.gserviceaccount.com"));
        assert_eq!(token.payload.sub, None);
        assert_eq!(token.payload.scope, "");
        assert_eq!(token.payload.aud, "https://oauth2.googleapis.com/token");
        assert!(token.payload.exp > 0);
        assert_eq!(token.payload.iat, token.payload.exp - 3600);
    }

    #[test]
    fn test_jwt_token() {
        let mut token = JwtToken::from_file(SERVICE_ACCOUNT_KEY_PATH).unwrap();
        assert_jwt_fields(&token);

        token = token
            .sub(String::from("some@email.domain"))
            .scope(String::from("test_scope1 test_scope2 test_scope3"));

        assert_eq!(token.payload.sub, Some(String::from("some@email.domain")));
        assert_eq!(token.payload.scope, "test_scope1 test_scope2 test_scope3");
    }

    #[test]
    fn test_jwt_token_from_bytes() {
        let bytes = std::fs::read(SERVICE_ACCOUNT_KEY_PATH).unwrap();
        let token = JwtToken::from_bytes(&bytes).unwrap();
        assert_jwt_fields(&token);
    }

    #[test]
    fn test_sign_rsa() {
        let message = String::from("hello, world");

        let token = JwtToken::from_file(SERVICE_ACCOUNT_KEY_PATH).unwrap();
        let signature = token.sign_rsa(message).unwrap();

        assert_eq!(signature.len(), 256);
    }

    #[test]
    fn test_token_to_string() {
        let token = JwtToken::from_file(SERVICE_ACCOUNT_KEY_PATH)
            .unwrap()
            .sub(String::from("some@email.com"))
            .scope(String::from("https://www.googleapis.com/auth/pubsub"));

        let token_string = token.to_string();

        assert!(token_string.is_ok(), "token string successfully created");
        assert!(
            !token_string.unwrap().is_empty(),
            "token string is not empty"
        );
    }

    #[test]
    fn from_file_nonexistent_returns_read_key_error() {
        let err = JwtToken::from_file("/no/such/file.json").unwrap_err();
        assert!(
            matches!(err, ServiceAccountError::ReadKey(_)),
            "expected ReadKey, got: {err:?}"
        );
    }

    #[test]
    fn from_bytes_invalid_json_returns_serde_error() {
        let err = JwtToken::from_bytes(b"not json").unwrap_err();
        assert!(
            matches!(err, ServiceAccountError::SerdeJson(_)),
            "expected SerdeJson, got: {err:?}"
        );
    }

    #[test]
    fn from_bytes_missing_field_returns_serde_error() {
        let partial = br#"{"type":"service_account","project_id":"p"}"#;
        let err = JwtToken::from_bytes(partial).unwrap_err();
        assert!(matches!(err, ServiceAccountError::SerdeJson(_)));
    }

    #[test]
    fn token_uri_matches_fixture() {
        let token = JwtToken::from_file(SERVICE_ACCOUNT_KEY_PATH).unwrap();
        assert_eq!(token.token_uri(), "https://oauth2.googleapis.com/token");
    }

    #[test]
    fn to_string_produces_three_dot_separated_segments() {
        let token = JwtToken::from_file(SERVICE_ACCOUNT_KEY_PATH).unwrap();
        let s = token.to_string().unwrap();
        assert_eq!(s.split('.').count(), 3, "JWT must have 3 segments");
    }

    #[test]
    fn sign_rsa_is_deterministic_length() {
        let token = JwtToken::from_file(SERVICE_ACCOUNT_KEY_PATH).unwrap();
        let sig1 = token.sign_rsa("msg_a".into()).unwrap();
        let sig2 = token.sign_rsa("msg_b".into()).unwrap();
        assert_eq!(
            sig1.len(),
            sig2.len(),
            "RSA signatures should be same length"
        );
        assert_ne!(
            sig1, sig2,
            "different messages should produce different signatures"
        );
    }

    #[test]
    fn sub_and_scope_are_chainable() {
        let token = JwtToken::from_file(SERVICE_ACCOUNT_KEY_PATH)
            .unwrap()
            .sub("a@b.com".into())
            .scope("s1 s2".into());

        let s = token.to_string().unwrap();
        let payload_b64 = s.split('.').nth(1).unwrap();
        let payload_bytes = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(payload["sub"], "a@b.com");
        assert_eq!(payload["scope"], "s1 s2");
    }
}
