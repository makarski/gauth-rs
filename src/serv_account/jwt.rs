use super::errors::{Result, ServiceAccountError};
use serde::Serialize;

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

use base64::{engine::general_purpose, Engine as _};
use ring::{rand, signature};
use serde_derive::Deserialize;

impl JwtToken {
    /// Creates a new JWT token from a service account key file
    pub fn from_file(key_path: &str) -> Result<Self> {
        let private_key_content = std::fs::read(key_path)
            .map_err(|err| ServiceAccountError::ReadKey(format!("{}: {}", err, key_path)))?;

        let key_data = serde_json::from_slice::<ServiceAccountKey>(&private_key_content)?;

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

    #[test]
    fn test_jwt_token() {
        let mut token = JwtToken::from_file(SERVICE_ACCOUNT_KEY_PATH).unwrap();

        assert_eq!(token.header.alg, "RS256");
        assert_eq!(token.header.typ, "JWT");
        assert!(token.payload.iss.contains("iam.gserviceaccount.com"));
        assert_eq!(token.payload.sub, None);
        assert_eq!(token.payload.scope, "");
        assert_eq!(token.payload.aud, "https://oauth2.googleapis.com/token");
        assert!(token.payload.exp > 0);
        assert_eq!(token.payload.iat, token.payload.exp - 3600);

        token = token
            .sub(String::from("some@email.domain"))
            .scope(String::from("test_scope1 test_scope2 test_scope3"));

        assert_eq!(token.payload.sub, Some(String::from("some@email.domain")));
        assert_eq!(token.payload.scope, "test_scope1 test_scope2 test_scope3");
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
}
