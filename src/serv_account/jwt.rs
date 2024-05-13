use super::errors::{GetAccessTokenError, ServiceAccountBuildError};
use base64::{engine::general_purpose, Engine as _};
use ring::{
    rand,
    signature::{self, RsaKeyPair},
};
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct JwtTokenSigner {
    key_pair: Arc<RsaKeyPair>,
    rng: rand::SystemRandom,
    iss: String,
    sub: Option<String>,
    scope: String,
    aud: String,
}

impl JwtTokenSigner {
    /// Creates a new JWT token from a service account key
    pub fn from_key(
        key: ServiceAccountKey,
        scope: String,
        sub: Option<String>,
    ) -> Result<Self, ServiceAccountBuildError> {
        let no_whitespace = key.private_key.replace('\n', "");
        let private_key = no_whitespace
            .strip_prefix("-----BEGIN PRIVATE KEY-----")
            .ok_or(ServiceAccountBuildError::RsaPrivateKeyNoPrefix)?
            .strip_suffix("-----END PRIVATE KEY-----")
            .ok_or(ServiceAccountBuildError::RsaPrivateKeyNoSuffix)?;
        println!("private_key: {:?}", private_key);

        let decoded = general_purpose::STANDARD
            .decode(private_key.as_bytes())
            .map_err(ServiceAccountBuildError::RsaPrivateKeyDecode)?;
        let key_pair = RsaKeyPair::from_pkcs8(&decoded)
            .map_err(ServiceAccountBuildError::RsaPrivateKeyParse)?;

        Ok(Self {
            iss: key.client_email,
            rng: rand::SystemRandom::new(),
            sub,
            scope,
            aud: key.token_uri,
            key_pair: Arc::new(key_pair),
        })
    }

    /// Returns a signed JWT token string
    pub fn sign(&self) -> Result<String, GetAccessTokenError> {
        #[derive(Clone, Debug, Default, Serialize)]
        struct JwtHeader<'a> {
            alg: &'a str,
            typ: &'a str,
        }
        let header = serde_json::to_vec(&JwtHeader {
            alg: "RS256",
            typ: "JWT",
        })
        .map_err(GetAccessTokenError::JsonSerialization)?;
        let header = general_purpose::STANDARD.encode(header);

        #[derive(Clone, Debug, Default, Serialize)]
        struct JwtPayload<'a> {
            iss: &'a str,
            sub: Option<&'a str>,
            scope: &'a str,
            aud: &'a str,
            exp: u64,
            iat: u64,
        }
        let iat = chrono::Utc::now().timestamp() as u64;
        let exp = iat + 3600;
        let payload = serde_json::to_vec(&JwtPayload {
            iss: &self.iss,
            sub: self.sub.as_deref(),
            scope: &self.scope,
            aud: &self.aud,
            exp,
            iat,
        })
        .map_err(GetAccessTokenError::JsonSerialization)?;
        let payload = general_purpose::STANDARD.encode(payload);

        let to_sign = format!("{header}.{payload}");
        let signature =
            sign_rsa(&self.key_pair, &self.rng, &to_sign).map_err(GetAccessTokenError::RsaSign)?;
        let signature = general_purpose::STANDARD.encode(signature);

        Ok(format!("{to_sign}.{signature}"))
    }

    /// Returns the token uri
    pub fn token_uri(&self) -> &str {
        &self.aud
    }
}

/// Signs a message with the private key
fn sign_rsa(
    key_pair: &RsaKeyPair,
    rng: &dyn rand::SecureRandom,
    message: &str,
) -> Result<Vec<u8>, ring::error::Unspecified> {
    // Sign the message, using PKCS#1 v1.5 padding and the SHA256 digest algorithm.
    let mut signature = vec![0; key_pair.public_modulus_len()];
    key_pair.sign(
        &signature::RSA_PKCS1_SHA256,
        rng,
        message.as_bytes(),
        &mut signature,
    )?;

    Ok(signature)
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceAccountKey {
    pub r#type: String,
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_x509_cert_url: String,
    pub universe_domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn read_key() -> ServiceAccountKey {
        serde_json::from_slice(include_bytes!(
            "../../test_fixtures/service-account-key.json"
        ))
        .unwrap()
    }

    #[test]
    fn test_rsa_sign() {
        let key = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCr/KzFiWfiw5vd8KrFPmsktUfmba4x8r0uPDxxdeI/zrENHPkef3Zd3Tt4bvdG4VRWAQ/zuomHcksTW1AYaaS/TfoiH5c/xivWptKHGS/eh91SgPunmoK9wbvdNW8C4goVdw57JUz6IG1vZpenHjI7ofHMfg+2cBiTsTSWFDnd1EoNkK2lmdP1R5lzxNSRce9HgugKvHAcvDtB2goL9coo8y+3kyBTiS5qCgpWplGwIMBACGW6U4a//GajvmvvZyfym7OXJeqjXznjNH32ghhjcP2DUuGf36wika1rOpmZKCJDKBoMPQERUDa1ydYLfY3v1g/8xFTL4ezuyYEkGuu5AgMBAAECggEAP3Meglno+53SuRR6y/31JTvD5Nz98Otuo8oROoKVD5k/dGkF9xxrHMHrmMjHbVzf8kK+Edr1tgSScfe0Gu2OnA02hLRG5n5D2hL9hF3kbSKOokt3jCPSrBL3Leryo4uk0Lp1mzTtqzGfbgPZWwwm2B0syZaQUWwVhRdRITUhDBcUW8cuxGXzNeDTJMUjij0li61H62rJFjE5nyxCpwlukqR96uVWN6wXhM4xhzwhaHt6oGVUAENG3Er+ZjYCgBISQkEuiaFUgB3Zkv3qYWhaWNhwhO6MDsT33xex4Ecw4epCrAfEirkP1AIYmVWFw3uxODOJ/u8mb6IQIobnxwRiIQKBgQDihX+XxV8tSvHxgHTN5vzp4oOgnKhmiClm7/MSbjwHjLcffWh6gqBLbPAvcrfA0aewIT29xgIO0CpygJcg/4RND30YKTilYo7/ieTkdwRYsCbt9zM/WBop1snZja4Zox/SK23u4OJ4uUw0e4onXOOzAogCtiEKMx+U6+JmsyhNFQKBgQDCXmAhdrinbfXtsC5J+HwC81XaFujE2l4EiLqVaHH6DIrVTNSucf6O/nsCHWhttb3U7xT7CIHCe1om8peKZsjuiQqmlKjeqPRhDNlLXV5TadIKUs8svPM+MUXArhTc3vAv1pArhi7RpQ5F1AeTJGkOvxcY6vmMjXIb/dSiZMp1FQKBgDIii+fidjtHEB98Z92+lxGI4cslgRwYXNl8mBbnMQAWw90DW6Fp0eJ/vPUzdboGbQ/Ne6XJ8mCm8A4hqdFS3ExV9kDntrLcCnxCX9e1A9BBRIx8nuoRLNE/ybMN6Y+hDATvOciaG2XO1S/0e9JUe8z97W50MwHX6NCEGLrUQkI1AoGADD4lj/YKa4FhnDccs0wTg5wQLEyFHOEkSuTR29dYVoeztvu/6b0Ea71bwiZYDZEFBASLLcS7Z6SdaRaetPkEbwHyyctTV7MMsZA9n6Gh718a+8t7gTXlnGU+H4TXi5H/TwQU0KkDCfF7lKpmT75bX7Jpoggq7895AIpcel4e4oECgYAbddARaP5mH2KAiSoBUlvh4P2beCv5HmWjIhS2nA7KaGOtGfOk9/VGTRLZXtPed70cGD5SrgMze3umI37nAtcVv+MHcZSXhjoSQZ6M3GChaDUwJNC+f6GVjfadn7LOsY5L1+0cu1pe6r4uXBOwmvv1tynpY6sGOE+tPJibK5Pm8Q==";
        let key_pair = RsaKeyPair::from_pkcs8(&general_purpose::STANDARD.decode(key).unwrap())
            .expect("Failed to parse key");
        let rng = rand::SystemRandom::new();
        let message = "hello world";
        let signature = sign_rsa(&key_pair, &rng, message).unwrap();
        assert_eq!(signature.len(), 256);
    }

    #[test]
    fn test_sign() {
        let scope = "test_scope1 test_scope2 test_scope3";
        let signer = JwtTokenSigner::from_key(read_key(), scope.to_owned(), None).unwrap();
        let token = signer.sign().unwrap();
        println!("token: {:?}", token);
        let parts = token.split('.').collect::<Vec<&str>>();
        assert_eq!(parts.len(), 3);
        let mut parts = parts.into_iter();

        let header = parts.next().unwrap();
        let header = general_purpose::STANDARD.decode(header).unwrap();
        let header = serde_json::from_slice::<Value>(&header).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");

        let payload = parts.next().unwrap();
        let payload = general_purpose::STANDARD.decode(payload).unwrap();
        let payload = serde_json::from_slice::<Value>(&payload).unwrap();
        assert_eq!(payload["scope"], Value::String(scope.to_owned()));
        assert_eq!(payload["sub"], Value::Null);
        assert_eq!(payload["aud"], "https://oauth2.googleapis.com/token");
        assert!(payload["exp"].as_i64().unwrap() > 0);
        assert_eq!(
            payload["iat"].as_i64().unwrap(),
            payload["exp"].as_i64().unwrap() - 3600
        );

        let signature = parts.next().unwrap();
        let signature = general_purpose::STANDARD.decode(signature).unwrap();
        assert_eq!(signature.len(), 256);
    }

    #[test]
    fn test_sign_email() {
        let sub = "some@email.domain";
        let signer =
            JwtTokenSigner::from_key(read_key(), "".to_owned(), Some(sub.to_owned())).unwrap();
        let token = signer.sign().unwrap();
        let parts = token.split('.').collect::<Vec<&str>>();
        assert_eq!(parts.len(), 3);
        let mut parts = parts.into_iter();

        let _header = parts.next().unwrap();

        let payload = parts.next().unwrap();
        let payload = general_purpose::STANDARD.decode(payload).unwrap();
        let payload = serde_json::from_slice::<Value>(&payload).unwrap();
        assert_eq!(payload["sub"], Value::String(sub.to_owned()));
    }
}
