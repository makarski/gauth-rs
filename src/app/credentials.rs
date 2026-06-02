use std::path::Path;

use serde_derive::Deserialize;
use url::Url;

use super::errors::{AuthError, Result};

// Auth code configs
const AUTH_CODE_RESP_TYPE: &str = "code";
const AUTH_CODE_STATE: &str = "pass-through value";
const AUTH_CODE_INCLUDE_GRANTED_SCOPES: &str = "true";
const AUTH_CODE_ACCESS_TYPE: &str = "offline";

#[derive(Deserialize, Debug)]
pub struct OauthConfig {
    pub installed: OauthCredentials,
}

#[derive(Deserialize, Debug)]
pub struct OauthCredentials {
    pub client_id: String,
    // Present in the credentials.json schema; not consumed today but kept
    // on the struct so the layout matches the file. `expect` over `allow`
    // so the suppression auto-fires if a future feature starts reading these.
    #[expect(dead_code)]
    pub project_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    #[expect(dead_code)]
    pub auth_provider_x509_cert_url: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
}

impl OauthCredentials {
    pub fn redirect_uri(&self) -> Result<&String> {
        self.redirect_uris
            .first()
            .ok_or(AuthError::RedirectUriCfgError)
    }
}

pub fn auth_code_uri_str(credentials: &OauthCredentials, scope: &str) -> Result<String> {
    let auth_code_link = auth_code_uri(credentials, scope)?;
    Ok(auth_code_link.to_string())
}

pub fn read_oauth_config(p: &Path) -> Result<OauthConfig> {
    let b = std::fs::read(p)?;
    let cfg = serde_json::from_slice::<OauthConfig>(&b)?;
    Ok(cfg)
}

fn auth_code_uri(credentials: &OauthCredentials, scope: &str) -> Result<url::Url> {
    let mut uri = Url::parse(credentials.auth_uri.as_str())?;

    let params = vec![
        ("client_id", credentials.client_id.as_str()),
        ("response_type", AUTH_CODE_RESP_TYPE),
        ("redirect_uri", credentials.redirect_uri()?),
        ("include_granted_scopes", AUTH_CODE_INCLUDE_GRANTED_SCOPES),
        ("scope", scope),
        ("access_type", AUTH_CODE_ACCESS_TYPE),
        ("state", AUTH_CODE_STATE),
    ];

    for (k, v) in params.into_iter() {
        uri.query_pairs_mut().append_pair(k, v);
    }

    uri.query_pairs_mut().finish();
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const FIXTURE: &str = "test_fixtures/oauth-credentials.json";

    #[test]
    fn read_oauth_config_parses_installed_app_schema() {
        let cfg = read_oauth_config(Path::new(FIXTURE)).unwrap();
        assert_eq!(
            cfg.installed.client_id,
            "test-client-id.apps.googleusercontent.com"
        );
        assert_eq!(cfg.installed.client_secret, "test-client-secret");
        assert_eq!(
            cfg.installed.token_uri,
            "https://oauth2.googleapis.com/token"
        );
        assert_eq!(cfg.installed.redirect_uris.len(), 2);
        assert_eq!(cfg.installed.redirect_uris[0], "urn:ietf:wg:oauth:2.0:oob");
    }

    #[test]
    fn read_oauth_config_missing_file_errors() {
        let err = read_oauth_config(Path::new("/no/such/file.json")).unwrap_err();
        assert!(
            matches!(err, AuthError::IOError(_)),
            "expected IoError, got: {err:?}"
        );
    }

    #[test]
    fn redirect_uri_returns_first_when_present() {
        let creds = OauthCredentials {
            client_id: "id".into(),
            project_id: "p".into(),
            auth_uri: "https://example.com/auth".into(),
            token_uri: "https://example.com/token".into(),
            auth_provider_x509_cert_url: "https://example.com/certs".into(),
            client_secret: "s".into(),
            redirect_uris: vec!["http://localhost".into(), "http://other".into()],
        };
        assert_eq!(creds.redirect_uri().unwrap(), "http://localhost");
    }

    #[test]
    fn redirect_uri_empty_errors() {
        let creds = OauthCredentials {
            client_id: "id".into(),
            project_id: "p".into(),
            auth_uri: "https://example.com/auth".into(),
            token_uri: "https://example.com/token".into(),
            auth_provider_x509_cert_url: "https://example.com/certs".into(),
            client_secret: "s".into(),
            redirect_uris: vec![],
        };
        assert!(matches!(
            creds.redirect_uri().unwrap_err(),
            AuthError::RedirectUriCfgError,
        ));
    }

    #[test]
    fn auth_code_uri_contains_scope_and_client_id() {
        let cfg = read_oauth_config(Path::new(FIXTURE)).unwrap();
        let uri =
            auth_code_uri_str(&cfg.installed, "https://www.googleapis.com/auth/drive").unwrap();
        assert!(uri.contains("client_id=test-client-id"));
        assert!(uri.contains("scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive"));
        assert!(uri.contains("response_type=code"));
        assert!(uri.contains("access_type=offline"));
    }
}
