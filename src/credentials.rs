use crate::errors::{Error, Result};
use std::io;
use std::path::Path;
use url::Url;

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
    pub project_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
}

impl OauthCredentials {
    pub fn redirect_uri(&self) -> Result<&String> {
        self.redirect_uris.get(0).ok_or(Error::RedirectUriCfgError)
    }
}

pub fn get_auth_code_uri(credentials: &OauthCredentials, scope: &str) -> Result<String> {
    let auth_code_link = auth_code_uri(credentials, scope)?;
    Ok(auth_code_link.into_string())
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
        &mut uri.query_pairs_mut().append_pair(k, v);
    }

    &mut uri.query_pairs_mut().finish();
    Ok(uri)
}
