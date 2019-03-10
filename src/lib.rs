#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

#[macro_use]
extern crate serde_derive;
extern crate dirs;
extern crate reqwest;

mod credentials;
use credentials::OauthCredentials;

mod errors;
use errors::{Error, Result};

use std::path;

// Token configs
const GRANT_TYPE: &str = "authorization_code";
const ACCESS_TOKEN_FILE: &str = "access_token.json";

#[derive(Deserialize, Serialize, Debug)]
pub struct Token {
    pub access_token: String,
    pub expires_in: u32,
    pub refresh_token: String,
    pub scope: Option<String>,
    pub token_type: String,
}

pub fn access_token(
    app_name: &String,
    credentials_path: &path::Path,
    scope: &str,
) -> Result<Token> {
    let tkn_filekey = token_filekey(app_name)?;

    token_from_file(tkn_filekey.as_path())
        .or_else(|err| {
            eprintln!("token read err: {}", err);
            credentials::get_auth_data(credentials_path, scope)
                .and_then(|(auth_code, cfg)| exchange(auth_code, &cfg.installed))
        })
        .and_then(|tkn| save(tkn, &tkn_filekey))
}

fn token_from_file(p: &path::Path) -> Result<Token> {
    let b = std::fs::read(p)?;
    let tkn = serde_json::from_slice::<Token>(&b)?;
    Ok(tkn)
}

fn exchange(auth_code: String, credentials: &OauthCredentials) -> Result<Token> {
    let mut resp = reqwest::Client::new()
        .post(credentials.token_uri.as_str())
        .form(&[
            ("code", auth_code.as_str()),
            ("client_secret", credentials.client_secret.as_str()),
            ("grant_type", GRANT_TYPE),
            ("client_id", credentials.client_id.as_str()),
            ("redirect_uri", credentials.redirect_uri()?),
        ])
        .send()?;

    let tkn = resp.json::<Token>()?;
    Ok(tkn)
}

fn token_filekey(app_name: &String) -> Result<path::PathBuf> {
    let home_dir = dirs::home_dir();
    let dir = match home_dir {
        Some(t) => t,
        None => return Err(Error::HomeDirError),
    };

    Ok(dir.join(format!(".{}", app_name)).join(ACCESS_TOKEN_FILE))
}

fn save(token: Token, tkn_filekey: &path::PathBuf) -> Result<Token> {
    let tkn_parent = tkn_filekey.parent();

    let tkn_dir = match tkn_parent {
        Some(t) => t,
        None => {
            return Err(Error::TokenPathError);
        }
    };

    std::fs::DirBuilder::new().recursive(true).create(tkn_dir)?;

    let file = std::fs::File::create(tkn_filekey)?;
    serde_json::to_writer_pretty(file, &token)?;

    Ok(token)
}
