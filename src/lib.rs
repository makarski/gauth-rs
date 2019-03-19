#[cfg(test)]
mod tests {
    use super::*;
    use errors::Error as intern_err;
    use serde_json::error as serde_errs;
    use serde_json::Error as serde_err;
    use std::fs;
    use std::io;

    #[test]
    fn token_path_success() {
        assert_eq!(
            token_path("myapp"),
            Ok(dirs::home_dir().unwrap().join(".myapp")),
            "expected token path format: $HOME/.{{app_name}}"
        );
    }

    #[test]
    fn access_token_filekey_test() {
        assert_eq!(
            access_token_filekey("myapp"),
            Ok(token_path("myapp").unwrap().join("access_token.json")),
            "expected token format: $HOME/.{{app_name}}/access_token.json"
        );
    }

    #[test]
    fn refresh_token_filekey_test() {
        assert_eq!(
            refresh_token_filekey("myapp"),
            Ok(token_path("myapp").unwrap().join("refresh_token.json")),
            "expected token format: $HOME/.{{app_name}}/refresh_token.json"
        );
    }

    #[test]
    fn token_from_file_success() {
        let token_json = r#"{
  "access_token": "access_token_value",
  "expires_in": 3600,
  "refresh_token": "refresh_token_value",
  "scope": "https://www.googleapis.com/auth/calendar.events",
  "token_type": "Bearer"
}"#;

        assert!(fs::write("testfile.json", token_json).is_ok());

        let tkn_res = token_from_file("testfile.json");
        assert!(
            tkn_res.is_ok(),
            "expect to have succesfully deserialized a test token"
        );
        assert_eq!(
            tkn_res.unwrap(),
            Token {
                access_token: String::from("access_token_value"),
                expires_in: 3600,
                refresh_token: Some(String::from("refresh_token_value")),
                scope: Some(String::from(
                    "https://www.googleapis.com/auth/calendar.events"
                )),
                token_type: String::from("Bearer"),
            },
            "deserialized token should match the test token"
        );

        fs::remove_file("testfile.json").expect("could not remove testfile.json");
    }

    #[test]
    fn token_from_file_deserialize_error() {
        let token_json = r#"{eapis.com/auth/calendar.events}"#;

        assert!(fs::write("testfile_de_err.json", token_json).is_ok());

        let expected_serde_err = serde_err::syntax(serde_errs::ErrorCode::KeyMustBeAString, 1, 2);
        let expected_err_msg = expected_serde_err.to_string();

        let tkn_err = token_from_file("testfile_de_err.json").unwrap_err();
        assert_eq!(tkn_err, intern_err::JSONError(expected_serde_err));
        assert_eq!(tkn_err.to_string(), expected_err_msg);
        fs::remove_file("testfile_de_err.json").expect("could not remove testfile.json");
    }

    #[test]
    fn token_from_file_read_error() {
        let expected_io_err = io::Error::new(
            io::ErrorKind::NotFound,
            "No such file or directory (os error 2)",
        );
        let expected_io_err_msg = expected_io_err.to_string();

        let tkn_err = token_from_file("non_existent_file.json").unwrap_err();

        assert_eq!(tkn_err, errors::Error::IOError(expected_io_err));
        assert_eq!(tkn_err.to_string(), expected_io_err_msg);
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

use std::fs;
use std::fs::{DirBuilder, File};
use std::path;

// Token configs
const GRANT_TYPE: &str = "authorization_code";

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct Token {
    pub access_token: String,
    pub expires_in: u32,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub token_type: String,
}

impl Token {
    fn filekeys(&self, app_name: &str) -> Result<Vec<path::PathBuf>> {
        let mut keys = vec![access_token_filekey(app_name)?];

        if self.is_refresh() {
            keys.push(refresh_token_filekey(app_name)?);
        }

        Ok(keys)
    }

    fn is_refresh(&self) -> bool {
        self.refresh_token.is_some()
    }

    fn save(self, app_name: &str) -> Result<Token> {
        let keys = self.filekeys(app_name)?;

        for (index, key) in keys.iter().enumerate() {
            if index == 0 {
                match &key.parent() {
                    Some(t) => DirBuilder::new().recursive(true).create(t)?,
                    None => {
                        return Err(Error::TokenPathError);
                    }
                };
            }

            let file = File::create(key)?;
            serde_json::to_writer_pretty(file, &self)?;
        }

        Ok(self)
    }
}

pub fn access_token(app_name: &str, credentials_path: &path::Path, scope: &str) -> Result<Token> {
    let tkn_filekey = access_token_filekey(app_name)?;

    token_from_file(tkn_filekey.as_path())
        .or_else(|err| {
            eprintln!("token read err: {}", err);
            credentials::get_auth_data(credentials_path, scope)
                .and_then(|(auth_code, cfg)| exchange(auth_code, &cfg.installed))
                .and_then(|tkn| tkn.save(app_name))
        })
        .and_then(|tkn| {
            if is_valid(&tkn) {
                Ok(tkn)
            } else {
                credentials::read_oauth_config(credentials_path)
                    .and_then(|cfg| refresh(tkn, &cfg.installed))
                    .and_then(|tkn| tkn.save(app_name))
            }
        })
}

fn token_from_file<P: AsRef<path::Path>>(p: P) -> Result<Token> {
    let b = fs::read(p)?;
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

fn refresh(token: Token, credentials: &OauthCredentials) -> Result<Token> {
    let tkn = reqwest::Client::new()
        .post(credentials.token_uri.as_str())
        .form(&[
            ("client_id", credentials.client_id.as_str()),
            ("client_secret", credentials.client_secret.as_str()),
            ("refresh_token", token.refresh_token.unwrap().as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()?
        .json::<Token>()?;

    Ok(tkn)
}

fn is_valid(token: &Token) -> bool {
    let url = format!(
        "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={}",
        token.access_token
    );

    let resp = reqwest::get(url.as_str());
    // todo: update to handle expiration timestamp
    match resp {
        Ok(t) => {
            if t.status() != reqwest::StatusCode::OK {
                false
            } else {
                true
            }
        }
        Err(_) => false,
    }
}

fn token_path(app_name: &str) -> Result<path::PathBuf> {
    match dirs::home_dir() {
        Some(t) => Ok(t.join(format!(".{}", app_name))),
        None => Err(Error::HomeDirError),
    }
}

fn refresh_token_filekey(app_name: &str) -> Result<path::PathBuf> {
    Ok(token_path(app_name)?.join("refresh_token.json"))
}

fn access_token_filekey(app_name: &str) -> Result<path::PathBuf> {
    Ok(token_path(app_name)?.join("access_token.json"))
}
