#[cfg(test)]
mod tests {
    use super::*;
    use errors::Error as intern_err;
    use serde_json::error as serde_errs;
    use serde_json::Error as serde_err;
    use std::fs;
    use std::io;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn auth_tkn_path_success() {
        let auth = Auth::new("myapp".to_owned(), PathBuf::new());

        assert_eq!(
            auth.tkn_path(),
            Ok(dirs::home_dir().unwrap().join(".myapp")),
            "expected token path format: $HOME/.{{app_name}}"
        );
    }

    #[test]
    fn auth_tkn_access_filekey_success() {
        let auth = Auth::new("myapp".to_owned(), PathBuf::new());

        assert_eq!(
            auth.tkn_access_filekey(),
            Ok(auth.tkn_path().unwrap().join("access_token.json")),
            "expected token format: $HOME/.{{app_name}}/access_token.json"
        );
    }

    #[test]
    fn auth_tkn_refresh_filekey_success() {
        let auth = Auth::new("myapp".to_owned(), PathBuf::new());

        assert_eq!(
            auth.tkn_refresh_filekey(),
            Ok(auth.tkn_path().unwrap().join("refresh_token.json")),
            "expected token format: $HOME/.{{app_name}}/refresh_token.json"
        );
    }

    #[test]
    fn tkn_from_file_success() {
        let token_json = r#"{
  "access_token": "access_token_value",
  "expires_in": 3600,
  "refresh_token": "refresh_token_value",
  "scope": "https://www.googleapis.com/auth/calendar.events",
  "token_type": "Bearer"
}"#;

        assert!(fs::write("testfile.json", token_json).is_ok());

        let tkn_res = tkn_from_file("testfile.json");
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
    fn tkn_from_file_deserialize_error() {
        let token_json = r#"{eapis.com/auth/calendar.events}"#;

        assert!(fs::write("testfile_de_err.json", token_json).is_ok());

        let expected_serde_err = serde_err::syntax(serde_errs::ErrorCode::KeyMustBeAString, 1, 2);
        let expected_err_msg = expected_serde_err.to_string();

        let tkn_err = tkn_from_file("testfile_de_err.json").unwrap_err();
        assert_eq!(tkn_err, intern_err::JSONError(expected_serde_err));
        assert_eq!(tkn_err.to_string(), expected_err_msg);
        fs::remove_file("testfile_de_err.json").expect("could not remove testfile.json");
    }

    #[test]
    fn tkn_from_file_read_error() {
        let expected_io_err = io::Error::new(
            io::ErrorKind::NotFound,
            "No such file or directory (os error 2)",
        );
        let expected_io_err_msg = expected_io_err.to_string();

        let tkn_err = tkn_from_file("non_existent_file.json").unwrap_err();

        assert_eq!(tkn_err, errors::Error::IOError(expected_io_err));
        assert_eq!(tkn_err.to_string(), expected_io_err_msg);
    }

    #[test]
    fn auth_tkn_is_expired() {
        let auth = Auth::new("myapp".to_owned(), PathBuf::new());

        let token_json_fmt = |exp_v: u64| -> String {
            format!(
                r###"{{
                        "access_token": "access_token_value",
                        "expires_in": {exp_val},
                        "refresh_token": "refresh_token_value",
                        "scope": "https://www.googleapis.com/auth/calendar.events",
                        "token_type": "Bearer"
                    }}"###,
                exp_val = exp_v
            )
        };

        let test_cases = vec![
            (
                "expected: token is expired",
                1,
                2,
                "expired_token.json",
                true,
            ),
            (
                "expected: token is not expired",
                3600,
                1,
                "non_expired_token.json",
                false,
            ),
        ];

        for test_case in test_cases.into_iter() {
            let (scenario, expires_in, sleep_secs, filename, expected_expired) = test_case;

            let tkn_json = format!("{}", token_json_fmt(expires_in));
            assert!(fs::write(filename, tkn_json).is_ok());

            sleep(Duration::from_secs(sleep_secs));

            let tkn_deserialized = tkn_from_file(filename)
                .expect("expect to have successfully read test fixture file");

            assert_eq!(
                auth.tkn_is_expired(&tkn_deserialized, filename),
                expected_expired,
                "scenario failed: {}",
                scenario,
            );

            fs::remove_file(filename).expect("could not remove test file");
        }
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

use std::error as std_err;
use std::fs;
use std::fs::{DirBuilder, File};
use std::ops::Add;
use std::path::{Path, PathBuf};
use std::result;
use std::time::{Duration, SystemTime};

// Token configs
const GRANT_TYPE: &str = "authorization_code";

pub struct Auth {
    app_name: String,
    crd_path: PathBuf,
    _http_client: reqwest::Client,
}

impl Auth {
    pub fn new(app_name: String, crd_path: PathBuf) -> Auth {
        Auth {
            app_name: app_name,
            crd_path: crd_path,
            _http_client: reqwest::Client::new(),
        }
    }

    pub fn access_token<F>(&self, scope: &str, get_auth_code: F) -> Result<Token>
    where
        F: Fn(String) -> result::Result<String, Box<dyn std_err::Error>>,
    {
        let tkn_filekey = self.tkn_access_filekey()?;
        let crds_cfg = credentials::read_oauth_config(&self.crd_path)?.installed;

        tkn_from_file(tkn_filekey.as_path())
            .or_else(|_| {
                credentials::get_auth_code_uri(&crds_cfg, scope)
                    .and_then(|consent_uri| {
                        get_auth_code(consent_uri).map_err(|err| Error::UserError(err))
                    })
                    .and_then(|auth_code| self.tkn_exchange(auth_code, &crds_cfg))
                    .and_then(|tkn| self.tkn_save(tkn))
            })
            .and_then(|tkn| {
                if self.tkn_is_valid(&tkn, tkn_filekey.as_path()) {
                    Ok(tkn)
                } else {
                    self.tkn_refresh(&crds_cfg)
                        .and_then(|tkn| self.tkn_save(tkn))
                }
            })
    }

    fn tkn_is_valid<P: AsRef<Path>>(&self, tkn: &Token, p: P) -> bool {
        if !self.tkn_is_expired(tkn, p) {
            return true;
        }

        let url = format!(
            "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={}",
            tkn.access_token
        );

        let resp = self._http_client.get(url.as_str()).send();
        match resp {
            Ok(t) => t.status() == reqwest::StatusCode::OK,
            Err(_) => false,
        }
    }

    fn tkn_is_expired<P: AsRef<Path>>(&self, tkn: &Token, p: P) -> bool {
        let f = std::fs::File::open(p);
        if f.is_err() {
            return true;
        }

        let m = f.unwrap().metadata();
        if m.is_err() {
            return true;
        }

        match m.unwrap().modified() {
            Ok(time) => time.add(Duration::from_secs(tkn.expires_in)) < SystemTime::now(),
            _ => return true,
        }
    }

    fn tkn_exchange(&self, auth_code: String, credentials: &OauthCredentials) -> Result<Token> {
        let mut resp = self
            ._http_client
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

    fn tkn_refresh(&self, credentials: &OauthCredentials) -> Result<Token> {
        let refresh_token = tkn_from_file(self.tkn_refresh_filekey()?)?;

        let tkn = self
            ._http_client
            .post(credentials.token_uri.as_str())
            .form(&[
                ("client_id", credentials.client_id.as_str()),
                ("client_secret", credentials.client_secret.as_str()),
                (
                    "refresh_token",
                    refresh_token
                        .refresh_token
                        .expect("refresh token is None")
                        .as_str(),
                ),
                ("grant_type", "refresh_token"),
            ])
            .send()?
            .json::<Token>()?;

        Ok(tkn)
    }

    fn tkn_save(&self, tkn: Token) -> Result<Token> {
        let keys = self.tkn_filekeys(&tkn)?;

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
            serde_json::to_writer_pretty(file, &tkn)?;
        }

        Ok(tkn)
    }

    fn tkn_filekeys(&self, tkn: &Token) -> Result<Vec<PathBuf>> {
        let mut keys = vec![self.tkn_access_filekey()?];

        if tkn.is_refresh() {
            keys.push(self.tkn_refresh_filekey()?);
        }

        Ok(keys)
    }

    fn tkn_path(&self) -> Result<PathBuf> {
        match dirs::home_dir() {
            Some(t) => Ok(t.join(format!(".{}", &self.app_name))),
            None => Err(Error::HomeDirError),
        }
    }

    fn tkn_refresh_filekey(&self) -> Result<PathBuf> {
        Ok(self.tkn_path()?.join("refresh_token.json"))
    }

    fn tkn_access_filekey(&self) -> Result<PathBuf> {
        Ok(self.tkn_path()?.join("access_token.json"))
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct Token {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub token_type: String,
}

impl Token {
    fn is_refresh(&self) -> bool {
        self.refresh_token.is_some()
    }
}

fn tkn_from_file<P: AsRef<Path>>(p: P) -> Result<Token> {
    let b = fs::read(p)?;
    let tkn = serde_json::from_slice::<Token>(&b)?;
    Ok(tkn)
}
