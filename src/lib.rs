#[macro_use]
extern crate serde_derive;
extern crate dirs;
extern crate reqwest;

mod credentials;
use credentials::OauthCredentials;

mod errors;
use errors::{Error, Result};

use std::env;
use std::error as std_err;
use std::fs;
use std::fs::{DirBuilder, File};
use std::ops::Add;
use std::path::{Path, PathBuf};
use std::result;
use std::time::{Duration, SystemTime};

// Token configs
const GRANT_TYPE: &str = "authorization_code";
const VALIDATE_HOST: &str = "https://www.googleapis.com";

// VALIDATE_HOST_ENV_NAME holds the name of the env var
// that used to validate the token.
// If env is not set the default google host is used.
//
// This configuration is intended in the first place for
// the testing purposes
const VALIDATE_HOST_ENV_NAME: &str = "GAUTH_VALIDATE_HOST";

// TOKEN_DIR_ENV_NAME holds the name of the env var
// that is used to configure the directory for storing tokens.
//
// If not set, $HOME will be used as the default value.
const TOKEN_DIR_ENV_NAME: &str = "GAUTH_TOKEN_DIR";

pub struct Auth {
    app_name: String,
    crd_path: PathBuf,
    validate_tkn_host: String,
    _http_client: reqwest::Client,
}

impl Auth {
    pub fn new(app_name: String, crd_path: PathBuf) -> Auth {
        Auth {
            app_name: app_name,
            crd_path: crd_path,
            validate_tkn_host: VALIDATE_HOST.to_owned(),
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

    fn set_validate_host(&mut self, host: &str) {
        self.validate_tkn_host = host.to_owned();
    }

    fn tkn_is_valid<P: AsRef<Path>>(&self, tkn: &Token, p: P) -> bool {
        if !self.tkn_is_expired(tkn, p) {
            return true;
        }

        let url = format!(
            "{}/oauth2/v3/tokeninfo?access_token={}",
            self.validate_tkn_host, tkn.access_token
        );

        let resp = self._http_client.get(url.as_str()).send();
        match resp {
            Ok(t) => t.status() == reqwest::StatusCode::OK,
            Err(_) => false,
        }
    }

    fn tkn_is_expired<P: AsRef<Path>>(&self, tkn: &Token, p: P) -> bool {
        let f = fs::File::open(p);
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
        let tkn = self
            ._http_client
            .post(credentials.token_uri.as_str())
            .form(&[
                ("code", auth_code.as_str()),
                ("client_secret", credentials.client_secret.as_str()),
                ("grant_type", GRANT_TYPE),
                ("client_id", credentials.client_id.as_str()),
                ("redirect_uri", credentials.redirect_uri()?),
            ])
            .send()?
            .json::<Token>()?;

        Ok(tkn)
    }

    fn tkn_refresh(&self, credentials: &OauthCredentials) -> Result<Token> {
        let refresh_token = tkn_from_file(self.tkn_refresh_filekey()?)?;

        let refresh_tkn_str = match refresh_token.refresh_token {
            Some(t) => t,
            None => return Err(Error::RefreshTokenValue),
        };

        let tkn = self
            ._http_client
            .post(credentials.token_uri.as_str())
            .form(&[
                ("client_id", credentials.client_id.as_str()),
                ("client_secret", credentials.client_secret.as_str()),
                ("refresh_token", refresh_tkn_str.as_str()),
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
        if let Ok(tkn_dir) = env::var(TOKEN_DIR_ENV_NAME) {
            Ok(PathBuf::from(tkn_dir))
        } else {
            match dirs::home_dir() {
                Some(t) => Ok(t.join(format!(".{}", &self.app_name))),
                None => Err(Error::HomeDirError),
            }
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::thread::sleep;
    use std::time::Duration;

    use mockito;
    use mockito::mock;
    use serde_json::error as serde_errs;
    use serde_json::Error as serde_err;

    use super::*;
    use errors::Error as intern_err;

    #[test]
    fn auth_tkn_path_success() {
        let auth = Auth::new("myapp".to_owned(), PathBuf::new());

        // todo: add checking from env var

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
        let token_json = test_tkn_fixture_string(3600, Some("refresh_token_value"));

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

            let tkn_json = format!(
                "{}",
                test_tkn_fixture_string(expires_in, Some("refresh_token"))
            );
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

    #[test]
    fn tkn_is_valid() {
        let mut auth = Auth::new("my_test_app".to_owned(), PathBuf::new());
        auth.set_validate_host(&mockito::server_url());

        let test_cases = vec![
            (
                "expected: token is valid, 200 OK from google",
                200..201,
                true,
            ),
            (
                "expected: token is not valid, google response status >= 100, < 200",
                100..200,
                false,
            ),
            (
                "expected: token is not valid, google response status > 200, <= 511",
                201..512,
                false,
            ),
        ];

        let filename = "test_token_name.json";
        let expires_in = 1;

        let tkn_json = format!(
            "{}",
            test_tkn_fixture_string(expires_in, Some("refresh_token"))
        );
        assert!(fs::write(filename, tkn_json).is_ok());

        sleep(Duration::from_secs(expires_in + 1));

        let tkn_deserialized =
            tkn_from_file(filename).expect("expect to have successfully read test fixture file");

        for test_case in test_cases.into_iter() {
            let (scenario, status_code_range, expected) = test_case;

            for status_code in status_code_range {
                let m = mock(
                    "GET",
                    format!(
                        "/oauth2/v3/tokeninfo?access_token={}",
                        tkn_deserialized.access_token
                    )
                    .as_str(),
                )
                .with_status(status_code)
                .create();

                let actual = auth.tkn_is_valid(&tkn_deserialized, filename);
                m.assert();
                assert_eq!(actual, expected, "scenario failed: {}", scenario);
                mockito::reset();
            }
        }

        fs::remove_file(filename).expect("could not remove test token fixture");
    }

    #[test]
    fn tkn_exchange_success() {
        let host = &mockito::server_url();

        let crds = &test_credentials_fixture(host);
        let auth = Auth::new("mytestapp".to_owned(), PathBuf::new());
        let expected = Token {
            access_token: "expected_access_token".to_owned(),
            expires_in: 3600,
            refresh_token: Some("expected_refresh_token".to_owned()),
            scope: Some("expected_scope".to_owned()),
            token_type: "expected_token_type".to_owned(),
        };

        let m = mock("POST", "/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body("code=myauth_code&client_secret=myclientsecret&grant_type=authorization_code&client_id=myclient_id&redirect_uri=urn%3Aredirect")
            .with_body(
                serde_json::to_string(&expected).expect("test token successfully serialized"),
            )
            .create();

        let obtained = auth.tkn_exchange("myauth_code".to_owned(), crds);
        m.assert();
        assert_eq!(
            obtained,
            Ok(expected),
            "expect to have successfully obtained token"
        );
        mockito::reset();
    }

    #[test]
    fn tkn_exchange_deserialize_error() {
        let host = &mockito::server_url();

        let crds = &test_credentials_fixture(host);
        let auth = Auth::new("mytestapp".to_owned(), PathBuf::new());

        let m = mock("POST", "/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body("code=myauth_code&client_secret=myclientsecret&grant_type=authorization_code&client_id=myclient_id&redirect_uri=urn%3Aredirect")
            .with_body("{asdasdas")
            .create();

        let obtained_err = auth
            .tkn_exchange("myauth_code".to_owned(), crds)
            .unwrap_err();

        m.assert();
        assert!(
            obtained_err.to_string().contains("key must be a string at"),
            "expect to get a json unmarshal error, actual: {}",
            obtained_err.to_string(),
        );
        mockito::reset();
    }

    #[test]
    fn tkn_refresh_success() {
        setup_token_storage_dir();

        let host = &mockito::server_url();
        let auth = Auth::new("tkn_refresh_test".to_owned(), PathBuf::new());

        let refresh_tkn_json = test_tkn_fixture_string(3600, Some("test_refresh_token"));
        assert!(fs::write(
            auth.tkn_refresh_filekey()
                .expect("successfully generated refresh token filekey"),
            refresh_tkn_json,
        )
        .is_ok());

        let expected_string = test_tkn_fixture_string(3600, None);

        let m = mockito::mock("POST", "/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body("client_id=myclient_id&client_secret=myclientsecret&refresh_token=test_refresh_token&grant_type=refresh_token")
            .with_body(&expected_string)
            .create();

        let credentials = test_credentials_fixture(host);
        let obtained = auth.tkn_refresh(&credentials);
        m.assert();

        let expected = test_tkn_fixture(expected_string.as_bytes());
        assert_eq!(obtained, Ok(expected));

        mockito::reset();

        fs::remove_file(auth.tkn_refresh_filekey().unwrap())
            .expect("could not remove test token fixture");

        teardown_token_storage_dir();
    }

    #[test]
    fn tkn_refresh_read_err() {
        let auth = Auth::new("tkn_refresh_read_err".to_owned(), PathBuf::new());
        let crds = &test_credentials_fixture("somehost");

        let expected_io_err = io::Error::new(
            io::ErrorKind::NotFound,
            "No such file or directory (os error 2)",
        );

        let expected_err_msg = expected_io_err.to_string();

        let expected_err = Error::IOError(expected_io_err);
        let obtained_err = auth.tkn_refresh(crds).unwrap_err();

        assert_eq!(obtained_err, expected_err);
        assert_eq!(obtained_err.to_string(), expected_err_msg);
    }

    #[test]
    fn tkn_refresh_empty_refresh_val() {
        setup_token_storage_dir();

        let auth = Auth::new("tkn_refresh_read_err".to_owned(), PathBuf::new());
        let crds = &test_credentials_fixture("somehost");

        let refresh_tkn_json = test_tkn_fixture_string(3600, None);
        assert!(fs::write(
            auth.tkn_refresh_filekey()
                .expect("successfully generated refresh token filekey"),
            refresh_tkn_json,
        )
        .is_ok());

        let obtained_err = auth.tkn_refresh(crds).unwrap_err();
        assert_eq!(obtained_err, Error::RefreshTokenValue);

        fs::remove_file(auth.tkn_refresh_filekey().unwrap())
            .expect("could not remove test token fixture");

        teardown_token_storage_dir();
    }

    #[test]
    fn tkn_refresh_unmarshal_err() {
        setup_token_storage_dir();

        let auth = Auth::new("tkn_refresh_unmarshal_err".to_owned(), PathBuf::new());

        let refresh_tkn_json = test_tkn_fixture_string(3600, Some("refresh_token"));
        assert!(fs::write(
            auth.tkn_refresh_filekey()
                .expect("successfully generated refresh token filekey"),
            refresh_tkn_json,
        )
        .is_ok());

        let host = &mockito::server_url();
        let crds = &test_credentials_fixture(host);

        let m = mock("POST", "/token").with_body("{aaaaa").create();

        let obtained_err = auth.tkn_refresh(crds).unwrap_err();
        m.assert();

        assert!(
            obtained_err.to_string().contains("key must be a string at"),
            "expect to get a json unmarshal error, actual: {}",
            obtained_err.to_string()
        );

        mockito::reset();

        fs::remove_file(auth.tkn_refresh_filekey().unwrap())
            .expect("could not remove test token fixture");

        teardown_token_storage_dir();
    }

    // fn tkn_save_success() {}
    // fn tkn_save_filekey_err() {}
    // fn tkn_save_dir_err() {}
    // fn tkn_save_tkn_path_err() {}
    // fn tkn_save_file_create_err() {}
    // fn tkn_save_write_json_err() {}

    #[test]
    fn tkn_filekeys_success() {
        let access_tkn_json = test_tkn_fixture_string(3600, None);
        let access_token = test_tkn_fixture(access_tkn_json.as_bytes());

        let refresh_tkn_json = test_tkn_fixture_string(3600, Some("refresh_token"));
        let refresh_token = test_tkn_fixture(refresh_tkn_json.as_bytes());

        let home_dir =
            dirs::home_dir().expect("tkn_filekeys_success: successfully retrieved home dir");

        let custom_dir = PathBuf::from("custom_dir");

        let test_name = "tkn_filekeys_success";
        let auth = Auth::new(test_name.to_owned(), PathBuf::new());

        let test_cases = vec![
            (
                "scenario: home_dir: token filekeys successfully generated for refresh token",
                &refresh_token,
                false,
                vec![
                    home_dir
                        .join(format!(".{}", test_name))
                        .join("access_token.json"),
                    home_dir
                        .join(format!(".{}", test_name))
                        .join("refresh_token.json"),
                ],

            ),
            (
                "scenario: custom_dir: token filekeys successfully generated for refresh token",
                &refresh_token,
                true,
                vec![
                    custom_dir.join("access_token.json"),
                    custom_dir.join("refresh_token.json"),
                ],

            ),
            (
                "scenario: home_dir: token filekeys successfully generated for access token",
                &access_token,
                false,
                vec![home_dir
                    .join(format!(".{}", test_name))
                    .join("access_token.json")],
            ),
            (
                "scenario: custom_dir: token filekeys successfully generated for access token",
                &access_token,
                true,
                vec![custom_dir.join("access_token.json")],
            ),
        ];


        for test_case in test_cases.into_iter() {
            let (scenario, token, is_custom_dir, expected_keys) = test_case;

            if is_custom_dir {
                env::set_var(TOKEN_DIR_ENV_NAME, &custom_dir);
            }

            let obtained = auth.tkn_filekeys(token).unwrap();
            assert_eq!(obtained.len(), expected_keys.len());

            for (i, obtained_key) in obtained.iter().enumerate() {
                assert_eq!(
                    obtained_key.to_str().unwrap(),
                    expected_keys.get(i).unwrap().to_str().unwrap(),
                    "failed test case: {}",
                    scenario,
                );
            }

            if is_custom_dir {
                env::remove_var(TOKEN_DIR_ENV_NAME);
            }
        }
    }

    fn setup_token_storage_dir() {
        let wd = env::current_dir().expect("successfully retrieved current dir");
        env::set_var(TOKEN_DIR_ENV_NAME, wd);
    }

    fn teardown_token_storage_dir() {
        env::remove_var(TOKEN_DIR_ENV_NAME);
    }

    fn setup_token_validate_host() {
        env::set_var(VALIDATE_HOST_ENV_NAME, &mockito::server_url());
    }

    fn teardown_token_validate_host() {
        env::remove_var(VALIDATE_HOST_ENV_NAME);
    }

    fn test_credentials_fixture(host: &str) -> OauthCredentials {
        OauthCredentials {
            client_id: "myclient_id".to_owned(),
            project_id: "myproject_id".to_owned(),
            auth_uri: format!("{}/o/oauth2/auth", host),
            token_uri: format!("{}/token", host),
            auth_provider_x509_cert_url: format!("{}/oauth2/v1/certs", host),
            client_secret: "myclientsecret".to_owned(),
            redirect_uris: vec!["urn:redirect".to_owned(), "http://localhost".to_owned()],
        }
    }

    fn test_tkn_fixture(b: &[u8]) -> Token {
        serde_json::from_slice::<Token>(b).expect("successfully unmarshalled test token string")
    }

    fn test_tkn_fixture_string(exp_v: u64, refresh_value: Option<&str>) -> String {
        let refresh = match refresh_value {
            Some(t) => format!("\"{}\"", t),
            None => "null".to_owned(),
        };

        format!(
            r###"{{
                    "access_token": "access_token_value",
                    "expires_in": {exp_val},
                    "refresh_token": {refresh_val},
                    "scope": "https://www.googleapis.com/auth/calendar.events",
                    "token_type": "Bearer"
                }}"###,
            exp_val = exp_v,
            refresh_val = refresh,
        )
    }
}
