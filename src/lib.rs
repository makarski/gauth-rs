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

/// VALIDATE_HOST_ENV_NAME holds the name of the env var
/// that used to validate the token.
/// If env is not set the default google host is used.
///
/// This configuration is intended in the first place for
/// the testing purposes
const VALIDATE_HOST_ENV_NAME: &str = "GAUTH_VALIDATE_HOST";

/// TOKEN_DIR_ENV_NAME holds the name of the env var
/// that is used to configure the directory for storing tokens.
///
/// If not set, $HOME will be used as the default value.
const TOKEN_DIR_ENV_NAME: &str = "GAUTH_TOKEN_DIR";

pub struct Auth {
    app_name: String,
    crd_path: PathBuf,
    validate_token_host: String,
    _http_client: reqwest::Client,
}

impl Auth {
    pub fn new(app_name: String, crd_path: PathBuf) -> Auth {
        Auth {
            app_name: app_name,
            crd_path: crd_path,
            validate_token_host: validate_host(),
            _http_client: reqwest::Client::new(),
        }
    }

    pub fn access_token<F>(&self, scope: &str, get_auth_code: F) -> Result<Token>
    where
        F: Fn(String) -> result::Result<String, Box<dyn std_err::Error>>,
    {
        let tkn_filekey = self.access_token_filekey()?;
        let crds_cfg = credentials::read_oauth_config(&self.crd_path)?.installed;

        token_from_file(tkn_filekey.as_path())
            .or_else(|_| {
                credentials::auth_code_uri_str(&crds_cfg, scope)
                    .and_then(|consent_uri| {
                        get_auth_code(consent_uri).map_err(|err| Error::UserError(err))
                    })
                    .and_then(|auth_code| self.exchange_auth_code(auth_code, &crds_cfg))
                    .and_then(|tkn| self.cache_token(tkn))
            })
            .and_then(|tkn| {
                if self.token_is_valid(&tkn, tkn_filekey.as_path()) {
                    Ok(tkn)
                } else {
                    self.refresh_token(&crds_cfg)
                        .and_then(|tkn| self.cache_token(tkn))
                }
            })
    }

    fn token_is_valid<P: AsRef<Path>>(&self, tkn: &Token, p: P) -> bool {
        if !self.token_is_expired(tkn, p) {
            return true;
        }

        let url = format!(
            "{}/oauth2/v3/tokeninfo?access_token={}",
            self.validate_token_host, tkn.access_token
        );

        let resp = self._http_client.get(url.as_str()).send();
        match resp {
            Ok(t) => t.status() == reqwest::StatusCode::OK,
            Err(_) => false,
        }
    }

    fn token_is_expired<P: AsRef<Path>>(&self, tkn: &Token, p: P) -> bool {
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

    fn exchange_auth_code(
        &self,
        auth_code: String,
        credentials: &OauthCredentials,
    ) -> Result<Token> {
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

    fn refresh_token(&self, credentials: &OauthCredentials) -> Result<Token> {
        let refresh_token = token_from_file(self.refresh_token_filekey()?)?;

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

    fn cache_token(&self, tkn: Token) -> Result<Token> {
        let keys = self.token_filekeys(&tkn)?;

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

    fn token_filekeys(&self, tkn: &Token) -> Result<Vec<PathBuf>> {
        let mut keys = vec![self.access_token_filekey()?];

        if tkn.is_refresh() {
            keys.push(self.refresh_token_filekey()?);
        }

        Ok(keys)
    }

    fn token_path(&self) -> Result<PathBuf> {
        if let Ok(tkn_dir) = env::var(TOKEN_DIR_ENV_NAME) {
            Ok(PathBuf::from(tkn_dir))
        } else {
            match dirs::home_dir() {
                Some(t) => Ok(t.join(format!(".{}", &self.app_name))),
                None => Err(Error::HomeDirError),
            }
        }
    }

    fn refresh_token_filekey(&self) -> Result<PathBuf> {
        Ok(self.token_path()?.join("refresh_token.json"))
    }

    fn access_token_filekey(&self) -> Result<PathBuf> {
        Ok(self.token_path()?.join("access_token.json"))
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

fn token_from_file<P: AsRef<Path>>(p: P) -> Result<Token> {
    let b = fs::read(p)?;
    let tkn = serde_json::from_slice::<Token>(&b)?;
    Ok(tkn)
}

/// Returns the value set in `GAUTH_VALIDATE_HOST` or default
fn validate_host() -> String {
    if let Ok(env_host) = env::var(VALIDATE_HOST_ENV_NAME) {
        return env_host;
    }

    VALIDATE_HOST.to_owned()
}

mod tests {
    #[cfg(test)]
    use std::fs;

    #[cfg(test)]
    use std::io;

    #[cfg(test)]
    use std::thread::sleep;

    #[cfg(test)]
    use std::time::Duration;

    #[cfg(test)]
    use mockito;

    #[cfg(test)]
    use mockito::mock;

    #[cfg(test)]
    use serde_json::error as serde_errs;

    #[cfg(test)]
    use serde_json::Error as serde_err;

    #[cfg(test)]
    use super::*;

    #[cfg(test)]
    use errors::Error as intern_err;

    #[test]
    fn token_path_success() {
        let auth = Auth::new("token_path_success".to_owned(), PathBuf::new());

        let test_cases = vec![
            (
                "expected token path format: mydir",
                Some("mydir"),
                Ok(PathBuf::from("mydir")),
            ),
            (
                "expected token path format: $HOME/.{{app_name}}",
                None,
                Ok(dirs::home_dir().unwrap().join(".token_path_success")),
            ),
        ];

        for test_case in test_cases.into_iter() {
            let (scenario, env_host, expected) = test_case;

            if env_host.is_some() {
                env::set_var(TOKEN_DIR_ENV_NAME, env_host.unwrap());
            }

            assert_eq!(auth.token_path(), expected, "scenario failed: {}", scenario);

            if env_host.is_some() {
                env::remove_var(TOKEN_DIR_ENV_NAME);
            }
        }
    }

    #[test]
    fn access_token_filekey_success() {
        let auth = Auth::new("myapp".to_owned(), PathBuf::new());

        assert_eq!(
            auth.access_token_filekey(),
            Ok(auth.token_path().unwrap().join("access_token.json")),
            "expected token format: $HOME/.{{app_name}}/access_token.json"
        );
    }

    #[test]
    fn refresh_token_filekey_success() {
        let auth = Auth::new("myapp".to_owned(), PathBuf::new());

        assert_eq!(
            auth.refresh_token_filekey(),
            Ok(auth.token_path().unwrap().join("refresh_token.json")),
            "expected token format: $HOME/.{{app_name}}/refresh_token.json"
        );
    }


    #[test]
    fn token_from_file_success() {
        let token_json = test_token_fixture_string(3600, Some("refresh_token_value"));
        assert!(fs::write("testfile.json", &token_json).is_ok());

        let expected = test_token_fixture(token_json.as_bytes());
        let tkn_res = token_from_file("testfile.json");
        assert_eq!(
            tkn_res,
            Ok(expected),
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

    #[test]
    fn token_is_expired() {
        let auth = Auth::new("token_is_expired".to_owned(), PathBuf::new());

        let test_cases = vec![
            (
                "expected: token is expired",
                1,
                2,
                "test_token_is_expired_expired_token.json",
                true,
            ),
            (
                "expected: token is not expired",
                3600,
                1,
                "test_token_is_expired_non_expired_token.json",
                false,
            ),
        ];

        for test_case in test_cases.into_iter() {
            let (scenario, expires_in, sleep_secs, filename, expected_is_expired) = test_case;

            let tkn_json = test_token_fixture_string(expires_in, Some("refresh_token"));
            assert!(fs::write(filename, tkn_json).is_ok());

            sleep(Duration::from_secs(sleep_secs));

            let tkn_deserialized = token_from_file(filename)
                .expect("expect to have successfully read test fixture file");

            assert_eq!(
                auth.token_is_expired(&tkn_deserialized, filename),
                expected_is_expired,
                "scenario failed: {}",
                scenario,
            );

            fs::remove_file(filename).expect("could not remove test file");
        }
    }

    #[test]
    fn token_is_valid() {
        setup_token_validate_host();
        let auth = Auth::new("token_is_valid".to_owned(), PathBuf::new());

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

        let filename = "test_token_is_valid_token_name.json";
        let expires_in = 1;

        let tkn_json = test_token_fixture_string(expires_in, Some("refresh_token"));
        assert!(fs::write(filename, tkn_json).is_ok());

        sleep(Duration::from_secs(expires_in + 1));

        let tkn_deserialized =
            token_from_file(filename).expect("expect to have successfully read test fixture file");

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

                let actual = auth.token_is_valid(&tkn_deserialized, filename);
                m.assert();
                assert_eq!(actual, expected, "scenario failed: {}", scenario);
                mockito::reset();
            }
        }

        fs::remove_file(filename).expect("could not remove test token fixture");
        teardown_token_validate_host();
    }

    #[test]
    fn exchange_auth_code_success() {
        let host = &mockito::server_url();

        let crds = &test_credentials_fixture(host);
        let auth = Auth::new("exchange_auth_code_success".to_owned(), PathBuf::new());

        let expected_token_str = test_token_fixture_string(3600, Some("expected_refresh_token"));
        let expected_token = test_token_fixture(&expected_token_str.as_bytes());

        let m = mock("POST", "/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body("code=myauth_code&client_secret=myclientsecret&grant_type=authorization_code&client_id=myclient_id&redirect_uri=urn%3Aredirect")
            .with_body(&expected_token_str)
            .create();

        let obtained = auth.exchange_auth_code("myauth_code".to_owned(), crds);
        m.assert();
        assert_eq!(
            obtained,
            Ok(expected_token),
            "expect to have successfully obtained token"
        );
        mockito::reset();
    }

    #[test]
    fn exchange_auth_code_deserialize_error() {
        let host = &mockito::server_url();

        let crds = &test_credentials_fixture(host);
        let auth = Auth::new(
            "exchange_auth_code_deserialize_error".to_owned(),
            PathBuf::new(),
        );

        let m = mock("POST", "/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body("code=myauth_code&client_secret=myclientsecret&grant_type=authorization_code&client_id=myclient_id&redirect_uri=urn%3Aredirect")
            .with_body("{asdasdas")
            .create();

        let obtained_err = auth
            .exchange_auth_code("myauth_code".to_owned(), crds)
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
    fn refresh_token_success() {
        setup_token_storage_dir();

        let host = &mockito::server_url();
        let auth = Auth::new("refresh_token_test".to_owned(), PathBuf::new());

        let refresh_tkn_json = test_token_fixture_string(3600, Some("test_refresh_token"));
        assert!(fs::write(
            auth.refresh_token_filekey()
                .expect("successfully generated refresh token filekey"),
            refresh_tkn_json,
        )
        .is_ok());

        let expected_string = test_token_fixture_string(3600, None);

        let m = mockito::mock("POST", "/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body("client_id=myclient_id&client_secret=myclientsecret&refresh_token=test_refresh_token&grant_type=refresh_token")
            .with_body(&expected_string)
            .create();

        let credentials = test_credentials_fixture(host);
        let obtained = auth.refresh_token(&credentials);
        m.assert();

        let expected = test_token_fixture(expected_string.as_bytes());
        assert_eq!(obtained, Ok(expected));

        mockito::reset();

        fs::remove_file(auth.refresh_token_filekey().unwrap())
            .expect("could not remove test token fixture");

        teardown_token_storage_dir();
    }

    #[test]
    fn refresh_token_read_err() {
        let auth = Auth::new("refresh_token_read_err".to_owned(), PathBuf::new());
        let crds = &test_credentials_fixture("somehost");

        let expected_io_err = io::Error::new(
            io::ErrorKind::NotFound,
            "No such file or directory (os error 2)",
        );

        let expected_err_msg = expected_io_err.to_string();

        let expected_err = Error::IOError(expected_io_err);
        let obtained_err = auth.refresh_token(crds).unwrap_err();

        assert_eq!(obtained_err, expected_err);
        assert_eq!(obtained_err.to_string(), expected_err_msg);
    }

    #[test]
    fn refresh_token_empty_refresh_val() {
        setup_token_storage_dir();

        let auth = Auth::new("refresh_token_read_err".to_owned(), PathBuf::new());
        let crds = &test_credentials_fixture("somehost");

        let refresh_tkn_json = test_token_fixture_string(3600, None);
        assert!(fs::write(
            auth.refresh_token_filekey()
                .expect("successfully generated refresh token filekey"),
            refresh_tkn_json,
        )
        .is_ok());

        let obtained_err = auth.refresh_token(crds).unwrap_err();
        assert_eq!(obtained_err, Error::RefreshTokenValue);

        fs::remove_file(auth.refresh_token_filekey().unwrap())
            .expect("could not remove test token fixture");

        teardown_token_storage_dir();
    }

    #[test]
    fn refresh_token_unmarshal_err() {
        setup_token_storage_dir();

        let auth = Auth::new("refresh_token_unmarshal_err".to_owned(), PathBuf::new());

        let refresh_tkn_json = test_token_fixture_string(3600, Some("refresh_token"));
        assert!(fs::write(
            auth.refresh_token_filekey()
                .expect("successfully generated refresh token filekey"),
            refresh_tkn_json,
        )
        .is_ok());

        let host = &mockito::server_url();
        let crds = &test_credentials_fixture(host);

        let m = mock("POST", "/token").with_body("{aaaaa").create();

        let obtained_err = auth.refresh_token(crds).unwrap_err();
        m.assert();

        assert!(
            obtained_err.to_string().contains("key must be a string at"),
            "expect to get a json unmarshal error, actual: {}",
            obtained_err.to_string()
        );

        mockito::reset();

        fs::remove_file(auth.refresh_token_filekey().unwrap())
            .expect("could not remove test token fixture");

        teardown_token_storage_dir();
    }

    #[test]
    fn cache_token_success() {
        setup_token_storage_dir();

        let tkn_json = test_token_fixture_string(3600, Some("refresh_token"));
        let token = test_token_fixture(tkn_json.as_bytes());

        let auth = Auth::new("cache_token_success".to_owned(), PathBuf::new());
        let obtained = auth.cache_token(token);

        assert_eq!(obtained, Ok(test_token_fixture(tkn_json.as_bytes())));

        let read_dir = fs::read_dir(env::var(TOKEN_DIR_ENV_NAME).unwrap())
            .expect("cache_token_success: expected to have successully read fixtures test dir");

        assert_eq!(
            read_dir.count(),
            2,
            "cache_token_success: expect to have found 2 files"
        );

        teardown_token_storage_dir();
    }

    // TODO: add the following tests
    // fn cache_token_filekey_err() {}
    // fn cache_token_dir_err() {}
    // fn cache_token_token_path_err() {}
    // fn cache_token_file_create_err() {}
    // fn cache_token_write_json_err() {}

    #[test]
    fn token_filekeys_success() {
        let access_tkn_json = test_token_fixture_string(3600, None);
        let access_token = test_token_fixture(access_tkn_json.as_bytes());

        let refresh_tkn_json = test_token_fixture_string(3600, Some("refresh_token"));
        let refresh_token = test_token_fixture(refresh_tkn_json.as_bytes());

        let home_dir =
            dirs::home_dir().expect("token_filekeys_success: successfully retrieved home dir");

        let custom_dir = PathBuf::from("custom_dir");

        let test_name = "token_filekeys_success";
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

            let obtained = auth.token_filekeys(token).unwrap();
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

    #[cfg(test)]
    fn setup_token_storage_dir() {
        let fixture_dir = env::current_dir()
            .and_then(|dir| {
                let target_dir = dir.join(".test_fixtures");
                DirBuilder::new()
                    .recursive(true)
                    .create(&target_dir)
                    .expect("created test fixture dir");
                return Ok(target_dir);
            })
            .map_err(|err| {
                panic!(
                    "successfully have retrieved and created test fixture dir: {}",
                    err
                )
            });

        env::set_var(TOKEN_DIR_ENV_NAME, fixture_dir.unwrap());
    }

    #[cfg(test)]
    fn teardown_token_storage_dir() {
        let env_dir = env::var(TOKEN_DIR_ENV_NAME).expect("successfully read env var");
        fs::remove_dir_all(env_dir).expect("successfully cleared fixtures test directory");

        env::remove_var(TOKEN_DIR_ENV_NAME);
    }

    #[cfg(test)]
    fn setup_token_validate_host() {
        env::set_var(VALIDATE_HOST_ENV_NAME, &mockito::server_url());
    }

    #[cfg(test)]
    fn teardown_token_validate_host() {
        env::remove_var(VALIDATE_HOST_ENV_NAME);
    }

    #[cfg(test)]
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

    #[cfg(test)]
    fn test_token_fixture(b: &[u8]) -> Token {
        serde_json::from_slice::<Token>(b).expect("successfully unmarshalled test token string")
    }

    #[cfg(test)]
    fn test_token_fixture_string(exp_v: u64, refresh_value: Option<&str>) -> String {
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
