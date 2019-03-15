use serde_json::error as serde_err;
use std::cmp;
use std::env;
use std::error;
use std::fmt;
use std::io;
use std::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    TokenPathError,
    HomeDirError,
    IOError(io::Error),
    JSONError(serde_err::Error),
    EnvVarError(env::VarError),
    ReqwestError(reqwest::Error),
    UrlError(url::ParseError),
    RedirectUriCfgError,
}

impl cmp::PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        match (&self, other) {
            (Error::TokenPathError, Error::TokenPathError) => true,
            (Error::HomeDirError, Error::HomeDirError) => true,
            (Error::IOError(_), Error::IOError(_)) => true,
            (Error::JSONError(_), Error::JSONError(_)) => true,
            (Error::EnvVarError(_), Error::EnvVarError(_)) => true,
            (Error::ReqwestError(_), Error::ReqwestError(_)) => true,
            (Error::UrlError(_), Error::UrlError(_)) => true,
            (Error::RedirectUriCfgError, Error::RedirectUriCfgError) => true,
            (_, _) => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // todo: get rid of duplication the info here and in self.description()
            Error::TokenPathError => write!(f, "failed to retrieve token dir from filekey"),
            Error::IOError(ref e) => e.fmt(f),
            Error::JSONError(ref e) => e.fmt(f),
            Error::EnvVarError(ref e) => e.fmt(f),
            Error::ReqwestError(ref e) => e.fmt(f),
            Error::UrlError(ref e) => e.fmt(f),
            Error::HomeDirError => write!(f, "{}", "failed to identify home directory"),
            Error::RedirectUriCfgError => {
                write!(f, "failed to retrieve redirect_uri from credentials")
            }
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::TokenPathError => "failed to retrieve token dir from filekey",
            Error::IOError(ref e) => e.description(),
            Error::JSONError(ref e) => e.description(),
            Error::EnvVarError(ref e) => e.description(),
            Error::ReqwestError(ref e) => e.description(),
            Error::UrlError(ref e) => e.description(),
            Error::HomeDirError => "failed to identify home directory",
            Error::RedirectUriCfgError => "failed to retrieve redirect_uri from credentials",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::TokenPathError => None,
            Error::IOError(ref e) => Some(e),
            Error::JSONError(ref e) => Some(e),
            Error::EnvVarError(ref e) => Some(e),
            Error::ReqwestError(ref e) => Some(e),
            Error::UrlError(ref e) => Some(e),
            Error::HomeDirError => None,
            Error::RedirectUriCfgError => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IOError(err)
    }
}

impl From<serde_err::Error> for Error {
    fn from(err: serde_err::Error) -> Error {
        Error::JSONError(err)
    }
}

impl From<env::VarError> for Error {
    fn from(err: env::VarError) -> Error {
        Error::EnvVarError(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::ReqwestError(err)
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::UrlError(err)
    }
}
