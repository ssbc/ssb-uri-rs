use core::str::Utf8Error;
use regex::Error as RegexError;
use std::{error, fmt};
use url::ParseError;

#[derive(Debug)]
pub enum SsbUriError {
    UnknownFormat(String),
    UnknownType(String),
    InvalidSuffix(String),
    InvalidUri(String),
    ParseUrl(url::ParseError),
    InvalidUtf8(core::str::Utf8Error),
    InvalidRegex(regex::Error),
}

impl error::Error for SsbUriError {}

impl fmt::Display for SsbUriError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SsbUriError::InvalidSuffix(ref err) => {
                write!(f, "{}", err)
            }
            SsbUriError::InvalidUri(ref err) => {
                write!(f, "{}", err)
            }
            SsbUriError::UnknownFormat(ref err) => {
                write!(f, "{}", err)
            }
            SsbUriError::UnknownType(ref err) => {
                write!(f, "{}", err)
            }
            SsbUriError::ParseUrl(ref err) => {
                write!(f, "{}", err)
            }
            SsbUriError::InvalidUtf8(ref err) => {
                write!(f, "{}", err)
            }
            SsbUriError::InvalidRegex(ref err) => {
                write!(f, "{}", err)
            }
        }
    }
}

impl From<ParseError> for SsbUriError {
    fn from(err: ParseError) -> SsbUriError {
        SsbUriError::ParseUrl(err)
    }
}

impl From<Utf8Error> for SsbUriError {
    fn from(err: Utf8Error) -> SsbUriError {
        SsbUriError::InvalidUtf8(err)
    }
}

impl From<RegexError> for SsbUriError {
    fn from(err: RegexError) -> SsbUriError {
        SsbUriError::InvalidRegex(err)
    }
}
