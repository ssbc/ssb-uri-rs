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

impl std::fmt::Display for SsbUriError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

impl From<url::ParseError> for SsbUriError {
    fn from(err: url::ParseError) -> SsbUriError {
        SsbUriError::ParseUrl(err)
    }
}

impl From<core::str::Utf8Error> for SsbUriError {
    fn from(err: core::str::Utf8Error) -> SsbUriError {
        SsbUriError::InvalidUtf8(err)
    }
}

impl From<regex::Error> for SsbUriError {
    fn from(err: regex::Error) -> SsbUriError {
        SsbUriError::InvalidRegex(err)
    }
}
