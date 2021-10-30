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
                write!(f, "Sigil error: {}", err)
            }
            SsbUriError::InvalidUri(ref err) => {
                write!(f, "URI error: {}", err)
            }
            SsbUriError::UnknownFormat(ref err) => {
                write!(f, "Format error: {}", err)
            }
            SsbUriError::UnknownType(ref err) => {
                write!(f, "Type error: {}", err)
            }
            SsbUriError::ParseUrl(ref err) => {
                write!(f, "Parse error: {}", err)
            }
            SsbUriError::InvalidUtf8(ref err) => {
                write!(f, "Decode error: {}", err)
            }
            SsbUriError::InvalidRegex(ref err) => {
                write!(f, "Regex error: {}", err)
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
