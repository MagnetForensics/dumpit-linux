use std::io;
use std::num;

pub type Result<T> = std::result::Result<T, Error>;

use log::{error};
use nix;

#[derive(Debug)]
pub enum Error {
    IoError(String),
    IntParseError(String),
    ElfParseError(String),
    ObjectParseError(String),
    NixError(String)
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            _ => {
                error!("{}", err.to_string());
                Error::IoError(err.to_string())
            },
        }
    }
}

impl From<num::ParseIntError> for Error {
    fn from(err: num::ParseIntError) -> Self {
        match err.kind() {
            _ => {
                error!("{}", err.to_string());
                Error::IntParseError(err.to_string())
            },
        }
    }
}

impl From<goblin::error::Error> for Error {
    fn from(err: goblin::error::Error) -> Self {
        match err {
            _ => {
                error!("{}", err.to_string());
                Error::ElfParseError(err.to_string())
            },
        }
    }
}

impl From<object::Error> for Error {
    fn from(err: object::Error) -> Self {
        match err {
            _ => {
                error!("{}", err.to_string());
                Error::ObjectParseError(err.to_string())
            },
        }
    }
}

impl From<object::write::Error> for Error {
    fn from(err: object::write::Error) -> Self {
        match err {
            _ => {
                error!("{}", err.to_string());
                Error::ObjectParseError(err.to_string())
            },
        }
    }
}

impl From<nix::errno::Errno> for Error {
    fn from(err: nix::errno::Errno) -> Self {
        match err {
            _ => {
                error!("{}", err.to_string());
                Error::NixError(err.to_string())
            },
        }
    }
}