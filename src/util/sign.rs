use super::error::{Error, Result};
use std::fmt::{Display, Formatter, Result as fmtResult};
use std::str::FromStr;

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignType {
    Cms,          // signed method for a CMS signed data
    KernelCms,    // signed method for a kernel CMS signed data
    Authenticode, // signed method for signing EFI image using authenticode spec
    PKCS7,        // signed method for a pkcs7 signed data
    RsaHash,      // signed method for a ima eam using rsa hash
}

impl Display for SignType {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            SignType::Cms => write!(f, "cms"),
            SignType::KernelCms => write!(f, "kernel-cms"),
            SignType::Authenticode => write!(f, "authenticode"),
            SignType::PKCS7 => write!(f, "pkcs7"),
            SignType::RsaHash => write!(f, "rsahash"),
        }
    }
}

impl FromStr for SignType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "cms" => Ok(SignType::Cms),
            "kernel-cms" => Ok(SignType::KernelCms),
            "authenticode" => Ok(SignType::Authenticode),
            "pkcs7" => Ok(SignType::PKCS7),
            "rsahash" => Ok(SignType::RsaHash),
            _ => Err(Error::ParameterError("Invalid sign_type param".to_string())),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FileType {
    Rpm,
    Generic,
    KernelModule,
    EfiImage,
    ImaEvm,
    P7s,
}

impl Display for FileType {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            FileType::Rpm => write!(f, "rpm"),
            FileType::Generic => write!(f, "generic"),
            FileType::KernelModule => write!(f, "ko"),
            FileType::EfiImage => write!(f, "efi"),
            FileType::ImaEvm => write!(f, "ima"),
            FileType::P7s => write!(f, "p7s"),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum KeyType {
    Pgp,
    X509,
    X509EE,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            KeyType::Pgp => write!(f, "pgp"),
            KeyType::X509EE => write!(f, "x509ee"),
            //client can use 'x509' to specify a x509 key type for the purpose of simplicity.
            KeyType::X509 => write!(f, "x509ee"),
        }
    }
}
