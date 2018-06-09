extern crate chrono;
#[macro_use] extern crate failure;
#[macro_use] extern crate log;
extern crate ring;
extern crate untrusted;

use std::str;

use chrono::prelude::*;
pub use failure::Error;
use ring::{rand, signature};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

// This is a new error type that you've created. It represents the ways a
// toolchain could be invalid.
//
// The custom derive for Fail derives an impl of both Fail and Display.
// We don't do any other magic like creating new types.
#[derive(Debug, Fail)]
pub enum LicenseError {
    #[fail(display = "invalid public key")]
    InvalidPublicKey,
    #[fail(display = "Missing license text")]
    MissingLicenseText,
    #[fail(display = "Missing public key")]
    MissingPublicKey,
    #[fail(display = "Missing signature")]
    MissingSignature,
}

#[derive(Default)]
pub struct LicenseBuilder<'a> {
    text: Option<&'a str>,
    public_key: Option<&'a [u8]>,
    signature: Option<&'a [u8]>,
}


impl<'a> LicenseBuilder<'a> {
    pub fn with_signature(mut self, signature: &'a [u8]) -> Self {
        self.signature = Some(signature);
        self
    }

    pub fn with_public_key(mut self, public_key: &'a [u8]) -> Self {
        self.public_key = Some(public_key);
        self
    }

    pub fn build(self) -> Result<License, LicenseError> {
        let public_key = match self.public_key {
            Some(s) => s,
            None => return Err(LicenseError::MissingPublicKey),
        };
        let signature = match self.signature {
            Some(s) => s,
            None => return Err(LicenseError::MissingSignature),
        };
        let text = match self.text {
            Some(s) => s,
            None => return Err(LicenseError::MissingLicenseText),
        };
        // Verify the signature of the message using the public key. Normally the
        // verifier of the message would parse the inputs to `signature::verify`
        // out of the protocol message(s) sent by the signer.
        let msg = untrusted::Input::from(text.as_bytes());
        let sig = untrusted::Input::from(signature);
        let pub_key = untrusted::Input::from(public_key);

        let valid_signature = match signature::verify(&signature::ED25519, pub_key, msg, sig) {
            Ok(_) => {
                true
            },
            Err(e) => {
                debug!("Erorr validating: {:?}", e);
                false
            }
        };
        let mut license = License::default();
        license.signature_valid = valid_signature;

        Ok(license)
    }
}

#[derive(Default)]
pub struct License {
    expires: Option<DateTime<Utc>>,
    signature_valid: bool,
}

impl License {
    pub fn new<'a>(input: &'a [u8]) -> LicenseBuilder<'a> {

        let mut lb = LicenseBuilder::default();
        match input.iter().position(|&r| r == 0x00) {
            Some(split_index) => {
                let (text, mut sig) = input.split_at(split_index);
                if let Ok(text) = str::from_utf8(text) {
                    lb.text = Some(text);
                }
                lb.signature = Some(&sig[1..]);
            },
            None => {}
        }

        lb
    }

    pub fn valid(&self) -> bool {
        if ! self.signature_valid {
            return false;
        }
        if let Some(expires) = self.expires {
            if expires > Utc::now() {
                return false;
            }
        }
        return true
    }
}