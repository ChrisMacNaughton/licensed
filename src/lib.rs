extern crate chrono;
#[macro_use] extern crate failure;
#[macro_use] extern crate log;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate ring;
extern crate untrusted;

use std::str;

use chrono::prelude::*;
pub use failure::Error;
use ring::signature;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_fails_with_missing_signature() {
        let license = License::new(b"test").with_public_key(b"a").build();
        match license {
            Ok(_) => unreachable!(),
            Err(e) => assert_eq!(e.downcast::<LicenseError>().unwrap(), LicenseError::MissingSignature)
        }
    }

    #[test]
    fn it_fails_with_missing_public_key() {
        let license = License::new(b"test").build();
        match license {
            Ok(_) => unreachable!(),
            Err(e) => assert_eq!(e.downcast::<LicenseError>().unwrap(), LicenseError::MissingPublicKey)
        }
    }

    #[test]
    fn it_fails_with_missing_text() {
        let builder = LicenseBuilder::default().with_public_key(&[0x08]).with_signature(&[0x08]);
        match builder.build() {
            Ok(_) => unreachable!(),
            Err(e) => assert_eq!(e.downcast::<LicenseError>().unwrap(), LicenseError::MissingLicenseText)
        }
    }

    #[test]
    fn it_validates_a_signature() {
        let license = include_bytes!("../examples/license");
        let public_key = include_bytes!("../examples/public.pks");

        let license = License::new(license).with_public_key(public_key).build().unwrap();
        assert!(license.valid());
    }
}

// This is a new error type that you've created. It represents the ways a
// toolchain could be invalid.
//
// The custom derive for Fail derives an impl of both Fail and Display.
// We don't do any other magic like creating new types.
#[derive(Debug, Fail, PartialEq)]
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

    pub fn build(self) -> Result<License, Error> {
        let public_key = match self.public_key {
            Some(s) => Ok(s),
            None => Err(LicenseError::MissingPublicKey),
        }?;
        let signature = match self.signature {
            Some(s) => Ok(s),
            None => Err(LicenseError::MissingSignature),
        }?;
        let text = match self.text {
            Some(s) => Ok(s),
            None => Err(LicenseError::MissingLicenseText),
        }?;
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
        let mut license: License = serde_json::from_str(&text)?;
        license.signature_valid = valid_signature;

        Ok(license)
    }
}

/// `License` is the primary struct through which to interact
/// with `licensed`.
/// ```
/// # use std::process;
/// static PUBLIC_KEY: &'static [u8] = include_bytes!("../examples/public.pks");
/// // Generally, it is suggested to read in the license from a file at runtime
/// let license_file: Vec<u8> = include_bytes!("../examples/license").to_vec();
/// let license = licensed::License::new(&license_file)
///     .with_public_key(&PUBLIC_KEY)
///     .build().unwrap();
/// if ! license.valid() {
///     println!("The provided license is invalid");
///     process::exit(1);
/// }
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct License {
    features: Vec<String>,
    expires: Option<DateTime<Utc>>,
    #[serde(default="false_f")]
    signature_valid: bool,
}

#[inline(always)]
fn false_f() -> bool { false }

impl License {
    /// Creates a new builder for the license, helping to construct and
    /// validate the license.
    /// ```
    /// # use licensed::Error;
    /// # static PUBLIC_KEY: &'static [u8] = include_bytes!("../examples/public.pks");
    /// # fn main() { let _ = call(); }
    /// # fn call() -> Result<(), Error> {
    /// # let license_file: Vec<u8> = include_bytes!("../examples/license").to_vec();
    /// let license = licensed::License::new(&license_file)
    ///     .with_public_key(&PUBLIC_KEY)
    ///     .build()?;
    /// #   Ok(())
    /// # }
    /// ```
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

    /// Is this license valid and non-expired?
    /// ```
    /// # use licensed::Error;
    /// # static PUBLIC_KEY: &'static [u8] = include_bytes!("../examples/public.pks");
    /// # fn main() { let _ = call(); }
    /// # fn call() -> Result<(), Error> {
    /// # let license_file: Vec<u8> = include_bytes!("../examples/license").to_vec();
    /// # let license = licensed::License::new(&license_file)
    /// #     .with_public_key(&PUBLIC_KEY)
    /// #     .build()?;
    /// assert!(license.valid());
    /// #   Ok(())
    /// # }
    /// ```
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

    /// Does this license have the specified feature?
    /// ```
    /// # use licensed::Error;
    /// # static PUBLIC_KEY: &'static [u8] = include_bytes!("../examples/public.pks");
    /// # fn main() { let _ = call(); }
    /// # fn call() -> Result<(), Error> {
    /// # let license_file: Vec<u8> = include_bytes!("../examples/license").to_vec();
    /// # let license = licensed::License::new(&license_file)
    /// #     .with_public_key(&PUBLIC_KEY)
    /// #     .build()?;
    /// assert!(license.has_feature("hello"));
    /// #   Ok(())
    /// # }
    /// ```
    pub fn has_feature<T: AsRef<str>>(&self, feature: T) -> bool {
        let feat = feature.as_ref();
        self.features.iter().position(|f| f == feat).is_some()
    }
}