extern crate licensed;
extern crate ring;
extern crate untrusted;

use std::env;
use std::fs::{read, write};
use std::process::exit;

use ring::signature;

fn main() -> Result<(), licensed::Error> {
    let mut args = env::args();
    let _ = args.next();
    let filename = {
        match args.next() {
            Some(s) => s,
            None => {
                println!("A Filename for the license is required as the first argument");
                exit(1);
            }
        }
    };
    let pkcs8_file = {
        match args.next() {
            Some(s) => s,
            None => {
                println!("A Filename for the key material is required as the second argument");
                exit(1);
            }
        }
    };
    let output_file = {
        match args.next() {
            Some(s) => s,
            None => {
                println!("A Filename for the output license is required as the thirs argument");
                exit(1);
            }
        }
    };
    let license_file: Vec<u8> = read(filename)?;
    let pkcs8_bytes: Vec<u8> = read(pkcs8_file)?;


    let key_pair =
       signature::Ed25519KeyPair::from_pkcs8(
                untrusted::Input::from(&pkcs8_bytes))?;

    let signature = key_pair.sign(&license_file);
    let sig = signature.as_ref();
    let mut out: Vec<u8> = Vec::with_capacity(sig.len() + license_file.len() + 1);
    out.extend(&license_file);
    out.extend(&[0x00]);
    out.extend(sig);
    write(&output_file, out)?;
    Ok(())
}