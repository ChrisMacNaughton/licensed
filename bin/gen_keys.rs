extern crate ring;
extern crate untrusted;

use std::env;
use std::fs;
use std::process::exit;

use ring::{rand, signature};

fn main() -> Result<(), String> {
    let key_path = {
        let mut args = env::args();
        match args.nth(1) {
            Some(s) => s,
            None => {
                println!("A path to store keys is required as the first argument");
                exit(1);
            }
        }
    };
    // Generate a key pair in PKCS#8 (v2) format.
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| format!("Error: {:?}", e))?;

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair =
    signature::Ed25519KeyPair::from_pkcs8(
                untrusted::Input::from(&pkcs8_bytes)).map_err(|e| format!("Error: {:?}", e))?;
    fs::write(&format!("{}/private.pks", key_path), pkcs8_bytes.as_ref()).map_err(|e| format!("FS Error: {:?}", e))?;

    fs::write(&format!("{}/public.pks", key_path), &key_pair.public_key_bytes()).map_err(|e| format!("FS Error: {:?}", e))?;
    Ok(())
}