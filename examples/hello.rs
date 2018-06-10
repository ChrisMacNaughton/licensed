extern crate licensed;

use std::env;
use std::fs::read;
use std::process::exit;

static PUBLIC_KEY: &'static [u8] = include_bytes!("public.pks");

fn main() -> Result<(), licensed::Error> {
    let filename = {
        let mut args = env::args();
        match args.nth(1) {
            Some(s) => s,
            None => {
                println!("A Filename for the license is required as the first argument");
                exit(1);
            }
        }
    };
    let license_file = read(filename)?;
    let license = licensed::License::new(&license_file)
        .with_public_key(&PUBLIC_KEY)
        .build()?;
    if ! license.valid() {
        println!("The provided license is invalid");
        exit(1);
    }

    println!("You're license is: {:?}", license);
    if license.has_feature("hello") {
        println!("Hello World!");
    }
    Ok(())
}