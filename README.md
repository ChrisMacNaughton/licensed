# Licensed

Licensed is a library for adding digitally signed licenses to
your binary projects in a simple, extensible manner. In addition
to providing library functions for usei n your code, it provides
key generation and license signing binaries in the crate.

## Usage

To use `licensed`, you will need to generate keys to use for your
signing. These keys should be kept private as they are used to
proove that a license is valid.

If you want to generate keys in the example directory, you can
invioke `gen_keys` with a single argument, as shown below through
the `cargo run` command:

    cargo run --bin=gen_keys -- examples

The above command will generatae two files in the target directory:

1. `private.pks`
2. `public.pks`

`private.pks` is actually the complete key material for the keys,
but is accompanied by `public.pks` as well to make including the
public key material into a destination binary easier.

`licensed` expects a certain format for its license files, such as:

```json
{
    "features": [
        "string key",
        "another feature"
    ],
    "expires": "2014-11-28T12:00:09Z"
}
```

`expires`, shown above, is an optional field that will be checked,
if present to ensure license validity.

Once you have the above file saved into, for example, `license.json`,
you can run:

    gen_license license.json $KEY_PATH/private.pks $OUTPUT_PATH

The generated file at `$OUTPUT_PATH` will look like the above json with a null byte and the signature appended.

Validating a license in your binary is as simple as:

```rust
let filename = "path/to/license";
let license_file = read(filename)?;
let license = licensed::License::new(&license_file)
    .with_public_key(&PUBLIC_KEY)
    .build()?;
if license.valid() {
    println!("The providded license is valid");
} else {
    println!("The provided license is invalid");
}
```