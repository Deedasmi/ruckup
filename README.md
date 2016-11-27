# Ruckup

Ruckups Prevent Fuckups!

## Purpose

Ruckup is a server/client backup system written in Rust as my senior project at Kansas State University. While I am using libsodium (via rust_sodium) and attempting to make something cryptographically secure, I probably wouldn't suggest using this anywhere. This is also my first attempt at Rust, so things may be odd.

## Instalation and Usage

``` 
git clone https://github.com/Deedasmi/ruckup.git && cd ruckup
cargo run -- -h
cargo run -- -t <TEMP_STORE> -b $(echo $(pwd)/"test_file") -e
```

## Known issues

* Nonces are randomly generated for every file. There is potential for a nonce collision to make the entire backup insecure.
  * Could solve with a hashset of used nonces
* Non UTF-8 file paths will be translated into a UTF-8 file path
  * This is largely because of a bug in rustc_serialize that does not allow hashmaps with non-primitive key types to be encoded. Serde should fix this, but still doesn't really work in stable
* The drive letter is lost when using recover_to on Windows
* Listing files is case sensitive

## TODO

* Configuation settings
  * Cores
  * Server information
* Export key
* Better documentation
* Basic server code
* Better error handling