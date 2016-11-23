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

## TODO

* Clean up test code
* Configuation settings
  * Cores
  * Server information
* Export key
* Better documentation
* Standerdize API
* Basic server code