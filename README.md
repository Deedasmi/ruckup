# Ruckup

Ruckups Prevent Fuckups!

## Purpose

Ruckup is a server/client backup system written in Rust as my senior project at Kansas State University. While I am using libsodium (via rust_sodium) and attempting to make something cryptographically secure, I probably wouldn't suggest using this anywhere. This is also my first attempt at Rust, so things may be odd.

## TODO

* Clean up test code
* Configuation settings
  * Cores
  * Server information
* Export key
* Figure out why nonce is wrong sometimes
* Deal will filenames that are too long
* Better documentation
* Standerdize API
* Basic server code
* File recovery code
* Everything