# Ruckup

Ruckups Prevent Fuckups!

## Purpose

Ruckup is a server/client backup system written in Rust as my senior project at Kansas State University. While I am using libsodium (via rust_sodium) and attempting to make something cryptographically secure, I probably wouldn't suggest using this anywhere. This is also my first attempt at Rust, so things may be odd.

## TODO

* Clean up test code
* Configuation settings
  * Key
  * Temporary storage for full file encryption (hash)
    * Optional?
  * Chunk size
  * Cores
  * Source locations
  * Server information
* Figure out why nonce is wrong sometimes
* Deal will filenames that are too long
* Better documentation
* Standerdize API
* Build meta-data table
  * Src file name
  * Destination file name
  * Nonce
  * Detect changes (plaintext hash? Date modified?)
  * Encypted hash (optional?)
* Basic server code
* File recovery code
* Everything