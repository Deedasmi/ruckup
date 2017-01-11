//! This crate acts as a back-end library for Ruckup. All interface style i/o and
//! supporting functions should go into the binary crate.
extern crate rust_sodium;
extern crate rustc_serialize;
extern crate walkdir;
extern crate chrono;
#[macro_use]
extern crate log;
// Import the macro. Don't forget to add `error-chain` in your
// `Cargo.toml`!
#[macro_use]
extern crate error_chain;

/// The size of data that should be encrypted at once
pub const CHUNK_SIZE: u64 = 4096000;
/// The size of the data after encryption with the auth tag
pub const CIPHER_SIZE: u64 = CHUNK_SIZE + (rust_sodium::crypto::secretbox::MACBYTES as u64);

pub mod crypto;
pub mod lib;
pub mod walker;
pub mod errors {
    // Simple and robust error handling with error-chain!
    // Use this as a template for new projects.

    // `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

    error_chain!{}
}