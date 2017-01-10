extern crate rust_sodium;
extern crate rustc_serialize;
extern crate walkdir;
extern crate chrono;
#[macro_use]
extern crate log;

const CHUNK_SIZE: u64 = 4096000;
use rust_sodium::crypto::secretbox;
const CIPHER_SIZE: u64 = CHUNK_SIZE + (secretbox::MACBYTES as u64);

pub mod crypto;
pub mod lib;
pub mod walker;