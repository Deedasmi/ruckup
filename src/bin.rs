extern crate rust_sodium;
extern crate lib;
use rust_sodium::crypto::secretbox;

fn main() {
    let key = secretbox::gen_key();

    // Gather files

    // Encrypt files
    println!("Encrypting files");
    let nonce = lib::encrypt(&key, "test_file/11mb.txt", "cipher.txt");

    // Decrypt files
    println!("Decrypting file");
    lib::decrypt(key, nonce, "cipher.txt", "output.txt");
}