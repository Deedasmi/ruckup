//! This library will be for all crypto related functions within Ruckup.
pub use rust_sodium::crypto::secretbox;
use std::path::PathBuf;
use super::*;
use std::fs::{remove_file, File};

/// Encrypts a file with a given key, writing output to new file
///
/// # Remarkes
/// Subject to changes. Known TODOs:
///
/// * Instead of taking a file name, take a proper Path object or file pointer
pub fn encrypt_f2f(key: &secretbox::Key, src_filename: &PathBuf, dest_filename: &PathBuf) {

    remove_file(dest_filename).ok();

    // Get nonce
    let mut nonce = secretbox::gen_nonce();
    lib::write_data(dest_filename, &nonce[..]);

    // Get file size
    let mut r: u64 = 0;
    let fs = lib::get_file_size(src_filename);

    // Get plaintext and encrypt
    while r * CHUNK_SIZE < fs {
        let plaintext = lib::read_data(src_filename, r * CHUNK_SIZE, CHUNK_SIZE);
        let ciphertext = encrypt(&plaintext[..], &nonce, &key);
        // Write cipher size instead of plaintext size
        lib::write_data(dest_filename, &ciphertext);
        r += 1;
        nonce = nonce.increment_le();
    }
}

/// Decrypts a given file with a given nonce and key, and saves that to a file
///
/// # Remarks
/// Subject to changes. Known TODOs:
///
/// * Instead of reading from file, 'stream' from buffer.
/// * Instead of taking a file name, take a proper Path object or file pointer
pub fn decrypt_f2f(key: &secretbox::Key, src_filename: &PathBuf, dest_filename: &PathBuf) {

    // Find a better way to do this
    remove_file(dest_filename).ok();

    let mut nonce =
        secretbox::Nonce::from_slice(&lib::read_data(src_filename, 0, secretbox::NONCEBYTES as u64)[..])
            .expect(&format!("Bad nonce for {:?}", src_filename));

    // Get file size
    let mut r = 0;
    let fs = lib::get_file_size(src_filename);
    let _ = File::create(&dest_filename);

    while r * CIPHER_SIZE < fs - secretbox::NONCEBYTES as u64 {
        let ciphertext = lib::read_data(src_filename,
                                        CIPHER_SIZE * r + secretbox::NONCEBYTES as u64,
                                        CIPHER_SIZE);
        let their_plaintext = decrypt(&ciphertext[..], &nonce, &key);
        lib::write_data(dest_filename, &their_plaintext[..]);
        r += 1;
        nonce = nonce.increment_le();
    }
}

/// Decrypts a given file with a given key into a string
pub fn decrypt_f2s(key: &secretbox::Key, enc_filename: &PathBuf) -> String {
    let mut nonce =
        secretbox::Nonce::from_slice(&lib::read_data(enc_filename, 0, secretbox::NONCEBYTES as u64)[..])
            .expect(&format!("Bad nonce for {:?}", enc_filename));
    let mut r = 0;
    let fs = lib::get_file_size(enc_filename);

    let mut o: String = String::new();

    while r * CIPHER_SIZE < fs - secretbox::NONCEBYTES as u64 {
        let ciphertext = lib::read_data(enc_filename,
                                        CIPHER_SIZE * r + secretbox::NONCEBYTES as u64,
                                        CIPHER_SIZE);
        let their_plaintext = decrypt(&ciphertext[..], &nonce, &key);
        o += &(String::from_utf8(their_plaintext).expect("Failed to convert plaintext to String!"));
        r += 1;
        nonce = nonce.increment_le();
    }
    o
}

/// Basic wrapper for encryption
pub fn encrypt(plaintext: &[u8], nonce: &secretbox::Nonce, key: &secretbox::Key) -> Vec<u8> {
    let cipher = secretbox::seal(plaintext, nonce, key);
    cipher
}

/// Basic wrapper for decyption.
///
/// # Error
/// Panics if the decryption fails
///
/// # Remarks
/// Subject to change
pub fn decrypt(ciphertext: &[u8], nonce: &secretbox::Nonce, key: &secretbox::Key) -> Vec<u8> {
    secretbox::open(&ciphertext, &nonce, &key).expect("Decryption failed!")
}