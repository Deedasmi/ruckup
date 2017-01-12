//! This library will be for all crypto related functions within Ruckup.
pub use rust_sodium::crypto::secretbox;
use super::*;
use errors::*;
use std::io::{Read, Write};

/// Encrypts a object that implements Read with a given key, writing output to an object with Write
pub fn encrypt_b2b<T: Read, U: Write>(key: &secretbox::Key, mut src: T, mut dest: U) -> Result<()> {

    // Get nonce
    let mut nonce = secretbox::gen_nonce();
    dest.write(&nonce[..])
        .chain_err(|| "Failed to write nonce")?;
    let mut buf: Vec<u8> = Vec::new();

    // Get plaintext and encrypt
    while src.by_ref()
        .take(CHUNK_SIZE)
        .read_to_end(&mut buf)
        .chain_err(|| "Failed to read from source file")? > 0 {
        let ciphertext = encrypt(&buf[..], &nonce, &key);
        // Write cipher size instead of plaintext size
        dest.write_all(ciphertext.as_slice()).chain_err(|| "Failed to write cipher to dest")?;
        nonce = nonce.increment_le();
        buf.clear();
    }
    Ok(())
}

/// Decrypts a given buffer with a given nonce and key, and saves that to a buffer
pub fn decrypt_b2b<T: Read, U: Write>(key: &secretbox::Key, mut src: T, mut dest: U) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    src.by_ref()
        .take(secretbox::NONCEBYTES as u64)
        .read_to_end(&mut buf)
        .chain_err(|| "Failed to read nonce")?;

    // TODO: Error chain this
    // TODO: Check for nonce collision
    let mut nonce = secretbox::Nonce::from_slice(&buf[..]).expect("Bad nonce");
    buf.clear();

    while src.by_ref()
        .take(CIPHER_SIZE)
        .read_to_end(&mut buf)
        .chain_err(|| "Failed to read from src")? > 0 {
        let plaintext = decrypt(&buf[..], &nonce, &key)?;
        dest.write_all(plaintext.as_slice())
            .chain_err(|| "Failed writing decrypted text to file")?;
        nonce = nonce.increment_le();
        buf.clear();
    }
    Ok(())
}

/// Decrypts a given buffer with a given key into a string
pub fn decrypt_b2s<T: Read>(key: &secretbox::Key, mut src: T) -> Result<String> {
    let mut buf: Vec<u8> = Vec::new();
    src.by_ref()
        .take(secretbox::NONCEBYTES as u64)
        .read_to_end(&mut buf)
        .chain_err(|| "Failed to read nonce from src")?;

    // TODO: Error chain this
    // TODO: Check for nonce collision
    let mut nonce = secretbox::Nonce::from_slice(&buf[..]).expect("Bad nonce from source file");
    buf.clear();

    let mut o: String = String::new();

    while src.by_ref()
        .take(CIPHER_SIZE)
        .read_to_end(&mut buf)
        .chain_err(|| "Failed to read from src")? > 0 {
        let plaintext = decrypt(&buf[..], &nonce, &key)?;
        o +=
            &(String::from_utf8(plaintext).chain_err(|| "Failed to convert plaintext to String!")?);
        buf.clear();
        nonce = nonce.increment_le();
    }
    Ok(o)
}

/// Basic wrapper for encryption
pub fn encrypt(plaintext: &[u8], nonce: &secretbox::Nonce, key: &secretbox::Key) -> Vec<u8> {
    let cipher = secretbox::seal(plaintext, nonce, key);
    cipher
}

/// Basic wrapper for decyption.
pub fn decrypt(ciphertext: &[u8],
               nonce: &secretbox::Nonce,
               key: &secretbox::Key)
               -> Result<Vec<u8>> {
    secretbox::open(&ciphertext, &nonce, &key)
        .map_err(|_| errors::ErrorKind::DecryptionError.into())
}