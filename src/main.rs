extern crate rust_sodium;
use rust_sodium::crypto::secretbox;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::fs::File;
use std::fs::OpenOptions;
use std::fs::metadata;
use std::fs::remove_file;

#[allow(dead_code)]
const CHUNK_SIZE: u64 = 4096000;
const CIPHER_SIZE: u64 = CHUNK_SIZE + (secretbox::MACBYTES as u64);

fn main() {
    match remove_file("cipher.txt") {
        _ => (),
    };
    match remove_file("output.txt") {
        _ => (),
    };
    let key = secretbox::gen_key();
    println!("Encrypting file");
    let nonce = test_encrypt(&key, "test_file/11mb.txt");
    println!("Decrypting file");
    test_decrypt(key, nonce);
}

fn test_encrypt(key: &secretbox::Key, filename: &str) -> secretbox::Nonce {
    // Get nonce
    let nonce = secretbox::gen_nonce();

    // Get file size
    let mut r: u64 = 0;
    let fs = get_file_size(filename);


    // Get plaintext and encrypt
    while r * CHUNK_SIZE < fs {
        let plaintext = read_data(filename, r * CHUNK_SIZE, CHUNK_SIZE);
        let ciphertext = secretbox::seal(&plaintext[..], &nonce, key);
        // Write cipher size instead of plaintext size
        write_data(&ciphertext, "cipher.txt");
        r += 1;
    }
    nonce
}

fn test_decrypt(key: secretbox::Key, nonce: secretbox::Nonce) {
    // Get file size
    let mut r = 0;
    let fs = get_file_size("cipher.txt");

    while r * CIPHER_SIZE < fs {
        let ciphertext = read_data("cipher.txt", CIPHER_SIZE * r, CIPHER_SIZE);
        let their_plaintext = match secretbox::open(&ciphertext, &nonce, &key) {
            Ok(val) => val,
            Err(err) => {
                panic!("Error! {:?}", err);
            }
        };
        write_data(&their_plaintext[..], "output.txt");
        r += 1;
    }
}

fn get_file_size(filename: &str) -> u64 {
    let m = metadata(filename).unwrap();
    m.len()
}

fn read_data(filename: &str, offset: u64, limit: u64) -> Vec<u8> {
    let mut f = File::open(filename).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf: Vec<u8> = Vec::new();
    match f.take(limit).read_to_end(&mut buf) {
        Ok(val) => {
            println!("Successfully read {} bytes. Expexted {}", val, limit);
        }
        Err(err) => {
            panic!("Error! {:?}", err);
        }
    }
    buf
}

fn write_data(data: &[u8], filename: &str) {
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(filename)
        .unwrap();
    f.write_all(data).unwrap();
}

#[test]
fn p_d_same() {
    match remove_file("cipher.txt") {
        _ => (),
    };
    match remove_file("output.txt") {
        _ => (),
    };
    let fs = get_file_size("test_file/11mb.txt");
    let key = secretbox::gen_key();
    let p = read_data("test_file/11mb.txt", 0, fs);
    let nonce = test_encrypt(&key, "test_file/11mb.txt");
    test_decrypt(key, nonce);
    let d = read_data("output.txt", 0, fs);
    assert!(p == d);
}