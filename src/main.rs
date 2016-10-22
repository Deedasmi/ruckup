extern crate rust_sodium;
use rust_sodium::crypto::secretbox;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::fs::File;
use std::fs::metadata;

#[allow(dead_code)]
const CHUNK_SIZE: u64 = 4096000;
const CHUNK_OFFSET: u64 = CHUNK_SIZE + (secretbox::NONCEBYTES as u64);

fn main() {
    println!("Encrypting file");
    test_encrypt("test_file/11mb.txt");
    println!("Decrypting file");
    test_decrypt();
}

fn test_encrypt(filename: &str) {
    // Get key and nonce
    let key = secretbox::gen_key();
    write_data(&key[..], "key.txt", 0);
    let nonce = secretbox::gen_nonce();
    write_data(&nonce[..], "nonce.txt", 0);

    // Get file size
    let mut r: u64 = 0;
    let fs = get_file_size(filename);


    // Get plaintext and encrypt
    while r * CHUNK_SIZE < fs {
        let plaintext = read_data(filename, r + r * CHUNK_SIZE, CHUNK_SIZE);
        let ciphertext = secretbox::seal(&plaintext[..], &nonce, &key);
        write_data(&ciphertext[..], "cipher.txt", r + r * CHUNK_OFFSET);
        r += 1;
    }
}

fn test_decrypt() {
    let k = read_data("key.txt", 0, 1024);
    let key = secretbox::Key::from_slice(&k[..]).unwrap();
    let n = read_data("nonce.txt", 0, 1024);
    let nonce = secretbox::Nonce::from_slice(&n[..]).unwrap();

    // Get file size

    let mut r = 0;
    let fs = get_file_size("cipher.txt");

    while r * CHUNK_OFFSET < fs {
        let ciphertext = read_data("cipher.txt", r + CHUNK_OFFSET * r, CHUNK_OFFSET);
        let their_plaintext = match secretbox::open(&ciphertext, &nonce, &key) {
            Ok(val) => val,
            Err(err) => {
                panic!("Error! {:?}", err);
            }
        };
        write_data(&their_plaintext[..], "output.txt", r + r * CHUNK_SIZE);
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

fn write_data(data: &[u8], filename: &str, offset: u64) {
    let mut f = File::create(filename).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(data).unwrap();
}

#[test]
fn p_d_same() {
    let p = read_data("test_file/11mb.txt", 0);
    test_encrypt("test_file/11mb.txt");
    test_decrypt();
    let d = read_data("output.txt", 0);
    assert!(p == d);
}