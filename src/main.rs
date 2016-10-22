extern crate rust_sodium;
use rust_sodium::crypto::secretbox;
use std::io::prelude::*;
use std::fs::File;

#[allow(dead_code)]
static CHUNK_SIZE: i64 = 4096000;

fn main() {
    test_encrypt("test_file/11mb.txt");
    test_decrypt();
}

fn test_encrypt(filename: &str) {
    let key = secretbox::gen_key();
    write_data(&key[..], "key.txt");
    let nonce = secretbox::gen_nonce();
    write_data(&nonce[..], "nonce.txt");
    let plaintext = read_data(filename);
    let ciphertext = secretbox::seal(&plaintext[..], &nonce, &key);
    write_data(&ciphertext[..], "cipher.txt");
}

fn test_decrypt() {
    let k = read_data("key.txt");
    let key = secretbox::Key::from_slice(&k[..]);
    let n = read_data("nonce.txt");
    let nonce = secretbox::Nonce::from_slice(&n[..]);
    let ciphertext = read_data("cipher.txt");
    let their_plaintext = secretbox::open(&ciphertext, &nonce.unwrap(), &key.unwrap()).unwrap();
    
    write_data(&their_plaintext[..], "output.txt");
}

fn read_data(filename: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut f = File::open(filename).unwrap();
    f.read_to_end(&mut buf).unwrap();
    buf
}

fn write_data(data: &[u8], filename: &str) {
    let mut f = File::create(filename).unwrap();
    f.write_all(data).unwrap();
}

#[test]
fn p_d_same() {
    let p = read_data("test_file/11mb.txt");
    test_encrypt("test_file/11mb.txt");
    test_decrypt();
    let d = read_data("output.txt");
    assert!(p==d);
}