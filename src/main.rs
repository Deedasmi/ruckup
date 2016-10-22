extern crate rust_sodium;
use rust_sodium::crypto::secretbox;
use std::io::prelude::*;
use std::fs::File;

fn main() {
    test_encrypt();
    test_decrypt();

}

fn test_encrypt() {
    let key = secretbox::gen_key();
    write_data(&key[..], "key.txt");
    let nonce = secretbox::gen_nonce();
    write_data(&nonce[..], "nonce.txt");
    let plaintext = b"some data";
    let ciphertext = secretbox::seal(plaintext, &nonce, &key);
    write_data(&ciphertext[..], "cipher.txt");
    
    //let tp = String::from_utf8(their_plaintext).unwrap();
    //println!("p: {:?} n: {:?} c: {:?} tp: {}", plaintext, nonce, ciphertext, tp);
}

fn test_decrypt() {
    let k = read_data("key.txt");
    let key = secretbox::Key::from_slice(&k[..]);
    let n = read_data("nonce.txt");
    let nonce = secretbox::Nonce::from_slice(&n[..]);
    let ciphertext = read_data("cipher.txt");
    let their_plaintext = secretbox::open(&ciphertext, &nonce.unwrap(), &key.unwrap()).unwrap();
    println!("{}", String::from_utf8(their_plaintext).unwrap());
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