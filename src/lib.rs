//! General library for use in libsodium
//! Will likely be broken out to multiple modules later
extern crate rust_sodium;
extern crate rustc_serialize;
extern crate walkdir;
extern crate itertools;
use rust_sodium::crypto::secretbox;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::fs::{File, OpenOptions, metadata, remove_file};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::UNIX_EPOCH;
use walkdir::{WalkDir, DirEntry};
use itertools::Itertools;

const CHUNK_SIZE: u64 = 4096000;
const CIPHER_SIZE: u64 = CHUNK_SIZE + (secretbox::MACBYTES as u64);

/// Encrypts a file with a given key, writing output to new file
///
/// # Remarkes
/// Subject to changes. Known TODOs:
///
/// * Instead of saving to file, take in an mpsc queue and place ciphertext there
/// * Instead of taking a file name, take a proper Path object or file pointer
pub fn encrypt(key: &secretbox::Key, src_filename: &str, dest_filename: &str) -> secretbox::Nonce {
    // Find a better way to do this
    match remove_file(dest_filename) {
        _ => (),
    };

    // Get nonce
    let nonce = secretbox::gen_nonce();

    // Get file size
    let mut r: u64 = 0;
    let fs = get_file_size(src_filename);


    // Get plaintext and encrypt
    while r * CHUNK_SIZE < fs {
        let plaintext = read_data(src_filename, r * CHUNK_SIZE, CHUNK_SIZE);
        let ciphertext = secretbox::seal(&plaintext[..], &nonce, key);
        // Write cipher size instead of plaintext size
        write_data(&ciphertext, dest_filename);
        r += 1;
    }
    nonce
}

/// Decrypts a given file with a given nonce and key
///
/// # Remarks
/// Subject to changes. Known TODOs:
///
/// * Instead of reading from file, 'stream' from buffer.
/// * Instead of taking a file name, take a proper Path object or file pointer
pub fn decrypt(key: secretbox::Key,
               nonce: secretbox::Nonce,
               src_filename: &str,
               dest_filename: &str) {

    // Find a better way to do this
    match remove_file(dest_filename) {
        _ => (),
    };

    // Get file size
    let mut r = 0;
    let fs = get_file_size(src_filename);

    while r * CIPHER_SIZE < fs {
        let ciphertext = read_data(src_filename, CIPHER_SIZE * r, CIPHER_SIZE);
        let their_plaintext = match secretbox::open(&ciphertext, &nonce, &key) {
            Ok(val) => val,
            Err(err) => {
                panic!("Error! {:?}", err);
            }
        };
        write_data(&their_plaintext[..], dest_filename);
        r += 1;
    }
}

/// Helper function to find size of file.
fn get_file_size(filename: &str) -> u64 {
    let m = metadata(filename).unwrap();
    m.len()
}

/// Helper function to read chunks from a file
///
/// TODO:
/// * Safely handle file operations
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

/// Helper function to append data to a file
///
/// TODO:
/// * Chunk files for mid-file resumption
/// * Safely handle file writing
fn write_data(data: &[u8], filename: &str) {
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(filename)
        .unwrap();
    f.write_all(data).unwrap();
}

pub fn get_file_vector(src_locs: Vec<PathBuf>) -> Vec<DirEntry> {
    // TODO do this better
    let mut direntrys: Vec<DirHash> = Vec::new();
    for loc in src_locs.into_iter() {
        let i = WalkDir::new(loc).into_iter();
        for f in i {
            direntrys.push(DirHash::new(f.unwrap()));
        }
    }
    let shittyfuckshit: Vec<DirHash> = direntrys.into_iter().unique().collect();
    let mut things: Vec<DirEntry> = Vec::new();
    for d in shittyfuckshit.into_iter() {
        things.push(d.dir);
    }
    things

}

#[derive(RustcDecodable, RustcEncodable, PartialEq, Eq)]
struct FileRecord {
    src: PathBuf,
    dst: PathBuf,
    last_modified: u64,
    is_file: bool,
    enc_hash: Option<String>,
}

impl Hash for FileRecord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src.hash(state);
    }
}

#[allow(dead_code)]
impl FileRecord {
    fn new(file: PathBuf, dst: PathBuf) -> FileRecord {
        let md = metadata(&file).unwrap();
        let t = md.modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap();
        FileRecord {
            src: file,
            dst: dst,
            last_modified: t,
            is_file: md.is_file(),
            enc_hash: None,
        }
    }
}

#[derive(Clone)]
struct DirHash {
    dir: DirEntry,
}

impl DirHash {
    fn new(d: DirEntry) -> DirHash {
        DirHash { dir: d }
    }
}

impl Hash for DirHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.dir.path().hash(state);
    }
}

impl Eq for DirHash {}

impl PartialEq for DirHash {
    fn eq(&self, other: &DirHash) -> bool {
        self.dir.path() == other.dir.path()
    }
}

#[test]
fn p_d_same() {
    let fs = get_file_size("test_file/11mb.txt");
    let key = secretbox::gen_key();
    let p = read_data("test_file/11mb.txt", 0, fs);
    let nonce = encrypt(&key, "test_file/11mb.txt", "cipher.txt");
    decrypt(key, nonce, "cipher.txt", "output.txt");
    let d = read_data("output.txt", 0, fs);
    assert_eq!(p, d);
}