//! General library for use in libsodium
//! Will likely be broken out to multiple modules later
extern crate rust_sodium;
extern crate rustc_serialize;
extern crate walkdir;
extern crate itertools;
#[macro_use]
extern crate log;
pub use rust_sodium::crypto::secretbox;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::fs::{File, OpenOptions, metadata, remove_file};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
pub use std::time::UNIX_EPOCH;
pub use walkdir::{WalkDir, DirEntry};
use itertools::Itertools;
use std::collections::{HashMap, VecDeque};
use std::collections::hash_map::Values;

const CHUNK_SIZE: u64 = 4096000;
const CIPHER_SIZE: u64 = CHUNK_SIZE + (secretbox::MACBYTES as u64);

/// Encrypts a file with a given key, writing output to new file
///
/// # Remarkes
/// Subject to changes. Known TODOs:
///
/// * Instead of taking a file name, take a proper Path object or file pointer
pub fn encrypt_f2f(key: &secretbox::Key,
                   src_filename: &PathBuf,
                   dest_filename: &PathBuf)
                   -> secretbox::Nonce {

    remove_file(dest_filename).ok();

    // Get nonce
    let mut nonce = secretbox::gen_nonce();
    write_data(dest_filename, &nonce[..]);

    // Get file size
    let mut r: u64 = 0;
    let fs = get_file_size(src_filename);

    // Get plaintext and encrypt
    while r * CHUNK_SIZE < fs {
        let plaintext = read_data(src_filename, r * CHUNK_SIZE, CHUNK_SIZE);
        let ciphertext = encrypt(&plaintext[..], &nonce, &key);
        // Write cipher size instead of plaintext size
        write_data(dest_filename, &ciphertext);
        r += 1;
        nonce = nonce.increment_le();
    }
    nonce
}

/// Decrypts a given file with a given nonce and key, and saves that to a file
///
/// # Remarks
/// Subject to changes. Known TODOs:
///
/// * Instead of reading from file, 'stream' from buffer.
/// * Instead of taking a file name, take a proper Path object or file pointer
pub fn decrypt_f2f(key: &secretbox::Key,
                   src_filename: &PathBuf,
                   dest_filename: &PathBuf) {

    // Find a better way to do this
    remove_file(dest_filename).ok();

    let mut nonce = secretbox::Nonce::from_slice(&read_data(src_filename, 0, secretbox::NONCEBYTES as u64)[..]).expect(&format!("Bad nonce for {:?}", src_filename));

    // Get file size
    let mut r = 0;
    let fs = get_file_size(src_filename);
    let _ = File::create(&dest_filename);

    while r * CIPHER_SIZE < fs - secretbox::NONCEBYTES as u64 {
        let ciphertext = read_data(src_filename, CIPHER_SIZE * r + secretbox::NONCEBYTES as u64, CIPHER_SIZE);
        let their_plaintext = decrypt(&ciphertext[..], &nonce, &key);
        write_data(dest_filename, &their_plaintext[..]);
        r += 1;
        nonce = nonce.increment_le();
    }
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

/// Helper function to find size of file.
fn get_file_size(filename: &PathBuf) -> u64 {
    metadata(filename)
        .map(|x| x.len())
        .expect(&format!("Getting file size failed! Filename: {:?}", filename))
}

/// Helper function to read chunks from a file
///
/// TODO:
/// * Safely handle file operations
fn read_data(filename: &PathBuf, offset: u64, limit: u64) -> Vec<u8> {
    let mut f = File::open(filename).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf: Vec<u8> = Vec::new();
    match f.take(limit).read_to_end(&mut buf) {
        Ok(val) => {
            debug!(target: "lib", "Successfully read {} bytes. Expexted {}", val, limit);
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
fn write_data(filename: &PathBuf, data: &[u8]) {
    let mut f = OpenOptions::new()
        .append(true)
        .open(filename)
        .expect(&format!("Failed to open or create file {:?}", filename));
    f.write_all(data).unwrap();
}

/// Converts a Vector of directories into a vector of all files and folders in those directories
/// # Note
/// Will only return one entry per file.
pub fn get_file_vector(src_locs: Vec<PathBuf>) -> Vec<DirEntry> {
    // TODO do this better
    debug!(target: "lib", "Getting file_vectors");
    let mut direntrys: Vec<DirHash> = Vec::new();
    for loc in src_locs.into_iter() {
        let i = WalkDir::new(loc).into_iter();
        for f in i {
            direntrys.push(DirHash::new(f.unwrap()));
        }
    }
    let hashable_dirs: Vec<DirHash> = direntrys.into_iter().unique().collect();
    hashable_dirs.into_iter().map(|x| x.dir).collect()
}

/// Struct for recording files that are walked into a serilazable format
/// # Example
/// ```
/// use rustc_serialize::json;
/// let fr = FileRecord::new("11mb.txt");
/// json::decode(&fr).unwrap();
///
#[derive(RustcDecodable, RustcEncodable, PartialEq, Eq, Debug)]
pub struct FileRecord {
    pub src: PathBuf,
    pub dst: PathBuf,
    pub last_modified: u64,
    enc_hash: Option<String>,
}

impl Hash for FileRecord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src.hash(state);
    }
}

impl FileRecord {
    /// Generates a new FileRecord from a file and a destination path
    pub fn new(file: &DirEntry, dst: PathBuf) -> FileRecord {
        let t = file.metadata()
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap();
        FileRecord {
            src: file.path().to_path_buf(),
            dst: dst.clone(),
            last_modified: t,
            enc_hash: None,
        }
    }
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct MetaTable {
    records: HashMap<String, VecDeque<FileRecord>>
}

impl MetaTable {
    pub fn new() -> MetaTable {MetaTable{records: HashMap::new()}}
    /// Inserts a record into the underlying HashMap
    /// Returns the number of records BEFORE entry
    pub fn insert(&mut self, k: &String, v: &DirEntry, dest: PathBuf) -> Option<usize> {
        let nv = FileRecord::new(v, dest);
        if self.records.contains_key(k) {
            let c = self.records.get(k).unwrap().len();
            if c == 3 {
                let o = self.records.get_mut(k).unwrap().pop_front().unwrap();
                debug!(target:"lib", "Dropped an old record for {:?}", o);
            }
            self.records.get_mut(k).unwrap().push_back(nv);
            Some(c)
        } else {
            debug!(target: "lib", "Creating new vector");
            let mut vd:VecDeque<FileRecord> = VecDeque::with_capacity(3);
            vd.push_front(nv);
            self.records.insert(k.clone(), vd);
            None
        }
    }
     pub fn values(&self) -> Values<String, VecDeque<FileRecord>> {
        self.records.values()
    }
    pub fn contains_key(&self, k: &String) -> bool {
        self.records.contains_key(k)
    }
    pub fn get_latest_modified(&self, k: &String) -> Option<u64> {
        self.records.get(k).map(|x| x.back().expect("Queue was empty somehow {}, k").last_modified)
    }
}

/// This is a really dumb struct to make DirEntry hashable
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