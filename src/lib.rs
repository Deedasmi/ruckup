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
use std::fs::{File, OpenOptions, metadata, remove_file, create_dir_all};
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
                   dest_filename: &PathBuf) {

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

/// Decrypts a given file with a given key into a string
pub fn decrypt_f2s(key: &secretbox::Key, enc_filename: &PathBuf) -> String {
    let mut nonce = secretbox::Nonce::from_slice(&read_data(enc_filename, 0, secretbox::NONCEBYTES as u64)[..]).expect(&format!("Bad nonce for {:?}", enc_filename));
    let mut r = 0;
    let fs = get_file_size(enc_filename);

    let mut o: String = String::new();

    while r * CIPHER_SIZE < fs - secretbox::NONCEBYTES as u64 {
        let ciphertext = read_data(enc_filename, CIPHER_SIZE * r + secretbox::NONCEBYTES as u64, CIPHER_SIZE);
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
        .create(true)
        .open(filename)
        .expect(&format!("Failed to open or create file {:?}", filename));
    f.write_all(data).unwrap();
}

/// Converts a Vector of directories into a vector of all files and folders in those directories
/// # Note
/// Will only return one entry per file.
pub fn get_file_vector(src_locs: &Vec<PathBuf>) -> Vec<DirEntry> {
    // TODO do this better
    debug!(target: "lib", "Getting file_vectors");
    let mut direntrys: Vec<DirHash> = Vec::new();
    for loc in src_locs.clone().into_iter() {
        let i = WalkDir::new(loc).into_iter();
        for f in i {
            direntrys.push(DirHash::new(f.unwrap()));
        }
    }
    let hashable_dirs: Vec<DirHash> = direntrys.into_iter().unique().collect();
    hashable_dirs.into_iter().map(|x| x.dir).collect()
}

/// Struct for recording files that are walked into a serilazable format
#[derive(RustcDecodable, RustcEncodable, PartialEq, Eq, Debug)]
pub struct FileRecord {
    pub src: PathBuf,
    pub file_num: u64,
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
    pub fn new(file: &DirEntry, file_num: u64) -> FileRecord {
        let t = file.metadata()
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap();
        FileRecord {
            src: file.path().to_path_buf(),
            file_num: file_num,
            last_modified: t,
            enc_hash: None,
        }
    }
}

/// Convience function to generate the folder where an encrypted file is stored
/// # Example
/// ```
/// use std::path::PathBuf;
/// let t = PathBuf::from("d:\\");
/// let num: u64 = 1263472;
/// assert_eq!(lib::enc_folder(&t, num), PathBuf::from("d:\\1\\263\\"));
/// ```
pub fn enc_folder(ts: &PathBuf, num: u64) -> PathBuf {
    let mut fp = ts.clone();
    fp.push((num / 1000000).to_string());
    fp.push((num % 1000000 / 1000).to_string());
    fp
}

/// Convience function to generate the full path where an encrypted file is stored
/// # Example
/// ```
/// use std::path::PathBuf;
/// let t = PathBuf::from("d:\\");
/// let num: u64 = 1263472;
/// assert_eq!(lib::enc_file(&t, num), PathBuf::from("d:\\1\\263\\472"));
/// ```
pub fn enc_file(ts: &PathBuf, num: u64) -> PathBuf {
    let mut fp = enc_folder(&ts, num);
    fp.push((num % 1000).to_string());
    fp
}

/// Convience function to generate the full path where an encrypted file is stored
/// Just a combination between enc_folder and std::fs::create_dir_all
pub fn create_enc_folder(ts: &PathBuf, num: u64) -> std::io::Result<()> {
    create_dir_all(enc_folder(&ts, num))
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct MetaTable {
    records: HashMap<String, VecDeque<FileRecord>>
}

impl MetaTable {
    pub fn new() -> MetaTable {MetaTable{records: HashMap::new()}}
    /// Inserts a record into the underlying HashMap
    /// Returns the inserted FileRecord
    pub fn insert(&mut self, k: &String, v: &DirEntry, dest: u64) -> &FileRecord {
        let nv = FileRecord::new(v, dest);
        if self.records.contains_key(k) {
            if self.records.get(k).unwrap().len() == 3 {
                let o = self.records.get_mut(k).unwrap().pop_front().unwrap();
                debug!(target:"lib", "Dropped an old record for {:?}", o);
            }
            self.records.get_mut(k).unwrap().push_back(nv);
        } else {
            debug!(target: "lib", "Creating new vector");
            let mut vd:VecDeque<FileRecord> = VecDeque::with_capacity(3);
            vd.push_front(nv);
            self.records.insert(k.clone(), vd);
        }
        self.records.get(k).unwrap().back().unwrap()
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
    let s = PathBuf::from("test_file/11mb.txt");
    let c = PathBuf::from("cipher.txt");
    let o = PathBuf::from("output.txt");
    let fs = get_file_size(&s);
    let key = secretbox::gen_key();
    let p = read_data(&s, 0, fs);
    encrypt_f2f(&key, &s, &c);
    decrypt_f2f(&key, &c, &o);
    let d = read_data(&o, 0, fs);
    assert_eq!(p, d);
}