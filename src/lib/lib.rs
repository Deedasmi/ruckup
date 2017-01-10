//! General library for use in libsodium
//! Will likely be broken out to multiple modules later
use std;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::fs::{File, OpenOptions, metadata, create_dir_all, Metadata};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
pub use std::time::UNIX_EPOCH;
use std::collections::VecDeque;
pub use walkdir::{WalkDir, DirEntry};
use std::collections::hash_map::*;
use chrono::{NaiveDateTime, DateTime};
use chrono::offset::local::Local;

/// Helper function to find size of file.
pub fn get_file_size(filename: &PathBuf) -> u64 {
    metadata(filename)
        .map(|x| x.len())
        .expect(&format!("Getting file size failed! Filename: {:?}", filename))
}

/// Helper function to read chunks from a file
///
/// TODO:
/// * Safely handle file operations
pub fn read_data(filename: &PathBuf, offset: u64, limit: u64) -> Vec<u8> {
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
pub fn write_data(filename: &PathBuf, data: &[u8]) {
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(filename)
        .expect(&format!("Failed to open or create file {:?}", filename));
    f.write_all(data).unwrap();
}

pub fn system_to_datetime(s: Metadata) -> DateTime<Local> {
    let n =
        NaiveDateTime::from_timestamp(s.modified()
                                          .unwrap()
                                          .duration_since(UNIX_EPOCH)
                                          .unwrap()
                                          .as_secs() as i64,
                                      0);
    let dtl = Local::now();
    DateTime::from_utc(n, dtl.offset().clone())
}

/// Struct for recording files that are walked into a serilazable format
#[derive(RustcDecodable, RustcEncodable, PartialEq, Eq, Debug, Clone)]
pub struct FileRecord {
    pub src: PathBuf,
    pub file_num: u64,
    pub last_modified: DateTime<Local>,
}

impl Hash for FileRecord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src.hash(state);
    }
}

impl FileRecord {
    /// Generates a new FileRecord from a file and a destination path
    pub fn new(file: &DirEntry, file_num: u64) -> FileRecord {
        let t = system_to_datetime(file.metadata().unwrap());
        FileRecord {
            src: file.path().to_path_buf(),
            file_num: file_num,
            last_modified: t,
        }
    }
}

impl std::fmt::Display for FileRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}: {} - {}", self.src.to_str().unwrap(), self.file_num, self.last_modified)
    }
}

/// Convience function to generate the folder where an encrypted file is stored
/// # Example
/// ```
/// use std::path::PathBuf;
/// let t = PathBuf::from("d:/");
/// let num: u64 = 1263472;
/// assert_eq!(lib::enc_folder(&t, num), PathBuf::from("d:/1/263/"));
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
/// let t = PathBuf::from("//home/");
/// let num: u64 = 1263472;
/// assert_eq!(lib::enc_file(&t, num), PathBuf::from("//home/1/263/472"));
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
    records: HashMap<String, VecDeque<FileRecord>>,
}

impl MetaTable {
    pub fn new() -> MetaTable {
        MetaTable { records: HashMap::new() }
    }
    /// Inserts a record into the underlying HashMap
    /// Returns a reference to the inserted FileRecord
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
            let mut vd: VecDeque<FileRecord> = VecDeque::with_capacity(3);
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
    /// Gets the last recorded modified time for a file
    pub fn get_latest_modified(&self, k: &String) -> Option<DateTime<Local>> {
        self.records
            .get(k)
            .map(|x| x.back().expect(&format!("Queue was empty somehow {}", k)).last_modified)
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn iter(&self) -> Iter<String, VecDeque<FileRecord>> {
        self.records.iter()
    }
    /// Takes a directory of DirEntry (likely generated with get_file_vector) and removes all files from the metadata table
    pub fn remove(&mut self, vk: Vec<DirEntry>) {
        for i in vk.into_iter() {
            info!(target: "lib", "Removing {:?}", i.path());
            self.records.remove(&i.path().to_str().unwrap().to_owned());
        }
    }
    /// Finds and return a FileRecord matching a given file_number
    pub fn find_record(&self, num: u64) -> Option<&FileRecord> {
        let mut fr: Option<&FileRecord> = None;
        for v in self.values() {
            for e in v.into_iter() {
                if e.file_num == num {
                    fr = Some(e)
                }
            }
        }
        fr
    }
}