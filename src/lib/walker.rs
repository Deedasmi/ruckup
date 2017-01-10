extern crate itertools;

use std::hash::{Hash, Hasher};
use walkdir::{WalkDir, DirEntry};
use super::lib;
use std::path::PathBuf;
use self::itertools::Itertools;

/// This is a really dumb struct to make DirEntry hashable
#[derive(Clone)]
pub struct DirHash {
    pub dir: DirEntry,
}

impl DirHash {
    pub fn new(d: DirEntry) -> DirHash {
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

pub fn get_changed_files(files: Vec<DirEntry>, dir_map: &lib::MetaTable) -> Vec<DirEntry> {
    let mut nv: Vec<DirEntry> = Vec::new();
    for entry in files.into_iter() {
        let md = entry.metadata().unwrap();
        if md.is_file() {
            let p = entry.path().to_str().expect("Unable to convert file_path to &str").to_owned();
            if let Some(fr) = dir_map.get_latest_modified(&p) {
                if lib::system_to_datetime(md) != fr {
                    nv.push(entry);
                }
            } else {
                nv.push(entry);
            }
        }
    }
    nv
}