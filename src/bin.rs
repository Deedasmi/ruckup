#[macro_use]
extern crate lazy_static;
extern crate preferences;
extern crate rustc_serialize;
extern crate app_dirs;
extern crate lib;
#[macro_use]
extern crate log;
extern crate log4rs;
#[macro_use]
extern crate clap;
use preferences::{AppInfo, PreferencesMap, Preferences};
use rustc_serialize::json;
use clap::App;
use app_dirs::{app_dir, AppDataType};
use std::path::PathBuf;
use std::fs::{File, create_dir_all};
use std::io::{Read, Write};
use std::time::SystemTime;
use lib::*;

const PREFLOC: &'static str = "preferences/ruckup";
const APP_INFO: AppInfo = AppInfo {
    name: "ruckup",
    author: "ruckup",
};
lazy_static! {
    static ref META_LOC: PathBuf  = { let mut x = app_dir(AppDataType::UserCache, &APP_INFO, "metadata").unwrap();
    x.push("meta.json");
    x };
}

#[allow(unused_variables)]
fn main() {
    println!("Welcome to Ruckup! Loading settings...");
    log4rs::init_file("src/config/log_config.yml", Default::default()).unwrap();
    debug!("Logger loaded");
    debug!("META_LOC set {:?}", *META_LOC);


    // Parse cli arguments
    let yaml = load_yaml!("config/cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    // Load preferences
    let mut prefmap = PreferencesMap::<String>::load(&APP_INFO, &PREFLOC)
        .unwrap_or(PreferencesMap::<String>::new());

    // Load key
    debug!("Loading key");

    let key: secretbox::Key = prefmap.get("key".into())
        .and_then(|x| json::decode(x).ok())
        .unwrap_or_else(|| {
            warn!("No key found! Assumed intentional");
            let k = secretbox::gen_key();
            prefmap.insert("key".into(), json::encode(&k).unwrap());
            k
        });
    debug!("Found key {:?}", key);

    // Load src folders
    let mut src_locs: Vec<PathBuf> =
        prefmap.get("src_locs".into()).and_then(|x| json::decode(x).ok()).unwrap_or_else(|| {
            warn!("No src locations found!");
            Vec::new()
        });

    println!("Settings loaded! Performing operations.");

    // Load file_num
    let mut file_num: u64 = prefmap.get("file_num".into()).and_then(|x| json::decode(x).ok()).unwrap_or(0);
    info!("Found file_num {}", &file_num);

    // Argument parsing
    // Parse -ts
    if let Some(ts) = matches.value_of("temporary_storage") {
        if PathBuf::from(ts).is_absolute() {
            prefmap.insert("temp_store".into(), json::encode(&ts).unwrap());
            println!("Set temporary storage to {}", ts);
            debug!("Set temporary storage to {}", ts);
        } else {
            warn!("Temporary storage path must be absolute path!");
        }
    }

    // Parse -s
    if let Some(s) = matches.value_of("src_loc") {
        // TODO Verify path
        let p = PathBuf::from(s);
        if src_locs.contains(&p) {
            println!("{} already in backup locations!", s);
            debug!("{} already in backup locations!", s);
        } else if !p.is_absolute() {
            warn!("Backup locations must be absolute paths!");
        } else {
            src_locs.push(PathBuf::from(s));
            prefmap.insert("src_locs".into(), json::encode(&src_locs).unwrap());
            println!("Added {} to backup locations!", s);
            debug!("Added {} to backup locations!", s);
        }
    };

    debug!("Source locations: {:?}", src_locs);

    // Load storage location
    let temp_store: PathBuf = prefmap.get("temp_store".into())
        .and_then(|x: &String| -> Option<String> {json::decode(&x).ok() })
        .map(|x| PathBuf::from(x))
        .expect("Need a temporary storage location! Set with ruckup -t <path>");

    // Create hashmap
    let mut dir_map = match matches.is_present("no_recover_meta") || file_num == 0 {
        true => get_meta_data(None),
        false => get_meta_data(Some((&key, enc_file(&temp_store, file_num))))
    };

    // Encrypt all src_locs into the temporary store
    if matches.is_present("encrypt") {
        let now = SystemTime::now();
        // Build walkdir iterator
        let all_files = get_file_vector(src_locs);
        let total_files = all_files.clone().into_iter().count();
        info!("{} files found", total_files);
        let mut num_files: u64 = 0;
        let mut enc_files: u64 = 0;

        println!("Running encryption!");
        info!("Starting encryption!");
        // Build encrypter iterator
        for entry in all_files.into_iter() {
            let md = entry.metadata().unwrap();
            if md.is_file() {
                num_files += 1;
                let p = entry.path().to_str().expect("Unable to convert file_path to &str").to_owned();
                if let Some(fr) = dir_map.get_latest_modified(&p) {
                    if md.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs() == fr {
                        debug!("File {} hasn't changed since last backup", &p);
                        continue;
                    }
                }
                let _ = dir_map.insert(&p, &entry, file_num);
                create_enc_folder(&temp_store, file_num).expect("Unable to create temporary encrypted file!");
                let p = PathBuf::from(&p);
                encrypt_f2f(&key, &p, &enc_file(&temp_store, file_num));
                debug!(target: "file_log", "{:?} - {}", &p, file_num);
                file_num += 1;
                enc_files += 1;
                if enc_files % 100 == 0 {
                    info!("{} files completed", enc_files);
                }
            }
        }
        prefmap.insert("file_num".into(), json::encode(&file_num).unwrap());
        println!("Found {} folders and {} files. Encrypted {} files in {} seconds.", total_files as u64 - num_files, num_files, enc_files, now.elapsed().unwrap().as_secs()); 
    if matches.is_present("scan") {
        let now = SystemTime::now();
        // Build walkdir iterator
        let all_files = get_file_vector(&src_locs);
        let total_files = all_files.clone().into_iter().count();
        let mut need_backup: u64 = 0;
        let mut num_files: u64 = 0;
        debug!(target: "print", "{} files found", total_files);
        for entry in all_files.into_iter() {
            let md = entry.metadata().unwrap();
            if md.is_file() {
                num_files += 1;
                let p =
                    entry.path().to_str().expect("Unable to convert file_path to &str").to_owned();
                if let Some(fr) = dir_map.get_latest_modified(&p) {
                    if md.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs() != fr {
                        need_backup += 1;
                    }
                } else {
                    need_backup += 1;
                }
            }
        }
        info!(target: "print::imporant", "Found {} files, {} of which need backed up. Took {} seconds.", num_files, need_backup, now.elapsed().unwrap().as_secs());
    }

    if matches.is_present("recover_all") {
        let now = SystemTime::now();
        let mut recovered: u64 = 0;
        for e in dir_map.values().map(|x| x.back().unwrap()) {
            restore_file(&key, enc_folder(&temp_store, e.file_num), &e.src);
            debug!("Recovered {:?}", &e.src);
            println!("Recovered {} files", recovered);
            recovered += 1;
            if recovered % 100 == 0 {
                println!("Recovered {} files", recovered);
            }
        }
        println!("Recovered {} files in {} seconds", recovered, now.elapsed().unwrap().as_secs());
    }

    if let Some(loc) = matches.value_of("recover_to") {
        let ploc = PathBuf::from(loc);
        if ploc.is_absolute() {
            let now = SystemTime::now();
            let mut recovered: u64 = 0;
            for e in dir_map.values().map(|x| x.back().unwrap()) {
                let mut floc = ploc.clone();
                let mut c = e.src.components();
                match c.next().unwrap() {
                    std::path::Component::Prefix(_) => { c.next(); },
                    _ => ()
                }
                floc.push(c.as_path());
                restore_file(&key, enc_file(&temp_store, e.file_num), &floc);
                debug!("Restored {:?} to {:?}", &e.src, floc);
                recovered += 1;
                if recovered % 100 == 0 {
                    println!("Recovered {} files", recovered);
                }
            } 
            println!("Recovered {} files in {} seconds", recovered, now.elapsed().unwrap().as_secs());
        } else {
            warn!("Recovery location must be an absolute path!");
        }
    }

    // Save meta data
    let mut f = File::create(&*META_LOC).expect("Failed to open meta_data for saving");
    f.write_all(&json::encode(&dir_map).expect("Failed to encode hashmap").as_bytes()).unwrap();
    info!("Encrypting meta-data table...");
    encrypt_f2f(&key, &*META_LOC, &enc_file(&temp_store, file_num));
    info!("Encryption complete!");

    // Save preferences
    prefmap.save(&APP_INFO, &PREFLOC).expect("Failed to save preferences!");
    println!("Preferences saved! Goodbye!");

}

/// Loads the meta-data table or creates a new one
fn get_meta_data(recover: Option<(&secretbox::Key, PathBuf)>) -> MetaTable {
    let mut v = Vec::new();
    let d: MetaTable = match File::open(&*META_LOC) {
        Ok(mut x) => { x.read_to_end(&mut v).expect("Failed on reading meta-data file");
                json::decode(&String::from_utf8(v).unwrap()).unwrap() },
        Err(_) => { if let Some(tuple) = recover {
                        warn!("Metadata table not found! Attempting to recover!");
                        let (k, p) = tuple;
                        let m = json::decode(&decrypt_f2s(&k, &p)).expect("Failed to recover metadata table!");
                        info!("Metadata table successfully recovered!");
                        m
                    } else {
                        info!("No metadata table found! Creating a new one");
                        MetaTable::new()
                    }
        }
    };
    d
}

fn restore_file(key: &secretbox::Key, enc_file: PathBuf, recover_path: &PathBuf) {
    let mut p = PathBuf::from(&recover_path);
    p.pop();
    debug!("Creating directories for {:?}", &p);
    create_dir_all(&p).expect(&format!("Error creating src directory {:?}", p));
    debug!("Decrypting {:?}", enc_file);
    decrypt_f2f(&key, &enc_file, &recover_path);
}