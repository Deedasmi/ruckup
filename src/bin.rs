#[macro_use]
extern crate lazy_static;
extern crate preferences;
extern crate rustc_serialize;
extern crate app_dirs;
extern crate lib;
extern crate threadpool;
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
use lib::lib::*;
use lib::errors::*;
use lib::walker::*;
use std::sync::Arc;
use threadpool::ThreadPool;
use std::sync::mpsc::channel;

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

fn main() {
    log4rs::init_file("src/config/log_config.yml", Default::default()).unwrap();
    debug!("Logger loaded");
    debug!("META_LOC set {:?}", *META_LOC);


    // Parse cli arguments
    let yaml = load_yaml!("config/cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    println!("Welcome to Ruckup! Loading settings...");

    // Load preferences
    let mut prefmap = PreferencesMap::<String>::load(&APP_INFO, &PREFLOC)
        .unwrap_or(PreferencesMap::<String>::new());

    // Load key
    debug!("Loading key");

    let key: lib::crypto::secretbox::Key = prefmap.get("key".into())
        .and_then(|x| json::decode(x).ok())
        .unwrap_or_else(|| {
            warn!(target: "print::important", "No key found! Assumed intentional");
            let k = lib::crypto::secretbox::gen_key();
            prefmap.insert("key".into(), json::encode(&k).unwrap());
            k
        });
    debug!("Found key {:?}", key);
    let key = Arc::new(key);

    // Load src folders
    let mut src_locs: Vec<PathBuf> =
        prefmap.get("src_locs".into()).and_then(|x| json::decode(x).ok()).unwrap_or_else(|| {
            if !matches.is_present("src_loc") {
                warn!(target: "print::important", "No src locations found!");
            }
            Vec::new()
        });

    info!(target: "print", "Settings loaded! Performing operations.");

    // Load file_num
    let mut file_num: u64 =
        prefmap.get("file_num".into()).and_then(|x| json::decode(x).ok()).unwrap_or(0);
    debug!(target: "print", "Found file_num {}", &file_num);

    // Set up threadpool
    let pool = ThreadPool::new_with_name(String::from("ThreadPool"), 4);

    // Argument parsing
    // Parse -ts
    if let Some(ts) = matches.value_of("temporary_storage") {
        if PathBuf::from(ts).is_absolute() {
            prefmap.insert("temp_store".into(), json::encode(&ts).unwrap());
            info!(target: "print::important", "Set temporary storage to {}", ts);
        } else {
            warn!(target: "print", "Temporary storage path must be absolute path!");
        }
    }

    // Parse -s
    if let Some(s) = matches.value_of("src_loc") {
        // TODO Verify path
        let p = PathBuf::from(s);
        if src_locs.contains(&p) {
            info!(target: "print", "{} already in backup locations!", s);
        } else if !p.is_absolute() {
            warn!(target: "print", "Backup locations must be absolute paths!");
        } else {
            src_locs.push(PathBuf::from(s));
            prefmap.insert("src_locs".into(), json::encode(&src_locs).unwrap());
            info!(target: "print::important" ,"Added {} to backup locations!", s);
        }
    };

    debug!(target: "print", "Source locations: {:?}", src_locs);

    // Load storage location
    let temp_store: Arc<PathBuf> = Arc::new(prefmap.get("temp_store".into())
        .and_then(|x: &String| -> Option<String> { json::decode(&x).ok() })
        .map(|x| PathBuf::from(x))
        .expect("Need a temporary storage location! Set with ruckup -t <path>"));

    // Create hashmap
    let mut dir_map = match matches.is_present("no_recover_meta") || file_num == 0 {
        true => unwrap(get_meta_data(None)),
        false => unwrap(get_meta_data(Some((&key, enc_file(&temp_store.clone(), file_num))))),
    };


    // Parse --remove
    if let Some(remdir) = matches.value_of("remove") {
        info!(target: "print::important", "Removing {} from backup locations", &remdir);
        let pdir = PathBuf::from(remdir);
        src_locs.retain(|x| x != &pdir);
        dir_map.remove(get_file_vector(&vec!(pdir)));
    }

    // Encrypt all src_locs into the temporary store
    if matches.is_present("encrypt") {
        // Preperation
        let now = SystemTime::now();
        let (tx, rx) = channel();

        // Build walkdir iterator
        let all_files = get_file_vector(&src_locs);
        let total_files = all_files.len();
        info!(target: "print::important", "Starting encryption!");
        // Build encrypter iterator
        let changed_files = get_changed_files(all_files, &dir_map);
        let enc_files = changed_files.len();
        for entry in changed_files.into_iter() {
            let (temp_store, key, tx) = clone_three(&temp_store, &key, &tx);
            unwrap(create_enc_folder(&temp_store, file_num)
                .chain_err(|| "Unable to create temporary encrypted file!"));
            let p = PathBuf::from(&entry.path());
            let key = key.clone();
            pool.execute(move || {
                info!(target: "log", "Encrypting file {:?} to {}", &p, file_num);
                unwrap(encrypt(&key, &p, &enc_file(&temp_store, file_num)));
                tx.send((p, entry.clone(), file_num)).unwrap();
                debug!(target: "log", "Finished encrypting {}", file_num);
            });
            file_num += 1
        }
        let mut enc: u64 = 0;
        // Take and encrypt files
        for _ in 0..enc_files {
            let (p, e, num) = rx.recv().unwrap();
            let p = p.to_str().unwrap().to_owned();
            let _ = dir_map.insert(&p, &e, num);
            debug!(target: "print::important", "Added {} to the dirmap", p);
            enc += 1;
            if enc % 100 == 0 {
                info!(target: "print", "{} files encrypted. {} remaining.", enc, enc_files as u64 - enc);
            }
        }
        prefmap.insert("file_num".into(), json::encode(&file_num).unwrap());
        info!(target: "print::imporant", "Found {} folders/files. Encrypted {} files in {} seconds.",
            total_files, enc_files, now.elapsed().unwrap().as_secs());
    }

    if matches.is_present("scan") {
        let now = SystemTime::now();
        // Build walkdir iterator
        let all_files = get_file_vector(&src_locs);
        let total_files = all_files.len();
        debug!(target: "print", "{} files found", total_files);
        let changed = get_changed_files(all_files, &dir_map);
        info!(target: "print::imporant", "Found {} files/folders, {} of which need backed up. Took {} seconds.", total_files, changed.len(), now.elapsed().unwrap().as_secs());
    }

    // Both bulk recovery options
    if matches.is_present("recover_all") {
        if matches.is_present("overwrite") || matches.is_present("recover_to") {
            let prepend = matches.value_of("recover_to");
            let now = SystemTime::now();
            let (tx, rx) = channel();
            // Some weird interaction with the move closure meant I needed to change how the loop worked
            let mut nv: Vec<FileRecord> = Vec::new();
            for e in dir_map.values() {
                nv.push(e.back().unwrap().clone());
            }
            for e in nv.into_iter() {
                let (temp_store, key, tx) = clone_three(&temp_store, &key, &tx);
                let path = join_path(prepend, &e.src).expect("Recovery path must be absolute!");
                pool.execute(move || {
                info!(target: "print::important", "Decrypting file {:?} to {:?}", enc_file(&temp_store, e.file_num), path);
                unwrap(restore_file(&key, enc_file(&temp_store, e.file_num), &path));
                debug!(target: "print::important", "Finished decrypting file {}", e.file_num);
                tx.send(path).unwrap();
            });
            }
            for _ in 0..dir_map.len() {
                let src = rx.recv().unwrap();
                debug!(target: "print::important", "Decrypted {:?}", src);
            }
            info!(target: "print::imporatnt", "Recovered {} files in {} seconds", dir_map.len(), now.elapsed().unwrap().as_secs());
        } else {

        }
    }

    if let Some(num) = matches.value_of("one_file") {
        if matches.is_present("overwrite") || matches.is_present("recover_to") {
            let prepend = matches.value_of("recover_to");
            let fnum = unwrap(num.parse::<u64>()
                .chain_err(|| "File number must be a positive number!"));
            let fr = dir_map.find_record(fnum)
                .expect(&format!("No record found with file_num {}", fnum));
            let path = join_path(prepend, &fr.src).expect("Recovery path must be absolute!");
            info!(target: "print::important", "Decrypting file {:?} to {:?}", enc_file(&temp_store, fr.file_num), path);
            unwrap(restore_file(&key, enc_file(&temp_store, fr.file_num), &path));
            debug!(target: "print::important", "Finished decrypting file {}", fr.file_num);
        } else {
            panic!("Must specify backup location! Either -o or -r $PATH");
        }
    }

    // Finds files
    if let Some(findir) = matches.value_of("files") {
        for (_, v) in dir_map.iter().filter(|v| v.0.starts_with(findir)) {
            for e in v.into_iter() {
                println!("{}", e);
            }
        }
    }

    // Save meta data
    let mut f = unwrap(File::create(&*META_LOC)
        .chain_err(|| "Failed to open meta_data for saving"));
    f.write_all(unwrap(json::encode(&dir_map).chain_err(|| "Failed to encode hashmap"))
            .as_bytes())
        .unwrap();
    debug!(target: "print", "Encrypting meta-data table...");
    unwrap(encrypt(&key, &*META_LOC, &enc_file(&temp_store, file_num)));
    debug!(target: "print", "Encryption complete!");

    // Save preferences
    prefmap.save(&APP_INFO, &PREFLOC).expect("Failed to save preferences!");
    println!("Preferences saved! Goodbye!");

}

/// Loads the meta-data table or creates a new one
fn get_meta_data(recover: Option<(&lib::crypto::secretbox::Key, PathBuf)>) -> Result<MetaTable> {
    let mut v = Vec::new();
    let d: MetaTable = match File::open(&*META_LOC) {
        Ok(mut x) => {
            x.read_to_end(&mut v).chain_err(|| "Failed on reading meta-data file")?;
            json::decode(&String::from_utf8(v).chain_err(|| "From_utf8 failed")?)
                .chain_err(|| "Json decoding failed")?
        }
        Err(_) => {
            if let Some(tuple) = recover {
                warn!(target: "print::important", "Metadata table not found! Attempting to recover!");
                let (k, p) = tuple;
                let m = json::decode(&decrypt_string(&k, &p).chain_err(|| "Failed to recover meta_data table")?)
                    .chain_err(|| "Failed to decode meta data table")?;
                info!(target: "print::important", "Metadata table successfully recovered!");
                m
            } else {
                info!(target: "print::important", "No metadata table found! Creating a new one");
                MetaTable::new()
            }
        }
    };
    Ok(d)
}

fn restore_file(key: &lib::crypto::secretbox::Key,
                enc_file: PathBuf,
                recover_path: &PathBuf)
                -> Result<()> {
    let mut p = PathBuf::from(&recover_path);
    p.pop();
    debug!("Creating directories for {:?}", &p);
    create_dir_all(&p).chain_err(|| format!("unwrap creating src directory {:?}", p))?;
    debug!("Decrypting {:?}", enc_file);
    decrypt(&key, &enc_file, &recover_path)
        .chain_err(|| format!("Failed to restore {:?}", recover_path))
}

fn clone_three<T: Clone, U: Clone, V: Clone>(t: &T, u: &U, v: &V) -> (T, U, V) {
    (t.clone(), u.clone(), v.clone())
}

fn join_path(loc: Option<&str>, p: &PathBuf) -> Result<PathBuf> {
    let p = match loc {
        Some(expr) => {
            let mut floc = PathBuf::from(expr);
            if !floc.is_absolute() {
                ()
            }
            let mut c = p.components();
            match c.next().unwrap() {
                std::path::Component::Prefix(_) => {
                    c.next();
                }
                _ => (),
            }
            floc.push(c.as_path());
            Ok(floc)
        }
        None => Ok(p.to_owned()),
    };
    p
}

/// Currently ends the program. May not later.
fn unwrap<T>(r: Result<T>) -> T {
    if let Err(ref e) = r {
        warn!(target: "print::important", "Error: {}", e);

        for e in e.iter().skip(1) {
            warn!(target: "print::important", "caused by: {}", e);
        }

        // The backtrace is not always generated. Try to run this example
        // with `RUST_BACKTRACE=1`.
        if let Some(backtrace) = e.backtrace() {
            warn!(target: "print::important", "backtrace: {:?}", backtrace);
        }

        ::std::process::exit(1);
    }
    r.unwrap()
}