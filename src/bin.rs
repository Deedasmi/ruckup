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
use std::fs::File;
use std::io::{Read, Write};
use std::fs::{remove_file, create_dir_all};

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

    // TODO Have this effect logging level
    // Set verbosity level
    let v = matches.occurrences_of("verbose");

    // Load preferences
    let mut prefmap = PreferencesMap::<String>::load(&APP_INFO, &PREFLOC)
        .unwrap_or(PreferencesMap::<String>::new());

    // Load key
    debug!("Loading key");

    let key: lib::secretbox::Key = prefmap.get("key".into())
        .and_then(|x| json::decode(x).ok())
        .unwrap_or_else(|| {
            warn!("No key found! Assumed intentional");
            let k = lib::secretbox::gen_key();
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
        // TODO Verify path
        prefmap.insert("temp_store".into(), json::encode(&ts).unwrap());
        println!("Set temporary storage to {}", ts);
        debug!("Set temporary storage to {}", ts);
    }

    // Parse -s
    if let Some(s) = matches.value_of("src_loc") {
        // TODO Verify path
        let p = PathBuf::from(s);
        if src_locs.contains(&p) {
            println!("{} already in backup locations!", s);
            debug!("{} already in backup locations!", s);
        } else {
        src_locs.push(PathBuf::from(s));
        prefmap.insert("src_locs".into(), json::encode(&src_locs).unwrap());
        println!("Added {} to backup locations!", s);
        debug!("Added {} to backup locations!", s);
        }
    }

    debug!("Source locations: {:?}", src_locs);

    // Create hashmap
    let mut dir_map = get_meta_data();

    // Build walkdir iterator
    let all_files = lib::get_file_vector(src_locs);
    info!("{} files found", all_files.clone().into_iter().count());

    // Load storage location
    let temp_store: PathBuf = prefmap.get("temp_store".into())
        .and_then(|x: &String| -> Option<String> {json::decode(&x).ok() })
        .map(|x| PathBuf::from(x))
        .expect("Need a temporary storage location! Set with ruckup -t <path>");

    // Encrypt all src_locs into the temporary store
    if matches.is_present("encrypt") {
        println!("Running encryption!");
        info!("Starting encryption!");
        // Build encrypter iterator
        for entry in all_files.into_iter() {
            let md = entry.metadata().unwrap();
            if md.is_file() {
                let p = entry.path().to_str().expect("Unable to convert file_path to &str").to_owned();
                if let Some(fr) = dir_map.get_latest_modified(&p) {
                    if md.modified().unwrap().duration_since(lib::UNIX_EPOCH).unwrap().as_secs() == fr {
                        debug!("File {} hasn't changed since last backup", &p);
                        continue;
                    }
                }
                let mut fp = temp_store.clone();
                fp.push((file_num / 100000).to_string());
                fp.push((file_num % 100000 / 1000).to_string());
                create_dir_all(&fp).expect("Unable to write to temporary store!");
                fp.push((file_num % 1000).to_string());
                let c = dir_map.insert(&p, &entry, fp.clone());
                let p = PathBuf::from(&p);
                debug!("{:?} had {:?} before entry", &p, c);
                let n = lib::encrypt_f2f(&key, &p, &fp);
                file_num += 1;
            }
        }
        prefmap.insert("file_num".into(), json::encode(&file_num).unwrap());
    }

    if matches.is_present("recover_all") {
        for v in dir_map.values() {
            for e in v.into_iter() {
                info!("Decrypting {:?}", e.src);
                lib::decrypt_f2f(&key, &e.dst, &e.src);
            }
        }
}

    // Save meta data (TEMP)
    let mut f = File::create(&*META_LOC).expect("Failed to open meta_data for saving");
    f.write_all(&json::encode(&dir_map).expect("Failed to encode hashmap").as_bytes()).unwrap();

    // Save preferences
    prefmap.save(&APP_INFO, &PREFLOC).expect("Failed to save preferences!");
    println!("Preferences saved! Goodbye!");

}

/// Loads the meta-data table or creates a new one
fn get_meta_data() -> lib::MetaTable {
    let mut v = Vec::new();
    let d: lib::MetaTable = match File::open(&*META_LOC) {
        Ok(mut x) => { x.read_to_end(&mut v).expect("Failed on reading meta-data file");
                json::decode(&String::from_utf8(v).unwrap()).unwrap() },
        Err(_) => lib::MetaTable::new()
    };
    d
}