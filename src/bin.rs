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
use std::fs::create_dir_all;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Read;

const PREFLOC: &'static str = "preferences/ruckup";
const APP_INFO: AppInfo = AppInfo {
    name: "ruckup",
    author: "ruckup",
};
lazy_static! {
    static ref META_LOC: PathBuf  = app_dir(AppDataType::UserCache, &APP_INFO, "metadata/meta").unwrap();
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
            warn!("No src locations found! Adding metadata table to backup locations.");
            prefmap.insert("src_locs".into(), json::encode(&*META_LOC).unwrap());
            vec![(*META_LOC).clone()]
        });

    println!("Settings loaded! Performing operations.");

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
    let temp_store: String = prefmap.get("temp_store".into())
        .and_then(|x| json::decode(x).ok())
        .expect("Need a temporary storage location! Set with ruckup -t <path>");

    // Build encrypter iterator
    for entry in all_files.into_iter() {
        if entry.metadata().unwrap().is_file() {
        } else {
            create_dir_all(entry.path()).expect(&format!("Failed to create directory for {:?}", entry.path()));
        }
    }

    // Save preferences
    prefmap.save(&APP_INFO, &PREFLOC).expect("Failed to save preferences!");
    println!("Preferences saved! Goodbye!");

}

fn get_meta_data() -> HashMap<PathBuf, VecDeque<lib::FileRecord>> {
    let mut v = Vec::new();
    let d: HashMap<PathBuf, VecDeque<lib::FileRecord>> = match File::open(&*META_LOC) {
        Ok(mut x) => { x.read_to_end(&mut v).expect("Failed on reading meta-data file");
                json::decode(&String::from_utf8(v).unwrap()).unwrap() },
        Err(_) => HashMap::new()
    };
    d
}