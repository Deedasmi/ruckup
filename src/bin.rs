extern crate rust_sodium;
extern crate preferences;
extern crate rustc_serialize;
extern crate app_dirs;
extern crate lib;
#[macro_use]
extern crate clap;
use preferences::{AppInfo, PreferencesMap, Preferences};
use rust_sodium::crypto::secretbox;
use rustc_serialize::json;
use clap::App;
use app_dirs::{app_dir, AppDataType};
use std::path::PathBuf;

const PREFLOC: &'static str = "preferences/ruckup";
const APP_INFO: AppInfo = AppInfo {
    name: "ruckup",
    author: "ruckup",
};

#[allow(unused_variables)]
fn main() {
    let meta_loc = app_dir(AppDataType::UserCache, &APP_INFO, "metadata/meta").unwrap();
    println!("Welcome to Ruckup! Loading settings...");

    // Parse cli arguments
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    // Set verbosity level
    let v = matches.occurrences_of("verbose");

    // Load preferences
    let mut prefmap = PreferencesMap::<String>::load(&APP_INFO, &PREFLOC)
        .unwrap_or(PreferencesMap::<String>::new());
    // Load key
    if v > 0 {
        println!("Loading key");
    }
    let key: secretbox::Key = prefmap.get("key".into())
        .and_then(|x| json::decode(x).ok())
        .unwrap_or_else(|| {
            if v > 0 {
                println!("No key found! Assumed intentional");
            }
            let k = secretbox::gen_key();
            prefmap.insert("key".into(), json::encode(&k).unwrap());
            k
        });
    if v > 1 {
        println!("Found key {:?}", key);
    }

    // Load src folders
    let mut src_locs: Vec<PathBuf> =
        prefmap.get("src_locs".into()).and_then(|x| json::decode(x).ok()).unwrap_or_else(|| {
            if v > 0 {
                println!("No src locations found! Adding metadata table to backup locations.");
            }
            prefmap.insert("src_locs".into(), json::encode(&meta_loc).unwrap());
            vec![meta_loc]
        });

    println!("Settings loaded! Performing operations.");

    // Parse -ts
    if let Some(ts) = matches.value_of("temporary_storage") {
        // TODO Verify path
        prefmap.insert("temp_store".into(), json::encode(&ts).unwrap());
        println!("Set temporary storage to {}", ts);
    }

    // Parse -s
    if let Some(s) = matches.value_of("src_loc") {
        // TODO Verify path
        src_locs.push(PathBuf::from(s));
        prefmap.insert("src_locs".into(), json::encode(&src_locs).unwrap());
        println!("Added {} to backup locations!", s);
    }

    // let t: Vec<PathBuf> =
    // prefmap.get("src_locs".into()).and_then(|x| json::decode(x).unwrap()).unwrap();
    // println!("Source locations: {:?}", t);

    // Build walkdir iterator
    let all_files = lib::get_file_vector(src_locs);
    println!("{:?}", all_files);

    // Load storage location
    let temp_store: String = prefmap.get("temp_store".into())
        .and_then(|x| json::decode(x).ok())
        .expect("Need a temporary storage location! Set with ruckup -t <path>");

    // Save preferences
    prefmap.save(&APP_INFO, &PREFLOC).expect("Failed to save preferences!");
    if v == 0 {
        println!("Goodbye!")
    } else {
        println!("Preferences saved! Goodbye!");
    }

}