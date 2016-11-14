#[macro_use]
extern crate lazy_static;
extern crate rust_sodium;
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
lazy_static! {
    static ref META_LOC: PathBuf  = app_dir(AppDataType::UserCache, &APP_INFO, "metadata/meta").unwrap();
}

#[allow(unused_variables)]
fn main() {
    println!("Welcome to Ruckup! Loading settings...");
    log4rs::init_file("log_config.yml", Default::default()).unwrap();
    debug!("Logger loaded");
    debug!("META_LOC set {:?}", *META_LOC);


    // Parse cli arguments
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    // TODO Have this effect logging level
    // Set verbosity level
    let v = matches.occurrences_of("verbose");

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
    }

    // Parse -s
    if let Some(s) = matches.value_of("src_loc") {
        // TODO Verify path
        src_locs.push(PathBuf::from(s));
        prefmap.insert("src_locs".into(), json::encode(&src_locs).unwrap());
        println!("Added {} to backup locations!", s);
    }

    debug!("Source locations: {:?}", src_locs);

    // Build walkdir iterator
    let all_files = lib::get_file_vector(src_locs);
    info!("{} files found", all_files.into_iter().count());

    // Load storage location
    let temp_store: String = prefmap.get("temp_store".into())
        .and_then(|x| json::decode(x).ok())
        .expect("Need a temporary storage location! Set with ruckup -t <path>");

    // Save preferences
    prefmap.save(&APP_INFO, &PREFLOC).expect("Failed to save preferences!");
    println!("Preferences saved! Goodbye!");

}