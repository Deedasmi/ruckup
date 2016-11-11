extern crate rust_sodium;
extern crate preferences;
extern crate rustc_serialize;
use preferences::{AppInfo, PreferencesMap, Preferences, PreferencesError};
use rust_sodium::crypto::secretbox;
use rustc_serialize::{json, Encodable};
use std::io;


static PREFLOC: &'static str = "ruckup";
const APP_INFO: AppInfo = AppInfo {
    name: "ruckup",
    author: "ruckup",
};

fn main() {
    // Load preferences
    let prefmap = PreferencesMap::<String>::load(&APP_INFO, &PREFLOC)
        .unwrap_or(PreferencesMap::<String>::new());
    // Load key
    let key: secretbox::Key = if prefmap.contains_key("key".into()) {
        println!("Loading key");
        let k = prefmap.get("key".into()).unwrap();
        json::decode(k).unwrap()
    } else {
        println!("No key found! Assumed intentional");
        let k = secretbox::gen_key();
        insert_pref(prefmap, "key".into(), &k).unwrap();
        k
    };
    println!("Found key {:?}", key);
    loop {
        match input().trim() {
            "help" | "h" | "?" => println!("I should really add a help section"),
            "quit" | "q" => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Not implemented!"),
        };
    }


    // Gather files

    // // Encrypt files
    // println!("Encrypting files");
    // let nonce = lib::encrypt(&key, "test_file/11mb.txt", "cipher.txt");
    //
    // Decrypt files
    // println!("Decrypting file");
    // lib::decrypt(key, nonce, "cipher.txt", "output.txt");
}

fn input() -> String {
    let mut input = String::new();
    println!("Please enter a command");
    io::stdin().read_line(&mut input).unwrap();
    input.to_lowercase()
}

fn insert_pref<T: Encodable>(mut prefs: PreferencesMap,
                             key: String,
                             value: T)
                             -> Result<(), PreferencesError> {
    prefs.insert(key.into(), json::encode(&value).unwrap());
    prefs.save(&APP_INFO, &PREFLOC)
}