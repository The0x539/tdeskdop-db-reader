#![allow(dead_code)]

use once_cell::sync::OnceCell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

static KEY_FILE: OnceCell<PathBuf> = OnceCell::new();

pub fn set_key_file(path: impl AsRef<[u8]>) {
    let mut processed = OsString::new();
    for byte in path.as_ref() {
        if !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'\\' | b'-' | b'_') {
            continue;
        }
        let c = [byte.to_ascii_lowercase()];
        let s = std::str::from_utf8(&c).unwrap();
        processed.push(s);
    }
    KEY_FILE
        .set(processed.into())
        .expect("Key file was already set");
}

pub fn data_file() -> &'static Path {
    if let Some(key_file) = KEY_FILE.get() {
        key_file
    } else {
        "data".as_ref()
    }
}

#[cfg(not(debug_assertions))]
fn app_data_path() -> PathBuf {
    // TODO: platform-specific to match tdesktop
    if let Some(home) = dirs::home_dir() {
        let old_path = home.join(".TelegramDesktop");
        let old_settings_base = old_path.join("tdata/settings");
        if ["0", "1", "s"]
            .iter()
            .any(|c| old_settings_base.join(c).exists())
        {
            return old_path;
        }
    }

    dirs::data_local_dir().unwrap().join("TelegramDesktop")
}

#[cfg(debug_assertions)]
fn app_data_path() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}

static WORKING_DIR: OnceCell<PathBuf> = OnceCell::new();
pub fn working_dir() -> &'static PathBuf {
    WORKING_DIR.get_or_init(app_data_path)
}
