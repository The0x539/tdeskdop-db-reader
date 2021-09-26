use anyhow::{bail, ensure, Context, Result};
use num_enum::TryFromPrimitive;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::Write;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;

mod descriptor;
use descriptor::{EncryptedDescriptor, FileReadDescriptor, StreamWithEnd, ValueStream};

mod crypto;
use crypto::{aes_decrypt_local, MtpAuthKey};

mod settings;

mod schema;
use schema::Setting;

const MAX_ACCOUNTS: i32 = 3;

fn base_global_path() -> PathBuf {
    let home = std::env::var_os("HOME").unwrap();
    let wdir = if cfg!(debug_assertions) {
        "src/telegram-nonsense/tdesktop/out/Debug/bin"
    } else {
        ".local/share/TelegramDesktop"
    };
    Path::new(&home).join(wdir).join("tdata")
}
static BASE_GLOBAL_PATH: Lazy<PathBuf> = Lazy::new(base_global_path);

// this is some wacky linking stuff in tdesktop
const fn c_data_file() -> &'static str {
    "data"
}

fn compute_key_name(data_name: &str) -> String {
    format!("key_{}", data_name)
}

fn compose_data_string(data_name: &str, index: i32) -> String {
    let mut result = data_name.replace('#', "");
    if index > 0 {
        write!(&mut result, "#{}", index + 1).unwrap();
    }
    result
}

#[allow(dead_code)]
struct MainAccount {
    data_name: String,
    index: i32,
    local: StorageAccount,
}

impl MainAccount {
    fn new(data_name: &str, index: i32) -> Self {
        Self {
            data_name: data_name.to_owned(),
            index,
            local: StorageAccount::new(compose_data_string(data_name, index)),
        }
    }

    fn prepare_to_start(&mut self, local_key: Rc<MtpAuthKey>) {
        self.local.start(local_key);
    }
}

#[derive(Default, Copy, Clone)]
pub struct FileKey(u64);

impl FileKey {
    fn compute(data_name: &str) -> Self {
        let hash = md5::compute(data_name);
        let first_half = hash[..8].try_into().unwrap();
        Self(u64::from_le_bytes(first_half))
    }

    fn to_file_part(&self) -> String {
        let mut val = self.0;
        let mut result = String::with_capacity(16);
        for _ in 0..16 {
            let v = (val & 0x0F) as u8;
            let c = if v < 0x0A {
                b'0' + v
            } else {
                b'A' + (v - 0x0A)
            };
            result.push(c as char);
            val >>= 4;
        }
        result
    }
}

#[derive(Default)]
struct StorageKeys {
    #[allow(dead_code)]
    settings: FileKey,
}

#[allow(dead_code)]
struct StorageAccount {
    local_key: Rc<MtpAuthKey>,
    data_name_key: FileKey,
    data_name: String,
    base_path: PathBuf,
    keys: StorageKeys,
}

impl StorageAccount {
    fn new(data_name: String) -> Self {
        let data_name_key = FileKey::compute(&data_name);
        let base_path = BASE_GLOBAL_PATH.join(data_name_key.to_file_part());
        Self {
            local_key: Rc::new(MtpAuthKey::BLANK),
            data_name_key,
            base_path,
            data_name,
            keys: StorageKeys::default(),
        }
    }

    fn start(&mut self, local_key: Rc<MtpAuthKey>) {
        self.local_key = local_key;
        self.read_map().unwrap();
    }

    // this originally accepted a local key, but... it's already in self
    // pls
    fn read_map(&mut self) -> Result<()> {
        let mut map_data = FileReadDescriptor::open("map", &self.base_path)?;

        let _legacy_salt = map_data.read_bytes().context("read legacy salt")?;
        let _legacy_key_encrypted = map_data.read_bytes().context("read legacy key")?;
        let map_encrypted = map_data.read_bytes().context("read encrypted map")?;
        map_data.should_be_done().context("reading map data")?;

        // there's a big "if !localKey" block here. I'm going to ignore it for now.

        let mut map = EncryptedDescriptor::decrypt_local(&map_encrypted, &self.local_key)?;

        while !map.is_done() {
            let key_type: LocalStorageKey = map
                .read_val::<u32>()?
                .try_into()
                .context("unknown key type in encrypted map")?;
            use LocalStorageKey::*;
            match key_type {
                Draft => {
                    let count = map.read_val::<u32>()?;
                    for _ in 0..count {
                        let _key = FileKey(map.read_val::<u64>()?);
                        let _peer_id_serialized = map.read_val::<u64>()?;
                    }
                }
                SelfSerialized => {
                    let _ = map.read_bytes()?;
                }
                DraftPosition => {
                    let count = map.read_val::<u32>()?;
                    for _ in 0..count {
                        let _key = FileKey(map.read_val::<u64>()?);
                        let _peer_id_serialized = map.read_val::<u64>()?;
                    }
                }
                LegacyImages | LegacyStickerImages | LegacyAudios => {
                    let count = map.read_val::<u32>()?;
                    for _ in 0..count {
                        let key = FileKey(map.read_val()?);
                        let (first, second) = map.read_val::<(u64, u64)>()?;
                        let size = map.read_val::<u32>()?;
                        // ignore the key
                        drop((key, first, second, size))
                    }
                }
                UserSettings => {
                    self.keys.settings = FileKey(map.read_val()?);
                }
                // these are split in the tdesktop source, but I'm not using them
                Locations
                | ReportSpamStatusesOld
                | TrustedBots
                | RecentStickersOld
                | BackgroundOldOld
                | RecentHashtagsAndBots
                | StickersOld
                | FavedStickers
                | SavedGifsOld
                | SavedGifs
                | SavedPeersOld
                | ExportSettings => map.skip_val::<u64>()?,
                BackgroundOld => map.skip_val::<(u64, u64)>()?,
                StickersKeys => map.skip_val::<(u64, u64, u64, u64)>()?,
                MasksKeys => map.skip_val::<(u64, u64, u64)>()?,
                UserMap => bail!("UserMap"),
            }
        }

        Ok(())
    }

    // TODO: return a SessionSettings (boxed?)
    fn read_session_settings(&self) -> Result<()> {
        let mut foo = FileReadDescriptor::open(self.keys.settings.to_file_part(), &self.base_path)?;
        let encrypted_settings = foo.read_bytes()?;

        let _stream = EncryptedDescriptor::decrypt_local(&encrypted_settings, &self.local_key)?;

        /*
        while !stream.at_end() {
            let setting = stream.read_val::<Setting>(&mut stream, foo.version())?;
        }
        */

        Ok(())
    }
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
enum LocalStorageKey {
    UserMap = 0x00,
    Draft = 0x01,                 // data: PeerId peer
    DraftPosition = 0x02,         // data: PeerId peer
    LegacyImages = 0x03,          // legacy
    Locations = 0x04,             // no data
    LegacyStickerImages = 0x05,   // legacy
    LegacyAudios = 0x06,          // legacy
    RecentStickersOld = 0x07,     // no data
    BackgroundOldOld = 0x08,      // no data
    UserSettings = 0x09,          // no data
    RecentHashtagsAndBots = 0x0a, // no data
    StickersOld = 0x0b,           // no data
    SavedPeersOld = 0x0c,         // no data
    ReportSpamStatusesOld = 0x0d, // no data
    SavedGifsOld = 0x0e,          // no data
    SavedGifs = 0x0f,             // no data
    StickersKeys = 0x10,          // no data
    TrustedBots = 0x11,           // no data
    FavedStickers = 0x12,         // no data
    ExportSettings = 0x13,        // no data
    BackgroundOld = 0x14,         // no data
    SelfSerialized = 0x15,        // serialized self
    MasksKeys = 0x16,             // no data
}

fn start_modern(passcode: &[u8]) -> Result<()> {
    let data_name = c_data_file(); // a field
    let name = compute_key_name(data_name);

    let mut key_data = FileReadDescriptor::open(name, &*BASE_GLOBAL_PATH)?;

    let salt = key_data.read_bytes()?;
    let key_encrypted = key_data.read_bytes()?;
    let info_encrypted = key_data.read_bytes()?;
    key_data.should_be_done().context("reading key data")?;

    let salt = salt
        .as_slice()
        .try_into()
        .context("bad salt in info file")?;

    let passcode_key = MtpAuthKey::create_local(passcode, salt);

    let mut key_inner_data = EncryptedDescriptor::decrypt_local(&key_encrypted, &passcode_key)?;
    let local_key = key_inner_data.read_val::<Rc<MtpAuthKey>>()?;
    key_inner_data
        .should_be_done()
        .context("reading key inner data")?;

    let mut info = EncryptedDescriptor::decrypt_local(&info_encrypted, &local_key)?;

    let count = info.read_val::<i32>()?;
    if count <= 0 || count > MAX_ACCOUNTS {
        bail!("bad accounts count");
    }

    let mut tried = HashSet::new();
    //let mut sessions = HashSet::new();
    //let mut active = 0;
    let mut accounts = HashMap::new();
    for _ in 0..count {
        let index = info.read_val::<i32>()?;
        if !(index >= 0 && index < MAX_ACCOUNTS && tried.insert(index)) {
            continue;
        }

        let mut account = MainAccount::new(&data_name, index);
        account.prepare_to_start(Rc::clone(&local_key));
        account.local.read_session_settings()?;
        accounts.insert(index, account);
    }

    Ok(())
}

fn start_local_storage() -> Result<()> {
    let base_path = settings::working_dir().join("tdata");
    let mut settings_data = FileReadDescriptor::open("settings", &base_path)?;
    let salt = settings_data.read_bytes()?;
    let settings_encrypted = settings_data.read_bytes()?;
    settings_data.should_be_done()?;
    let salt = salt[..].try_into().context("bad salt size")?;
    let settings_key = MtpAuthKey::create_legacy_local(b"", &salt);
    let mut settings = EncryptedDescriptor::decrypt_local(&settings_encrypted, &settings_key)?;

    while !settings.is_done() {
        let setting = settings.read_val::<Setting>()?;
        match setting {
            Setting::ThemeKey {
                day,
                night,
                night_mode,
            } => {
                let key = if night_mode { night } else { day };
                println!("{:?}", read_theme_using_key(key, &settings_key)?);
            }
            _ => (),
        }
    }

    Ok(())
}

type BareId = u64;

#[derive(Debug, Default)]
struct ChatIdType<const SHIFT: u8> {
    bare: BareId,
}

type UserId = ChatIdType<0>;

type DocumentId = u64;

#[derive(Debug, Default)]
struct CloudTheme {
    id: u64,
    access_hash: u64,
    slug: String,
    title: String,
    document_id: DocumentId,
    created_by: UserId,
    users_count: i32,
}

#[derive(Debug, Default)]
struct ThemeObject {
    path_relative: String,
    path_absolute: String,
    content: Vec<u8>,
    cloud: CloudTheme,
}

#[derive(Debug, Default)]
struct CachedTheme {
    colors: Vec<u8>,
    background: Vec<u8>,
    tiled: bool,
    palette_checksum: i32,
    content_checksum: i32,
}

#[derive(Debug, Default)]
struct SavedTheme {
    object: ThemeObject,
    cache: CachedTheme,
}

const THEME_NEW_PATH_RELATIVE_TAG: &str = "special://new_tag";
const THEME_FILE_SIZE_LIMIT: u64 = 5 * 1024 * 1024;

// TODO: share better between this and start_local_storage. stupid C++ globals.
fn read_theme_using_key(key: FileKey, auth_key: &MtpAuthKey) -> Result<SavedTheme> {
    let base_path = settings::working_dir().join("tdata");
    let theme_encrypted = FileReadDescriptor::open(key.to_file_part(), &base_path)?.read_bytes()?;
    let mut theme = EncryptedDescriptor::decrypt_local(&theme_encrypted, auth_key)?;

    let mut result = SavedTheme::default();
    let (object, cache) = (&mut result.object, &mut result.cache);
    object.content = theme.read_bytes()?;
    let tag = theme.read_val::<String>()?;
    object.path_absolute = theme.read_val()?;

    let field1: i32;
    let field2: u32;

    let is_new_tag = tag == THEME_NEW_PATH_RELATIVE_TAG;
    if is_new_tag {
        object.path_relative = theme.read_val()?;
        object.cloud.id = theme.read_val()?;
        object.cloud.access_hash = theme.read_val()?;
        object.cloud.slug = theme.read_val()?;
        object.cloud.title = theme.read_val()?;
        object.cloud.document_id = theme.read_val()?;
        field1 = theme.read_val()?;
    } else {
        object.path_relative = tag;
        field1 = 0;
    }

    let mut ignore_cache = false;
    if object.cloud.id == 0 {
        let rel = &object.path_relative;
        let path = if rel != "" && Path::new(rel).exists() {
            rel
        } else {
            &object.path_absolute
        };

        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        ensure!(
            len < THEME_FILE_SIZE_LIMIT,
            "Theme file too large: {} (should be less than 5 MB, got {})",
            path,
            len,
        );

        let mut file_content = Vec::with_capacity(len as usize);
        file.read_to_end(&mut file_content)?;
        if object.content != file_content {
            object.content = file_content;
            ignore_cache = true;
        }
    }

    let cache_palette_checksum = theme.read_val::<i32>()?;
    let cache_content_checksum = theme.read_val::<i32>()?;
    let cache_colors = theme.read_bytes()?;
    let cache_background = theme.read_bytes()?;
    field2 = theme.read_val()?;

    if !ignore_cache {
        *cache = CachedTheme {
            palette_checksum: cache_palette_checksum,
            content_checksum: cache_content_checksum,
            colors: cache_colors,
            background: cache_background,
            tiled: field2 & 0xFF == 1,
        }
    }

    if is_new_tag {
        object.cloud.created_by.bare = ((field2 as u64 >> 8) << 32) | field1 as u64;
    }

    Ok(result)
}

fn main() -> Result<()> {
    start_local_storage()?;
    start_modern(b"")?;
    Ok(())
}

// storage/localstorage.cpp:953          || !Window::Theme::Initialize(std::move(read))) {
