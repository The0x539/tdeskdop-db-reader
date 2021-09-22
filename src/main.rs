use anyhow::{bail, Context, Result};
use num_enum::TryFromPrimitive;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

mod descriptor;
use descriptor::{DescriptorStream, EncryptedDescriptor, FileReadDescriptor};

mod crypto;
use crypto::{aes_decrypt_local, MtpAuthKey};

mod settings;

mod schema;

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
struct SessionSettings {}

#[derive(Default)]
struct ReadSettingsContext {
    //session_settings_storage: SessionSettings,
}

impl ReadSettingsContext {
    fn read_setting(&mut self, stream: &mut impl DescriptorStream, _version: i32) -> Result<()> {
        let block_id: DatabaseBlockId = stream
            .read_u32()?
            .try_into()
            .context("unknown block id in read_setting")?;

        use DatabaseBlockId::*;
        println!("{:?}", block_id);
        match block_id {
            UseExternalVideoPlayer => stream.skip::<u32>()?,
            CacheSettings => stream.skip::<(i32, i32, i64, i64)>()?,
            SessionSettings => stream.skip_bytes()?,
            RecentStickers => stream.skip::<Vec<(u64, u16)>>()?,

            AutoStart | StartMinimized | SendToMenu | SeenTrayTooltip | AutoUpdate
            | ScalePercent | LastUpdateCheck | AnimationsDisabled => stream.skip::<i32>()?,

            FallbackProductionConfig => stream.skip_bytes()?,
            ApplicationSettings => {
                let _serialized = stream.read_bytes()?;
            }
            DialogLastPath => stream.skip_bytes()?,

            ThemeKey => {
                let key_day = stream.read::<u64>()?;
                let key_night = stream.read::<u64>()?;
                let night_mode = stream.read::<u32>()?;

                println!("{} {} {}", key_day, key_night, night_mode);
            }

            BackgroundKey => {
                let key_day = stream.read::<u64>()?;
                let key_night = stream.read::<u64>()?;
                println!("{} {}", key_day, key_night);
            }

            TileBackground => {
                let tile_day = stream.read::<i32>()?;
                let tile_night = stream.read::<i32>()?;
                println!("{} {}", tile_day, tile_night);
                // context.tile_read = true;
            }

            LangPackKey => stream.skip::<u64>()?,

            x => todo!("{:?}", x),
        }

        Ok(())
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

        while !map.at_end() {
            let key_type: LocalStorageKey = map
                .read_u32()?
                .try_into()
                .context("unknown key type in encrypted map")?;
            use LocalStorageKey::*;
            match key_type {
                Draft => {
                    let count = map.read_u32()?;
                    for _ in 0..count {
                        let _key = FileKey(map.read_u64()?);
                        let _peer_id_serialized = map.read_u64()?;
                    }
                }
                SelfSerialized => {
                    let _ = map.read_bytes()?;
                }
                DraftPosition => {
                    let count = map.read_u32()?;
                    for _ in 0..count {
                        let _key = FileKey(map.read_u64()?);
                        let _peer_id_serialized = map.read_u64()?;
                    }
                }
                LegacyImages | LegacyStickerImages | LegacyAudios => {
                    let count = map.read_u32()?;
                    for _ in 0..count {
                        let key = FileKey(map.read_u64()?);
                        let (first, second) = (map.read_u64()?, map.read_u64()?);
                        let size = map.read_u32()?;
                        // ignore the key
                        drop((key, first, second, size))
                    }
                }
                UserSettings => {
                    self.keys.settings = FileKey(map.read_u64()?);
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
                | ExportSettings => {
                    let _ = map.read_u64()?;
                }
                BackgroundOld => {
                    let _ = map.read_u64()?;
                    let _ = map.read_u64()?;
                }
                StickersKeys => {
                    let _installed_stickers_key = map.read_u64()?;
                    let _featured_stickers_key = map.read_u64()?;
                    let _recent_stickers_key = map.read_u64()?;
                    let _archived_stickers_key = map.read_u64()?;
                }
                MasksKeys => {
                    let _installed_masks_key = map.read_u64()?;
                    let _recent_masks_key = map.read_u64()?;
                    let _archived_masks_key = map.read_u64()?;
                }
                UserMap => {
                    bail!("UserMap");
                }
            }
        }

        Ok(())
    }

    // TODO: return a SessionSettings (boxed?)
    fn read_session_settings(&self) -> Result<()> {
        let mut foo = FileReadDescriptor::open(self.keys.settings.to_file_part(), &self.base_path)?;
        let encrypted_settings = foo.read_bytes()?;

        let mut stream = EncryptedDescriptor::decrypt_local(&encrypted_settings, &self.local_key)?;
        let mut ctx = ReadSettingsContext::default();

        while !stream.at_end() {
            ctx.read_setting(&mut stream, foo.version())?;
        }

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

#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
enum DatabaseBlockId {
    Key = 0x00,
    User = 0x01,
    DcOptionOldOld = 0x02,
    ChatSizeMaxOld = 0x03,
    MutePeerOld = 0x04,
    SendKeyOld = 0x05,
    AutoStart = 0x06,
    StartMinimized = 0x07,
    SoundFlashBounceNotifyOld = 0x08,
    WorkModeOld = 0x09,
    SeenTrayTooltip = 0x0a,
    DesktopNotifyOld = 0x0b,
    AutoUpdate = 0x0c,
    LastUpdateCheck = 0x0d,
    WindowPositionOld = 0x0e,
    ConnectionTypeOldOld = 0x0f,
    // 0x10 reserved
    DefaultAttach = 0x11,
    CatsAndDogsOld = 0x12,
    ReplaceEmojiOld = 0x13,
    AskDownloadPathOld = 0x14,
    DownloadPathOldOld = 0x15,
    ScaleOld = 0x16,
    EmojiTabOld = 0x17,
    RecentEmojiOldOldOld = 0x18,
    LoggedPhoneNumberOld = 0x19,
    MutedPeersOld = 0x1a,
    // 0x1b reserved
    NotifyViewOld = 0x1c,
    SendToMenu = 0x1d,
    CompressPastedImageOld = 0x1e,
    LangOld = 0x1f,
    LangFileOld = 0x20,
    TileBackgroundOld = 0x21,
    AutoLockOld = 0x22,
    DialogLastPath = 0x23,
    RecentEmojiOldOld = 0x24,
    EmojiVariantsOldOld = 0x25,
    RecentStickers = 0x26,
    DcOptionOld = 0x27,
    TryIPv6Old = 0x28,
    SongVolumeOld = 0x29,
    WindowsNotificationsOld = 0x30,
    IncludeMutedOld = 0x31,
    MegagroupSizeMaxOld = 0x32,
    DownloadPathOld = 0x33,
    AutoDownloadOld = 0x34,
    SavedGifsLimitOld = 0x35,
    ShowingSavedGifsOld = 0x36,
    AutoPlayOld = 0x37,
    AdaptiveForWideOld = 0x38,
    HiddenPinnedMessagesOld = 0x39,
    RecentEmojiOld = 0x3a,
    EmojiVariantsOld = 0x3b,
    DialogsModeOld = 0x40,
    ModerateModeOld = 0x41,
    VideoVolumeOld = 0x42,
    StickersRecentLimitOld = 0x43,
    NativeNotificationsOld = 0x44,
    NotificationsCountOld = 0x45,
    NotificationsCornerOld = 0x46,
    ThemeKeyOld = 0x47,
    DialogsWidthRatioOld = 0x48,
    UseExternalVideoPlayer = 0x49,
    DcOptionsOld = 0x4a,
    MtpAuthorization = 0x4b,
    LastSeenWarningSeenOld = 0x4c,
    SessionSettings = 0x4d,
    LangPackKey = 0x4e,
    ConnectionTypeOld = 0x4f,
    StickersFavedLimitOld = 0x50,
    SuggestStickersByEmojiOld = 0x51,
    SuggestEmojiOld = 0x52,
    TxtDomainStringOldOld = 0x53,
    ThemeKey = 0x54,
    TileBackground = 0x55,
    CacheSettingsOld = 0x56,
    AnimationsDisabled = 0x57,
    ScalePercent = 0x58,
    PlaybackSpeedOld = 0x59,
    LanguagesKey = 0x5a,
    CallSettingsOld = 0x5b,
    CacheSettings = 0x5c,
    TxtDomainStringOld = 0x5d,
    ApplicationSettings = 0x5e,
    DialogsFiltersOld = 0x5f,
    FallbackProductionConfig = 0x60,
    BackgroundKey = 0x61,

    EncryptedWithSalt = 333,
    Encrypted = 444,

    // 500-600 reserved
    Version = 666,
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
    let local_key = MtpAuthKey::from_reader(key_inner_data.stream_mut())?;
    key_inner_data
        .should_be_done()
        .context("reading key inner data")?;

    let mut info = EncryptedDescriptor::decrypt_local(&info_encrypted, &local_key)?;

    let count = info.read_i32()?;
    if count <= 0 || count > MAX_ACCOUNTS {
        bail!("bad accounts count");
    }

    let mut tried = HashSet::new();
    //let mut sessions = HashSet::new();
    //let mut active = 0;
    let mut accounts = HashMap::new();
    for _ in 0..count {
        let index = info.read_i32()?;
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
    let mut settings_data = FileReadDescriptor::open("settings", base_path)?;
    let salt = settings_data.read_bytes()?;
    let settings_encrypted = settings_data.read_bytes()?;
    settings_data.should_be_done()?;
    let salt = salt[..].try_into().context("bad salt size")?;
    let settings_key = MtpAuthKey::create_legacy_local(b"", &salt);
    let mut settings = EncryptedDescriptor::decrypt_local(&settings_encrypted, &settings_key)?;

    let mut ctx = ReadSettingsContext::default();
    while !settings.at_end() {
        ctx.read_setting(&mut settings, settings_data.version())?;
    }

    Ok(())
}

fn main() -> Result<()> {
    start_local_storage()?;
    start_modern(b"")?;
    Ok(())
}

// storage/localstorage.cpp:953          || !Window::Theme::Initialize(std::move(read))) {
