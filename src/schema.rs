use crate::descriptor::{Readable, ValueStream};
use crate::FileKey;
use num_enum::TryFromPrimitive;
use std::convert::TryInto;
use std::io::Read;

#[non_exhaustive]
pub enum Setting {
    #[allow(dead_code)]
    Key,
    User {
        user_id: i32,
        dc_id: u32,
    },
    AutoStart(bool),
    StartMinimized(bool),
    SeenTrayTooltip(bool),
    AutoUpdate(bool),
    LastUpdateCheck(i32),
    DefaultAttach(i32),
    SendToMenu(bool),
    DialogLastPath(Vec<u8>),
    RecentStickers(Vec<(u64, u16)>),
    UseExternalVideoPlayer(bool),
    MtpAuthorization {
        serialized: Vec<u8>,
    },
    SessionSettings {
        serialized: Vec<u8>,
    },
    LangPackKey(FileKey),
    ThemeKey {
        day: FileKey,
        night: FileKey,
        night_mode: bool,
    },
    TileBackground {
        day: i32,
        night: i32,
    },
    AnimationsDisabled(bool),
    ScalePercent(i32),
    LanguagesKey(FileKey),
    #[allow(dead_code)]
    CacheSettings,
    ApplicationSettings {
        serialized: Vec<u8>,
    },
    FallbackProductionConfig(Vec<u8>),
    BackgroundKey {
        day: FileKey,
        night: FileKey,
    },
    /*
    EncryptedWithSalt,
    Encrypted,
    Version,
    */
}

impl Readable for Setting {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        let kind: SettingKind = stream
            .read_val::<u32>()?
            .try_into()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        macro_rules! sbool {
            () => {
                stream.read_val::<i32>()? == 1
            };
        }

        use SettingKind::*;
        let setting = match kind {
            ApplicationSettings => Setting::ApplicationSettings {
                serialized: stream.read_bytes()?,
            },

            User => Setting::User {
                user_id: stream.read_val()?,
                dc_id: stream.read_val()?,
            },

            Key => todo!(),

            MtpAuthorization => Setting::MtpAuthorization {
                serialized: stream.read_bytes()?,
            },

            AutoStart => Setting::AutoStart(sbool!()),
            StartMinimized => Setting::StartMinimized(sbool!()),
            SendToMenu => Setting::SendToMenu(sbool!()),
            UseExternalVideoPlayer => Setting::UseExternalVideoPlayer(sbool!()),

            CacheSettings => {
                let _size = stream.read_val::<i64>()?;
                let _time = stream.read_val::<i32>()?;
                let _size_big = stream.read_val::<i64>()?;
                let _time_big = stream.read_val::<i32>()?;
                todo!()
            }

            AnimationsDisabled => Setting::AnimationsDisabled(sbool!()),

            SessionSettings => Setting::SessionSettings {
                serialized: stream.read_bytes()?,
            },

            ThemeKey => Setting::ThemeKey {
                day: FileKey(stream.read_val()?),
                night: FileKey(stream.read_val()?),
                night_mode: stream.read_val::<u32>()? == 1,
            },

            BackgroundKey => Setting::BackgroundKey {
                day: FileKey(stream.read_val()?),
                night: FileKey(stream.read_val()?),
            },

            LangPackKey => Setting::LangPackKey(FileKey(stream.read_val()?)),
            LanguagesKey => Setting::LanguagesKey(FileKey(stream.read_val()?)),
            SeenTrayTooltip => Setting::SeenTrayTooltip(sbool!()),
            AutoUpdate => Setting::AutoUpdate(sbool!()),
            LastUpdateCheck => Setting::LastUpdateCheck(stream.read_val()?),
            ScalePercent => Setting::ScalePercent(stream.read_val()?),

            TileBackground => Setting::TileBackground {
                day: stream.read_val()?,
                night: stream.read_val()?,
            },

            DefaultAttach => Setting::DefaultAttach(stream.read_val()?),
            RecentStickers => Setting::RecentStickers(stream.read_val()?),
            DialogLastPath => Setting::DialogLastPath(stream.read_bytes()?),
            FallbackProductionConfig => Setting::FallbackProductionConfig(stream.read_bytes()?),

            k => todo!("{:?}", k),
        };
        Ok(setting)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SettingKind {
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
