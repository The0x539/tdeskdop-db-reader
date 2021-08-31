#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use byteorder::{ReadBytesExt, BE, LE};
use grammers_crypto::aes;
use ring::{digest, pbkdf2};
use std::collections::HashSet;
use std::convert::TryInto;
use std::ffi::OsStr;
use std::fmt::Write;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const LOCAL_ENCRYPT_SALT_SIZE: usize = 32;
const MAX_ACCOUNTS: i32 = 3;
const TDF_MAGIC: [u8; 4] = *b"TDF$";

fn base_global_path() -> PathBuf {
    let home = std::env::var_os("HOME").unwrap();
    let wdir = if cfg!(debug_assertions) {
        "src/telegram-nonsense/tdesktop/out/Debug/bin"
    } else {
        ".local/share/TelegramDesktop"
    };
    Path::new(&home).join(wdir).join("tdata")
}

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
        write!(&mut result, "#{}", index + 1);
    }
    result
}

struct FileReadDescriptor {
    version: i32,
    data: Cursor<Vec<u8>>,
}

impl FileReadDescriptor {
    fn open(name: impl AsRef<OsStr>, base_path: impl AsRef<Path>) -> Result<Self> {
        let path = base_path.as_ref().join(name.as_ref());

        let modern = {
            let mut s = path.into_os_string();
            s.push("s");
            PathBuf::from(s)
        };

        let mut f = if modern.exists() {
            File::open(modern)?
        } else {
            // NOTE: tdesktop tries all possible files.
            // if one is invalid, it tries the next.
            unimplemented!("modern files only")
        };

        let mut magic = [0; TDF_MAGIC.len()];
        f.read_exact(&mut magic)?;
        if magic != TDF_MAGIC {
            bail!("bad magic");
        }

        let version = f.read_i32::<LE>()?;

        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        let data_size = bytes.len() - 16;

        let mut md5 = md5::Context::new();
        md5.consume(&bytes[..data_size]);
        md5.consume(&(data_size as i32).to_le_bytes());
        md5.consume(&version.to_le_bytes());
        md5.consume(&magic);

        if md5.compute().0 != &bytes[data_size..] {
            bail!("signature mismatch");
        }

        bytes.truncate(data_size);

        Ok(Self {
            version,
            data: Cursor::new(bytes),
        })
    }

    fn read_bytes(&mut self) -> std::io::Result<Vec<u8>> {
        let len = self.data.read_u32::<BE>()? as usize;
        let mut buf = vec![0; len];
        self.data.read_exact(&mut buf)?;
        Ok(buf)
    }
}

struct MtpAuthKey {
    data: [u8; Self::K_SIZE],
}

impl MtpAuthKey {
    const K_SIZE: usize = 256;
    const BLANK: Self = Self {
        data: [0; Self::K_SIZE],
    };
    const LOCAL_ENCRYPT_ITER_COUNT: u32 = 4000;
    fn create_local(passcode: &[u8], salt: &[u8; LOCAL_ENCRYPT_SALT_SIZE]) -> Rc<Self> {
        let mut key = Self::BLANK;
        let hash = {
            let mut ctx = digest::Context::new(&digest::SHA512);
            ctx.update(salt);
            ctx.update(passcode);
            ctx.update(salt);
            ctx.finish()
        };
        let iterations = if passcode.is_empty() {
            1
        } else {
            Self::LOCAL_ENCRYPT_ITER_COUNT
        };

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            iterations.try_into().unwrap(),
            salt,
            hash.as_ref(),
            &mut key.data,
        );

        Rc::new(key)
    }

    fn prepare_aes_oldmtp(
        &self,
        msg_key: &[u8; 16],
        aes_key: &mut [u8; 32],
        aes_iv: &mut [u8; 32],
        send: bool,
    ) {
        let x = if send { 0 } else { 8 };
        let data = &self.data[x..];

        let new_sha = || digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        let mut sha;

        sha = new_sha();
        sha.update(msg_key);
        sha.update(&data[0..32]);
        let sha1_a = sha.finish();

        sha = new_sha();
        sha.update(&data[32..48]);
        sha.update(msg_key);
        sha.update(&data[48..64]);
        let sha1_b = sha.finish();

        sha = new_sha();
        sha.update(&data[64..96]);
        sha.update(msg_key);
        let sha1_c = sha.finish();

        sha = new_sha();
        sha.update(msg_key);
        sha.update(&data[96..128]);
        let sha1_d = sha.finish();

        let (a, b, c, d) = (
            sha1_a.as_ref(),
            sha1_b.as_ref(),
            sha1_c.as_ref(),
            sha1_d.as_ref(),
        );

        aes_key[0..8].copy_from_slice(&a[0..8]);
        aes_key[8..20].copy_from_slice(&b[8..20]);
        aes_key[20..32].copy_from_slice(&c[4..16]);

        aes_iv[0..12].copy_from_slice(&a[8..20]);
        aes_iv[12..20].copy_from_slice(&b[0..8]);
        aes_iv[20..24].copy_from_slice(&c[16..20]);
        aes_iv[24..32].copy_from_slice(&d[0..8]);
    }

    fn from_reader<R: Read>(mut reader: R) -> std::io::Result<Rc<Self>> {
        let mut key = Self::BLANK;
        reader.read_exact(&mut key.data)?;
        Ok(Rc::new(key))
    }
}

struct EncryptedDescriptor {
    data: Cursor<Vec<u8>>,
}

impl EncryptedDescriptor {
    fn decrypt_local(encrypted: &[u8], key: &MtpAuthKey) -> Result<Self> {
        if encrypted.len() <= 16 || encrypted.len() & 0xF != 0 {
            bail!("bad encrypted part size");
        }
        let full_len = encrypted.len() - 16;

        let (encrypted_key, encrypted_data) = encrypted.split_at(16);
        let encrypted_key = encrypted_key.try_into().unwrap();
        let mut decrypted = aes_decrypt_local(encrypted_data, key, encrypted_key);

        let sha = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &decrypted);
        if sha.as_ref()[..16] != encrypted_key[..] {
            bail!("bad decrypt key");
        }

        const FOUR: usize = std::mem::size_of::<u32>();

        let data_len = u32::from_le_bytes(decrypted[..4].try_into().unwrap()) as usize;
        if data_len > decrypted.len() || data_len <= full_len - 16 || data_len < FOUR {
            bail!("bad decrypted part");
        }

        decrypted.truncate(data_len);

        let mut data = Cursor::new(decrypted);
        data.set_position(FOUR as u64);
        Ok(Self { data })
    }
}

fn aes_decrypt_local(src: &[u8], key: &MtpAuthKey, key128: &[u8; 16]) -> Vec<u8> {
    let (mut aes_key, mut aes_iv) = ([0; 32], [0; 32]);
    key.prepare_aes_oldmtp(key128, &mut aes_key, &mut aes_iv, false);
    aes::ige_decrypt(src, &aes_key, &aes_iv)
}

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

struct StorageAccount {
    local_key: Rc<MtpAuthKey>,
    data_name: String,
    base_path: PathBuf,
}

impl StorageAccount {
    fn new(data_name: String) -> Self {
        Self {
            local_key: Rc::new(MtpAuthKey::BLANK),
            base_path: todo!(),
            data_name,
        }
    }

    fn start(&mut self, local_key: Rc<MtpAuthKey>) {
        self.local_key = local_key;
    }

    fn read_map_with(&mut self, local_key: &MtpAuthKey) -> Result<()> {
        let map_data = FileReadDescriptor::open("map", &self.base_path);
        Ok(())
    }
}

fn start_modern(passcode: &[u8]) -> Result<()> {
    let data_name = c_data_file(); // a field
    let name = compute_key_name(data_name);

    let mut key_data = FileReadDescriptor::open(name, base_global_path())?;

    let salt = key_data.read_bytes()?;
    let key_encrypted = key_data.read_bytes()?;
    let info_encrypted = key_data.read_bytes()?;
    if key_data.data.position() != key_data.data.get_ref().len() as u64 {
        bail!("extraneous data");
    }

    let salt = salt
        .as_slice()
        .try_into()
        .context("bad salt in info file")?;

    let passcode_key = MtpAuthKey::create_local(passcode, salt);

    let mut key_inner_data = EncryptedDescriptor::decrypt_local(&key_encrypted, &passcode_key)?;
    let local_key = MtpAuthKey::from_reader(&mut key_inner_data.data)?;
    if key_inner_data.data.position() != key_inner_data.data.get_ref().len() as u64 {
        bail!("extraneous data");
    }

    let mut info = EncryptedDescriptor::decrypt_local(&info_encrypted, &local_key)?;

    let count = info.data.read_i32::<BE>()?;
    if count <= 0 || count > MAX_ACCOUNTS {
        bail!("bad accounts count");
    }

    let mut tried = HashSet::new();
    //let mut sessions = HashSet::new();
    //let mut active = 0;
    for _ in 0..count {
        let index = info.data.read_i32::<BE>()?;
        if !(index >= 0 && index < MAX_ACCOUNTS && tried.insert(index)) {
            continue;
        }

        let account = MainAccount::new(&data_name, index);

        println!("{}", index);
    }

    todo!("got here")
}

fn main() -> Result<()> {
    start_modern(b"")?;
    Ok(())
}
