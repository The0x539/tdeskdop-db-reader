use anyhow::{bail, ensure, Result};
use byteorder::{ReadBytesExt, BE, LE};
use ring::digest;
use std::convert::TryInto;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use super::{aes_decrypt_local, MtpAuthKey};

const TDF_MAGIC: [u8; 4] = *b"TDF$";

pub struct FileReadDescriptor {
    version: i32,
    data: Cursor<Vec<u8>>,
}

impl FileReadDescriptor {
    pub fn open(name: impl AsRef<OsStr>, base_path: impl AsRef<Path>) -> Result<Self> {
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

    #[allow(dead_code)]
    pub fn version(&self) -> i32 {
        self.version
    }
}

impl Read for FileReadDescriptor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Read::read(&mut self.data, buf)
    }
}

pub struct EncryptedDescriptor {
    data: Cursor<Vec<u8>>,
}

impl EncryptedDescriptor {
    pub(crate) fn decrypt_local(encrypted: &[u8], key: &MtpAuthKey) -> Result<Self> {
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

impl Read for EncryptedDescriptor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.data.read(buf)
    }
}

pub trait Readable: Sized {
    fn read_from(stream: impl Read) -> std::io::Result<Self>;
    fn skip_from(stream: impl Read) -> std::io::Result<()> {
        Self::read_from(stream).map(drop)
    }
}

impl Readable for i32 {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        stream.read_i32::<BE>()
    }
}
impl Readable for i64 {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        stream.read_i64::<BE>()
    }
}
impl Readable for u16 {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        stream.read_u16::<BE>()
    }
}
impl Readable for u32 {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        stream.read_u32::<BE>()
    }
}
impl Readable for u64 {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        stream.read_u64::<BE>()
    }
}
impl<T: Readable> Readable for Vec<T> {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        let len = u32::read_from(&mut stream)?;
        let mut v = Vec::with_capacity(len as usize);
        for _ in 0..len {
            v.push(T::read_from(&mut stream)?);
        }
        Ok(v)
    }
    fn skip_from(mut stream: impl Read) -> std::io::Result<()> {
        let len = u32::read_from(&mut stream)?;
        for _ in 0..len {
            T::skip_from(&mut stream)?;
        }
        Ok(())
    }
}
impl Readable for String {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        let bytes = Bytes::read_from(&mut stream)?.0;
        let result = encoding_rs::UTF_16BE.decode(&bytes);
        if result.2 {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid UTF-16",
            ))
        } else {
            Ok(result.0.into_owned())
        }
    }
}
impl<A: Readable, B: Readable> Readable for (A, B) {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        Ok((A::read_from(&mut stream)?, B::read_from(&mut stream)?))
    }
}
impl<A: Readable, B: Readable, C: Readable> Readable for (A, B, C) {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        Ok((
            A::read_from(&mut stream)?,
            B::read_from(&mut stream)?,
            C::read_from(&mut stream)?,
        ))
    }
}
impl<A: Readable, B: Readable, C: Readable, D: Readable> Readable for (A, B, C, D) {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        Ok((
            A::read_from(&mut stream)?,
            B::read_from(&mut stream)?,
            C::read_from(&mut stream)?,
            D::read_from(&mut stream)?,
        ))
    }
}

pub struct Bytes(pub Vec<u8>);
impl Readable for Bytes {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        let len = u32::read_from(&mut stream)? as usize;

        // ?????
        if len == 0 || len == u32::MAX as usize {
            return Ok(Self(Vec::new()));
        }

        let mut buf = vec![0; len];
        stream.read_exact(&mut buf)?;
        Ok(Self(buf))
    }
}

pub trait ValueStream {
    fn read_val<T: Readable>(&mut self) -> std::io::Result<T>;
    fn skip_val<T: Readable>(&mut self) -> std::io::Result<()>;
    fn read_bytes(&mut self) -> std::io::Result<Vec<u8>> {
        self.read_val::<Bytes>().map(|b| b.0)
    }
    fn skip_bytes(&mut self) -> std::io::Result<()> {
        self.read_bytes().map(drop)
    }
}

impl<R: Read> ValueStream for R {
    fn read_val<T: Readable>(&mut self) -> std::io::Result<T> {
        T::read_from(self)
    }

    fn skip_val<T: Readable>(&mut self) -> std::io::Result<()> {
        T::skip_from(self)
    }
}

pub trait StreamWithEnd {
    fn is_done(&self) -> bool;
    fn should_be_done(&self) -> Result<()>;
}

impl StreamWithEnd for FileReadDescriptor {
    fn is_done(&self) -> bool {
        self.data.position() == self.data.get_ref().len() as u64
    }

    fn should_be_done(&self) -> Result<()> {
        let pos = self.data.position();
        let len = self.data.get_ref().len() as u64;
        ensure!(pos == len, "extraneous data: {} bytes", len - pos);
        Ok(())
    }
}

impl StreamWithEnd for EncryptedDescriptor {
    fn is_done(&self) -> bool {
        self.data.position() == self.data.get_ref().len() as u64
    }

    fn should_be_done(&self) -> Result<()> {
        let pos = self.data.position();
        let len = self.data.get_ref().len() as u64;
        ensure!(pos == len, "extraneous data: {} bytes", len - pos);
        Ok(())
    }
}
