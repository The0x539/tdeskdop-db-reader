use grammers_crypto::aes;
use ring::{digest, pbkdf2};
use std::convert::TryInto;
use std::io::Read;
use std::rc::Rc;

use crate::descriptor::Readable;

const LOCAL_ENCRYPT_SALT_SIZE: usize = 32;

pub struct MtpAuthKey {
    data: [u8; Self::K_SIZE],
}

impl MtpAuthKey {
    const K_SIZE: usize = 256;
    pub(crate) const BLANK: Self = Self {
        data: [0; Self::K_SIZE],
    };

    const STRONG_ITERATIONS_COUNT: u32 = 100_000;
    const LOCAL_ENCRYPT_ITER_COUNT: u32 = 4000;
    const LOCAL_ENCRYPT_NO_PWD_ITER_COUNT: u32 = 4;

    pub fn create_local(passcode: &[u8], salt: &[u8; LOCAL_ENCRYPT_SALT_SIZE]) -> Rc<Self> {
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
            Self::STRONG_ITERATIONS_COUNT
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

    pub fn create_legacy_local(passcode: &[u8], salt: &[u8; LOCAL_ENCRYPT_SALT_SIZE]) -> Rc<Self> {
        let mut key = Self::BLANK;
        let iterations = if passcode.is_empty() {
            Self::LOCAL_ENCRYPT_NO_PWD_ITER_COUNT
        } else {
            Self::LOCAL_ENCRYPT_ITER_COUNT
        };
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA1,
            iterations.try_into().unwrap(),
            salt,
            passcode,
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
        fn sha1_of_parts(parts: &[&[u8]]) -> digest::Digest {
            let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
            for part in parts {
                ctx.update(part);
            }
            ctx.finish()
        }

        let data = if send {
            &self.data[0..128]
        } else {
            &self.data[8..136]
        };

        let a = sha1_of_parts(&[msg_key, &data[0..32]]);
        let b = sha1_of_parts(&[&data[32..48], msg_key, &data[48..64]]);
        let c = sha1_of_parts(&[&data[64..96], msg_key]);
        let d = sha1_of_parts(&[msg_key, &data[96..128]]);

        let [a, b, c, d] = [&a, &b, &c, &d].map(AsRef::as_ref);

        aes_key[0..8].copy_from_slice(&a[0..8]);
        aes_key[8..20].copy_from_slice(&b[8..20]);
        aes_key[20..32].copy_from_slice(&c[4..16]);

        aes_iv[0..12].copy_from_slice(&a[8..20]);
        aes_iv[12..20].copy_from_slice(&b[0..8]);
        aes_iv[20..24].copy_from_slice(&c[16..20]);
        aes_iv[24..32].copy_from_slice(&d[0..8]);
    }
}

impl Readable for Rc<MtpAuthKey> {
    fn read_from(mut stream: impl Read) -> std::io::Result<Self> {
        let mut key = MtpAuthKey::BLANK;
        stream.read_exact(&mut key.data)?;
        Ok(Rc::new(key))
    }
}

pub fn aes_decrypt_local(src: &[u8], key: &MtpAuthKey, key128: &[u8; 16]) -> Vec<u8> {
    let (mut aes_key, mut aes_iv) = ([0; 32], [0; 32]);
    key.prepare_aes_oldmtp(key128, &mut aes_key, &mut aes_iv, false);
    aes::ige_decrypt(src, &aes_key, &aes_iv)
}
