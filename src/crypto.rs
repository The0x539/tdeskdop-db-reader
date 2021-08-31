use grammers_crypto::aes;
use ring::{digest, pbkdf2};
use std::convert::TryInto;
use std::io::Read;
use std::rc::Rc;

const LOCAL_ENCRYPT_SALT_SIZE: usize = 32;

pub struct MtpAuthKey {
    data: [u8; Self::K_SIZE],
}

impl MtpAuthKey {
    const K_SIZE: usize = 256;
    pub(crate) const BLANK: Self = Self {
        data: [0; Self::K_SIZE],
    };
    const LOCAL_ENCRYPT_ITER_COUNT: u32 = 4000;
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

    pub fn from_reader<R: Read>(mut reader: R) -> std::io::Result<Rc<Self>> {
        let mut key = Self::BLANK;
        reader.read_exact(&mut key.data)?;
        Ok(Rc::new(key))
    }
}

pub fn aes_decrypt_local(src: &[u8], key: &MtpAuthKey, key128: &[u8; 16]) -> Vec<u8> {
    let (mut aes_key, mut aes_iv) = ([0; 32], [0; 32]);
    key.prepare_aes_oldmtp(key128, &mut aes_key, &mut aes_iv, false);
    aes::ige_decrypt(src, &aes_key, &aes_iv)
}
