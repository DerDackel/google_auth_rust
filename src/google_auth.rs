extern crate base32;

use rand::{OsRng, Rng};
use std::mem::transmute;
use std::u64;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::mac::Mac;

const SECRET_BITS: u32 = 80;
const CODE_DIGITS: u32 = 6;
const WINDOW_SIZE: u64 = 30;

pub struct AuthKey {
    pub key: String,
}

fn decode_key(key: String) -> Vec<u8> {
    match base32::decode(base32::Alphabet::RFC4648 {padding: false}, &key) {
        Some(v) => v,
        None => panic!("Could not decode secret!"),
    }
}

pub fn create_credentials() -> AuthKey {
    let mut rng: OsRng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e)
    };

    let mut buffer: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut buffer);
    println!("Buffer: {:?}", &buffer);
    AuthKey {key: calculate_secret_key(&buffer)}
}

fn calculate_secret_key(buffer: &[u8]) -> String {
        base32::encode(base32::Alphabet::RFC4648 {padding: false}, buffer)
}

fn disc_truncate(hash: &[u8]) -> u32 {
    let offset = (hash[hash.len() - 1] & 0xF) as usize;
    (unsafe {transmute::<[u8; 4], u32>([hash[offset], hash[offset + 1], hash[offset + 2], hash[offset + 3]]) }) & 0x7FFFFFFF
}

fn calculate_code(key: &[u8], time: u64) -> u32 {
    let value: u64 = u64::to_be(time);
    let data: &[u8; 8] = unsafe { transmute(&value)};
    let mut hmac = Hmac::new(Sha1::new(), key);
    hmac.input(data);
    let result = hmac.result();
    let hash: &[u8] = result.code();
    disc_truncate(hash) % (10 as u32).pow(CODE_DIGITS)
}

pub fn validate_code(key: AuthKey, time: u64, code: u32) -> bool {
    let key_base = decode_key(key.key);
    for i in time - WINDOW_SIZE..time + WINDOW_SIZE {
        if calculate_code(key_base.as_slice(), i) == code {
            return true
        }
    }
    false
}