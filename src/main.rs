extern crate rand;
extern crate base32;
extern crate crypto;

use rand::{OsRng, Rng};
use std::mem::transmute;
use std::u64;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::mac::Mac;
use std::env;
use std::process;

const SECRET_BITS: u32 = 80;
const CODE_DIGITS: u32 = 6;

pub fn create_credentials() {
    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e)
    };
    let buffer = std::iter::repeat(0).map(|_| rng.gen::<u8>()).take((SECRET_BITS / 8) as usize).collect::<Vec<u8>>();
    println!("Buffer: {:?}", &buffer);
    println!("Secret: {}", calculate_secret_key(&buffer));
    println!("Code: {}", calculate_code(&buffer, 65535))
}

fn calculate_secret_key(buffer: &[u8]) -> String {
    base32::encode(base32::Alphabet::RFC4648 {padding: false}, buffer)
}

fn decode_key(key: String) -> Vec<u8> {
    match base32::decode(base32::Alphabet::RFC4648 {padding: false}, &key) {
        Some(v) => v,
        None => panic!("Could not decode secret!"),
    }
}

fn calculate_code(key: &[u8], time: u64) -> u32 {
    let value: u64 = u64::to_be(time);
    let data: &[u8; 8] = unsafe { transmute(&value)};
    println!("{:?}", data);
    let mut hmac = Hmac::new(Sha1::new(), key);
    hmac.input(data);
    let result = hmac.result();
    let hash: &[u8] = result.code();
    println!("Hash: {:?}, {}", hash, hash.len());
    let offset = (hash[hash.len() - 1] & 0xF) as usize;
    println!("{}", offset);
    let dt: u32 = (unsafe {transmute::<[u8; 4], u32>([hash[offset], hash[offset + 1], hash[offset + 2], hash[offset + 3]]) }) & 0x7FFFFFFF;
    dt % (10 as u32).pow(CODE_DIGITS)
}

fn main() {
    create_credentials();
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: google_auth KEY TIMESTAMP");
        process::exit(0);
    }
    let key = args[1].to_string();
    let timestamp = match args[2].parse::<u64>() {
        Ok(v) => v,
        Err(e) => panic!("Could not parse {} into a number: {}", args[2], e),
    };
    println!("Code: {}", calculate_code(&decode_key(key), timestamp));
}