extern crate rand;

extern crate crypto;

mod google_auth;

use std::env;
use std::process;

use google_auth::*;

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
    //println!("Code: {}", calculate_code(&decode_key(key), timestamp));
}