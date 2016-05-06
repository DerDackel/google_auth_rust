extern crate rand;
extern crate crypto;
extern crate chrono;

mod google_auth;

use std::env;
use std::process;
use chrono::{UTC};

use google_auth::*;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: google_auth KEY TIMESTAMP");
        process::exit(0);
    }
    let code = match args[2].parse::<u32>() {
        Ok(v) => v,
        Err(e) => panic!("Could not parse {} into a valid code: {}", args[2], e),
    };
    let at_time =
        if args.len() == 4 {
            match args[3].parse::<i64>() {
                Ok(v) => v,
                Err(e) => panic!("Could not parse {} into a valid timestamp: {}", args[3], e),
            }
        } else {
            UTC::now().timestamp()
        };
    let auth = google_auth::default();
    println!("Code should be '{}' at T {}", auth.calculate_code(auth.decode_secret_key(args[1].to_string()).as_slice(), at_time), at_time);
    println!("Logged in: {}", auth.validate_code(AuthKey {key: args[1].clone()}, at_time, code));
}