use rand::{OsRng, Rng};
use std::mem::transmute;
use std::u64;
use std::string::String;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::mac::Mac;
use time::Timespec;
use data_encoding::base32;
use data_encoding::base64;
use data_encoding::decode::Error;


#[derive(Debug, Clone)]
pub struct AuthKey {
    pub key: String,
}

#[derive(Debug, Clone)]
pub enum Base {
    BASE32,
    BASE64,
}

/// Holds the configuration parameters for TOTP authenticators
///
/// `secret_bits` hold the length of the secret key before encoding
/// `code_digits` holds the length of the passcodes that are to be generated
/// `window_timestep_size` holds the step size in which to proceed when validating a passcode within a time window
/// `window size` holds the absolute size of the time window
/// `base` holds whether the secret key is encoded using Base32 or Base64
pub struct AuthConfig {
    secret_bits: u32,
    code_digits: u32,
    window_timestep_size: u32,
    window_size: u32,
    base: Base,
}

/// Base struct for a TOTP Authenticator.
///
/// Holds its `AuthConfig`, is constructed using the `new`
/// method
pub struct TOTPAuthenticator {
    pub config: AuthConfig
}

/// An Authenticator
pub trait Authenticator {
    /// Create a new set of credentials
    fn create_credentials(&self) -> AuthKey;

    /// Validate a passcode against a given secret at a given time
    fn validate_code(&self, key: AuthKey, time: Timespec, code: u32) -> bool;

    /// Calculate a passcode for a given key at a given timestamp
    fn calculate_code(&self, key: &[u8], time: i64) -> u32;
}


impl Authenticator for TOTPAuthenticator {

    fn create_credentials(&self) -> AuthKey {
        let mut rng: OsRng = match OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Failed to obtain OS RNG: {}", e)
        };

        let mut buffer: Vec<u8> = Vec::with_capacity((self.config.secret_bits/8) as usize);
        buffer.resize((self.config.secret_bits/8) as usize, 0);
        rng.fill_bytes(&mut buffer);
        let auth_key = encode_secret_key(self.config.base.clone(), buffer);
        AuthKey {key: auth_key}
    }

    fn validate_code(&self, key: AuthKey, time: Timespec, code: u32) -> bool {
        let window: i64 = self.config.window_size as i64;
        let key_base = match decode_secret_key(self.config.base.clone(), key.key) {
            Ok(v) => v,
            Err(e) => panic!("Could not decode key: {}", e)
        };
        let time_window = time.sec / (self.config.window_timestep_size as i64);
        for i in -((window - 1)/2)..window / 2 {
            if self.calculate_code(key_base.as_slice(), time_window + i) == code {
                return true
            }
        }
        false
    }

    fn calculate_code(&self, key: &[u8], time: i64) -> u32 {
        let value: u64 = u64::to_be(time as u64);
        let data: &[u8; 8] = unsafe { transmute(&value)};
        let mut hmac = Hmac::new(Sha1::new(), key);
        hmac.input(data);
        let result = hmac.result();
        let hash: &[u8] = result.code();
        dyn_truncate(hash) % (10 as u32).pow(self.config.code_digits)
    }
}

fn encode_secret_key(base: Base, buffer: Vec<u8>) -> String {
    match base {
        Base::BASE32 => base32::encode(buffer.as_slice()),
        Base::BASE64 => base64::encode(buffer.as_slice())
    }
}

fn decode_secret_key(base: Base, key: String) -> Result<Vec<u8>, Error> {
    match base {
        Base::BASE32 => base32::decode(key.into_bytes().as_slice()),
        Base::BASE64 => base64::decode(key.into_bytes().as_slice())
    }
}

/// Creates a new Authenticator using the default settings used by Google Authenticator
pub fn with_defaults() -> TOTPAuthenticator {
    new(AuthConfig { secret_bits: 80, code_digits: 6, window_timestep_size: 30, window_size: 3, base: Base::BASE32})
}

/// Creates a new Authenticator based on a provided configuration
pub fn new(auth_config: AuthConfig) -> TOTPAuthenticator {
    TOTPAuthenticator { config: auth_config}
}

fn dyn_truncate(hash: &[u8]) -> u32 {
    let offset = (hash[hash.len() - 1] & 0xF) as usize;
    let result = (unsafe {transmute::<[u8; 4], u32>([hash[offset + 3], hash[offset + 2], hash[offset + 1], hash[offset]]) }) & 0x7FFFFFFF;
    result
}


#[cfg(test)]
mod test {
    use time::Timespec;
    use super::{new, with_defaults, Authenticator, Base, AuthConfig, decode_secret_key, encode_secret_key};

    #[test]
    fn encode_secret_key_ten_chars_base32_should_yield_16_char_string() {
            let key = encode_secret_key(Base::BASE32, vec![100, 100, 100, 100, 100, 100, 100, 100, 100, 100]);
            assert!(key.len() == 16)
    }

    #[test]
    fn validate_code_should_work_sixty_seconds_with_default_settings() {
        let auth = with_defaults();
        let creds = auth.create_credentials();
        assert!(creds.key.len() == 16);
        let key_base = decode_secret_key(auth.config.base.clone(), creds.key.to_string()).unwrap();
        let code = auth.calculate_code(key_base.as_slice(), 0);
        for i in 1..60 {
            assert!(auth.validate_code(creds.clone(), Timespec { sec: i, nsec: 0}, code));
        }
        assert!(!auth.validate_code(creds.clone(), Timespec { sec: 61, nsec: 0}, code));
    }

    #[test]
    fn validate_code_should_work_with_base64() {
        let auth = new(AuthConfig {secret_bits: 80, code_digits: 6, window_timestep_size: 30, window_size: 3, base: Base::BASE64});
        let creds = auth.create_credentials();
        assert!(creds.key.len() == 16);
        let key_base = decode_secret_key(auth.config.base.clone(), creds.key.to_string()).unwrap();
        let code = auth.calculate_code(key_base.as_slice(), 0);
        for i in 1..60 {
            assert!(auth.validate_code(creds.clone(), Timespec { sec: i, nsec: 0}, code));
        }
        assert!(!auth.validate_code(creds.clone(), Timespec { sec: 61, nsec: 0}, code));
    }
}
