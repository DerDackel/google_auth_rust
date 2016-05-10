TOTP-Authentication library
===========================

This library ()partially) implements secret generation and passcode verification according to [RFC 6238] (https://tools.ietf.org/html/rfc6238 "RFC 6238").
It was done as an exercise to learn some Rust and is provided as-is, without any guarantees on correctness, functionality and security, but if you find anything wrong with it or know a way to improve it, feel free to make a PR.

It currently provides
---------------------

* Generating Authentication Secrets
* Calculating passcodes for timestamps
* Verifying passcodes within a time-step-window according to RFC6238
* Defaults matching Google Authenticator

It currently doesn't do
-----------------------

* Scratch codes
* Probably f*ed up on Big Endian architectures, as I didn't really bother with them
* Documentation
* Proper unit tests

Usage
-----

```
use google_auth::Authenticator;

...

// create authenticator with defaults
let authenticator = google_auth::default()

let auth_key = authenticator.create_credentials();

...

let passcode: u32 = ... // read passcode from user
println!("Correct code? : {}", authenticator.validate_code(auth_key, time::get_time(), passcode));
```

Inspiration
-----------

I mostly relied on a Java implementation of TOTP available [here] (https://github.com/wstrange/GoogleAuth)