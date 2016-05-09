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
* Probably f*ed up on Big Endian architectures, as I didn't 100% account for them
* Documentation