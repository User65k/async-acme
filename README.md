[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Crates.io][crates-badge]][crates-url]
[![Released API docs](https://docs.rs/async-acme/badge.svg)](https://docs.rs/async-acme)
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/async-acme.svg
[crates-url]: https://crates.io/crates/async-acme
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/User65k/async-acme/blob/master/LICENSE

A generic async ACME crate.

The main goal is to allow binaries to choose what async runtime and TLS library is used.

# Features
You need to specify via features what crates are used in the actual work.

|feature flag|Meaning|
|---|---|
|use_tokio | Use [tokio](https://crates.io/crates/tokio) as async runtime|
|use_async_std | Use [async_std](https://crates.io/crates/async_std) as async runtime|
|use_rustls | Use [rustls](https://crates.io/crates/rustls) for HTTPS and generate Certificates tailored to it|
|hyper_rustls | `use_rustls`+`use_tokio` ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/User65k/async-acme/example_hyper_rustls.yml) |
|async_std_rustls | `use_rustls`+`use_async_std` ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/User65k/async-acme/example_async_std_rustls.yml)|

Without anything specified you will end up with *no async backend selected* or *no crypto backend selected*.
If you use this crate for a library, please [reexport](https://doc.rust-lang.org/cargo/reference/features.html#dependency-features) the appropriate features.

# Motivation

Rust offers different async runtimes that - on a high level - offer the same thing: asynchronous functions for files, sockets and so on.

So if you write a lib and need some basic features (like an http client) you sometimes have to make choices that are not what your crate's users would have liked.
For example:
I wrote a [webserver](https://github.com/User65k/flash_rust_ws) based on hyper and wanted to add ACME.
A crate I found did what I needed but used async-h1 and async-std. While that worked, it did increase the binary size and number of crates I depend on by a good amount.

So I wrote this. You can specify which backend to use.
In the Webserver case, using `--features="hyper_rustls"` (same dependencies) instead of `--features="async_std_rustls"` lead to 81 less crates and a 350kB smaller binary.
Using:
```
[profile.release]
lto = "fat"
codegen-units = 1
```

# Examples
These query certs from Let's Encrypt's Staging endpoint.
In order for them to work you need to change the email and domain from `example.com` to your own.

1. Hyper server with rustls: `cargo run --example hyper_rustls --features="hyper_rustls"`
2. async-std server with rustls: `cargo run --example async_rustls --features="async_std_rustls"`

# Plans

1. Add native_tls
2. Add openssl cert generation
