# enzo-crypto

Small collection of Rust utilities for simple encryption, decryption and a custom Base52 encoder/decoder.

[![Linux](https://github.com/LorenzoLeonardo/enzo-crypto/actions/workflows/rust-linux.yml/badge.svg)](https://github.com/LorenzoLeonardo/enzo-crypto/actions/workflows/rust-linux.yml)
[![macOS](https://github.com/LorenzoLeonardo/enzo-crypto/actions/workflows/rust-macos.yml/badge.svg)](https://github.com/LorenzoLeonardo/enzo-crypto/actions/workflows/rust-macos.yml)
[![Windows](https://github.com/LorenzoLeonardo/enzo-crypto/actions/workflows/rust-windows.yml/badge.svg)](https://github.com/LorenzoLeonardo/enzo-crypto/actions/workflows/rust-windows.yml)
[![License](https://img.shields.io/github/license/LorenzoLeonardo/enzo-crypto.svg)](https://github.com/LorenzoLeonardo/enzo-crypto/blob/master/LICENSE)

Overview
- Library provides AES-based encrypt/decrypt helpers and a small scrypt-based wrapper for password-derived encryption.
- Includes a custom Base52 encoder/decoder.
- CLI tools build from `src/bin/` for quick encode/decode and encrypt/decrypt helpers.

Structure
- src/lib.rs — core library (encrypt, decrypt)
- src/scrypt.rs — password-based functions (encrypt_base64, decrypt_base64)
- src/base52.rs — Base52 encoding/decoding and tests
- src/bin/* — CLI tools:
  - encode/decode (base64)  
  - encode52/decode52 (custom base52)  
  - encrypt/decrypt (library AES)  
  - scrypt-encrypt/scrypt-decrypt (password-based)

Build & test
- Format: cargo fmt
- Lint: cargo clippy
- Test: cargo test --all-features
- Build: cargo build --release
- Binaries appear in `target/release/`

Usage (examples)
- Base64 encode: target/release/encode "hello world"
- Base52 encode: target/release/encode52 "plaintext"
- Encrypt with scrypt: target/release/scrypt-encrypt

CI / Releases
- CI workflows in .github/workflows (rust-linux.yml, rust-macos.yml, rust-windows.yml).
- Add tags and publish via cargo when ready.

Contributing
- Follow existing code style (cargo fmt, clippy).
- Add tests for new crypto behavior or encoding changes.
- Ensure compatibility across supported platforms.

Changelog template
- Keep a simple `CHANGELOG.md` with headings:
  - Unreleased
  - [x.y.z] - YYYY-MM-DD
    - Added
    - Changed
    - Fixed

Notes
- Review cryptographic parameters before using in production.

License
This project is licensed under the MIT License — see the LICENSE file for details.

MIT License
Copyright (c) 2025 Lorenzo Leonardo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.