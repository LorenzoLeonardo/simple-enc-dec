use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use openssl::pkcs5;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, decrypt, encrypt};

const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const KEY_LEN: usize = 32;

// scrypt parameters (adjust for your threat model)
const SCRYPT_N: u64 = 16384;
const SCRYPT_R: u64 = 8;
const SCRYPT_P: u64 = 1;
const SCRYPT_MAXMEM: u64 = 512 * 1024 * 1024; // 512 MB Max Memory

/// Derive a 32-byte key using OpenSSL scrypt
fn derive_key_scrypt(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let mut key = vec![0u8; KEY_LEN];
    // pkcs5::scrypt returns Result<(), ErrorStack> and fills key slice
    pkcs5::scrypt(
        password.as_bytes(),
        salt,
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        SCRYPT_MAXMEM,
        &mut key,
    )
    .map_err(|e| anyhow!("scrypt failed: {e}"))?;
    log::info!(
        "Derived key (hex): {}",
        key.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    Ok(key)
}

/// Encrypt plaintext with password -> returns Base64(salt || iv || ciphertext)
pub fn encrypt_base64(plaintext: &[u8], password: &str) -> Result<String> {
    // generate salt and iv
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    rand_bytes(&mut salt).map_err(|e| anyhow!("rand salt failed: {e}"))?;
    rand_bytes(&mut iv).map_err(|e| anyhow!("rand iv failed: {e}"))?;

    let key = derive_key_scrypt(password, &salt)?;

    let cipher = Cipher::aes_256_cbc();
    let ciphertext = encrypt(cipher, &key, Some(&iv), plaintext)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;

    // pack salt || iv || ciphertext
    let mut packed = Vec::with_capacity(SALT_LEN + IV_LEN + ciphertext.len());
    packed.extend_from_slice(&salt);
    packed.extend_from_slice(&iv);
    packed.extend_from_slice(&ciphertext);

    Ok(general_purpose::STANDARD.encode(&packed))
}

/// Decrypt Base64(salt || iv || ciphertext) with password -> returns plaintext bytes
pub fn decrypt_base64(b64: &str, password: &str) -> Result<Vec<u8>> {
    let raw = general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow!("base64 decode failed: {e}"))?;

    if raw.len() < SALT_LEN + IV_LEN {
        return Err(anyhow!("input too short"));
    }

    let salt = &raw[..SALT_LEN];
    let iv = &raw[SALT_LEN..SALT_LEN + IV_LEN];
    let ciphertext = &raw[SALT_LEN + IV_LEN..];

    let key = derive_key_scrypt(password, salt)?;

    let cipher = Cipher::aes_256_cbc();
    let plaintext = decrypt(cipher, &key, Some(iv), ciphertext)
        .map_err(|e| anyhow!("decryption failed: {e}"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose};

    const PASSWORD: &str = "correct horse battery staple";

    //
    // ────────────────────────────────────────────────
    //  BASIC FUNCTIONAL TESTS
    // ────────────────────────────────────────────────
    //

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello world! This is a test.";

        let enc = encrypt_base64(plaintext, PASSWORD).unwrap();
        let dec = decrypt_base64(&enc, PASSWORD).unwrap();

        assert_eq!(dec, plaintext);
    }

    #[test]
    fn test_incorrect_password_fails() {
        let plaintext = b"Secret data";

        let enc = encrypt_base64(plaintext, PASSWORD).unwrap();
        let dec = decrypt_base64(&enc, "wrong-pass");

        assert!(dec.is_err());
    }

    #[test]
    fn test_randomness_encrypt_twice() {
        let plaintext = b"same-msg";
        let e1 = encrypt_base64(plaintext, PASSWORD).unwrap();
        let e2 = encrypt_base64(plaintext, PASSWORD).unwrap();
        assert_ne!(e1, e2, "salt or IV not random");
    }

    #[test]
    fn test_contains_salt_iv_ciphertext() {
        let e = encrypt_base64(b"ok", PASSWORD).unwrap();
        let raw = general_purpose::STANDARD.decode(e).unwrap();

        assert!(raw.len() > SALT_LEN + IV_LEN);
    }

    //
    // ────────────────────────────────────────────────
    //  EDGE CASES
    // ────────────────────────────────────────────────
    //

    #[test]
    fn test_empty_plaintext() {
        let enc = encrypt_base64(b"", PASSWORD).unwrap();
        let dec = decrypt_base64(&enc, PASSWORD).unwrap();
        assert_eq!(dec, b"");
    }

    #[test]
    fn test_password_empty_string() {
        let enc = encrypt_base64(b"data", "").unwrap();
        let dec = decrypt_base64(&enc, "").unwrap();
        assert_eq!(dec, b"data");
    }

    #[test]
    fn test_binary_data_non_utf8() {
        // includes null, high-bit, control chars
        let binary = vec![0x00, 0xFF, 0x10, 0x9A, 0xCE, 0x33];

        let enc = encrypt_base64(&binary, PASSWORD).unwrap();
        let dec = decrypt_base64(&enc, PASSWORD).unwrap();

        assert_eq!(dec, binary);
    }

    #[test]
    fn test_large_plaintext() {
        let big = vec![0xAB; 1_000_000]; // 1MB of data
        let enc = encrypt_base64(&big, PASSWORD).unwrap();
        let dec = decrypt_base64(&enc, PASSWORD).unwrap();

        assert_eq!(dec, big);
    }

    #[test]
    fn test_tampered_ciphertext_bit_flip() {
        let enc = encrypt_base64(b"Hello world", PASSWORD).unwrap();
        let mut raw = general_purpose::STANDARD.decode(&enc).unwrap();

        // flip one random bit in ciphertext region (after salt + iv)
        if raw.len() > SALT_LEN + IV_LEN {
            raw[SALT_LEN + IV_LEN] ^= 0x01;
        }

        let tampered = general_purpose::STANDARD.encode(raw);
        let result = decrypt_base64(&tampered, PASSWORD);

        assert!(result.is_err(), "decryption must fail if tampered");
    }

    #[test]
    fn test_truncated_input() {
        // too short (missing salt/IV/ciphertext)
        let short = general_purpose::STANDARD.encode(vec![1, 2, 3, 4]);
        let result = decrypt_base64(&short, PASSWORD);

        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_base64() {
        let corrupted = "###not-base64###";

        let result = decrypt_base64(corrupted, PASSWORD);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_base64_padding() {
        // Still invalid base64
        let corrupted = "abcd====";
        let result = decrypt_base64(corrupted, PASSWORD);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_encrypt_decrypt_cycles() {
        let mut msg = b"initial message".to_vec();

        for i in 0..10 {
            let enc = encrypt_base64(&msg, PASSWORD).unwrap();
            msg = decrypt_base64(&enc, PASSWORD).unwrap();

            assert!(
                !msg.is_empty(),
                "message should always decrypt correctly (iteration {i})"
            );
        }
    }

    //
    // ────────────────────────────────────────────────
    //  INTERNAL: CHECK DERIVE_KEY_SCRYPT WITH FIXED SALT
    // ────────────────────────────────────────────────
    //

    #[test]
    fn test_derive_key_scrypt_fixed_salt() {
        // fixed salt for deterministic output
        let salt = [0x11u8; SALT_LEN];

        let k1 = derive_key_scrypt(PASSWORD, &salt).unwrap();
        let k2 = derive_key_scrypt(PASSWORD, &salt).unwrap();

        assert_eq!(k1, k2, "scrypt must be deterministic");
        assert_eq!(k1.len(), KEY_LEN);
    }
}
