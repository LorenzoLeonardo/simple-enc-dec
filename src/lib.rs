pub mod base52;

use base64::{Engine as _, engine::general_purpose};

use openssl::hash::{MessageDigest, hash};
use openssl::symm::{Cipher, Crypter, Mode};
use std::error::Error;

fn derive_key(password: &str) -> Vec<u8> {
    // SHA-256 hash of password
    hash(MessageDigest::sha256(), password.as_bytes())
        .expect("SHA256 hash failed")
        .to_vec()
}

pub fn encrypt(plaintext: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let key = derive_key(password);
    let iv = [0u8; 16]; // 16 zero bytes IV

    let cipher = Cipher::aes_256_cbc();

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;
    crypter.pad(true);

    log::info!("[encrypt] Cipher Block Size: {}", cipher.block_size());
    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let mut count = crypter.update(plaintext.as_bytes(), &mut ciphertext)?;
    count += crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);

    Ok(general_purpose::STANDARD.encode(&ciphertext))
}

pub fn decrypt(ciphertext_b64: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let key = derive_key(password);
    let iv = [0u8; 16];

    let cipher = Cipher::aes_256_cbc();

    let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64)?;

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;
    crypter.pad(true);

    log::info!("[decrypt] Cipher Block Size: {}", cipher.block_size());
    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(&ciphertext, &mut plaintext)?;
    count += crypter.finalize(&mut plaintext[count..])?;
    plaintext.truncate(count);

    Ok(String::from_utf8(plaintext)?)
}
