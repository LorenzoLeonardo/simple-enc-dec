use enzo_crypto::{self, scrypt};
use std::{borrow::Cow, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        log::error!("Usage: {} <base64_ciphertext> <password>", args[0]);
        std::process::exit(1);
    }

    let base64_cipher_text = &args[1];
    let password = &args[2];

    let plaintext =
        scrypt::decrypt_base64(Cow::Borrowed(base64_cipher_text), Cow::Borrowed(password))
            .map(String::from_utf8)??;
    log::info!("[Decrypted Text] {plaintext}");

    Ok(())
}
