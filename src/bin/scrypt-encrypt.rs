use enzo_crypto::{self, scrypt};
use std::{borrow::Cow, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        log::error!("Usage: {} <plaintext> <password>", args[0]);
        std::process::exit(1);
    }

    let plaintext = &args[1];
    let password = &args[2];

    let base64_cipher_text = scrypt::encrypt_base64(plaintext.as_bytes(), Cow::Borrowed(password))?;
    log::info!("[Encrypted Text] {base64_cipher_text}");

    Ok(())
}
