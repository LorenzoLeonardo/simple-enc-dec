use enzo_crypto::encrypt;
use std::error::Error; // assuming your crate name is enzo_crypto

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        log::error!("Usage: {} <plaintext> <password>", args[0]);
        std::process::exit(1);
    }

    let plaintext = &args[1];
    let password = &args[2];

    let encrypted = encrypt(plaintext, password)?;
    log::info!("[Encrypted Text] {encrypted}");

    Ok(())
}
