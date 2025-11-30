use enzo_crypto::decrypt;
use std::error::Error; // assuming your crate name is enzo_crypto

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        log::error!("Usage: {} <base64_ciphertext> <password>", args[0]);
        std::process::exit(1);
    }

    let ciphertext_b64 = &args[1];
    let password = &args[2];

    let decrypted = decrypt(ciphertext_b64, password)?;
    log::info!("[Decrypted Text] {decrypted}");

    Ok(())
}
