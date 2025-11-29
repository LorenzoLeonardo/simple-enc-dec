use base64::{Engine, engine::general_purpose};
use std::error::Error; // assuming your crate name is simple_enc_dec

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        log::error!("Usage: {} <plaintext>", args[0]);
        std::process::exit(1);
    }

    let plaintext = &args[1];

    log::info!(
        "[Encoded Text] {}",
        general_purpose::STANDARD.encode(plaintext)
    );

    Ok(())
}
