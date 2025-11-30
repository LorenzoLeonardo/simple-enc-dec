use base64::{Engine, engine::general_purpose};
use std::error::Error; // assuming your crate name is enzo_crypto

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        log::error!("Usage: {} <base64 string>", args[0]);
        std::process::exit(1);
    }

    let base64 = &args[1];

    let decoded = general_purpose::STANDARD.decode(base64)?;
    log::info!(
        "[Decoded Text] {}",
        decoded.iter().map(|&b| b as char).collect::<String>()
    );

    Ok(())
}
