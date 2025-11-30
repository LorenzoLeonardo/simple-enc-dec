use base64::{Engine, engine::general_purpose};
use std::error::Error; // assuming your crate name is enzo_crypto

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <base64 string>", args[0]);
        std::process::exit(1);
    }

    let base64 = &args[1];

    let decoded = general_purpose::STANDARD_NO_PAD.decode(base64)?;
    println!("[Decoded Text] {}", String::from_utf8(decoded)?);

    Ok(())
}
