use base64::{Engine, engine::general_purpose};
use std::error::Error; // assuming your crate name is enzo_crypto

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <plaintext>", args[0]);
        std::process::exit(1);
    }

    let plaintext = &args[1];

    println!(
        "[Encoded Text] {}",
        general_purpose::STANDARD_NO_PAD.encode(plaintext)
    );

    Ok(())
}
