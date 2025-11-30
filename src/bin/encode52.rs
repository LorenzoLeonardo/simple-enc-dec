use enzo_crypto::base52::Base52Codec;
use std::error::Error; // assuming your crate name is enzo_crypto

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        log::error!("Usage: {} <plaintext>", args[0]);
        std::process::exit(1);
    }

    let plaintext = &args[1];

    let codec = Base52Codec;

    log::info!("[Encoded Text] {}", codec.encode(plaintext));

    Ok(())
}
