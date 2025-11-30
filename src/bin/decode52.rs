use enzo_crypto::base52::Base52Codec;
use std::error::Error; // assuming your crate name is enzo_crypto

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        log::error!("Usage: {} <base52 string>", args[0]);
        std::process::exit(1);
    }

    let base52 = &args[1];

    let codec = Base52Codec;

    let decoded = codec.decode(base52)?; // Validate input
    log::info!(
        "[Decoded Text] {}",
        decoded.iter().map(|&b| b as char).collect::<String>()
    );

    Ok(())
}
