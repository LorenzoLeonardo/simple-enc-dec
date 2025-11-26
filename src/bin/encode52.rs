use simple_enc_dec::base52::Base52Codec;
use std::error::Error; // assuming your crate name is simple_enc_dec

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <plaintext>", args[0]);
        std::process::exit(1);
    }

    let plaintext = &args[1];

    let codec = Base52Codec;

    println!("[Encoded Text] {}", codec.encode(plaintext));

    Ok(())
}
