use simple_enc_dec::encrypt;
use std::error::Error; // assuming your crate name is simple_enc_dec

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <plaintext> <password>", args[0]);
        std::process::exit(1);
    }

    let plaintext = &args[1];
    let password = &args[2];

    let encrypted = encrypt(plaintext, password)?;
    println!("[Encrypted Text] {}", encrypted);

    Ok(())
}
