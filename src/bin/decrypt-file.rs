use enzo_crypto::file_gcm::decrypt_file;
use std::{error::Error, path::PathBuf}; // assuming your crate name is enzo_crypto

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: {} <input path> <output path> <password>", args[0]);
        std::process::exit(1);
    }

    let input_path = PathBuf::from(&args[1]);
    let output_path = PathBuf::from(&args[2]);
    let password = &args[3];

    // Check if input path exists and is a file
    if !input_path.exists() {
        eprintln!(
            "Error: Input file '{}' does not exist.",
            input_path.display()
        );
        std::process::exit(1);
    }

    if !input_path.is_file() {
        eprintln!(
            "Error: Input path '{}' is not a file.",
            input_path.display()
        );
        std::process::exit(1);
    }

    decrypt_file(input_path.as_path(), output_path.as_path(), password)?;

    println!(
        "Decryption successful. Decrypted file saved to: {}",
        output_path.display()
    );

    Ok(())
}
