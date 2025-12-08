use std::io::{Write, stdout};
use std::time::Duration;
use std::{error::Error, path::PathBuf}; // assuming your crate name is enzo_crypto

use enzo_crypto::{async_file_gcm, file_gcm::encrypt_file};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 {
        eprintln!(
            "Usage: {} <input path> <output path> <password> [--progress]",
            args[0]
        );
        std::process::exit(1);
    }

    let input_path = PathBuf::from(&args[1]);
    let output_path = PathBuf::from(&args[2]);
    let password = &args[3];
    let progress = if args.len() > 4 {
        if &args[4] == "--progress" {
            true
        } else {
            eprintln!("Unknown option: {}", args[4]);
            std::process::exit(1);
        }
    } else {
        false
    };

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

    if progress {
        let (tx_progress, mut rx_progress) =
            tokio::sync::mpsc::channel::<enzo_crypto::async_file_gcm::Progress>(10);
        let enc_task = tokio::task::spawn({
            let plain = input_path.clone();
            let enc = output_path.clone();
            async move {
                async_file_gcm::encrypt_file(
                    &plain,
                    &enc,
                    "testpassword",
                    tx_progress,
                    Duration::from_millis(500),
                )
                .await
            }
        });
        while let Some(p) = rx_progress.recv().await {
            print!(
                "\rEncrypting: {} bytes of {} bytes ({:.2}%)",
                p.bytes_processed(),
                p.total_bytes(),
                p.percentage()
            );
            stdout().flush()?;
        }
        enc_task.await??;
        println!(); // move to new line at the end
    } else {
        encrypt_file(input_path.as_path(), output_path.as_path(), password)?;
    }
    println!(
        "Encryption successful. Encrypted file saved to: {}",
        output_path.display()
    );
    Ok(())
}
