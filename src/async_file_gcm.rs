use std::path::Path;

use anyhow::{Result, anyhow};
use openssl::pkcs5;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, Instant};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; // Recommended nonce size for GCM
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

// scrypt parameters (adjust based on your security requirements)
const SCRYPT_N: u64 = 16384;
const SCRYPT_R: u64 = 8;
const SCRYPT_P: u64 = 1;
const SCRYPT_MAXMEM: u64 = 512 * 1024 * 1024;

fn derive_key_scrypt(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let mut key = vec![0u8; KEY_LEN];
    pkcs5::scrypt(
        password.as_bytes(),
        salt,
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        SCRYPT_MAXMEM,
        &mut key,
    )?;
    Ok(key)
}

pub struct Progress(usize, usize); // bytes processed, total bytes
impl Progress {
    pub fn percentage(&self) -> f64 {
        if self.1 == 0 {
            0.0
        } else {
            (self.0 as f64 / self.1 as f64) * 100.0
        }
    }

    pub fn bytes_processed(&self) -> usize {
        self.0
    }

    pub fn total_bytes(&self) -> usize {
        self.1
    }
}

/// Encrypt large file with password and write output file with format:
/// [salt(16 bytes)] [nonce(12 bytes)] [ciphertext stream ...] [tag(16 bytes)]
pub async fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    progress_tx: Sender<Progress>,
    interval: Duration,
) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand_bytes(&mut salt)?;
    rand_bytes(&mut nonce)?;

    let key = derive_key_scrypt(password, &salt)?;

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&nonce))?;
    crypter.pad(false); // GCM does not use padding

    let mut infile = BufReader::new(File::open(input_path).await?);
    let mut outfile = BufWriter::new(File::create(output_path).await?);

    // Write salt and nonce at the start of output
    outfile.write_all(&salt).await?;
    outfile.write_all(&nonce).await?;

    let mut buffer = [0u8; 4096];
    let mut ciphertext_chunk = vec![0u8; 4096 + cipher.block_size()];

    let metadata = tokio::fs::metadata(input_path).await?;
    let total_bytes = metadata.len() as usize;
    let mut total_bytes_read = 0u64 as usize;
    // --- PROGRESS THROTTLE ---
    let mut last_sent = Instant::now();
    loop {
        let count = infile.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        total_bytes_read += count;
        let len = crypter.update(&buffer[..count], &mut ciphertext_chunk)?;
        outfile.write_all(&ciphertext_chunk[..len]).await?;

        // Send progress only every 500ms
        if last_sent.elapsed() >= interval {
            progress_tx
                .send(Progress(total_bytes_read, total_bytes))
                .await?;
            last_sent = Instant::now();
        }
    }
    progress_tx
    .send(Progress(total_bytes_read, total_bytes))
    .await?;

    // Finalize encryption (writes any remaining data)
    let len = crypter.finalize(&mut ciphertext_chunk)?;
    outfile.write_all(&ciphertext_chunk[..len]).await?;

    // Get and write authentication tag at the end
    // Read the tag at the end of file
    let mut tag = [0u8; TAG_LEN];
    crypter.get_tag(&mut tag)?;
    outfile.write_all(&tag).await?;

    outfile.flush().await?;
    Ok(())
}

/// Decrypt large file with password from file format:
/// [salt(16 bytes)] [nonce(12 bytes)] [ciphertext stream ...] [tag(16 bytes)]
pub async fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    progress_tx: Sender<Progress>,
) -> Result<()> {
    let mut infile = BufReader::new(File::open(input_path).await?);

    // Read salt and nonce from file start
    let mut salt = [0u8; SALT_LEN];
    infile.read_exact(&mut salt).await?;
    let mut nonce = [0u8; NONCE_LEN];
    infile.read_exact(&mut nonce).await?;

    // Determine file length to find where tag is located
    let metadata = infile.get_ref().metadata().await?;
    let file_size = metadata.len();

    // Calculate ciphertext size: total - salt - nonce - tag
    let ciphertext_len = file_size as usize - SALT_LEN - NONCE_LEN - TAG_LEN;
    let total_bytes = ciphertext_len;

    let key = derive_key_scrypt(password, &salt)?;

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&nonce))?;
    crypter.pad(false);

    let mut outfile = BufWriter::new(File::create(output_path).await?);

    // Buffer for reading ciphertext chunks
    let mut buffer = vec![0u8; 4096];
    // Buffer for decrypted plaintext output
    let mut plaintext_chunk = vec![0u8; 4096 + cipher.block_size()];

    // Read ciphertext chunks until just before tag
    let mut total_read = 0usize;

    while total_read < ciphertext_len {
        let to_read = std::cmp::min(4096, ciphertext_len - total_read);
        let read_bytes = infile.read(&mut buffer[..to_read]).await?;
        if read_bytes == 0 {
            return Err(anyhow!("Unexpected end of file while reading ciphertext"));
        }
        total_read += read_bytes;

        let len = crypter.update(&buffer[..read_bytes], &mut plaintext_chunk)?;
        outfile.write_all(&plaintext_chunk[..len]).await?;

        progress_tx.send(Progress(total_read, total_bytes)).await?;
    }

    // Read the tag at the end of file
    let mut tag = [0u8; TAG_LEN];
    infile.read_exact(&mut tag).await?;
    crypter.set_tag(&tag)?;

    // Finalize decryption (checks authentication)
    let len = crypter
        .finalize(&mut plaintext_chunk)
        .map_err(|_| anyhow!("Decryption failed: authentication tag mismatch"))?;
    outfile.write_all(&plaintext_chunk[..len]).await?;

    outfile.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_encrypt_decrypt_file_progress() -> Result<()> {
        use tokio::io::AsyncWriteExt;

        // Create a temporary directory
        let temp_dir = TempDir::new()?;
        let plain_path = temp_dir.path().join("plaintext.txt");
        let encrypted_path = temp_dir.path().join("encrypted.enc");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        // Write test data to plaintext file
        let test_data = b"The quick brown fox jumps over the lazy dog";
        let mut plain_file = tokio::fs::File::create(&plain_path).await?;
        plain_file.write_all(test_data).await?;
        plain_file.flush().await?;

        // --- Encryption ---
        let (enc_progress_tx, mut enc_progress_rx) = mpsc::channel::<Progress>(10);

        let enc_path_clone = plain_path.clone();
        let enc_output_clone = encrypted_path.clone();

        // Spawn encryption
        let enc_handle = tokio::spawn(async move {
            encrypt_file(
                &enc_path_clone,
                &enc_output_clone,
                "testpassword",
                enc_progress_tx,
                Duration::from_millis(500),
            )
            .await
        });

        // Collect progress concurrently
        let mut last_progress = None;
        while let Some(progress) = enc_progress_rx.recv().await {
            println!("Encryption Progress: {:.2}%", progress.percentage());
            assert!(progress.bytes_processed() <= progress.total_bytes());
            assert!(progress.percentage() <= 100.0);
            last_progress = Some(progress);
        }

        assert!(matches!(last_progress, Some(p) if (p.percentage() - 100.0).abs() < f64::EPSILON));

        // Wait for encryption to finish
        enc_handle.await??;

        // --- Decryption ---
        let (dec_progress_tx, mut dec_progress_rx) = mpsc::channel::<Progress>(10);

        let dec_input_clone = encrypted_path.clone();
        let dec_output_clone = decrypted_path.clone();

        // Spawn decryption
        let dec_handle = tokio::spawn(async move {
            decrypt_file(
                &dec_input_clone,
                &dec_output_clone,
                "testpassword",
                dec_progress_tx,
            )
            .await
        });

        let mut last_dec_progress = None;
        while let Some(progress) = dec_progress_rx.recv().await {
            println!("Decryption Progress: {:.2}%", progress.percentage());
            assert!(progress.bytes_processed() <= progress.total_bytes());
            assert!(progress.percentage() <= 100.0);
            last_dec_progress = Some(progress);
        }

        assert!(
            matches!(last_dec_progress, Some(p) if (p.percentage() - 100.0).abs() < f64::EPSILON)
        );

        // Wait for decryption
        dec_handle.await??;

        // Validate decrypted content matches original
        let decrypted_data = tokio::fs::read(&decrypted_path).await?;
        assert_eq!(decrypted_data, test_data);

        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_file_invalid_password_fails_decryption() -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let temp_dir = TempDir::new()?;
        let plain_path = temp_dir.path().join("plaintext.txt");
        let encrypted_path = temp_dir.path().join("encrypted.enc");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let test_data = b"Some sensitive data";
        let mut plain_file = tokio::fs::File::create(&plain_path).await?;
        plain_file.write_all(test_data).await?;
        plain_file.flush().await?;

        // --- Encrypt ---
        let (enc_progress_tx, _enc_progress_rx) = mpsc::channel::<Progress>(10);
        let encrypted_path_clone = encrypted_path.clone();
        let plain_path_clone = plain_path.clone();
        let enc_task = tokio::spawn(async move {
            encrypt_file(
                &plain_path_clone,
                &encrypted_path_clone,
                "correct_password",
                enc_progress_tx,
                Duration::from_millis(500),
            )
            .await
        });

        enc_task.await??;

        // --- Decrypt with WRONG password ---
        let (dec_progress_tx, _dec_progress_rx) = mpsc::channel::<Progress>(10);

        let dec_task = tokio::spawn(async move {
            decrypt_file(
                &encrypted_path,
                &decrypted_path,
                "wrong_password",
                dec_progress_tx,
            )
            .await
        });

        let result = dec_task.await?;

        // Ensure failure
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_huge_file_progress() -> Result<()> {
        use tokio::task;

        const CHUNK_SIZE: usize = 32 * 1024; // 32 KB
        const NUM_CHUNKS: usize = 320; // ~10 MB
        let huge_chunk = vec![0xABu8; CHUNK_SIZE];

        let temp_dir = TempDir::new()?;
        let plain_path = temp_dir.path().join("plaintext.bin");
        let encrypted_path = temp_dir.path().join("encrypted.enc");
        let decrypted_path = temp_dir.path().join("decrypted.bin");

        // --- Generate ~10MB file ---
        let mut plain_file = tokio::fs::File::create(&plain_path).await?;
        for _ in 0..NUM_CHUNKS {
            plain_file.write_all(&huge_chunk).await?;
        }
        plain_file.flush().await?;

        // ---------------------------
        // Encrypt (spawned)
        // ---------------------------
        let (enc_tx, mut enc_rx) = mpsc::channel::<Progress>(32);

        let enc_task = task::spawn({
            let plain = plain_path.clone();
            let enc = encrypted_path.clone();
            async move {
                encrypt_file(
                    &plain,
                    &enc,
                    "testpassword",
                    enc_tx,
                    Duration::from_millis(500),
                )
                .await
            }
        });

        let mut last_enc = None;
        while let Some(p) = enc_rx.recv().await {
            println!("Enc: {:.2}%", p.percentage());
            last_enc = Some(p);
        }
        enc_task.await??;
        assert!(matches!(last_enc, Some(p) if (p.percentage() - 100.0).abs() < f64::EPSILON));

        // ---------------------------
        // Decrypt (spawned)
        // ---------------------------
        let (dec_tx, mut dec_rx) = mpsc::channel::<Progress>(32);

        let dec_task = task::spawn({
            let enc = encrypted_path.clone();
            let dec = decrypted_path.clone();
            async move { decrypt_file(&enc, &dec, "testpassword", dec_tx).await }
        });

        let mut last_dec = None;
        while let Some(p) = dec_rx.recv().await {
            println!("Dec: {:.2}%", p.percentage());
            last_dec = Some(p);
        }
        dec_task.await??;
        assert!(matches!(last_dec, Some(p) if (p.percentage() - 100.0).abs() < f64::EPSILON));

        // ---------------------------
        // Validate correctness
        // ---------------------------
        let original = tokio::fs::read(&plain_path).await?;
        let decrypted = tokio::fs::read(&decrypted_path).await?;
        assert_eq!(original, decrypted);

        Ok(())
    }
}
