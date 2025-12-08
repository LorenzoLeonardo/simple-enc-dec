use anyhow::{Result, anyhow};
use openssl::pkcs5;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

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

/// Encrypt large file with password and write output file with format:
/// [salt(16 bytes)] [nonce(12 bytes)] [ciphertext stream ...] [tag(16 bytes)]
pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand_bytes(&mut salt)?;
    rand_bytes(&mut nonce)?;

    let key = derive_key_scrypt(password, &salt)?;

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&nonce))?;
    crypter.pad(false); // GCM does not use padding

    let mut infile = BufReader::new(File::open(input_path)?);
    let mut outfile = BufWriter::new(File::create(output_path)?);

    // Write salt and nonce at the start of output
    outfile.write_all(&salt)?;
    outfile.write_all(&nonce)?;

    let mut buffer = [0u8; 4096];
    let mut ciphertext_chunk = vec![0u8; 4096 + cipher.block_size()];
    loop {
        let count = infile.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let len = crypter.update(&buffer[..count], &mut ciphertext_chunk)?;
        outfile.write_all(&ciphertext_chunk[..len])?;
    }

    // Finalize encryption (writes any remaining data)
    let len = crypter.finalize(&mut ciphertext_chunk)?;
    outfile.write_all(&ciphertext_chunk[..len])?;

    // Get and write authentication tag at the end
    // Read the tag at the end of file
    let mut tag = [0u8; TAG_LEN];
    crypter.get_tag(&mut tag)?;
    outfile.write_all(&tag)?;

    outfile.flush()?;
    Ok(())
}

/// Decrypt large file with password from file format:
/// [salt(16 bytes)] [nonce(12 bytes)] [ciphertext stream ...] [tag(16 bytes)]
pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    let mut infile = BufReader::new(File::open(input_path)?);

    // Read salt and nonce from file start
    let mut salt = [0u8; SALT_LEN];
    infile.read_exact(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    infile.read_exact(&mut nonce)?;

    // Determine file length to find where tag is located
    let metadata = infile.get_ref().metadata()?;
    let file_size = metadata.len();

    // Calculate ciphertext size: total - salt - nonce - tag
    let ciphertext_len = file_size as usize - SALT_LEN - NONCE_LEN - TAG_LEN;

    let key = derive_key_scrypt(password, &salt)?;

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&nonce))?;
    crypter.pad(false);

    let mut outfile = BufWriter::new(File::create(output_path)?);

    // Buffer for reading ciphertext chunks
    let mut buffer = vec![0u8; 4096];
    // Buffer for decrypted plaintext output
    let mut plaintext_chunk = vec![0u8; 4096 + cipher.block_size()];

    // Read ciphertext chunks until just before tag
    let mut total_read = 0usize;

    while total_read < ciphertext_len {
        let to_read = std::cmp::min(4096, ciphertext_len - total_read);
        let read_bytes = infile.read(&mut buffer[..to_read])?;
        if read_bytes == 0 {
            return Err(anyhow!("Unexpected end of file while reading ciphertext"));
        }
        total_read += read_bytes;

        let len = crypter.update(&buffer[..read_bytes], &mut plaintext_chunk)?;
        outfile.write_all(&plaintext_chunk[..len])?;
    }

    // Read the tag at the end of file
    let mut tag = [0u8; TAG_LEN];
    infile.read_exact(&mut tag)?;
    crypter.set_tag(&tag)?;

    // Finalize decryption (checks authentication)
    let len = crypter
        .finalize(&mut plaintext_chunk)
        .map_err(|_| anyhow!("Decryption failed: authentication tag mismatch"))?;
    outfile.write_all(&plaintext_chunk[..len])?;

    outfile.flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::TryRngCore;
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // Helper: write data to a file inside the temp dir and return the file path
    fn write_temp_file(dir: &TempDir, filename: &str, data: &[u8]) -> PathBuf {
        let file_path = dir.path().join(filename);
        std::fs::write(&file_path, data).expect("write failed");
        file_path
    }

    // Helper: read all bytes from a file
    fn read_file_to_vec(path: &Path) -> Vec<u8> {
        let mut f = fs::File::open(path).expect("open failed");
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).expect("read failed");
        buf
    }

    #[test]
    fn test_derive_key_scrypt() {
        let password = "password123";
        let salt = [1u8; SALT_LEN];
        let key = derive_key_scrypt(password, &salt).expect("derive_key_scrypt failed");
        assert_eq!(key.len(), KEY_LEN);

        let salt2 = [2u8; SALT_LEN];
        let key2 = derive_key_scrypt(password, &salt2).expect("derive_key_scrypt failed");
        assert_ne!(key, key2);

        let key_empty = derive_key_scrypt("", &salt).expect("derive_key_scrypt failed");
        assert_eq!(key_empty.len(), KEY_LEN);
    }

    #[test]
    fn test_encrypt_decrypt_file_roundtrip() {
        let password = "strongpassword";
        let tempdir = TempDir::with_prefix_in("test", "./").unwrap();

        // Normal content
        let infile = write_temp_file(&tempdir, "input.txt", b"Hello, this is a test.");
        assert!(infile.exists(), "Input file does not exist after creation");
        let outfile_enc = tempdir.path().join("encrypted.bin");
        let outfile_dec = tempdir.path().join("decrypted.txt");

        encrypt_file(&infile, &outfile_enc, password).expect("encryption failed");
        decrypt_file(&outfile_enc, &outfile_dec, password).expect("decryption failed");

        let decrypted_data = read_file_to_vec(&outfile_dec);
        assert_eq!(b"Hello, this is a test.", &decrypted_data[..]);

        // Empty file test
        let empty_infile = write_temp_file(&tempdir, "empty.txt", b"");
        let empty_enc = tempdir.path().join("empty_encrypted.bin");
        let empty_dec = tempdir.path().join("empty_decrypted.txt");

        encrypt_file(&empty_infile, &empty_enc, password).expect("encrypt empty failed");
        decrypt_file(&empty_enc, &empty_dec, password).expect("decrypt empty failed");

        let decrypted_empty = read_file_to_vec(&empty_dec);
        assert!(decrypted_empty.is_empty());
    }

    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let tempdir = TempDir::with_prefix_in("test", "./").unwrap();

        let infile = write_temp_file(&tempdir, "input.txt", b"Sensitive data");
        let outfile_enc = tempdir.path().join("encrypted.bin");
        let outfile_dec = tempdir.path().join("decrypted.txt");

        encrypt_file(&infile, &outfile_enc, password).expect("encryption failed");

        let result = decrypt_file(&outfile_enc, &outfile_dec, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext_fails() {
        let password = "password123";
        let tempdir = TempDir::with_prefix_in("test", "./").unwrap();

        let infile = write_temp_file(&tempdir, "input.txt", b"Data to encrypt");
        let outfile_enc = tempdir.path().join("encrypted.bin");
        let outfile_dec = tempdir.path().join("decrypted.txt");

        encrypt_file(&infile, &outfile_enc, password).expect("encryption failed");

        // Corrupt ciphertext by truncating last byte from encrypted file
        let mut corrupted = fs::read(&outfile_enc).expect("read encrypted file");
        if corrupted.len() > SALT_LEN + NONCE_LEN + TAG_LEN {
            corrupted.pop();
        }
        fs::write(&outfile_enc, &corrupted).expect("write corrupted file");

        let result = decrypt_file(&outfile_enc, &outfile_dec, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_output_format() {
        let password = "test";
        let tempdir = TempDir::with_prefix_in("test", "./").unwrap();

        let infile = write_temp_file(&tempdir, "input.txt", b"1234567890");
        let outfile_enc = tempdir.path().join("encrypted.bin");

        encrypt_file(&infile, &outfile_enc, password).expect("encrypt failed");

        let encrypted_content = fs::read(&outfile_enc).expect("read encrypted failed");

        // Minimum length check (salt + nonce + tag)
        assert!(encrypted_content.len() > SALT_LEN + NONCE_LEN + TAG_LEN);

        let salt = &encrypted_content[0..SALT_LEN];
        let nonce = &encrypted_content[SALT_LEN..SALT_LEN + NONCE_LEN];
        let tag = &encrypted_content[encrypted_content.len() - TAG_LEN..];

        // Check salt, nonce, tag are not all zeroes (highly improbable)
        assert!(salt.iter().any(|&b| b != 0));
        assert!(nonce.iter().any(|&b| b != 0));
        assert!(tag.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_encrypt_decrypt_huge_file() {
        use rand::rngs::OsRng;
        use std::fs;
        use std::io::Write;
        use tempfile::TempDir;

        const HUGE_FILE_SIZE: usize = 100 * 1024 * 1024; // 100 MB

        let password = "strong_password_for_huge_file_test";
        let tempdir = TempDir::with_prefix_in("test", "./").expect("failed to create temp dir");

        // Create huge random input file
        let huge_input_path = tempdir.path().join("huge_input.bin");
        let mut huge_file = fs::File::create(&huge_input_path).expect("failed to create huge file");

        let mut data = vec![0u8; HUGE_FILE_SIZE];
        OsRng
            .try_fill_bytes(&mut data)
            .expect("failed to fill random bytes");

        huge_file
            .write_all(&data)
            .expect("failed to write huge file");
        huge_file.sync_all().expect("failed to sync huge file");

        assert!(huge_input_path.exists(), "Huge input file does not exist");

        // Prepare output paths
        let encrypted_path = tempdir.path().join("huge_encrypted.bin");
        let decrypted_path = tempdir.path().join("huge_decrypted.bin");

        // Encrypt
        encrypt_file(&huge_input_path, &encrypted_path, password).expect("encryption failed");

        // Decrypt
        decrypt_file(&encrypted_path, &decrypted_path, password).expect("decryption failed");

        // Verify decrypted content matches original
        let decrypted_data = fs::read(&decrypted_path).expect("failed to read decrypted file");

        assert_eq!(
            decrypted_data.len(),
            data.len(),
            "Decrypted file size mismatch"
        );
        assert_eq!(
            decrypted_data, data,
            "Decrypted data does not match original"
        );
    }
}
