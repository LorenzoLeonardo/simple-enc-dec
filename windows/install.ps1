# ================================
# Windows Installer for simple-enc-dec
# ================================

$ErrorActionPreference = "Stop"

$DEST_DIR = "$env:USERPROFILE\bin\simple-enc-dec"

# Remove old files
if (Test-Path $DEST_DIR) {
    Write-Host "Removing directory $DEST_DIR"
    Remove-Item -Recurse -Force $DEST_DIR
}

# Build files
Write-Host "Running cargo fmt..."
cargo fmt --check

Write-Host "Running cargo clippy..."
cargo clippy
cargo clippy --tests

Write-Host "Running cargo tests..."
cargo test --all-features

Write-Host "Running cargo build --release..."
cargo build --release

# Install binaries
Write-Host "Installing new binaries..."
New-Item -ItemType Directory -Force -Path $DEST_DIR | Out-Null

$releaseDir = Join-Path $PWD "target\release"

Copy-Item "$releaseDir\crypto.exe" "$DEST_DIR"
Copy-Item "$releaseDir\decode64.exe" "$DEST_DIR"
Copy-Item "$releaseDir\encode64.exe" "$DEST_DIR"
Copy-Item "$releaseDir\decode64-nopad.exe" "$DEST_DIR"
Copy-Item "$releaseDir\encode64-nopad.exe" "$DEST_DIR"
Copy-Item "$releaseDir\encrypt.exe" "$DEST_DIR"
Copy-Item "$releaseDir\decrypt.exe" "$DEST_DIR"
Copy-Item "$releaseDir\decode52.exe" "$DEST_DIR"
Copy-Item "$releaseDir\encode52.exe" "$DEST_DIR"
Copy-Item "$releaseDir\scrypt-encrypt.exe" "$DEST_DIR"
Copy-Item "$releaseDir\scrypt-decrypt.exe" "$DEST_DIR"
Copy-Item "$releaseDir\encrypt-file.exe" "$DEST_DIR"
Copy-Item "$releaseDir\decrypt-file.exe" "$DEST_DIR"

# ================================
# Add DEST_DIR to PATH (User-level)
# ================================
Write-Host "Updating PATH..."

$existingPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($existingPath -notlike "*$DEST_DIR*") {
    $newPath = "$existingPath;$DEST_DIR"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Added to PATH: $DEST_DIR"
}
else {
    Write-Host "PATH already contains: $DEST_DIR"
}

Write-Host "`nInstallation complete!"
Write-Host "Restart your terminal to use the commands globally."