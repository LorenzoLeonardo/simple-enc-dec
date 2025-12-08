REMOTE_PC=lleonardo@enzotechcomputersolutions.com
REMOTE_DEST_DIR=/home/lleonardo/bin/simple-enc-dec
SSH_KEY_PATH=$HOME/.ssh/linuxubuntu-enzo-tech-webserver.pem
SERVICE_NAME=enzo-crypto.service
EXECUTABLE_NAME=crypto

set -e

echo "Build, Check, Test . . ."
cargo fmt --check
cargo clippy
cargo clippy --tests
cargo test --all-features
cargo build --release

echo "Uninstall previous packages..."
# Kill existing screen sessions and remove old files
ssh -i $SSH_KEY_PATH $REMOTE_PC \
    "sudo systemctl stop $SERVICE_NAME; \
     sudo systemctl disable $SERVICE_NAME; \
     sudo rm -f $REMOTE_DEST_DIR/*; \
     sudo rm -f /etc/systemd/system/$SERVICE_NAME; \
     mkdir -p $REMOTE_DEST_DIR"

echo "Copying new files to remote destination . . ."
scp -i $SSH_KEY_PATH $PWD/target/release/$EXECUTABLE_NAME $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/encrypt $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/decrypt $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/encode64 $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/decode64 $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/encode64-nopad $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/decode64-nopad $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/encode52 $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/decode52 $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/scrypt-decrypt $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/scrypt-encrypt $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/decrypt-file $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/target/release/encrypt-file $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/linux/systemd/$SERVICE_NAME $REMOTE_PC:$REMOTE_DEST_DIR

# Set executable permission
echo "Setting of permissions . . ."
ssh -i $SSH_KEY_PATH $REMOTE_PC \
    "chmod +x $REMOTE_DEST_DIR/$EXECUTABLE_NAME; \
     chmod +x $REMOTE_DEST_DIR/encrypt; \
     chmod +x $REMOTE_DEST_DIR/decrypt; \
     chmod +x $REMOTE_DEST_DIR/encrypt-file; \
     chmod +x $REMOTE_DEST_DIR/decrypt-file; \
     chmod +x $REMOTE_DEST_DIR/decode64; \
     chmod +x $REMOTE_DEST_DIR/encode64; \
     chmod +x $REMOTE_DEST_DIR/decode64-nopad; \
     chmod +x $REMOTE_DEST_DIR/encode64-nopad; \
     chmod +x $REMOTE_DEST_DIR/decode52; \
     chmod +x $REMOTE_DEST_DIR/encode52; \
     chmod +x $REMOTE_DEST_DIR/scrypt-decrypt; \
     chmod +x $REMOTE_DEST_DIR/scrypt-encrypt"

# Install systemd of this service and run the webserver as service
echo "Installing dependencies and systemd . . ."
ssh -i $SSH_KEY_PATH $REMOTE_PC \
    "sudo mv $REMOTE_DEST_DIR/$SERVICE_NAME /etc/systemd/system/; \
     sudo systemctl daemon-reexec; \
     sudo systemctl daemon-reload; \
     sudo systemctl enable $SERVICE_NAME; \
     sudo systemctl restart $SERVICE_NAME; \
     sudo systemctl status $SERVICE_NAME"
