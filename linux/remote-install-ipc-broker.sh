REMOTE_PC=lleonardo@enzotechcomputersolutions.com
REMOTE_DEST_DIR=/home/lleonardo/bin/ipc-broker
SSH_KEY_PATH=$HOME/.ssh/linuxubuntu-enzo-tech-webserver.pem
SERVICE_NAME=ipc-broker.service
EXECUTABLE_NAME=ipc-broker

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
     sudo rm -f $REMOTE_DEST_DIR/$EXECUTABLE_NAME; \
     sudo rm -f /etc/systemd/system/$SERVICE_NAME; \
     mkdir -p $REMOTE_DEST_DIR"

echo "Copying new files to remote destination . . ."
scp -i $SSH_KEY_PATH $PWD/target/release/$EXECUTABLE_NAME $REMOTE_PC:$REMOTE_DEST_DIR
scp -i $SSH_KEY_PATH $PWD/linux/systemd/$SERVICE_NAME $REMOTE_PC:$REMOTE_DEST_DIR

# Set executable permission
echo "Setting of permissions . . ."
ssh -i $SSH_KEY_PATH $REMOTE_PC "chmod +x $REMOTE_DEST_DIR/$EXECUTABLE_NAME"

# Install systemd of this service and run the webserver as service
echo "Installing dependencies and systemd . . ."
ssh -i $SSH_KEY_PATH $REMOTE_PC \
    "sudo mv $REMOTE_DEST_DIR/$SERVICE_NAME /etc/systemd/system/; \
     sudo systemctl daemon-reexec; \
     sudo systemctl daemon-reload; \
     sudo systemctl enable $SERVICE_NAME; \
     sudo systemctl restart $SERVICE_NAME; \
     sudo systemctl status $SERVICE_NAME"
