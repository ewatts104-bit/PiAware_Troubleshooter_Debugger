#!/usr/bin/env bash
# install.sh — Deploy PiAware RTL-SDR Troubleshooter to /opt/piaware-troubleshooter
# Run as: bash install.sh
set -euo pipefail

INSTALL_DIR=/opt/piaware-troubleshooter
SERVICE_NAME=piaware-troubleshooter
SUDOERS_FILE=/etc/sudoers.d/piaware-troubleshooter
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== PiAware RTL-SDR Troubleshooter Installer ==="
echo "Install dir : $INSTALL_DIR"
echo ""

# 1. Create install directory
sudo mkdir -p "$INSTALL_DIR"
sudo chown pi:pi "$INSTALL_DIR"

# 2. Copy application files
rsync -av --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='venv' --exclude='deploy' --exclude='install.sh' \
    "$SCRIPT_DIR/" "$INSTALL_DIR/"

# 3. Create Python venv and install deps
if [ ! -d "$INSTALL_DIR/venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
fi

echo "[*] Installing Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip wheel
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# 4. Install sudoers config
echo "[*] Installing sudoers config..."
sudo cp "$SCRIPT_DIR/deploy/sudoers.d/piaware-troubleshooter" "$SUDOERS_FILE"
sudo chmod 440 "$SUDOERS_FILE"
sudo chown root:root "$SUDOERS_FILE"

echo "[*] Verifying sudoers syntax..."
sudo visudo -c -f "$SUDOERS_FILE" || {
    echo "ERROR: sudoers file failed validation! Removing."
    sudo rm -f "$SUDOERS_FILE"
    exit 1
}

# 5. Install systemd service
echo "[*] Installing systemd service..."
sudo cp "$SCRIPT_DIR/deploy/systemd/piaware-troubleshooter.service" \
    /etc/systemd/system/piaware-troubleshooter.service
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

# 6. Done
sleep 2
STATUS=$(systemctl is-active "$SERVICE_NAME" || true)
echo ""
echo "=== Installation complete ==="
echo "Service status: $STATUS"
echo "Dashboard URL : http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "Manage with:"
echo "  sudo systemctl {start,stop,restart,status} $SERVICE_NAME"
echo "  sudo journalctl -u $SERVICE_NAME -f"
