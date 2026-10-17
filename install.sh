#!/usr/bin/env bash
# Install the Remote ACP Bridge system service.  Run it as root:
#
#   sudo ./install.sh
#   sudo systemctl enable --now remote-acp-server@<instance>
#   sudo systemctl enable --now remote-acp-helper.service      # workspace mount helper
#
# The units carry an @ROOT@ placeholder; this script replaces it with its own directory
# at install time, then symlinks the rendered unit into /usr/lib/systemd/system. Idempotent.
# It does not touch configs/, keys, certificates or model credentials.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="agent"
SERVER_UNIT="remote-acp-server@.service"
HELPER_UNIT="remote-acp-helper.service"
UNIT_DIR="/usr/lib/systemd/system"

step() { printf '[install] %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    printf '[install] ERROR: must run as root\n' >&2
    exit 1
fi

# 1. the service account
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    step "user '$SERVICE_USER' already exists (uid $(id -u "$SERVICE_USER"))"
else
    useradd -d "/home/$SERVICE_USER" -m -U -s /bin/bash "$SERVICE_USER"
    step "created user '$SERVICE_USER' (uid $(id -u "$SERVICE_USER"))"
fi

# 2. Install dependencies
dnf install -y python3-websockets cifs-utils nfs-utils

# 3. link the bridge unit and the workspace mount helper unit
for u in "$SERVER_UNIT" "$HELPER_UNIT"; do
    [[ -f "$ROOT/systemd/$u" ]] || { printf '[install] ERROR: unit not found at %s\n' "$ROOT/systemd/$u" >&2; exit 1; }
    sed "s|@ROOT@|$ROOT|g" "$ROOT/systemd/$u" > "$ROOT/systemd/$u.tmp" && mv "$ROOT/systemd/$u.tmp" "$ROOT/systemd/$u"
    ln -sf "$ROOT/systemd/$u" "$UNIT_DIR/$u"
    step "linked $UNIT_DIR/$u -> $ROOT/systemd/$u"
done

# 4. reload
systemctl daemon-reload
step "done. next: sudo systemctl enable --now remote-acp-server@<instance>"
step "            sudo systemctl enable --now remote-acp-helper.service"
