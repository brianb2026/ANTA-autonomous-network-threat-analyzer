#!/bin/sh
# Install ANTA for the current user (no root needed):
#   ~/.local/opt/anta            the application
#   ~/.local/share/applications  a menu entry
#   ~/.local/bin/anta            a launcher on PATH
# Live capture asks for your password through polkit each time. To allow capture
# without prompting, grant the engine the capture capability once (optional):
#   sudo setcap cap_net_raw,cap_net_admin=eip ~/.local/opt/anta/anta-engine
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
DEST="${HOME}/.local/opt/anta"
mkdir -p "${HOME}/.local/opt" "${HOME}/.local/share/applications" "${HOME}/.local/bin"
rm -rf "$DEST"
cp -R "$SRC" "$DEST"
chmod -R go-w "$DEST"
sed "s#@INSTALL_DIR@#${DEST}#g" "$SRC/anta.desktop" > "${HOME}/.local/share/applications/anta.desktop"
ln -sf "$DEST/ANTA" "${HOME}/.local/bin/anta"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "${HOME}/.local/share/applications" || true
echo "ANTA installed to $DEST. Launch it from your application menu or run: anta"
command -v pkexec >/dev/null 2>&1 || echo "Note: pkexec (polkit) not found; live capture will need the setcap step above."
