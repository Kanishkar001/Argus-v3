#!/bin/bash
set -euo pipefail
say(){ printf "%s\n" "$*"; }
DEST_DIR="/root/.local/bin"
say "[STEP] Removing launcher(s)"
rm -f "$DEST_DIR/argus" 2>/dev/null || true
# Also try common system paths in case of previous installs:
sudo rm -f /usr/local/bin/argus 2>/dev/null || true
sudo rm -f /usr/bin/argus 2>/dev/null || true
say "[STEP] (Optional) Remove PATH line in ~/.zshrc or ~/.bashrc if you added one."
say "[STEP] (Optional) Remove user-site Python deps via:"
say "  # if packaged: python3 -m pip uninstall argus -y"
say "  # or from your repo: pip3 uninstall -r requirements.txt"
say "[OK] Uninstall steps completed"
