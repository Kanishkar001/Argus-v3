#!/bin/bash
# ==========================================
#   Argus Installation Script 
# ==========================================

set -e
APP_NAME="argus"
INSTALL_DIR="/opt/$APP_NAME"
BIN_PATH="/usr/local/bin/$APP_NAME"
UNINSTALLER="$INSTALL_DIR/uninstall.sh"
LOCAL_REQ="$(pwd)/requirements.txt"

# Colors
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; RESET="\e[0m"

echo ""
echo -e "${BLUE}==========================================${RESET}"
echo -e "${BLUE}        ARGUS GLOBAL INSTALLER TOOL        ${RESET}"
echo -e "${BLUE}==========================================${RESET}"
echo ""

# --- Step 1: Privilege check ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[❌] Please run this installer as root (sudo ./install.sh)${RESET}"
    exit 1
fi

# --- Step 2: Requirements check ---
command -v python3 >/dev/null 2>&1 || { echo -e "${RED}[ERROR] Python3 not found.${RESET}"; exit 1; }
command -v pip3 >/dev/null 2>&1 || { echo -e "${RED}[ERROR] pip3 not found.${RESET}"; exit 1; }

echo -e "${GREEN}[✔] Python environment verified.${RESET}"

# --- Step 3: Remove old installation ---
echo -e "${YELLOW}[INFO] Cleaning previous installations...${RESET}"
rm -rf "$INSTALL_DIR" "$BIN_PATH"

# --- Step 4: Copy Argus to /opt ---
echo -e "${BLUE}[INFO] Copying Argus source to $INSTALL_DIR...${RESET}"
mkdir -p "$INSTALL_DIR"
cp -r "$(pwd)/argus" "$INSTALL_DIR/"
chmod -R 755 "$INSTALL_DIR"

# --- Step 5: Auto-create __main__.py if missing ---
if [ ! -f "$INSTALL_DIR/argus/__main__.py" ]; then
    echo -e "${YELLOW}[INFO] Missing __main__.py detected. Creating automatically...${RESET}"
    cat <<'EOF' > "$INSTALL_DIR/argus/__main__.py"
from argus.cli.main import main

if __name__ == "__main__":
    main()
EOF
fi

# --- Step 6: Install dependencies from local requirements.txt ---
if [ -f "$LOCAL_REQ" ]; then
    echo -e "${BLUE}[INFO] Installing dependencies from $(basename "$LOCAL_REQ")...${RESET}"
    pip3 install -r "$LOCAL_REQ" >/dev/null 2>&1 && \
    echo -e "${GREEN}[✔] Dependencies installed successfully.${RESET}" || \
    echo -e "${YELLOW}[⚠] Warning: Some dependencies may already exist.${RESET}"
else
    echo -e "${YELLOW}[INFO] No requirements.txt found in installer directory. Skipping dependency install.${RESET}"
fi

# --- Step 7: Create global launcher ---
echo -e "${BLUE}[INFO] Creating global launcher in /usr/local/bin...${RESET}"
cat <<EOF > "$BIN_PATH"
#!/bin/bash
if [ "\$1" == "uninstall" ]; then
    sudo bash $UNINSTALLER
else
    PYTHONPATH=/opt/argus python3 -m argus "\$@"
fi
EOF
chmod +x "$BIN_PATH"

# --- Step 8: Create uninstaller ---
echo -e "${BLUE}[INFO] Creating uninstaller script...${RESET}"
cat <<'UNINSTALL' > "$UNINSTALLER"
#!/bin/bash
# ==========================================
#   Argus Uninstallation Script (Auto)
# ==========================================
APP_NAME="argus"
INSTALL_DIR="/opt/$APP_NAME"
BIN_PATH="/usr/local/bin/$APP_NAME"
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; RESET="\e[0m"

echo ""
echo -e "${BLUE}==========================================${RESET}"
echo -e "${BLUE}          ARGUS UNINSTALLER TOOL          ${RESET}"
echo -e "${BLUE}==========================================${RESET}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[❌] Please run as root (sudo argus uninstall)${RESET}"
    exit 1
fi

echo -e "${YELLOW}This will permanently remove Argus.${RESET}"
read -p "Type 'yes' to confirm: " confirm
if [ "$confirm" != "yes" ]; then
    echo -e "${YELLOW}[INFO] Uninstallation cancelled.${RESET}"
    exit 0
fi

rm -rf "$INSTALL_DIR" "$BIN_PATH"
echo -e "${GREEN}[✔] Argus successfully removed.${RESET}"
echo ""
UNINSTALL

chmod +x "$UNINSTALLER"

# --- Step 9: Verification ---
echo -e "${BLUE}[INFO] Verifying installation...${RESET}"
PYTHONPATH=/opt/argus python3 -c "import argus" >/dev/null 2>&1 && \
echo -e "${GREEN}[✔] Verification successful.${RESET}" || \
{ echo -e "${RED}[❌] Verification failed.${RESET}"; exit 1; }

# --- Step 10: Final summary ---
echo ""
echo -e "${BLUE}==========================================${RESET}"
echo -e "${GREEN}✅ ARGUS INSTALLED SUCCESSFULLY (GLOBAL)${RESET}"
echo -e "${BLUE}==========================================${RESET}"
echo ""
echo -e "📦 Location:      $INSTALL_DIR"
echo -e "⚙️  Executable:    $BIN_PATH"
echo -e "📜 Requirements:  Installed from $(basename "$LOCAL_REQ")"
echo -e "🧹 Uninstall via: ${YELLOW}argus uninstall${RESET}"
echo ""
echo -e "🚀 Launch Argus globally using: ${YELLOW}argus${RESET}"
echo ""
echo -e "${BLUE}==========================================${RESET}"
echo ""
