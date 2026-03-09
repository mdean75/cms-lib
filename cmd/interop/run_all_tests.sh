#!/usr/bin/env bash
# run_all_tests.sh — exercises all four signing combinations and verifies each
# with the cms-lib Go library, OpenSSL, Bouncy Castle, and go.mozilla.org/pkcs7.
#
# Usage:
#   ./run_all_tests.sh [--skip-bc] [--skip-pkcs7]
#
# Flags:
#   --skip-bc     skip Bouncy Castle tests (requires groovy + Java)
#   --skip-pkcs7  skip the pkcs7 verifier tests
#
# Run from cmd/interop/

set -euo pipefail

# --- option parsing ---
SKIP_BC=false
SKIP_PKCS7=false
for arg in "$@"; do
    case "$arg" in
        --skip-bc)     SKIP_BC=true ;;
        --skip-pkcs7)  SKIP_PKCS7=true ;;
        *) echo "Unknown option: $arg  (usage: ./run_all_tests.sh [--skip-bc] [--skip-pkcs7])" >&2; exit 1 ;;
    esac
done

# --- counters ---
PASS=0
FAIL=0
KNOWN_FAIL=0
SKIP=0

# --- color helpers (no-op when not a tty) ---
if [[ -t 1 ]]; then
    GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[0;33m"; RESET="\033[0m"
else
    GREEN=""; RED=""; YELLOW=""; RESET=""
fi

pass()       { echo -e "  ${GREEN}PASS${RESET}  $1"; PASS=$((PASS + 1)); }
fail()       { echo -e "  ${RED}FAIL${RESET}  $1"; FAIL=$((FAIL + 1)); }
known_fail() { echo -e "  ${YELLOW}KNOWN FAIL${RESET}  $1"; KNOWN_FAIL=$((KNOWN_FAIL + 1)); }
skipped()    { echo -e "         SKIP  $1"; SKIP=$((SKIP + 1)); }

# run_step <label> <known_failure:true|false> <command...>
run_step() {
    local label="$1" known="$2"; shift 2
    local out
    if out=$("$@" 2>&1); then
        pass "$label"
    else
        if [[ "$known" == "true" ]]; then
            known_fail "$label"
        else
            fail "$label"
            echo "$out" | sed 's/^/    /' >&2
        fi
    fi
}

# --- prerequisite checks ---
if ! command -v openssl &>/dev/null; then
    echo "openssl not found in PATH — exiting" >&2
    exit 1
fi

if [[ "$SKIP_BC" == "false" ]] && ! command -v groovy &>/dev/null; then
    echo "groovy not found in PATH; use --skip-bc to skip Bouncy Castle tests" >&2
    exit 1
fi

# --- combinations ---
# Each entry: "identifier embed_flag embed_bool"
# embed_bool controls which --embed/--no-embed flag the scripts receive.
combinations=(
    "isn  true  --embed"
    "isn  false --no-embed"
    "ski  true  --embed"
    "ski  false --no-embed"
)

for combo in "${combinations[@]}"; do
    read -r identifier embed_bool embed_arg <<< "$combo"
    label="identifier=${identifier} embed=${embed_bool}"

    echo ""
    echo "=== $label ==="

    # 1. Sign (also does library verify internally)
    run_step "cms-lib sign+verify  ($label)" false \
        go run . -identifier "$identifier" -embed="$embed_bool"

    # 2. OpenSSL verify
    run_step "OpenSSL verify       ($label)" false \
        bash verify.sh "$embed_arg"

    # 3. Bouncy Castle verify
    if [[ "$SKIP_BC" == "true" ]]; then
        skipped "Bouncy Castle verify ($label)"
    else
        run_step "Bouncy Castle verify ($label)" false \
            groovy verify_bc.groovy "$embed_arg"
    fi

    # 4. pkcs7 verify — known failure for ski
    if [[ "$SKIP_PKCS7" == "true" ]]; then
        skipped "pkcs7 verify         ($label)"
    else
        known=""
        [[ "$identifier" == "ski" ]] && known="true" || known="false"
        run_step "pkcs7 verify         ($label)" "$known" \
            go run ../verify-pkcs7/ -identifier "$identifier" -embed="$embed_bool"
    fi
done

# --- summary ---
echo ""
echo "================================================"
echo "  Results"
echo "------------------------------------------------"
echo -e "  ${GREEN}PASS${RESET}        $PASS"
if [[ $KNOWN_FAIL -gt 0 ]]; then
    echo -e "  ${YELLOW}KNOWN FAIL${RESET}  $KNOWN_FAIL  (pkcs7 SKI limitation — expected)"
fi
if [[ $SKIP -gt 0 ]]; then
    echo "  SKIP        $SKIP"
fi
if [[ $FAIL -gt 0 ]]; then
    echo -e "  ${RED}FAIL${RESET}        $FAIL"
fi
echo "================================================"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
