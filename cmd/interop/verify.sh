#!/usr/bin/env bash
# verify.sh — verifies signed.der using OpenSSL and prints the recovered message.
#
# Usage:
#   ./verify.sh [--no-embed]
#
# Flags:
#   --embed      leaf cert is embedded in the payload (default)
#   --no-embed   leaf cert is not embedded; loaded from leaf.pem out-of-band
#
# Run from cmd/interop/ after 'go run . [-identifier isn|ski] [-embed=true|false]'
# Note: OpenSSL handles both ISN and SKI signer identifiers transparently.

set -euo pipefail

EMBED="true"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --embed)    EMBED="true";  shift ;;
        --no-embed) EMBED="false"; shift ;;
        *) echo "Unknown option: $1  (usage: ./verify.sh [--embed|--no-embed])" >&2; exit 1 ;;
    esac
done

SIGNED="signed.der"
ROOT_CA="root_ca.pem"
INTERMEDIATE="intermediate_ca.pem"
LEAF="leaf.pem"

required=("$SIGNED" "$ROOT_CA" "$INTERMEDIATE")
[[ "$EMBED" == "false" ]] && required+=("$LEAF")

for f in "${required[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "error: $f not found — run 'go run .' first" >&2
        exit 1
    fi
done

echo "Verifying $SIGNED with OpenSSL (embed=$EMBED)..."

# Build a CA bundle (intermediate + root) for chain validation.
BUNDLE=$(mktemp /tmp/ca_bundle.XXXXXX.pem)
trap 'rm -f "$BUNDLE"' EXIT
cat "$INTERMEDIATE" "$ROOT_CA" > "$BUNDLE"

if [[ "$EMBED" == "true" ]]; then
    # Leaf cert is embedded in the payload; OpenSSL finds it automatically.
    openssl cms -verify \
        -in "$SIGNED" \
        -inform DER \
        -CAfile "$BUNDLE" \
        -out /dev/stdout 2>/dev/null
else
    # Leaf cert is out-of-band; supply it via -certfile for signer lookup.
    openssl cms -verify \
        -in "$SIGNED" \
        -inform DER \
        -certfile "$LEAF" \
        -CAfile "$BUNDLE" \
        -out /dev/stdout 2>/dev/null
fi

echo ""
echo "Verification successful."
