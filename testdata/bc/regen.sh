#!/usr/bin/env bash
# regen.sh — regenerate BC-compatible CMS test fixtures
#
# Run from the repository root:
#   testdata/bc/regen.sh
#
# The Go generator (gen.go) produces fixtures that replicate Bouncy Castle's
# ASN.1 encoding choices:
#   - digestAlgorithm AlgorithmIdentifier with explicit NULL parameters
#   - RSA PKCS1v15 signatureAlgorithm uses sha256WithRSAEncryption OID
#   - RSA-PSS RSASSA-PSS-params include trailerField=1 explicitly
#
# If you wish to regenerate from actual BC output, run:
#   testdata/bc/regen-docker.sh
# (requires Docker; downloads BC JARs on first run and caches them locally)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
go run testdata/bc/gen.go
