#!/usr/bin/env bash
# regen-docker.sh — regenerate BC-compatible CMS test fixtures using actual
# Bouncy Castle, via Docker. No local Groovy or Java installation required.
#
# Run from the repository root:
#   testdata/bc/regen-docker.sh
#
# BC JARs are downloaded from Maven Central on first run and cached under
# ${XDG_CACHE_HOME:-~/.cache}/cms-lib/bc-jars. Subsequent runs are offline.
#
# To upgrade BC, update BC_VERSION below.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

BC_VERSION="1.80"
JAR_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/cms-lib/bc-jars"
BCPROV_JAR="${JAR_DIR}/bcprov-jdk18on-${BC_VERSION}.jar"
BCPKIX_JAR="${JAR_DIR}/bcpkix-jdk18on-${BC_VERSION}.jar"
BCUTIL_JAR="${JAR_DIR}/bcutil-jdk18on-${BC_VERSION}.jar"
MAVEN_BASE="https://repo1.maven.org/maven2/org/bouncycastle"

if [[ ! -f "${BCPROV_JAR}" ]] || [[ ! -f "${BCPKIX_JAR}" ]] || [[ ! -f "${BCUTIL_JAR}" ]]; then
    echo "Downloading Bouncy Castle ${BC_VERSION} JARs..."
    mkdir -p "${JAR_DIR}"
    curl -fsSL -o "${BCPROV_JAR}" \
        "${MAVEN_BASE}/bcprov-jdk18on/${BC_VERSION}/bcprov-jdk18on-${BC_VERSION}.jar"
    curl -fsSL -o "${BCPKIX_JAR}" \
        "${MAVEN_BASE}/bcpkix-jdk18on/${BC_VERSION}/bcpkix-jdk18on-${BC_VERSION}.jar"
    curl -fsSL -o "${BCUTIL_JAR}" \
        "${MAVEN_BASE}/bcutil-jdk18on/${BC_VERSION}/bcutil-jdk18on-${BC_VERSION}.jar"
    echo "JARs cached in ${JAR_DIR}"
fi

docker run --rm \
    -v "$(pwd):/workspace" \
    -v "${JAR_DIR}:/bc-jars:ro" \
    -w /workspace \
    groovy:4-jdk21 \
    groovy -cp "/bc-jars/bcprov-jdk18on-${BC_VERSION}.jar:/bc-jars/bcpkix-jdk18on-${BC_VERSION}.jar:/bc-jars/bcutil-jdk18on-${BC_VERSION}.jar" \
    testdata/bc/CMSGenerator.groovy
