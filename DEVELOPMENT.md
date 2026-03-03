# Development

## Interop Test Fixtures

The test suite verifies this library against output from OpenSSL and Bouncy Castle.
All fixtures are pre-generated static files committed to `testdata/` — running the
tests requires no external tools.

Regenerate fixtures only when adding new test cases or updating the fixture
generation logic.

### Bouncy Castle fixtures

Two options are available. Both write to `testdata/bc/signed/` and
`testdata/bc/enveloped/`.

**Go simulator** (no external dependencies — models BC's ASN.1 encoding choices):

```bash
testdata/bc/regen.sh
```

**Actual Bouncy Castle** via Docker (produces genuine BC output; authoritative source
of truth for BC encoding behaviour):

```bash
testdata/bc/regen-docker.sh
```

On first run, `regen-docker.sh` downloads `bcpkix-jdk18on` and `bcprov-jdk18on`
from Maven Central (~10 MB) and caches them under
`${XDG_CACHE_HOME:-~/.cache}/cms-lib/bc-jars`. Subsequent runs use the cache and
are fully offline. The BC version is controlled by `BC_VERSION` at the top of
`regen-docker.sh`.

The Go simulator (`gen.go`) post-processes the library's own output to replicate BC's
encoding quirks (explicit `NULL` digest parameters, `sha256WithRSAEncryption` OID for
PKCS#1 v1.5, `trailerField=1` in RSA-PSS params). `CMSGenerator.groovy` produces
these naturally because Bouncy Castle itself generates them.

### OpenSSL fixtures

Requires OpenSSL 3.0 or later. Writes to `testdata/openssl/signed/` and
`testdata/openssl/enveloped/`.

```bash
bash testdata/openssl/regen.sh
```

Signer private keys are deleted after generation and are not committed to the
repository. Recipient private keys are kept so that decryption tests can run without
regenerating fixtures.
