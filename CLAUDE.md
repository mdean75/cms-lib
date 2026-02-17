# Claude Instructions for cms-lib

This file defines coding standards, conventions, and workflow expectations for all
implementation work on `github.com/mdean75/cms`.

---

## Minimum Go Version Policy

This module targets a minimum of **Go 1.24**. A version is supported until two
newer major releases exist. With Go 1.26 current, Go 1.24, 1.25, and 1.26 are all
supported; Go 1.23 and older are not.

When Go 1.27 releases, the minimum will move to Go 1.25. Update `go.mod` and this
file at that time.

---

## Project Overview

A comprehensive Go implementation of RFC 5652 Cryptographic Message Syntax (CMS).
See `docs/implementation-plan.md` for the full design and `docs/start-here.md` for
orientation. Always consult the implementation plan before writing new code.

---

## Error Handling

### Error Types
All errors are defined in `errors.go` as `*cms.Error` with a `Code`, `Message`, and
`Cause`. Every error code has a corresponding sentinel variable for `errors.Is()`
checks. See `errors.go` for the full list.

### Descriptive Messages
Error messages must be descriptive enough to diagnose the problem without reading
source code. Prefer:
```go
// good
&Error{Code: CodeInvalidSignature, Message: "RSA-PSS signature verification failed: hash algorithm mismatch"}

// bad
&Error{Code: CodeInvalidSignature, Message: "signature failed"}
```

When wrapping an underlying error, always add context:
```go
&Error{Code: CodeParse, Message: "failed to parse SignedData structure", Cause: err}
```

### Builder Error Accumulation
Builder methods (e.g., `WithCertificate`, `WithPrivateKey`) must NOT return errors.
They accumulate validation errors in an internal slice. The terminal method (`Sign`,
`CounterSign`) reports all accumulated errors at once using `errors.Join()`:

```go
// Each accumulated error is a *cms.Error with CodeInvalidConfiguration.
// errors.Is(err, cms.ErrInvalidConfiguration) returns true for any config failure.
result, err := cms.NewSigner().
    WithCertificate(nil). // stored: "certificate is nil"
    WithPrivateKey(nil).  // stored: "private key is nil"
    Sign(r)
// err contains both failures; caller does not need to fix one at a time
```

Callers MUST NOT add `id-contentType` or `id-messageDigest` via
`AddAuthenticatedAttribute` — the library injects these automatically. If attempted,
accumulate a `CodeInvalidConfiguration` error.

### Conflicting Options
Redundant or inapplicable builder options (e.g., `WithMaxAttachedContentSize` when
`WithDetachedContent` is also set) are silently ignored. Options that would produce
genuinely ambiguous behavior accumulate a `CodeInvalidConfiguration` error.

---

## Testing

### Style
Use table-driven tests in the gotests style with `t.Run` subtests as the default:

```go
func TestFunctionName(t *testing.T) {
    tests := []struct {
        name    string
        // fields for inputs and expected outputs
        wantErr bool
    }{
        {
            name:    "descriptive test case name",
            wantErr: false,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // test body
        })
    }
}
```

### Package Scope
Default to white-box tests (same package). Use a `_test` package suffix for
black-box tests only when testing the public API in isolation adds meaningful value.

### Assertions
Use `testify` (`assert` / `require`) where it reduces boilerplate. Use stdlib
`testing.T` methods where they are sufficient. Prefer `require` (stops the test)
over `assert` (continues) when subsequent test steps depend on the current assertion.

### Benchmarks
Include benchmarks only for performance-sensitive operations (e.g., `ber.Normalize`,
`ParseSignedData`, signedAttrs re-encoding). Always assign all return values to a
package-level sink variable to prevent the compiler from optimizing away the work:

```go
var benchResult []byte

func BenchmarkNormalize(b *testing.B) {
    var r []byte
    for b.Loop() {
        r, _ = ber.Normalize(input)
    }
    benchResult = r
}
```

### Interop Test Fixtures
OpenSSL and Bouncy Castle interop test data lives in `testdata/` as pre-generated
static files committed to the repository. These tests have no external tool
dependency and run as part of the normal test suite. A separate regeneration script
(`testdata/regen.sh`) requires OpenSSL but is not invoked by `go test`.

### No Example Functions
Do not create `func Example*()` test functions. API documentation lives in godoc
comments only.

---

## Code Style

### Early Returns
Prefer early returns for guard clauses and error handling. Use judgment for cases
where a single return point is genuinely clearer.

```go
// preferred
func (s *Signer) validate() error {
    if s.certificate == nil {
        return errors.New("certificate is nil")
    }
    if s.key == nil {
        return errors.New("private key is nil")
    }
    return nil
}
```

### Cognitive Complexity
All functions and methods must have a cognitive complexity of 15 or less. This is
enforced via `golangci-lint`. If a function exceeds this limit, break it into
smaller, well-named helpers rather than restructuring logic to game the metric.

### Documentation Comments
Every exported symbol must have a godoc comment following
[Effective Go](https://go.dev/doc/effective_go#commentary) conventions:

- Comments begin with the name of the thing being documented
- Use complete sentences
- Package-level documentation uses a block comment before the `package` declaration

```go
/*
Package cms implements the Cryptographic Message Syntax as defined in RFC 5652.
*/
package cms

// Signer builds a CMS SignedData structure using a fluent builder API.
type Signer struct { ... }

// NewSigner returns a new Signer with default settings. Configure it with
// builder methods before calling Sign.
func NewSigner() *Signer { ... }

// Sign reads content from r, computes the CMS SignedData, and returns the
// DER-encoded result. Any configuration errors accumulated during building
// are returned as a joined error.
func (s *Signer) Sign(r io.Reader) ([]byte, error) { ... }
```

Non-exported symbols do not require comments unless the logic is non-obvious.

---

## Architecture

### Concurrency
`Sign()` (and other terminal methods) are safe for concurrent use by multiple
goroutines. Builder methods are NOT concurrent-safe. The expected pattern is:
configure the `Signer` sequentially once, then call `Sign()` concurrently as needed.

Terminal methods must not mutate the `Signer` struct — all working state is created
as local variables within the call.

### Dependencies
- **Standard library**: always preferred
- **`golang.org/x/`**: pre-approved, use freely
- **Other third-party packages**: require explicit discussion and justification before
  adding; do not add without approval

`testify` is pre-approved for test files only.

---

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**

| Type | Use for |
|---|---|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes only |
| `style` | Formatting, no logic change |
| `refactor` | Code restructuring, no feature or bug change |
| `test` | Adding or correcting tests |
| `perf` | Performance improvements |
| `chore` | Build process, tooling, dependencies |
| `ci` | CI configuration changes |

**Examples:**
```
feat(ber): implement BER to DER normalizer with indefinite-length support

fix(signeddata): correctly re-encode signedAttrs with EXPLICIT SET tag for digest

test(ber): add table-driven tests for 0-byte payload edge case
```

Descriptions are lowercase, imperative mood, no trailing period.

---

## Uncertainty During Implementation

If the right approach is not clear from the implementation plan or these instructions,
**stop and ask** before proceeding. Do not make undocumented assumptions, leave
unresolved `TODO` comments, or implement a guess. The cost of a wrong implementation
in a cryptographic library is high.
