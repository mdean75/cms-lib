# Contributing to cms-lib

Thank you for your interest in contributing! Please take a moment to review this
document before submitting an issue or pull request.

## Code of Conduct

Be respectful and constructive. Focus on what is best for the project and its users.

## How to Report Issues

Use the [GitHub issue tracker](https://github.com/mdean75/cms-lib/issues) for:

- Bug reports
- Feature requests
- Questions about usage

Please search existing issues before opening a new one to avoid duplicates.

## Reporting Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Please use GitHub's [private vulnerability reporting](https://github.com/Mhttps://mastercard.sharepoint.com/sites/TEAMHiringInterviewMaterials/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2FTEAMHiringInterviewMaterials%2FShared%20Documents%2FGeneral%2FSoftware%20Engineering%2FTechnical%20Screen&viewid=70c56dc9%2Dcc41%2D480b%2Da076%2D9df61bc52bb7&csf=1&cid=13ab289f%2D9d23%2D4837%2D985f%2D7c575a1c0eea&FolderCTID=0x01200025908EC23D0EFE45AD52B2DC1917BDFCastercard/cms-lib/security/advisories/new)
feature so the issue can be assessed and patched before public disclosure. We will
acknowledge your report as soon as possible.

## Contributing Code

### 1. Open an Issue First

Before submitting a pull request for anything beyond a trivial fix, please open an
issue describing the problem or feature. This gives maintainers a chance to provide
feedback before you invest significant time in an implementation.

### 2. Fork and Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/cms-lib
cd cms-lib
git remote add upstream https://github.com/mdean75/cms-lib
```

### 3. Create a Branch

```bash
git checkout -b my-fix-or-feature
```

### 4. Make Your Changes

- Follow the code style conventions described below.
- Add or update tests to cover your changes.
- Ensure all existing tests still pass: `go test ./...`

### 5. Commit

Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification. Use lowercase, imperative mood, no trailing period. Examples:

```
feat(signeddata): add support for multiple digest algorithms
fix(ber): correctly handle indefinite-length encoding in nested structures
test(envelopeddata): add table-driven tests for ECDH key agreement
```

### 6. Submit a Pull Request

Push your branch to your fork and open a pull request against `main`. Include a
clear description of the change and a reference to the issue it addresses (e.g.,
`Closes #42`).

## Code Style

- **Go version**: minimum Go 1.24
- **Formatting**: code must be formatted with `gofmt`
- **Imports**: managed with `goimports`
- **Naming**: follow standard Go conventions (mixedCaps, no underscores)
- **Early returns**: prefer early returns for guard clauses over nested if-else
- **Comments**: all exported symbols must have godoc comments beginning with the
  symbol name
- **Cognitive complexity**: functions must have a cognitive complexity of 15 or less

## Testing

- Use table-driven tests with `t.Run` subtests
- Use `testify/assert` and `testify/require` to reduce boilerplate
- New features and bug fixes must include tests
- Test coverage is expected to remain above 80%

## Review Process

Submitted pull requests will be reviewed as soon as possible. You may be asked to
make changes before a pull request is merged. Once approved, a maintainer will
merge it.

## AI-Assisted Contributions

AI-assisted code changes are welcome. However, contributors are expected to
personally review, understand, and take full ownership of any AI-generated code
before submitting it. Do not submit AI-generated changes that you have not read
and verified yourself. The maintainers will not be responsible for reviewing
AI-generated code on a contributor's behalf.

## License

By submitting a contribution you agree that your work will be licensed under the
[Apache License 2.0](LICENSE) that covers this project. No contributor license
agreement is required.
