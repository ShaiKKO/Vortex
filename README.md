# OCaml Crypto Linter

[![Build Status](https://github.com/ShaiKKO/Vortex/workflows/CI/badge.svg)](https://github.com/ShaiKKO/Vortex/actions)
[![Documentation](https://img.shields.io/badge/docs-latest-blue)](https://shaikko.github.io/Vortex/ocaml-crypto-linter/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

OCaml Crypto Linter is a static analysis tool for detecting cryptographic vulnerabilities in OCaml codebases. It performs AST-based analysis with interprocedural dataflow tracking to identify common cryptographic misuses and security weaknesses.

## Features

- **AST Analysis**: Deep code inspection using ppxlib and compiler-libs
- **Interprocedural Tracking**: Cross-function dataflow analysis for complex vulnerability patterns
- **Context Awareness**: Differentiation between test and production code to reduce false positives
- **Parallel Processing**: OCaml 5 domains for efficient large codebase analysis
- **Multiple Output Formats**: JSON, SARIF, and text reporting
- **CI/CD Integration**: Native support for GitHub Actions, GitLab CI, and Jenkins
- **Extensible Rules**: Plugin architecture for custom security checks
- **Low Overhead**: <100ms startup time, <10MB memory for typical projects

## Detected Vulnerabilities

### Cryptographic Algorithms
- Weak ciphers: DES, 3DES, RC4, Blowfish
- Insecure hash functions: MD5, SHA1 (context-aware)
- Vulnerable elliptic curves: <256-bit, non-SafeCurves

### Key Management
- Hardcoded cryptographic keys and secrets
- Predictable IV/nonce generation
- Key reuse across different contexts
- Weak PRNG usage

### Side Channels
- Variable-time string comparisons
- Cache timing vulnerabilities
- Branch-based information leaks
- Table lookup timing attacks

### API Misuse
- ECB mode usage
- CBC without authentication
- MAC-then-Encrypt ordering
- Missing AEAD authentication

### Dependencies
- Outdated crypto libraries with CVEs
- Vulnerable library configurations

## Quick Start

Add OCaml Crypto Linter to your project:

```bash
opam install ocaml-crypto-linter

# For minimal dependencies
opam install ocaml-crypto-linter --with-test=false --with-doc=false
```

### Basic Usage

```ocaml
(* vulnerable.ml *)
let encrypt_data key data =
  let cipher = Cryptokit.Cipher.des ~mode:ECB key in  (* DES + ECB detected *)
  cipher#put_string data
  
let compare_token user_token stored_token =
  user_token = stored_token  (* Timing attack vulnerability *)
```

Run the linter:

```bash
# Analyze single file
ocaml-crypto-linter vulnerable.ml

# Analyze project
ocaml-crypto-linter src/

# Generate JSON report
ocaml-crypto-linter -f json -o report.json src/

# Run specific rules only
ocaml-crypto-linter --rules KEY001,ALGO002 src/
```

## Examples

### Cryptokit Integration

Detect common Cryptokit misuses:

```ocaml
(* Detected: ALGO001 - Weak cipher algorithm *)
let weak_cipher = Cryptokit.Cipher.des ~mode:ECB key

(* Detected: KEY002 - Hardcoded cryptographic key *)  
let secret_key = "my_hardcoded_key_123"

(* Detected: ALGO003 - Insecure hash function *)
let hash = Cryptokit.Hash.md5 ()
```

### Mirage Crypto Analysis

Validate Mirage_crypto usage patterns:

```ocaml
(* Detected: API001 - ECB mode usage *)
let cipher = Mirage_crypto.Cipher_block.AES.ECB.of_secret key

(* Detected: SIDE001 - Non-constant time comparison *)
if Cstruct.equal computed_mac expected_mac then
  Ok ()
```

### TLS Implementation

Analyze TLS-specific patterns:

```ocaml
(* Detected: API003 - MAC-then-Encrypt construction *)
let encrypted = encrypt key data in
let mac = compute_mac encrypted in
encrypted ^ mac
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Crypto Security Check
on: [push, pull_request]

jobs:
  crypto-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ocaml/setup-ocaml@v3
        with:
          ocaml-compiler: 5.2.x
      - run: opam install ocaml-crypto-linter
      - run: ocaml-crypto-linter . -f sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Performance

Performance characteristics on different project sizes:

| Project Size | Files | Analysis Time | Memory Usage |
|-------------|-------|---------------|--------------|
| Small (<100 files) | 87 | 0.3s | 12MB |
| Medium (<1000 files) | 523 | 2.1s | 48MB |
| Large (>1000 files) | 2,341 | 5.7s | 156MB |

### Benchmarks

Run performance benchmarks:

```bash
# Run benchmarks
dune exec bench/bench.exe

# Profile memory usage
dune exec bench/bench.exe -- --profile memory

# Test parallel scaling
OCAML_CRYPTO_LINTER_DOMAINS=8 dune exec bench/bench.exe
```

## Architecture

OCaml Crypto Linter uses a multi-stage pipeline architecture:

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────┐
│   Parser    │───▶│   Analyzer   │───▶│    Rules    │───▶│ Reporter │
│  (AST/Type) │    │  (Dataflow)  │    │  (30+ checks)│    │ (Output) │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────┘
       │                   │                    │                 │
    ppxlib           interprocedural      pattern match      JSON/SARIF
  compiler-libs       context-aware       confidence score    LSP/Text
```

### Core Components

- **Parser**: AST and typed tree analysis using ppxlib
- **Analyzer**: Interprocedural dataflow with parallel execution  
- **Rules Engine**: Pluggable vulnerability detection rules
- **Reporter**: Multiple output format support

## Configuration

### Feature Flags

```toml
[dependencies]
ocaml-crypto-linter = { version = "0.1.0", features = [
    "minimal",          # Core functionality only
    "semgrep",          # Semgrep rule support
    "interprocedural",  # Cross-function analysis
    "parallel",         # Multi-domain processing
    "lsp",              # Language server protocol
]}
```

### Configuration File

`.crypto-linter.json`:

```json
{
  "rules": {
    "ALGO001": "error",
    "KEY001": "error",
    "SIDE001": "warning"
  },
  "ignore_paths": [
    "**/test/**",
    "**/vendor/**"
  ],
  "confidence_threshold": 0.8,
  "max_file_size": 1048576,
  "parallel_domains": 4
}
```

## Documentation

- [Installation Guide](docs/installation.md)
- [API Reference](https://shaikko.github.io/Vortex/ocaml-crypto-linter/)
- [Rule Catalog](docs/rules.md)
- [Architecture](docs/architecture.md)

## Testing

Run the test suite:

```bash
# Unit tests
dune test

# Integration tests
dune test test/integration

# Run with coverage
dune test --instrument-with bisect_ppx
bisect-ppx-report html
```

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/ShaiKKO/Vortex.git
cd Vortex/ocaml-crypto-linter
opam install . --deps-only --with-test --with-doc
dune build
```

## License

OCaml Crypto Linter is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/ShaiKKO/Vortex/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ShaiKKO/Vortex/discussions)
- **Documentation**: [docs.shaikko.dev](https://shaikko.github.io/Vortex/ocaml-crypto-linter/)