# Changelog

All notable changes to OCaml Crypto Linter will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-19

### Added
- Initial release of OCaml Crypto Linter
- AST-based vulnerability detection using ppxlib
- Support for Cryptokit, Nocrypto, and Mirage-crypto libraries
- 30+ security rules across 7 categories:
  - ALGO: Algorithm weakness detection
  - KEY: Key management issues
  - SIDE: Side-channel vulnerabilities
  - API: API misuse patterns
  - DEP: Dependency vulnerabilities
  - RAND: Random number generation issues
  - DOS: Denial of service vulnerabilities
- Interprocedural dataflow analysis
- Context-aware analysis to reduce false positives
- Statistical confidence scoring
- Multiple output formats: text, JSON, SARIF
- Parallel analysis using OCaml 5 domains
- Dune integration support
- GitHub Actions workflows
- Docker container support
- Comprehensive test suite

### Security Rules
- ALGO001: Weak cipher algorithm (DES, 3DES, RC4)
- ALGO002: Insecure hash function (MD5, SHA1)
- ALGO003: Small key sizes
- KEY001: Hardcoded cryptographic keys
- KEY002: Weak key derivation
- SIDE001: Non-constant time string comparison
- SIDE002: Table lookup timing attacks
- API001: ECB mode usage
- API002: CBC without MAC
- And 20+ more rules...

### Known Issues
- Semgrep integration requires manual semgrep installation
- LSP support is experimental
- Some false positives in test code detection

[0.1.0]: https://github.com/ShaiKKO/Vortex/releases/tag/v0.1.0