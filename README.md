# OCaml Crypto Linter

A comprehensive static analysis tool for detecting cryptographic vulnerabilities in OCaml codebases.

## Features

- **AST-based Analysis**: Deep inspection of OCaml code structure using ppxlib
- **Interprocedural Analysis**: Tracks data flow across function boundaries to detect complex patterns
- **Context-Aware Detection**: Reduces false positives by understanding code context (test vs production)
- **Semgrep Integration**: Extensible pattern matching for vulnerability detection
- **Modular Architecture**: Pluggable rules engine for custom security checks
- **Multi-format Output**: JSON and text reporting with LSP support planned
- **Parallel Processing**: Efficient analysis of large codebases using OCaml 5 domains
- **Dune Plugin**: Seamless integration with OCaml build workflows

## Detected Vulnerabilities

### Algorithm Weaknesses
- Weak ciphers (DES, 3DES, RC4, Blowfish)
- Insecure hash functions (MD5, SHA1) with context awareness
- Insecure elliptic curves (<256-bit, non-SafeCurves)

### Key & Nonce Management
- Hardcoded cryptographic keys
- Predictable IV/nonce usage
- Key reuse across different algorithms
- Weak random number generation

### Side-Channel Vulnerabilities
- Variable-time string comparisons
- Cache timing in table lookups
- Branch-based information leaks
- Power analysis vulnerable operations

### API Misuse
- ECB mode usage
- CBC without MAC (interprocedural detection)
- MAC-then-Encrypt pattern
- Missing authentication in encryption

### Dependency Issues
- Outdated crypto libraries with known CVEs
- Insecure library configurations

## Installation

```bash
opam install ocaml-crypto-linter
```

## Usage

### Command Line

```bash
# Analyze a single file
ocaml-crypto-linter src/crypto.ml

# Analyze with JSON output
ocaml-crypto-linter -f json -o report.json src/**/*.ml

# Enable Semgrep integration
ocaml-crypto-linter --semgrep src/

# Disable interprocedural analysis for faster scans
ocaml-crypto-linter --no-interprocedural src/

# Run with specific rule categories
ocaml-crypto-linter --rules side-channel,api-misuse src/
```

### Dune Integration

Add to your `dune` file:

```dune
(alias
 (name crypto-lint)
 (deps (source_tree .))
 (action (run ocaml-crypto-linter %{deps})))
```

### GitHub Actions

The project includes a pre-configured CI workflow that:
- Runs the linter on pull requests
- Posts results as PR comments
- Generates coverage reports
- Tests across multiple OCaml versions

## Architecture

```
ocaml-crypto-linter/
├── src/
│   ├── parser/         # AST analysis with ppxlib
│   │   ├── ast_analyzer.ml
│   │   └── typedtree_analyzer.ml
│   ├── analyzer/       # Core analysis engines
│   │   ├── analyzer.ml         # Main analyzer orchestrator
│   │   ├── dataflow_cfg.ml     # Control flow analysis
│   │   ├── interprocedural.ml  # Cross-function analysis
│   │   ├── import_tracker.ml   # Crypto library detection
│   │   └── parallel_engine.ml  # Multicore processing
│   ├── rules/          # Pluggable vulnerability rules (~30 rules)
│   │   ├── algorithm_weakness_rules.ml
│   │   ├── key_nonce_rules.ml
│   │   ├── side_channel_rules.ml
│   │   ├── api_misuse_rules.ml
│   │   └── dependency_rules.ml
│   ├── reporter/       # JSON/text/LSP output formats
│   └── dune_plugin/    # Build system integration
```

## Contributing

1. Add new rules in `src/rules/`
2. Implement custom analyzers in `src/analyzer/`
3. Submit PRs with test cases

## License

MIT