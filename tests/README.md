# OCaml Crypto Linter Tests

This directory contains all tests for the OCaml Crypto Linter.

## Structure

- `unit/` - Unit tests for individual components
  - `test_confidence_scoring.ml` - Tests for confidence scoring
  - `test_interprocedural.ml` - Tests for interprocedural analysis
  - `test_interprocedural_runner.ml` - Runner for interprocedural tests

- `integration/` - Integration tests
  - `simple_test.ml` - Basic integration test
  - `vulnerable_cryptokit_examples.ml` - Examples of vulnerable Cryptokit usage
  - `vulnerable_tls_patterns.ml` - Examples of vulnerable TLS patterns
  - `hash_collision_dos.ml` - Hash collision DoS examples
  - `dependency_test/` - Dependency testing

- `samples/` - Sample code for testing the linter
  - `vulnerable/` - Known vulnerable patterns
    - `api_misuse.ml` - API misuse examples
    - `edge_cases.ml` - Edge case examples
    - `hardcoded_keys.ml` - Hardcoded key examples
    - `timing_attacks.ml` - Timing attack examples
    - `weak_algorithms.ml` - Weak algorithm examples
  - `secure/` - Secure code examples
    - `good_crypto.ml` - Examples of good cryptographic practices
  - `real_world/` - Real-world examples
    - `jwt_implementation.ml` - JWT implementation example

- `reports/` - Test reports and analysis results
  - `crypto_audit_report.md` - Audit report
  - `crypto_lint_report.sarif` - SARIF format lint report

## Running Tests

To run all tests:
```bash
./run_tests.sh
```

To run specific test categories:
```bash
# Run unit tests
dune test tests/unit

# Run integration tests  
dune test tests/integration

# Test the linter on sample code
dune exec ocaml-crypto-linter -- tests/samples/vulnerable/*.ml
```