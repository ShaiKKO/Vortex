# Quick Start Guide

Get started with OCaml Crypto Linter in 5 minutes.

## Basic Usage

### 1. Analyze a Single File

```bash
ocaml-crypto-linter src/crypto.ml
```

Example vulnerable code:
```ocaml
(* crypto.ml *)
let encrypt_data data =
  let key = "my_secret_key_123" in  (* KEY001: Hardcoded key *)
  let cipher = Cryptokit.Cipher.des key in  (* ALGO001: Weak cipher *)
  cipher#put_string data;
  cipher#get_string
```

Output:
```
Files analyzed: 1
Time taken: 0.05s
Findings: 2

[KEY001] Hardcoded Cryptographic Key
  File: src/crypto.ml:2:13
  Severity: CRITICAL
  Suggestion: Use environment variables or secure key management

[ALGO001] Weak Cipher Algorithm
  File: src/crypto.ml:3:16
  Severity: ERROR
  Suggestion: Use AES-256-GCM or ChaCha20-Poly1305
```

### 2. Analyze a Project

```bash
# Analyze all OCaml files in src/
ocaml-crypto-linter src/**/*.ml

# Analyze current directory recursively
ocaml-crypto-linter .
```

### 3. Generate Reports

#### JSON Report
```bash
ocaml-crypto-linter src/ -f json -o report.json
```

Example output:
```json
{
  "findings": [
    {
      "rule_id": "ALGO002",
      "severity": "error",
      "message": "Weak hash algorithm: MD5 is vulnerable to collision attacks",
      "location": {
        "file": "src/auth.ml",
        "line": 15,
        "column": 8
      },
      "suggestion": "Use SHA-256, SHA-3, or BLAKE2b"
    }
  ],
  "summary": {
    "files_analyzed": 10,
    "total_findings": 3,
    "critical": 1,
    "errors": 2
  }
}
```

#### SARIF Report (for GitHub)
```bash
ocaml-crypto-linter src/ -f sarif -o results.sarif
```

### 4. Common Vulnerability Examples

#### Weak Algorithms
```ocaml
(* Detected vulnerabilities *)
let hash = Digest.string data  (* ALGO002: MD5 is weak *)
let cipher = Cryptokit.Cipher.arcfour key  (* ALGO001: RC4 is broken *)
let curve = Nocrypto.Ec.P192  (* ALGO003: Weak elliptic curve *)
```

#### Key Management Issues
```ocaml
(* Hardcoded secrets *)
let api_key = "sk_live_abcd1234"  (* KEY001 *)

(* Predictable randomness *)
let iv = String.make 16 '\000'  (* KEY004: Static IV *)
Random.self_init ()  (* API005: Weak random seed *)
```

#### Timing Attacks
```ocaml
(* Variable-time comparison *)
if password = stored_password then  (* SIDE001: Timing leak *)
  authenticate ()

(* Secure alternative *)
if Eqaf.equal password stored_password then
  authenticate ()
```

### 5. Filter by Rule Categories

```bash
# Only check for timing attacks and key issues
ocaml-crypto-linter --rules SIDE,KEY src/

# Exclude certain rules
ocaml-crypto-linter --exclude-rules ALGO002,API006 src/
```

### 6. Integration with Build Systems

#### Dune
Add to your `dune` file:
```dune
(alias
 (name runtest)
 (deps (source_tree .))
 (action (run ocaml-crypto-linter %{deps})))
```

Run with:
```bash
dune build @runtest
```

#### Makefile
```makefile
.PHONY: lint
lint:
	ocaml-crypto-linter src/ -f json -o lint-report.json
	@echo "Linting complete. Report: lint-report.json"

test: lint
	dune test
```

### 7. CI/CD Quick Setup

#### GitHub Actions
```yaml
- name: Run OCaml Crypto Linter
  run: |
    opam install ocaml-crypto-linter
    ocaml-crypto-linter . -f sarif -o results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Common Patterns to Check

### 1. Cryptographic Library Usage
```ocaml
(* Check your imports *)
open Cryptokit
open Nocrypto
open Mirage_crypto

(* The linter automatically detects crypto library usage *)
```

### 2. Authentication Code
```ocaml
(* Vulnerable *)
let verify_mac data mac =
  mac = compute_mac data  (* Timing attack *)

(* Secure *)
let verify_mac data mac =
  Eqaf.equal mac (compute_mac data)
```

### 3. Encryption Patterns
```ocaml
(* Vulnerable *)
let encrypt key data =
  let cipher = Cipher.aes ~mode:ECB key in  (* ECB mode *)
  cipher#put_string data

(* Secure *)
let encrypt key data =
  let iv = Mirage_crypto_rng.generate 16 in
  let cipher = Cipher.aes ~mode:GCM ~iv key in
  cipher#put_string data
```

## What to Do with Findings

1. **Critical (Red)**: Fix immediately - security breach risk
2. **Error (Orange)**: Fix before release - known vulnerabilities
3. **Warning (Yellow)**: Review and plan fixes - best practice violations
4. **Info (Blue)**: Consider fixing - minor issues

## Next Steps

- [Configure the linter](configuration.md) for your project
- Learn about [all security rules](../rules/index.md)
- Set up [IDE integration](ide-integration.md)
- Add to your [CI/CD pipeline](ci-integration.md)

## Getting Help

```bash
# Show help
ocaml-crypto-linter --help

# List all rules
ocaml-crypto-linter --list-rules

# Show version
ocaml-crypto-linter --version
```