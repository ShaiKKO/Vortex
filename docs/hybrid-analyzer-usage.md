# Hybrid Analyzer Usage Guide

## Overview

The OCaml Crypto Linter hybrid analyzer combines pure OCaml performance with optional Semgrep integration for comprehensive cryptographic vulnerability detection.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Hybrid Analyzer                      │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─────────────┐    ┌──────────────┐              │
│  │   Import    │───▶│    Mode      │              │
│  │  Tracker    │    │   Manager    │              │
│  └─────────────┘    └──────────────┘              │
│         │                    │                      │
│         ▼                    ▼                      │
│  ┌─────────────────────────────────┐               │
│  │    Parallel Analysis Engine     │               │
│  ├─────────────────────────────────┤               │
│  │ • Pure OCaml Rules (Fast Path)  │               │
│  │ • Semgrep Bridge (Complex)      │               │
│  │ • Context Manager (Inter-module)│               │
│  └─────────────────────────────────┘               │
│                     │                               │
│                     ▼                               │
│            ┌────────────────┐                      │
│            │ Result Merger  │                      │
│            └────────────────┘                      │
└─────────────────────────────────────────────────────┘
```

## Features

### 1. Import Detection & Mode Switching
- Automatically detects crypto libraries (Cryptokit, Nocrypto, Mirage_crypto, etc.)
- Activates specialized rules based on detected libraries
- Supports custom crypto library patterns

### 2. Parallel Analysis with Multicore OCaml
- Work-stealing algorithm for load balancing
- Incremental analysis with caching
- Memory-mapped file processing for large codebases
- Priority-based scheduling (crypto files first)

### 3. Context-Sensitive Analysis
- Inter-module crypto flow tracking
- Functor-aware analysis
- First-class module support
- Taint propagation across module boundaries

### 4. Semgrep Integration
- Optional complex pattern matching
- Dependency vulnerability scanning
- CVE database integration

## Usage

### Command Line

```bash
# Basic analysis (auto-detects mode)
ocaml-crypto-linter src/

# Force pure OCaml mode (fastest)
ocaml-crypto-linter --mode pure src/

# Hybrid mode with parallel processing
ocaml-crypto-linter --mode hybrid --parallel src/

# Full Semgrep integration
ocaml-crypto-linter --mode semgrep --check-deps src/
```

### Dune Integration

Add to your `dune` file:
```dune
(crypto-linter)
```

Or with configuration:
```dune
(crypto-linter
 (enabled true)
 (fail_on_error true)
 (parallel true))
```

### Configuration File

Create `.crypto-linter.json` in your project root:
```json
{
  "enabled": true,
  "fail_on_error": false,
  "parallel": true,
  "custom_rules": ["project-specific-rule"],
  "excluded_paths": ["_build", "test", "bench"]
}
```

## Analysis Modes

### Pure OCaml Mode
- Fastest analysis using only AST traversal
- No external dependencies
- Best for CI/CD pipelines

### Hybrid Mode (Default)
- Combines OCaml analysis with optional Semgrep
- Activates based on detected crypto libraries
- Balanced performance and coverage

### Semgrep-Only Mode
- Maximum pattern matching capability
- Slower but more comprehensive
- Best for security audits

## Detected Patterns

### Import-Based Activation
```ocaml
(* Triggers Cryptokit-specific rules *)
open Cryptokit
open Cryptokit.Cipher

(* Triggers Nocrypto rules *)
open Nocrypto
module R = Nocrypto.Rsa

(* Triggers Mirage-crypto rules *)
open Mirage_crypto
open Mirage_crypto.AES
```

### Inter-Module Analysis
```ocaml
(* Module A *)
module A = struct
  let key = Cryptokit.Random.string 32
end

(* Module B - detects cross-module key usage *)
module B = struct
  let encrypt data = 
    Cryptokit.Cipher.aes ~key:A.key data
end
```

### Functor Analysis
```ocaml
module Make_cipher (C : CIPHER) = struct
  let secure_encrypt key data =
    (* Analyzes functor parameter usage *)
    C.encrypt ~key data
end
```

## Performance

### Benchmarks (1000 files)
- Pure OCaml: ~10 seconds
- Hybrid: ~15 seconds
- Semgrep-only: ~45 seconds

### Optimization Tips
1. Use `.crypto-linter.json` to exclude non-critical paths
2. Enable incremental analysis for large repos
3. Use parallel mode on multicore systems
4. Configure custom rules for project-specific patterns

## Dependency Vulnerability Scanning

The analyzer automatically checks for known CVEs in crypto dependencies:

```bash
# Check project dependencies
ocaml-crypto-linter --check-deps .

# Output includes:
# - Cryptokit < 1.16.1: CVE-2022-24793
# - SSL < 0.5.9: CVE-2020-12802
# - Deprecated libraries (nocrypto)
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Crypto Security Check
  run: |
    opam install ocaml-crypto-linter
    ocaml-crypto-linter --mode hybrid --fail-on-error src/
```

### Dune Build
```bash
# Run during build
dune build @crypto-lint

# Fail build on errors
dune build @crypto-check
```

## Advanced Features

### Custom Import Patterns
```ocaml
let ctx = Import_tracker.create_context () in
Import_tracker.add_custom_pattern ctx "Company.Crypto" "internal-crypto";
```

### Work-Stealing Parallelism
- Automatic load balancing across CPU cores
- Handles uneven file sizes efficiently
- Minimal synchronization overhead

### Incremental Analysis
- Caches results based on file modification time
- Skips unchanged files automatically
- Persistent cache across runs

## Troubleshooting

### Import Not Detected
- Check if crypto library is in the supported list
- Add custom patterns for proprietary libraries
- Ensure proper module aliasing

### Performance Issues
- Enable parallel mode
- Exclude test/benchmark directories
- Use pure OCaml mode for faster CI

### False Positives
- Configure severity levels
- Add project-specific exclusions
- Submit issues for rule improvements