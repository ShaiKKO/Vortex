# CLI Reference

Complete command-line interface documentation for OCaml Crypto Linter.

## Synopsis

```bash
ocaml-crypto-linter [OPTIONS] FILE...
```

## Description

OCaml Crypto Linter is a static analysis tool that detects cryptographic vulnerabilities in OCaml source code. It performs AST-based analysis to identify weak algorithms, key management issues, timing attacks, and API misuse.

## Arguments

### FILE...
One or more OCaml source files to analyze. Supports glob patterns.

Examples:
```bash
ocaml-crypto-linter src/crypto.ml
ocaml-crypto-linter src/**/*.ml
ocaml-crypto-linter *.ml lib/*.ml
```

## Options

### Output Options

#### `-f, --format FORMAT`
Output format for the analysis results.

- **Values**: `text` (default), `json`, `sarif`
- **Example**: `-f json`

```bash
# Human-readable text output (default)
ocaml-crypto-linter src/ -f text

# Machine-readable JSON
ocaml-crypto-linter src/ -f json

# SARIF for GitHub/IDE integration
ocaml-crypto-linter src/ -f sarif
```

#### `-o, --output FILE`
Write output to a file instead of stdout.

- **Example**: `-o report.json`

```bash
ocaml-crypto-linter src/ -f json -o report.json
ocaml-crypto-linter src/ -f sarif -o results.sarif
```

### Analysis Options

#### `--semgrep`
Enable Semgrep integration for additional pattern-based checks.

- **Requires**: Semgrep to be installed (`pip install semgrep`)
- **Example**: `--semgrep`

```bash
ocaml-crypto-linter --semgrep src/
```

#### `--rules CATEGORIES`
Run only specific rule categories (comma-separated).

- **Values**: `ALGO`, `KEY`, `SIDE`, `API`, `CRYPTO`
- **Example**: `--rules KEY,SIDE`

```bash
# Only key management and side-channel rules
ocaml-crypto-linter --rules KEY,SIDE src/

# Only algorithm weakness checks
ocaml-crypto-linter --rules ALGO src/
```

#### `--exclude-rules RULE_IDS`
Exclude specific rules from analysis (comma-separated).

- **Example**: `--exclude-rules ALGO002,KEY001`

```bash
# Skip MD5 and hardcoded key checks
ocaml-crypto-linter --exclude-rules ALGO002,KEY001 src/
```

### Information Options

#### `--version`
Display version information.

```bash
ocaml-crypto-linter --version
# Output: ocaml-crypto-linter version 0.1.0
```

#### `--help`
Show help message with all available options.

```bash
ocaml-crypto-linter --help
```

#### `--list-rules`
List all available security rules with descriptions.

```bash
ocaml-crypto-linter --list-rules

# Output:
# ALGO001: Weak Cipher Algorithm - Detects DES, 3DES, RC4
# ALGO002: Weak Hash Algorithm - Detects MD5, SHA-1
# KEY001: Hardcoded Cryptographic Key
# ...
```

## Exit Codes

- **0**: Success, no vulnerabilities found
- **1**: Vulnerabilities detected
- **2**: Error during analysis (e.g., syntax errors)
- **3**: Invalid command-line arguments

## Environment Variables

### `OCAML_CRYPTO_LINTER_CONFIG`
Path to configuration file (default: `.crypto-linter.json`)

```bash
export OCAML_CRYPTO_LINTER_CONFIG=/path/to/config.json
ocaml-crypto-linter src/
```

### `OCAML_CRYPTO_LINTER_RULES_PATH`
Additional directory for custom rules

```bash
export OCAML_CRYPTO_LINTER_RULES_PATH=/opt/custom-rules
ocaml-crypto-linter src/
```

## Examples

### Basic Analysis
```bash
# Analyze single file
ocaml-crypto-linter crypto.ml

# Analyze directory
ocaml-crypto-linter src/

# Analyze with globs
ocaml-crypto-linter "src/**/*.ml" "lib/**/*.ml"
```

### Generate Reports
```bash
# JSON report for processing
ocaml-crypto-linter src/ -f json -o report.json

# SARIF for GitHub Actions
ocaml-crypto-linter . -f sarif -o results.sarif

# Human-readable to file
ocaml-crypto-linter src/ -o findings.txt
```

### Selective Analysis
```bash
# Only timing attacks
ocaml-crypto-linter --rules SIDE src/

# Skip test files
ocaml-crypto-linter src/ --exclude "*_test.ml"

# Exclude specific rules
ocaml-crypto-linter --exclude-rules API001,KEY004 src/
```

### CI/CD Integration
```bash
# GitHub Actions with SARIF
ocaml-crypto-linter . -f sarif -o results.sarif || exit 0

# Fail on critical issues only
ocaml-crypto-linter src/ | grep -q "CRITICAL" && exit 1 || exit 0

# Generate JSON for further processing
ocaml-crypto-linter src/ -f json | jq '.summary.critical'
```

### Docker Usage
```bash
# Analyze current directory
docker run -v $(pwd):/workspace \
  ghcr.io/shaikko/ocaml-crypto-linter /workspace

# With options
docker run -v $(pwd):/workspace \
  ghcr.io/shaikko/ocaml-crypto-linter \
  /workspace -f json -o /workspace/report.json
```

## Configuration File

Create `.crypto-linter.json` in your project root:

```json
{
  "rules": {
    "ALGO001": "error",
    "ALGO002": "warning",
    "KEY001": "error"
  },
  "exclude_paths": [
    "**/test/**",
    "**/vendor/**"
  ],
  "custom_rules_path": "./security-rules",
  "output_format": "json",
  "semgrep_enabled": true
}
```

## Performance Considerations

- Use `--rules` to limit analysis scope for faster runs
- Parallel analysis is automatic with OCaml 5.x
- Large codebases: consider analyzing by module

```bash
# Analyze in batches for large projects
find src -name "*.ml" | xargs -n 50 ocaml-crypto-linter
```

## Troubleshooting

### No output
```bash
# Enable verbose mode (if available in future versions)
ocaml-crypto-linter --verbose src/

# Check file patterns
ls src/**/*.ml  # Verify files exist
```

### Syntax errors
```bash
# The linter will report files it couldn't parse
# Output: Error parsing src/bad.ml: Syntax error
```

### Performance issues
```bash
# Limit scope
ocaml-crypto-linter --rules KEY src/

# Process fewer files at once
find . -name "*.ml" -print0 | xargs -0 -n 10 ocaml-crypto-linter
```