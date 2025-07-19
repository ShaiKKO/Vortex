# Configuration Guide

OCaml Crypto Linter can be configured through JSON files, command-line options, and environment variables.

## Configuration File

Create `.crypto-linter.json` in your project root:

```json
{
  "rules": {
    "ALGO001": "error",
    "ALGO002": "warning",
    "KEY001": "error",
    "SIDE001": "error",
    "API002": "off"
  },
  "exclude_paths": [
    "**/test/**",
    "**/vendor/**",
    "**/*_test.ml"
  ],
  "include_paths": [
    "src/**/*.ml",
    "lib/**/*.ml"
  ],
  "severity_threshold": "warning",
  "output_format": "json",
  "semgrep_enabled": false,
  "custom_rules_path": "./security-rules",
  "confidence_threshold": 0.8,
  "max_file_size": 1048576,
  "parallel_analysis": true,
  "context_aware": true
}
```

## Configuration Options

### Rule Configuration

#### `rules`
Configure individual rule severities.

**Values**: `"error"`, `"warning"`, `"info"`, `"off"`

```json
{
  "rules": {
    "ALGO001": "error",    // Treat as error
    "ALGO002": "warning",  // Treat as warning
    "KEY001": "error",     // Critical issue
    "API002": "off"        // Disable rule
  }
}
```

#### `rule_categories`
Enable/disable entire rule categories.

```json
{
  "rule_categories": {
    "ALGO": true,
    "KEY": true,
    "SIDE": true,
    "API": false,  // Disable all API rules
    "CRYPTO": true
  }
}
```

### Path Configuration

#### `exclude_paths`
Glob patterns for files to skip.

```json
{
  "exclude_paths": [
    "**/test/**",           // Skip test directories
    "**/vendor/**",         // Skip vendored code
    "**/*_test.ml",         // Skip test files
    "**/node_modules/**",   // Skip JS dependencies
    "**/.opam/**"          // Skip OPAM switches
  ]
}
```

#### `include_paths`
Glob patterns for files to analyze (overrides excludes).

```json
{
  "include_paths": [
    "src/**/*.ml",
    "lib/**/*.ml",
    "bin/*.ml"
  ]
}
```

### Analysis Options

#### `severity_threshold`
Minimum severity level to report.

**Values**: `"info"`, `"warning"`, `"error"`, `"critical"`

```json
{
  "severity_threshold": "warning"  // Only show warnings and above
}
```

#### `confidence_threshold`
Minimum confidence score for findings (0.0-1.0).

```json
{
  "confidence_threshold": 0.8  // High confidence only
}
```

#### `context_aware`
Enable context-aware analysis to reduce false positives.

```json
{
  "context_aware": true
}
```

#### `max_file_size`
Maximum file size to analyze (bytes).

```json
{
  "max_file_size": 1048576  // 1MB limit
}
```

### Output Options

#### `output_format`
Default output format.

**Values**: `"text"`, `"json"`, `"sarif"`

```json
{
  "output_format": "json"
}
```

#### `output_file`
Default output file path.

```json
{
  "output_file": "crypto-lint-report.json"
}
```

#### `verbose`
Enable verbose output.

```json
{
  "verbose": true
}
```

### Integration Options

#### `semgrep_enabled`
Enable Semgrep integration.

```json
{
  "semgrep_enabled": true,
  "semgrep_rules_path": "./semgrep-rules"
}
```

#### `custom_rules_path`
Directory containing custom rule definitions.

```json
{
  "custom_rules_path": "./security-rules"
}
```

## Environment Variables

Override configuration with environment variables:

```bash
# Configuration file path
export OCAML_CRYPTO_LINTER_CONFIG=/path/to/config.json

# Custom rules directory
export OCAML_CRYPTO_LINTER_RULES_PATH=/opt/custom-rules

# Output format
export OCAML_CRYPTO_LINTER_OUTPUT_FORMAT=sarif

# Parallel analysis threads
export OCAML_CRYPTO_LINTER_THREADS=8
```

## Per-Project Configuration

### Monorepo Setup

Create different configs for different parts:

`frontend/.crypto-linter.json`:
```json
{
  "rules": {
    "API006": "off"  // Frontend doesn't use TLS directly
  }
}
```

`backend/.crypto-linter.json`:
```json
{
  "rules": {
    "API006": "error",  // Backend must verify certificates
    "KEY001": "critical"
  }
}
```

### Library vs Application

Libraries might allow more flexibility:

```json
{
  "context": "library",
  "rules": {
    "ALGO002": "warning"  // Warn but don't error on MD5
  }
}
```

Applications should be stricter:

```json
{
  "context": "application",
  "rules": {
    "ALGO002": "error"  // No weak algorithms in production
  }
}
```

## Rule Customization

### Custom Rule Patterns

Add patterns to detect project-specific issues:

```json
{
  "custom_patterns": {
    "hardcoded_api_endpoints": {
      "pattern": "let.*api_url.*=.*\"https://\"",
      "message": "API endpoints should be configurable",
      "severity": "warning"
    }
  }
}
```

### Algorithm Whitelist

Allow specific algorithms in certain contexts:

```json
{
  "algorithm_whitelist": [
    {
      "algorithm": "md5",
      "allowed_for": ["caching", "non_cryptographic"],
      "require_comment": true
    }
  ]
}
```

## CI/CD Configuration

### GitHub Actions

`.github/workflows/crypto-lint.yml`:
```yaml
env:
  OCAML_CRYPTO_LINTER_CONFIG: .crypto-linter.ci.json
```

`.crypto-linter.ci.json`:
```json
{
  "severity_threshold": "error",
  "output_format": "sarif",
  "fail_on_error": true
}
```

### Pre-commit Hook

`.pre-commit-config.yaml`:
```yaml
repos:
  - repo: local
    hooks:
      - id: crypto-lint
        name: OCaml Crypto Linter
        entry: ocaml-crypto-linter
        language: system
        files: '\.ml$'
        args: ['-f', 'text']
```

## Examples

### Strict Security

```json
{
  "rules": {
    "ALGO001": "error",
    "ALGO002": "error",
    "KEY001": "error",
    "SIDE001": "error"
  },
  "severity_threshold": "warning",
  "confidence_threshold": 0.7,
  "context_aware": true,
  "fail_on_warning": true
}
```

### Development Mode

```json
{
  "rules": {
    "ALGO002": "warning",
    "KEY001": "warning"
  },
  "exclude_paths": [
    "**/test/**",
    "**/examples/**"
  ],
  "verbose": true
}
```

### Legacy Codebase

```json
{
  "rules": {
    "ALGO001": "warning",
    "ALGO002": "info",
    "ALGO006": "off"
  },
  "migration_mode": true,
  "show_migration_hints": true
}
```

## Configuration Validation

The linter validates configuration on startup:

```bash
# Validate configuration
ocaml-crypto-linter --validate-config

# Show effective configuration
ocaml-crypto-linter --show-config
```

## Best Practices

1. **Start Strict**: Begin with all rules as errors, then relax as needed
2. **Document Exceptions**: Comment why rules are disabled
3. **Review Regularly**: Security standards evolve
4. **Use Context**: Different configs for dev/staging/production
5. **Automate**: Integrate into CI/CD pipeline