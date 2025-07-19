# Frequently Asked Questions (FAQ)

## General Questions

### What is OCaml Crypto Linter?

OCaml Crypto Linter is a static analysis tool that detects cryptographic vulnerabilities in OCaml source code. It uses AST-based analysis to find issues like weak algorithms, hardcoded keys, timing attacks, and API misuse.

### Why do I need this tool?

Cryptographic code is notoriously difficult to get right. Even experienced developers can introduce vulnerabilities. This tool automates the detection of common crypto mistakes specific to OCaml's ecosystem.

### How is this different from general linters?

Unlike general linters that check style and common bugs, OCaml Crypto Linter specifically understands cryptographic APIs and security patterns. It knows about:
- OCaml crypto libraries (Cryptokit, Nocrypto, Mirage_crypto)
- Cryptographic best practices
- Known vulnerable patterns
- Context-aware analysis (test vs production code)

### Is it free to use?

Yes, OCaml Crypto Linter is open source under the MIT license.

## Installation Issues

### "ocaml-crypto-linter: command not found"

Make sure OPAM environment is set:
```bash
eval $(opam env)
```

Or add to your shell profile:
```bash
echo 'eval $(opam env)' >> ~/.bashrc  # or ~/.zshrc
```

### Build fails with "Package not found"

Update OPAM and repositories:
```bash
opam update
opam upgrade
opam install ocaml-crypto-linter
```

### "No switch is currently set"

Create an OCaml switch:
```bash
opam switch create 5.2.0
eval $(opam env)
```

### Docker image not found

The image name is case-sensitive:
```bash
# Correct
docker pull ghcr.io/shaikko/ocaml-crypto-linter:latest

# Incorrect
docker pull ghcr.io/ShaiKKO/ocaml-crypto-linter:latest
```

## Usage Questions

### How do I scan my entire project?

```bash
# From project root
ocaml-crypto-linter .

# Or specify directories
ocaml-crypto-linter src/ lib/ test/
```

### Can I exclude test files?

Yes, use configuration or command line:
```bash
# Command line
ocaml-crypto-linter src/ --exclude "*_test.ml"

# Config file
{
  "exclude_paths": ["**/test/**", "**/*_test.ml"]
}
```

### How do I get machine-readable output?

Use JSON or SARIF format:
```bash
# JSON
ocaml-crypto-linter src/ -f json -o report.json

# SARIF for GitHub
ocaml-crypto-linter src/ -f sarif -o results.sarif
```

### Can I disable specific rules?

Yes, in multiple ways:
```bash
# Command line
ocaml-crypto-linter --exclude-rules ALGO002,KEY001 src/

# Config file
{
  "rules": {
    "ALGO002": "off",
    "KEY001": "warning"
  }
}
```

## False Positives

### "It flags MD5 but I'm not using it for security"

The linter has context-aware rules. You can:

1. Add a comment to indicate non-security use:
```ocaml
(* Non-cryptographic use: cache key generation *)
let cache_key = Digest.string data
```

2. Configure the rule severity:
```json
{
  "rules": {
    "ALGO002": "info"  // Downgrade from error
  }
}
```

### "It complains about test code"

Test files can have relaxed rules:
```json
{
  "test_paths": ["**/test/**"],
  "test_rule_overrides": {
    "KEY001": "off"  // Allow hardcoded keys in tests
  }
}
```

### "Legacy code has many issues"

Use gradual enforcement:
```bash
# Phase 1: Only fail on critical
ocaml-crypto-linter --severity-threshold critical src/

# Phase 2: Include errors
ocaml-crypto-linter --severity-threshold error src/

# Phase 3: Full enforcement
ocaml-crypto-linter src/
```

## Performance

### Scanning is slow on large codebases

Try these optimizations:

1. Use OCaml 5.x for parallel analysis:
```bash
opam switch create 5.2.0
```

2. Limit scope:
```bash
# Scan only changed files
git diff --name-only | grep '\.ml$' | xargs ocaml-crypto-linter
```

3. Disable expensive checks:
```bash
ocaml-crypto-linter --no-interprocedural src/
```

### Out of memory errors

Limit file size or split analysis:
```json
{
  "max_file_size": 524288,  // 512KB
  "parallel_analysis": false
}
```

## Integration

### How do I integrate with VS Code?

1. Install OCaml Platform extension
2. Add to settings.json:
```json
{
  "ocaml.linters": ["ocaml-crypto-linter"]
}
```

### GitHub Actions not showing results

Make sure to:
1. Use SARIF format
2. Upload with correct action:
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit hooks?

Create `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: local
    hooks:
      - id: crypto-lint
        name: OCaml Crypto Linter
        entry: ocaml-crypto-linter
        language: system
        files: '\.ml$'
```

## Security Questions

### Is it safe to use in CI/CD?

Yes, the linter:
- Only reads files (no modifications)
- Doesn't send data anywhere
- Runs in isolated container if using Docker
- Open source for audit

### Can it detect all vulnerabilities?

No static analysis tool can detect all vulnerabilities. OCaml Crypto Linter detects:
- Known vulnerable patterns
- Common API misuse
- Weak algorithms

It cannot detect:
- Logic errors
- Novel attack vectors
- Runtime-only issues

### Should I rely only on this tool?

No, use defense in depth:
1. OCaml Crypto Linter for static analysis
2. Code reviews by security experts
3. Dynamic testing and fuzzing
4. Security audits for critical code
5. Runtime protections

## Advanced Usage

### How do I write custom rules?

See the [Writing Custom Rules](writing-rules.md) guide. Basic example:

```ocaml
let my_rule = {
  Rule.id = "CUSTOM001";
  name = "My Security Check";
  severity = Error;
  check = fun ast -> 
    (* Pattern matching logic *)
}
```

### Can I use Semgrep rules?

Yes, enable Semgrep integration:
```bash
# Install Semgrep
pip install semgrep

# Run with Semgrep
ocaml-crypto-linter --semgrep src/
```

### How do I contribute?

See [CONTRIBUTING.md](../../CONTRIBUTING.md). We welcome:
- New vulnerability rules
- Performance improvements
- Documentation updates
- Bug reports

## Troubleshooting

### Debug output?

Future versions will support:
```bash
ocaml-crypto-linter --verbose src/
ocaml-crypto-linter --debug src/
```

### Report bugs?

1. Check [existing issues](https://github.com/ShaiKKO/Vortex/issues)
2. Create minimal reproduction
3. Include:
   - OCaml version
   - Linter version
   - Error message
   - Code sample

### Get help?

- GitHub Issues for bugs
- GitHub Discussions for questions
- Stack Overflow tag: `ocaml-crypto-linter`

## Best Practices

### When should I run the linter?

1. **During development**: Pre-commit hooks
2. **In CI/CD**: On every PR
3. **Before release**: Full scan
4. **Periodically**: Weekly security scans

### What severity should fail builds?

Recommended thresholds:
- **Development**: Warnings and above
- **Staging**: Errors and above
- **Production**: Critical only (initially)

### How often to update?

- **Linter**: Monthly (new rules, fixes)
- **Rules**: When new vulnerabilities discovered
- **Configuration**: As codebase evolves

## Future Features

Planned improvements:
- IDE plugins (VS Code, Emacs)
- Real-time analysis
- Auto-fix suggestions
- Cross-language support
- AI-powered rule generation

## More Questions?

- Read the [documentation](../index.md)
- Ask on [GitHub Discussions](https://github.com/ShaiKKO/Vortex/discussions)
- Email: shaiiko@proton.me