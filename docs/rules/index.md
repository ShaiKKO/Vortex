# Security Rules Catalog

OCaml Crypto Linter implements 25 security rules across 5 categories to detect cryptographic vulnerabilities.

## Rule Categories

| Category | Prefix | Count | Focus Area |
|----------|--------|-------|------------|
| [Algorithm Weakness](algorithm-weakness.md) | ALGO | 6 | Weak ciphers, hashes, and protocols |
| [Key Management](key-management.md) | KEY | 6 | Key generation, storage, and usage |
| [Side Channel](side-channel.md) | SIDE | 5 | Timing attacks and information leaks |
| [API Misuse](api-misuse.md) | API | 7 | Incorrect cryptographic API usage |
| [General Crypto](general-crypto.md) | CRYPTO | 3 | Cross-cutting concerns |

## All Rules

### Critical Severity

These rules detect vulnerabilities that could lead to immediate compromise:

- **KEY001**: Hardcoded Cryptographic Key
- **KEY003**: AEAD Nonce Reuse
- **SIDE001**: Variable-Time String Comparison
- **API002**: CBC Without MAC

### High Severity

These rules detect known vulnerable patterns:

- **ALGO001**: Weak Cipher Algorithm (DES, RC4)
- **ALGO002**: Weak Hash Algorithm (MD5, SHA-1)
- **KEY002**: Predictable Key Generation
- **API001**: ECB Mode Usage

### Medium Severity

These rules detect potentially vulnerable patterns:

- **ALGO003**: Insecure Elliptic Curve
- **KEY004**: Static IV in Block Cipher
- **SIDE002**: Non-Constant Time Modular Exponentiation
- **API003**: Improper IV Generation

### Low Severity

These rules detect best practice violations:

- **ALGO006**: Legacy SSL/TLS Version
- **KEY006**: Plaintext Key Storage
- **API007**: Missing CTR Mode Nonce Increment

## Quick Reference

| Rule ID | Name | Severity | Example |
|---------|------|----------|---------|
| ALGO001 | Weak Cipher Algorithm | High | `Cipher.des`, `Cipher.arcfour` |
| ALGO002 | Weak Hash Algorithm | High | `Digest.string` (MD5), `Hash.sha1` |
| ALGO003 | Insecure Elliptic Curve | Medium | `Ec.P192`, `secp224r1` |
| ALGO004 | Small Block Size Cipher | Medium | 64-bit block ciphers |
| ALGO005 | Weak Key Exchange | Medium | DH < 2048 bits |
| ALGO006 | Legacy SSL/TLS | Low | `Ssl.TLSv1`, `Ssl.SSLv3` |
| KEY001 | Hardcoded Key | Critical | `let key = "secret123"` |
| KEY002 | Predictable Key | High | `Random.int` for keys |
| KEY003 | AEAD Nonce Reuse | Critical | Fixed nonce with GCM |
| KEY004 | Static IV | Medium | `String.make 16 '\000'` |
| KEY005 | Weak KDF | Medium | PBKDF2 < 10000 iterations |
| KEY006 | Plaintext Key Storage | Low | Keys in files |
| SIDE001 | Timing Attack | Critical | `if password = input` |
| SIDE002 | Variable Exponentiation | High | Non-constant RSA |
| SIDE003 | Cache Timing | Medium | Table lookups |
| SIDE004 | Branch Leak | Medium | `if secret then` |
| SIDE005 | Power Analysis | Low | Vulnerable operations |
| API001 | ECB Mode | High | `~mode:ECB` |
| API002 | CBC No MAC | Critical | CBC without HMAC |
| API003 | Bad IV Generation | Medium | Predictable IVs |
| API004 | No Padding Check | High | Missing validation |
| API005 | Bad Random | Medium | `Random.self_init` |
| API006 | No Cert Verify | High | TLS without checks |
| API007 | CTR Nonce Issue | Low | Counter problems |

## Understanding Severity Levels

### Critical 🔴
Immediate security risk. Fix before deployment.
- Direct key exposure
- Authentication bypass
- Timing attack vulnerabilities

### High 🟠
Known vulnerabilities. Fix in current release.
- Broken algorithms
- Weak randomness
- Missing security checks

### Medium 🟡
Potential vulnerabilities. Plan fixes.
- Outdated algorithms
- Configuration issues
- Best practice violations

### Low 🔵
Minor issues. Consider fixing.
- Legacy compatibility
- Performance vs security tradeoffs
- Documentation issues

## Customizing Rules

### Disable Specific Rules

In `.crypto-linter.json`:
```json
{
  "rules": {
    "ALGO002": "off",
    "KEY001": "error",
    "SIDE001": "warning"
  }
}
```

### Command Line
```bash
# Exclude rules
ocaml-crypto-linter --exclude-rules ALGO002,API006 src/

# Run only specific categories
ocaml-crypto-linter --rules KEY,SIDE src/
```

## Rule Implementation

Each rule includes:
- **Pattern Matching**: AST patterns to detect
- **Context Analysis**: Understanding surrounding code
- **Severity Assessment**: Based on exploitability
- **Fix Suggestions**: Secure alternatives
- **References**: CVEs and security papers

## Contributing New Rules

See [Writing Custom Rules](../guides/writing-rules.md) to add new security checks.

Basic template:
```ocaml
let rule_custom = {
  Rule.id = "CUSTOM001";
  name = "My Security Check";
  severity = Error;
  check = fun ast ->
    (* Pattern matching logic *)
}
```