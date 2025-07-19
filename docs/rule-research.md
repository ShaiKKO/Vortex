# Cryptographic Vulnerability Research - CVE Analysis

## Critical CVEs for Rule Development

### 1. Hash Collision Attacks
- **CVE-2017-15999 (SHAttered)**: SHA-1 collision attack
  - Rule: Detect SHA-1 usage in signatures/certificates
  - Pattern: `Hash.sha1`, `Nocrypto.Hash.SHA1`
  
- **CVE-2012-2459**: Bitcoin MD5 collision
  - Rule: Flag MD5 for any security purpose
  - Pattern: `Hash.md5`, `Digest.string`

### 2. Weak Cipher Vulnerabilities
- **CVE-2016-2183 (SWEET32)**: 3DES birthday attack
  - Rule: Block ciphers with 64-bit blocks
  - Pattern: `Cipher.des3`, `Cipher_block.DES3`
  
- **CVE-2013-2566 (RC4 NOMORE)**: RC4 biases
  - Rule: Prohibit RC4 stream cipher
  - Pattern: `Cipher.arcfour`, `RC4.create`

### 3. Nonce/IV Reuse
- **CVE-2016-0270**: AES-GCM nonce reuse in NSS
  - Rule: Track IV variables across encryption calls
  - Pattern: Same IV identifier in multiple `encrypt` calls
  
- **CVE-2018-16869**: Nettle GCM nonce reuse
  - Rule: Detect hardcoded/static IVs
  - Pattern: `let iv = "\x00\x00..."` 

### 4. RSA Key Size
- **CVE-2012-4929**: 512-bit RSA factorization
  - Rule: Minimum 2048-bit RSA keys
  - Pattern: `RSA.new_key ~size:1024`
  
- **CVE-2015-7181**: 768-bit RSA in NSS
  - Rule: Warn on keys < 2048 bits
  - Pattern: Key size parameters

### 5. Timing Attacks
- **CVE-2016-2107**: OpenSSL AES-NI timing
  - Rule: Non-constant time operations
  - Pattern: `String.equal` on secrets
  
- **CVE-2018-0737**: RSA key timing leak
  - Rule: Flag direct comparisons
  - Pattern: `if key = expected_key`

### 6. KDF Weaknesses
- **CVE-2013-1443**: PBKDF2 iteration bypass
  - Rule: Minimum 10,000 iterations
  - Pattern: `pbkdf2 ~count:1000`

### 7. Missing Authentication
- **CVE-2013-0169 (Lucky13)**: CBC padding oracle
  - Rule: Encryption without MAC
  - Pattern: CBC mode without HMAC

## Advanced Pattern Detection

### Dataflow Analysis Requirements
1. **Taint Tracking**: Follow key material from generation to use
2. **Alias Analysis**: Detect nonce reuse through aliasing
3. **Path Sensitivity**: Different security levels per branch
4. **Interprocedural**: Cross-function vulnerability detection

### Semgrep Rule Templates
```yaml
rules:
  - id: ocaml.crypto.sha1-signature
    pattern: |
      $HASH.sha1($DATA)
    message: "SHA-1 is broken for signatures (CVE-2017-15999)"
    
  - id: ocaml.crypto.static-iv
    patterns:
      - pattern: |
          let $IV = $STRING
          ...
          $CIPHER.encrypt ~iv:$IV
      - metavariable-regex:
          metavariable: $STRING
          regex: "^\".*\"$"
    message: "Static IV detected (CVE-2016-0270)"
```

## OCaml-Specific Vulnerabilities

### 1. Functorized Crypto Modules
- Incorrect functor application may bypass security
- Pattern: `module Weak = Cipher.Make(DES)`

### 2. Phantom Types Bypass
- Type-level security guarantees circumvented
- Pattern: `Obj.magic` on crypto types

### 3. First-Class Modules
- Dynamic cipher selection vulnerabilities
- Pattern: `(module C : CIPHER) = if weak then...`

### 4. Effect Handlers (5.0+)
- Side channels through effect timing
- Pattern: Crypto ops in effect handlers

## Implementation Priority Matrix

| Vulnerability | Severity | Prevalence | Implementation Effort | Priority |
|--------------|----------|------------|---------------------|----------|
| Hardcoded keys | CRITICAL | High | Low | P0 |
| Weak ciphers | HIGH | Medium | Low | P0 |
| SHA-1/MD5 | HIGH | High | Low | P0 |
| Nonce reuse | CRITICAL | Low | High | P1 |
| Small RSA keys | HIGH | Medium | Medium | P1 |
| Timing attacks | MEDIUM | Medium | High | P2 |
| Missing MAC | HIGH | Low | Medium | P2 |
| Weak KDF | MEDIUM | Low | Low | P3 |