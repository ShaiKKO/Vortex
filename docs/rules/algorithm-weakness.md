# Algorithm Weakness Rules (ALGO)

These rules detect the use of cryptographically weak or broken algorithms that should not be used in production code.

## ALGO001: Weak Cipher Algorithm

**Severity**: High 🟠

Detects weak or broken encryption algorithms.

### Detected Patterns
- DES (Data Encryption Standard) - 56-bit key
- 3DES/Triple-DES - vulnerable to meet-in-the-middle
- RC4/ARC4 - biased output
- Blowfish - 64-bit block size

### Example Violations
```ocaml
(* Cryptokit *)
let cipher = Cryptokit.Cipher.des key          (* DES *)
let cipher = Cryptokit.Cipher.arcfour key      (* RC4 *)
let cipher = Cryptokit.Cipher.blowfish key     (* Blowfish *)

(* Nocrypto *)
let cipher = Nocrypto.Cipher_block.DES.of_secret key
```

### Secure Alternatives
```ocaml
(* Use AES with 256-bit keys *)
let cipher = Cryptokit.Cipher.aes ~pad:Cryptokit.Padding.length key

(* Use ChaCha20-Poly1305 *)
let cipher = Mirage_crypto.Chacha20.of_secret key

(* Use AES-GCM for authenticated encryption *)
let cipher = Cryptokit.AEAD.aes_gcm ~key
```

### References
- [CVE-2016-2183](https://nvd.nist.gov/vuln/detail/CVE-2016-2183) (SWEET32)
- [RFC 7465](https://datatracker.ietf.org/doc/html/rfc7465) (Prohibiting RC4)

---

## ALGO002: Weak Hash Algorithm

**Severity**: High 🟠

Detects cryptographically broken hash functions.

### Detected Patterns
- MD5 - collision vulnerabilities
- SHA-1 - collision attacks (SHAttered)
- MD4 - completely broken
- MD2 - vulnerable to preimage attacks

### Example Violations
```ocaml
(* OCaml Digest module uses MD5 *)
let hash = Digest.string data
let hash = Digest.file filename

(* Cryptokit *)
let hash = Cryptokit.Hash.md5 ()
let hash = Cryptokit.Hash.sha1 ()

(* Nocrypto *)
let hash = Nocrypto.Hash.MD5.digest
let hash = Nocrypto.Hash.SHA1.digest
```

### Secure Alternatives
```ocaml
(* SHA-256 *)
let hash = Cryptokit.Hash.sha256 ()
let digest = hash#add_string data; hash#result

(* SHA-3 *)
let hash = Cryptokit.Hash.sha3 256

(* BLAKE2b *)
let hash = Mirage_crypto.Hash.BLAKE2B.digest

(* For non-cryptographic use *)
let hash = Hashtbl.hash data  (* explicitly non-crypto *)
```

### Context-Aware Detection
The rule considers context to reduce false positives:
- Allows MD5/SHA-1 for non-security purposes (checksums, caching)
- Flags when used with passwords, tokens, or signatures

### References
- [CVE-2017-15999](https://shattered.io/) (SHA-1 collision)
- [CVE-2004-2761](https://www.kb.cert.org/vuls/id/836068) (MD5 collision)

---

## ALGO003: Insecure Elliptic Curve

**Severity**: Medium 🟡

Detects weak elliptic curves vulnerable to attacks.

### Detected Patterns
- Curves with <256-bit security
- Non-SafeCurves compliant curves
- Weak named curves: P-192, P-224, secp192r1, secp224r1
- Brainpool curves <256 bits

### Example Violations
```ocaml
(* Nocrypto *)
let key = Nocrypto.Ec.P192.generate ()
let key = Nocrypto.Ec.P224.generate ()

(* Mirage_crypto *)
let curve = Mirage_crypto_ec.P192
let curve = Mirage_crypto_ec.Secp192r1
```

### Secure Alternatives
```ocaml
(* Use P-256 or stronger *)
let key = Nocrypto.Ec.P256.generate ()
let key = Nocrypto.Ec.P384.generate ()
let key = Nocrypto.Ec.P521.generate ()

(* Use Curve25519 for ECDH *)
let key = Mirage_crypto_ec.X25519.generate ()

(* Use Ed25519 for signatures *)
let key = Mirage_crypto_ec.Ed25519.generate ()
```

### References
- [SafeCurves](https://safecurves.cr.yp.to/) criteria
- NIST SP 800-57 recommendations

---

## ALGO004: Small Block Size Cipher

**Severity**: Medium 🟡

Detects ciphers with 64-bit blocks vulnerable to birthday attacks.

### Detected Patterns
- DES (64-bit blocks)
- 3DES (64-bit blocks)
- Blowfish (64-bit blocks)
- CAST5 (64-bit blocks)

### Example Violations
```ocaml
let cipher = Cryptokit.Cipher.des key        (* 64-bit blocks *)
let cipher = Cryptokit.Cipher.triple_des key (* 64-bit blocks *)
let cipher = Cryptokit.Cipher.blowfish key   (* 64-bit blocks *)
```

### Why It Matters
With 64-bit blocks, after encrypting ~32GB of data:
- 50% chance of block collision
- Enables SWEET32 attack
- Leaks plaintext information

### Secure Alternatives
```ocaml
(* Use 128-bit block ciphers *)
let cipher = Cryptokit.Cipher.aes key      (* 128-bit blocks *)
let cipher = Mirage_crypto.AES.of_secret key

(* Or use stream ciphers *)
let cipher = Mirage_crypto.Chacha20.of_secret key
```

### References
- [SWEET32 Attack](https://sweet32.info/)
- CVE-2016-2183

---

## ALGO005: Weak Key Exchange Parameters

**Severity**: Medium 🟡

Detects weak parameters in key exchange algorithms.

### Detected Patterns
- RSA keys <2048 bits
- DH parameters <2048 bits
- DSA keys <2048 bits
- ECDH with weak curves

### Example Violations
```ocaml
(* Weak RSA key *)
let key = Nocrypto.Rsa.generate ~bits:1024

(* Weak DH parameters *)
let params = Cryptokit.DH.generate_parameters ~bits:1024

(* Small DSA key *)
let key = Cryptokit.DSA.generate_key ~bits:1024
```

### Secure Alternatives
```ocaml
(* RSA: Use 2048 bits minimum, 3072 recommended *)
let key = Nocrypto.Rsa.generate ~bits:3072

(* DH: Use 2048 bits minimum *)
let params = Cryptokit.DH.generate_parameters ~bits:2048

(* ECDH: Use P-256 or Curve25519 *)
let key = Mirage_crypto_ec.X25519.generate ()
```

### References
- NIST SP 800-57 Part 1
- [Logjam Attack](https://weakdh.org/)

---

## ALGO006: Legacy SSL/TLS Version

**Severity**: Low 🔵

Detects use of deprecated SSL/TLS protocol versions.

### Detected Patterns
- SSLv2 - completely broken
- SSLv3 - POODLE attack
- TLS 1.0 - BEAST, Lucky13
- TLS 1.1 - deprecated

### Example Violations
```ocaml
(* Conduit/Lwt_ssl *)
let config = Ssl.{
  protocol = Ssl.SSLv3;  (* Vulnerable *)
  (* ... *)
}

(* Explicit version setting *)
Ssl.set_protocol ctx Ssl.TLSv1  (* Deprecated *)
```

### Secure Alternatives
```ocaml
(* Use TLS 1.2 minimum *)
let config = Ssl.{
  protocol = Ssl.TLSv1_2;
  (* ... *)
}

(* Prefer TLS 1.3 when available *)
let config = Ssl.{
  protocol = Ssl.TLSv1_3;
  (* ... *)
}

(* Let library choose secure defaults *)
let config = Ssl.default_configuration ()
```

### References
- [RFC 8996](https://datatracker.ietf.org/doc/html/rfc8996) (Deprecating TLS 1.0/1.1)
- [POODLE Attack](https://en.wikipedia.org/wiki/POODLE)

---

## Configuration

Control algorithm rules in `.crypto-linter.json`:

```json
{
  "rules": {
    "ALGO001": "error",
    "ALGO002": "warning",
    "ALGO003": "warning",
    "ALGO004": "info",
    "ALGO005": "warning",
    "ALGO006": "info"
  },
  "algorithm_whitelist": [
    "md5_for_cache",
    "sha1_git_compat"
  ]
}
```

## Best Practices

1. **Stay Updated**: Cryptographic recommendations change over time
2. **Use High-Level APIs**: Prefer authenticated encryption (AEAD)
3. **Follow Standards**: NIST, ENISA, or industry guidelines
4. **Plan Migration**: Have a crypto-agility strategy
5. **Document Exceptions**: If you must use weak algorithms, document why