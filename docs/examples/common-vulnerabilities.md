# Common Vulnerabilities Examples

This document shows real examples of cryptographic vulnerabilities that OCaml Crypto Linter detects.

## Hardcoded Secrets (KEY001)

### ❌ Vulnerable Code

```ocaml
(* Direct hardcoded key *)
let secret_key = "my_super_secret_key_123"
let encrypted = Cryptokit.Cipher.aes secret_key

(* Hardcoded in record *)
let config = {
  api_key = "sk_live_4242424242424242";
  endpoint = "https://api.example.com";
}

(* Base64 encoded but still hardcoded *)
let encoded_key = "bXlfc2VjcmV0X2tleQ=="
let key = Base64.decode encoded_key
```

### ✅ Secure Alternative

```ocaml
(* Read from environment *)
let secret_key = Sys.getenv "ENCRYPTION_KEY"
let encrypted = Cryptokit.Cipher.aes secret_key

(* Use secure configuration *)
let config = {
  api_key = Config.get_required "API_KEY";
  endpoint = Config.get_string ~default:"https://api.example.com" "API_ENDPOINT";
}

(* Key derivation from password *)
let key = Cryptokit.Password.derive_key 
  ~password:(read_password ())
  ~salt:(Cryptokit.Random.string 16)
  ~iterations:100000
```

## Weak Algorithms (ALGO001, ALGO002)

### ❌ Vulnerable Code

```ocaml
(* Weak ciphers *)
let cipher = Cryptokit.Cipher.des key              (* 56-bit DES *)
let cipher = Cryptokit.Cipher.arcfour key          (* RC4 stream cipher *)
let cipher = Cryptokit.Cipher.blowfish key         (* 64-bit blocks *)

(* Weak hashes *)
let hash = Digest.string data                      (* MD5 *)
let hash = Cryptokit.Hash.md5 ()                   (* MD5 *)
let hash = Cryptokit.Hash.sha1 ()                  (* SHA-1 *)

(* Weak curves *)
let key = Nocrypto.Ec.P192.generate ()             (* 192-bit curve *)
```

### ✅ Secure Alternative

```ocaml
(* Strong ciphers *)
let cipher = Cryptokit.Cipher.aes ~pad:Cryptokit.Padding.length key  (* AES-256 *)
let cipher = Mirage_crypto.Chacha20.of_secret key                    (* ChaCha20 *)

(* Strong hashes *)
let hash = Cryptokit.Hash.sha256 ()                (* SHA-256 *)
let hash = Cryptokit.Hash.sha3 256                 (* SHA3-256 *)
let hash = Mirage_crypto.Hash.SHA512.digest        (* SHA-512 *)

(* Strong curves *)
let key = Nocrypto.Ec.P256.generate ()             (* P-256 *)
let key = Mirage_crypto_ec.Ed25519.generate ()     (* Ed25519 *)
```

## Timing Attacks (SIDE001)

### ❌ Vulnerable Code

```ocaml
(* String comparison timing leak *)
let verify_password input stored =
  input = stored  (* Leaks length and content via timing *)

(* MAC verification timing leak *)
let verify_mac data mac =
  let computed = compute_mac data in
  computed = mac  (* Early exit on first difference *)

(* Token comparison *)
let is_valid_token token =
  token = expected_token
```

### ✅ Secure Alternative

```ocaml
(* Constant-time comparison *)
let verify_password input stored =
  Eqaf.equal input stored

(* Constant-time MAC verification *)
let verify_mac data mac =
  let computed = compute_mac data in
  Eqaf.equal computed mac

(* Using cryptokit's built-in *)
let is_valid_token token =
  Cryptokit.Timing_safe.compare token expected_token = 0
```

## ECB Mode Usage (API001)

### ❌ Vulnerable Code

```ocaml
(* ECB mode - never use! *)
let cipher = Cryptokit.Cipher.aes ~mode:ECB key
let encrypted = cipher#put_string plaintext

(* Even with padding *)
let cipher = Cryptokit.Cipher.aes ~mode:ECB ~pad:PKCS7 key
```

### ✅ Secure Alternative

```ocaml
(* Use CBC with random IV *)
let iv = Cryptokit.Random.string 16
let cipher = Cryptokit.Cipher.aes ~mode:CBC ~iv key
let encrypted = iv ^ cipher#put_string plaintext

(* Better: Use authenticated encryption *)
let encrypt_aead key plaintext =
  let nonce = Mirage_crypto_rng.generate 12 in
  let cipher = Mirage_crypto.AES.GCM.of_secret key in
  let ciphertext = Mirage_crypto.AES.GCM.encrypt ~nonce cipher plaintext in
  (nonce, ciphertext)
```

## Predictable Randomness (KEY002, API005)

### ❌ Vulnerable Code

```ocaml
(* Predictable seed *)
Random.init 42
let key = Random.string 32

(* Time-based seed *)
Random.init (int_of_float (Unix.time ()))

(* Weak self-init *)
Random.self_init ()  (* Uses /dev/urandom, not crypto-safe *)
let iv = Bytes.create 16
Random.fill_bytes iv

(* Sequential nonces *)
let nonce = ref 0
let get_nonce () = incr nonce; string_of_int !nonce
```

### ✅ Secure Alternative

```ocaml
(* Cryptographically secure random *)
let key = Cryptokit.Random.string 32
let iv = Mirage_crypto_rng.generate 16

(* Secure nonce generation *)
let generate_nonce () =
  Mirage_crypto_rng.generate 12  (* For GCM *)

(* Initialize RNG properly *)
let () = Mirage_crypto_rng_unix.initialize ()
```

## Static IV/Nonce (KEY003, KEY004)

### ❌ Vulnerable Code

```ocaml
(* Zero IV *)
let iv = String.make 16 '\000'
let cipher = Cryptokit.Cipher.aes ~mode:CBC ~iv key

(* Hardcoded IV *)
let iv = "1234567890123456"

(* Reused nonce in AEAD *)
let nonce = "constant_nonce_bad"
let encrypt data =
  Aead.encrypt ~nonce ~key data  (* Same nonce every time! *)
```

### ✅ Secure Alternative

```ocaml
(* Random IV for each encryption *)
let encrypt_cbc key plaintext =
  let iv = Cryptokit.Random.string 16 in
  let cipher = Cryptokit.Cipher.aes ~mode:CBC ~iv key in
  let ciphertext = cipher#put_string plaintext in
  (iv, ciphertext)  (* Return IV with ciphertext *)

(* Unique nonce for AEAD *)
let counter = ref 0L
let encrypt_gcm key plaintext =
  let nonce = 
    let n = !counter in
    counter := Int64.succ n;
    Bytes.create 12 |> fun b ->
    Bytes.set_int64_be b 4 n; b
  in
  Aead.encrypt ~nonce ~key plaintext
```

## Missing Authentication (API002)

### ❌ Vulnerable Code

```ocaml
(* CBC without MAC - padding oracle vulnerable *)
let decrypt_cbc key iv ciphertext =
  let cipher = Cryptokit.Cipher.aes ~mode:CBC ~iv key in
  cipher#get_string (cipher#put_string ciphertext)

(* Encrypt-then-MAC but no verification *)
let decrypt data =
  let ciphertext = String.sub data 0 (String.length data - 32) in
  let mac = String.sub data (String.length data - 32) 32 in
  decrypt_cbc key iv ciphertext  (* Forgot to verify MAC! *)
```

### ✅ Secure Alternative

```ocaml
(* Encrypt-then-MAC *)
let encrypt_authenticated key plaintext =
  let iv = Cryptokit.Random.string 16 in
  let cipher = Cryptokit.Cipher.aes ~mode:CBC ~iv key in
  let ciphertext = cipher#put_string plaintext in
  let mac = Cryptokit.MAC.hmac_sha256 key (iv ^ ciphertext) in
  iv ^ ciphertext ^ mac

let decrypt_authenticated key data =
  let iv = String.sub data 0 16 in
  let ciphertext_mac = String.sub data 16 (String.length data - 16) in
  let ciphertext_len = String.length ciphertext_mac - 32 in
  let ciphertext = String.sub ciphertext_mac 0 ciphertext_len in
  let mac = String.sub ciphertext_mac ciphertext_len 32 in
  let expected_mac = Cryptokit.MAC.hmac_sha256 key (iv ^ ciphertext) in
  if not (Eqaf.equal mac expected_mac) then
    failwith "MAC verification failed";
  let cipher = Cryptokit.Cipher.aes ~mode:CBC ~iv key in
  cipher#get_string (cipher#put_string ciphertext)

(* Better: Use AEAD *)
let encrypt_gcm key plaintext =
  let open Mirage_crypto.AES.GCM in
  let nonce = Mirage_crypto_rng.generate 12 in
  let cipher = of_secret key in
  let ciphertext = encrypt ~nonce cipher plaintext in
  (nonce, ciphertext)
```

## Weak Key Derivation (KEY005)

### ❌ Vulnerable Code

```ocaml
(* Too few iterations *)
let key = Cryptokit.Password.pbkdf2 
  ~password 
  ~salt 
  ~iterations:1000  (* Way too low! *)

(* Simple hash of password *)
let key = Cryptokit.Hash.sha256#hash_string password

(* No salt *)
let key = derive_key password ""
```

### ✅ Secure Alternative

```ocaml
(* PBKDF2 with proper iterations *)
let derive_key_pbkdf2 password =
  let salt = Cryptokit.Random.string 16 in
  let key = Cryptokit.Password.pbkdf2
    ~password
    ~salt
    ~iterations:100_000  (* NIST minimum *)
    ~length:32
  in
  (salt, key)

(* Argon2 (if available) *)
let derive_key_argon2 password =
  let salt = Cryptokit.Random.string 16 in
  Argon2.hash
    ~pwd:password
    ~salt
    ~m_cost:65536   (* 64MB *)
    ~t_cost:3       (* 3 iterations *)
    ~parallelism:4
```

## Insufficient Validation (API004)

### ❌ Vulnerable Code

```ocaml
(* No padding validation *)
let decrypt data =
  try
    let plain = cipher#get_string data in
    Some plain
  with _ -> None  (* Swallowing padding errors *)

(* No certificate validation *)
let tls_config = {
  Ssl.verify_mode = Ssl.VerifyMode.verify_none;  (* Accepts any cert! *)
}
```

### ✅ Secure Alternative

```ocaml
(* Explicit padding check *)
let decrypt data =
  let plain = cipher#get_string data in
  match Padding.check_and_remove plain with
  | Ok unpadded -> Ok unpadded
  | Error _ -> Error "Invalid padding"

(* Proper certificate validation *)
let tls_config = {
  Ssl.verify_mode = Ssl.VerifyMode.verify_peer;
  Ssl.verify_callback = Some verify_hostname;
  Ssl.ca_file = Some "/etc/ssl/certs/ca-certificates.crt";
}
```

## Real-World CVE Examples

### CVE-2017-15999 (SHA-1 Collision)

```ocaml
(* Vulnerable: Using SHA-1 for digital signatures *)
let sign_document doc key =
  let hash = Cryptokit.Hash.sha1#hash_string doc in
  Rsa.sign key hash

(* Secure: Use SHA-256 or better *)
let sign_document doc key =
  let hash = Cryptokit.Hash.sha256#hash_string doc in
  Rsa.sign key hash
```

### CVE-2022-24793 (Nonce Reuse in PQCRYPTO)

```ocaml
(* Vulnerable: Fixed nonce *)
let encrypt_kyber key plaintext =
  let nonce = String.make 32 '\000' in  (* Never do this! *)
  Kyber.encrypt ~nonce key plaintext

(* Secure: Random nonce *)
let encrypt_kyber key plaintext =
  let nonce = Cryptokit.Random.string 32 in
  Kyber.encrypt ~nonce key plaintext
```

## Summary

Most cryptographic vulnerabilities fall into these categories:
1. **Using weak/broken algorithms** - Always use current recommendations
2. **Poor randomness** - Use crypto-secure RNGs
3. **Timing leaks** - Use constant-time operations
4. **Missing authentication** - Use AEAD modes
5. **Key management** - Never hardcode, always derive properly

Run OCaml Crypto Linter regularly to catch these issues early!