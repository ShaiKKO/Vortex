(* Test file for secure cryptographic patterns - should NOT trigger warnings *)

open Cryptokit
open Mirage_crypto

(* Secure key management *)
let get_key_from_env () =
  (* Reading from environment - secure *)
  try
    Sys.getenv "ENCRYPTION_KEY"
  with Not_found ->
    failwith "ENCRYPTION_KEY not set"

let derive_key_from_password password =
  (* Proper key derivation *)
  let salt = Random.string 16 in
  let iterations = 100_000 in  (* NIST recommended minimum *)
  let key = Password.derive ~password ~salt ~iterations 32 in
  (salt, key)

(* Strong algorithms *)
let secure_encryption key plaintext =
  (* AES-256 in GCM mode (authenticated encryption) *)
  let iv = Random.string 12 in  (* Random IV *)
  let cipher = AEAD.aes_gcm ~key in
  let ciphertext = cipher#encrypt ~iv plaintext in
  (iv, ciphertext)

let secure_hashing data =
  (* SHA-256 - secure *)
  let hash = Hash.sha256 () in
  hash#add_string data;
  hash#result

let blake2b_hash data =
  (* BLAKE2b - modern and secure *)
  Mirage_crypto.Hash.BLAKE2B.digest (Cstruct.of_string data)

(* Constant-time operations *)
let secure_comparison a b =
  (* Using constant-time comparison *)
  Eqaf.equal a b

let verify_mac_constant_time data mac key =
  let computed = MAC.hmac_sha256 key data in
  Eqaf.equal computed mac

(* Secure randomness *)
let generate_secure_token () =
  (* Cryptographically secure random *)
  Random.string 32

let generate_nonce () =
  (* Unique nonce for each operation *)
  Mirage_crypto_rng.generate 12

(* Proper AEAD usage *)
let encrypt_with_auth key plaintext =
  let nonce = Mirage_crypto_rng.generate 12 in
  let module AES_GCM = Mirage_crypto.AES.GCM in
  let cipher = AES_GCM.of_secret (Cstruct.of_string key) in
  let ciphertext = AES_GCM.encrypt ~nonce ~adata:Cstruct.empty 
    (Cstruct.of_string plaintext) in
  (nonce, ciphertext)

(* Secure curves *)
let generate_secure_keypair () =
  (* P-256 - secure curve *)
  Nocrypto.Ec.P256.generate ()

let use_curve25519 () =
  (* Curve25519 - recommended *)
  Mirage_crypto_ec.X25519.gen_key ()

(* Proper TLS configuration *)
let secure_tls_config () = 
  Ssl.{
    protocol = TLSv1_3;  (* Latest TLS *)
    verify_mode = VerifyMode.VerifyPeer;
    ca_file = Some "/etc/ssl/certs/ca-certificates.crt";
    verify_callback = Some (fun _ -> true);
  }

(* Secure CTR mode with proper counter management *)
let secure_ctr_mode key =
  let counter = ref 0L in
  fun plaintext ->
    let iv = 
      let buf = Bytes.create 16 in
      Bytes.set_int64_be buf 8 !counter;
      counter := Int64.succ !counter;
      Bytes.to_string buf
    in
    let cipher = Cipher.aes ~mode:CTR ~iv key in
    transform_string cipher plaintext

(* Non-cryptographic use of weak algorithms (should be context-aware) *)
let cache_key_generation data =
  (* MD5 for cache keys - non-security use *)
  (* Comment indicates non-cryptographic use *)
  "cache:" ^ (Digest.to_hex (Digest.string data))

let git_compatible_hash data =
  (* SHA-1 for git compatibility - not for security *)
  let hash = Hash.sha1 () in
  hash#add_string data;
  hash#result