(* Edge cases and complex patterns *)

(* Nonce reuse patterns - KEY003 *)
module AEAD_Nonce_Issues = struct
  (* Critical: Fixed nonce with GCM *)
  let encrypt_gcm_fixed_nonce key plaintext =
    let nonce = String.make 12 '\000' in  (* KEY003: AEAD nonce reuse *)
    let cipher = Cryptokit.AEAD.aes_gcm ~key ~nonce in
    cipher#encrypt plaintext
  
  (* Nonce reuse across multiple encryptions *)
  let bulk_encrypt_reused_nonce key messages =
    let nonce = Cryptokit.Random.string 12 in  (* Generated once *)
    List.map (fun msg ->
      (* Reusing same nonce for all messages! *)
      let cipher = Cryptokit.AEAD.aes_gcm ~key ~nonce in
      cipher#encrypt msg
    ) messages
end

(* Complex key derivation issues - KEY005 *)
module Weak_KDF = struct
  (* Too few iterations *)
  let weak_pbkdf2 password =
    let salt = Cryptokit.Random.string 16 in
    Cryptokit.Password.pbkdf2 
      ~password 
      ~salt 
      ~iterations:100  (* KEY005: Way too low! *)
      ~length:32
  
  (* Bad scrypt parameters *)
  let weak_scrypt password =
    (* Scrypt with weak parameters *)
    let n = 1024 in  (* Should be 16384 minimum *)
    let r = 1 in     (* Should be 8 *)
    let p = 1 in     (* OK *)
    Scrypt.password_hash ~n ~r ~p ~password
end

(* Plaintext key storage - KEY006 *)
module Key_Storage = struct
  (* Writing keys to files *)
  let save_key_to_file key =
    let oc = open_out "secret.key" in
    output_string oc key;  (* KEY006: Plaintext key storage *)
    close_out oc
  
  (* Logging keys *)
  let debug_key key =
    Printf.printf "Debug: key = %s\n" key;  (* KEY006 *)
    Logs.debug (fun m -> m "Secret key: %s" key)  (* KEY006 *)
end

(* MAC-then-Encrypt pattern *)
let mac_then_encrypt key data =
  (* Wrong order: should be encrypt-then-MAC *)
  let mac = Cryptokit.MAC.hmac_sha256 key data in
  let to_encrypt = data ^ mac in
  let cipher = Cryptokit.Cipher.aes key in
  Cryptokit.transform_string cipher to_encrypt

(* Missing randomness in signatures *)
module DSA_Issues = struct
  (* DSA/ECDSA without proper random k *)
  let sign_without_random key message =
    (* Using deterministic k (simulated) *)
    let k = Digest.string message in  (* Predictable! *)
    (* This would lead to key recovery *)
    ()
end

(* Nested vulnerable patterns *)
module Complex_Patterns = struct
  (* Multiple issues in one function *)
  let totally_broken_crypto () =
    let key = "hardcoded_key_123" in  (* KEY001 *)
    let iv = String.make 16 '\000' in  (* KEY004 *)
    let cipher = Cryptokit.Cipher.des ~mode:ECB key in  (* ALGO001, API001 *)
    let data = "sensitive_data" in
    let encrypted = Cryptokit.transform_string cipher data in
    
    (* Timing vulnerable comparison *)
    let verify mac = mac = "expected_mac" in  (* SIDE001 *)
    
    (* Weak hash *)
    let hash = Digest.string encrypted in  (* ALGO002 *)
    
    (encrypted, hash)
end

(* Context that should reduce severity *)
module Test_Context = struct
  (* In test file - might have reduced severity *)
  let test_encryption () =
    let test_key = "test_key_only" in  (* In test context *)
    Cryptokit.Cipher.aes test_key
  
  (* Migration/compatibility code *)
  let legacy_compatibility data =
    (* Comment: For backward compatibility only, will be removed in v2.0 *)
    let md5_hash = Digest.string data in  (* Context: migration *)
    md5_hash
end

(* Library wrapper that propagates vulnerabilities *)
module Crypto_Wrapper = struct
  (* Wrapper still has the vulnerability *)
  let hash_data = Digest.string  (* Wrapping MD5 *)
  
  let encrypt_ecb key = 
    Cryptokit.Cipher.aes ~mode:ECB key  (* Wrapping ECB *)
end