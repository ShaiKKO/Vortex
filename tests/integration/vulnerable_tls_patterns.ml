(* TLS-specific vulnerabilities based on ocaml-tls attack research *)

(* Bleichenbacher's PKCS#1 timing attack (CVE-1998) *)
module PKCS1_Timing_Attack = struct
  open Mirage_crypto
  open Mirage_crypto_pk
  
  (* Vulnerable RSA decryption with timing leak *)
  let decrypt_premaster_secret ~priv_key ~encrypted_premaster =
    try
      match Rsa.PKCS1.decrypt ~key:priv_key encrypted_premaster with
      | Ok plaintext -> 
          (* Check PKCS1 padding - timing varies based on padding validity *)
          if Bytes.length plaintext = 48 then
            Ok plaintext
          else
            Error "Invalid premaster length"  (* Fast fail - timing leak! *)
      | Error _ -> 
          Error "Decryption failed"  (* Different timing than padding error *)
    with _ ->
      Error "Critical error"  (* Another timing difference *)
      
  (* The fix: constant-time fake premaster secret *)
  let decrypt_premaster_constant_time ~priv_key ~encrypted_premaster =
    let fake_premaster = Mirage_crypto_rng.generate 48 in
    match Rsa.PKCS1.decrypt ~key:priv_key encrypted_premaster with
    | Ok plaintext when Bytes.length plaintext = 48 -> plaintext
    | _ -> fake_premaster  (* Always return 48 bytes, same timing *)
end

(* Vaudenay's CBC padding oracle attack *)
module CBC_Padding_Oracle_Attack = struct
  open Mirage_crypto.Cipher_block
  
  let key = AES.of_secret (Bytes.of_string "0123456789abcdef0123456789abcdef")
  
  (* Vulnerable: distinguishes between MAC and padding errors *)
  let decrypt_and_verify ~iv ~ciphertext ~mac =
    try
      let plaintext = AES.CBC.decrypt ~key ~iv ciphertext in
      (* Check MAC first - different error for MAC vs padding *)
      let computed_mac = Hash.SHA256.hmac ~key:(Bytes.create 32) plaintext in
      if not (Eqaf.equal computed_mac mac) then
        Error "MAC verification failed"  (* Timing: MAC checked first *)
      else
        Ok plaintext
    with
    | Invalid_argument _ -> Error "Padding error"  (* Different error! *)
    | _ -> Error "Decryption error"
    
  (* This error distinction allows padding oracle attacks! *)
end

(* BEAST attack - TLS 1.0 IV vulnerability *)
module BEAST_Attack_Pattern = struct
  open Mirage_crypto.Cipher_block
  
  type tls10_state = {
    mutable last_ciphertext_block: bytes;
    key: AES.key;
  }
  
  (* Vulnerable TLS 1.0 CBC implementation *)
  let create_tls10_cipher key =
    { 
      last_ciphertext_block = Bytes.create 16;
      key = AES.of_secret key;
    }
    
  let encrypt_tls10_vulnerable state plaintext =
    (* TLS 1.0 reuses last ciphertext block as IV - BEAST vulnerable! *)
    let iv = state.last_ciphertext_block in  (* KEY002: Predictable IV! *)
    let ciphertext = AES.CBC.encrypt ~key:state.key ~iv plaintext in
    (* Update IV for next block - predictable pattern *)
    let ct_len = Bytes.length ciphertext in
    Bytes.blit ciphertext (ct_len - 16) state.last_ciphertext_block 0 16;
    ciphertext
    
  (* Mitigation: 1/n-1 split (empty fragment) *)
  let encrypt_tls10_mitigated state plaintext =
    (* Send empty fragment first to randomize IV *)
    let empty = Bytes.create 0 in
    let _ = encrypt_tls10_vulnerable state empty in
    (* Now the real plaintext with randomized IV *)
    encrypt_tls10_vulnerable state plaintext
end

(* Lucky Thirteen - MAC-then-Encrypt timing attack (CVE-2013-0169) *)
module Lucky_Thirteen = struct
  open Mirage_crypto
  
  (* Vulnerable MAC-then-Encrypt (wrong order!) *)
  let mac_then_encrypt ~enc_key ~mac_key ~plaintext =
    (* Compute MAC on plaintext - wrong! *)
    let mac = Hash.SHA256.hmac ~key:mac_key plaintext in  (* API002: MAC-then-Encrypt *)
    let to_encrypt = Bytes.concat Bytes.empty [plaintext; mac] in
    (* Encrypt plaintext||MAC *)
    let iv = Mirage_crypto_rng.generate 16 in
    let ciphertext = Cipher_block.AES.CBC.encrypt ~key:enc_key ~iv to_encrypt in
    (iv, ciphertext)  (* Vulnerable to Lucky Thirteen *)
    
  (* The timing leak during decryption *)
  let decrypt_mac_then_encrypt ~enc_key ~mac_key ~iv ~ciphertext =
    try
      let decrypted = Cipher_block.AES.CBC.decrypt ~key:enc_key ~iv ciphertext in
      let len = Bytes.length decrypted in
      if len < 32 then Error "Too short"  (* Timing leak! *)
      else
        let plaintext = Bytes.sub decrypted 0 (len - 32) in
        let mac = Bytes.sub decrypted (len - 32) 32 in
        let expected_mac = Hash.SHA256.hmac ~key:mac_key plaintext in
        if Eqaf.equal mac expected_mac then
          Ok plaintext
        else
          Error "MAC mismatch"  (* Different timing than padding error *)
    with _ -> Error "Padding error"  (* Distinguishable error *)
end

(* Compression oracle attacks (CRIME/BREACH) *)
module Compression_Oracle = struct
  (* Vulnerable: compressing secrets with attacker-controlled data *)
  let compress_then_encrypt ~key ~secret ~user_input =
    (* NEVER compress secrets with user data! *)
    let combined = Printf.sprintf "secret=%s&input=%s" secret user_input in
    (* Compression will leak secret length via ciphertext size *)
    let compressed = Zlib.compress combined in  (* Information leak! *)
    let iv = Mirage_crypto_rng.generate 16 in
    Cipher_block.AES.CBC.encrypt ~key ~iv (Bytes.of_string compressed)
end

(* Downgrade attacks - allowing weak ciphers *)
module Downgrade_Vulnerabilities = struct
  type cipher_suite = 
    | AES_256_GCM
    | AES_128_CBC
    | DES_EDE3_CBC  (* 3DES - weak! *)
    | RC4_128       (* RC4 - broken! *)
    
  let supported_ciphers = [
    AES_256_GCM;
    AES_128_CBC;
    DES_EDE3_CBC;  (* ALGO001: Should not support 3DES *)
    RC4_128;       (* ALGO001: Should not support RC4 *)
  ]
  
  (* Vulnerable cipher selection *)
  let select_cipher client_ciphers =
    (* Selects first match - allows downgrade! *)
    List.find (fun c -> List.mem c client_ciphers) supported_ciphers
    
  (* Using selected weak cipher *)
  let encrypt_with_negotiated_cipher suite key plaintext =
    match suite with
    | RC4_128 -> 
        (* ALGO001: RC4 is completely broken *)
        let rc4 = Cryptokit.Cipher.arcfour key Cryptokit.Cipher.Encrypt in
        Cryptokit.transform_string rc4 (Bytes.to_string plaintext)
    | DES_EDE3_CBC ->
        (* ALGO001: 3DES vulnerable to SWEET32 *)
        let iv = Bytes.create 8 in
        Cryptokit.Cipher.triple_des ~mode:Cryptokit.Cipher.CBC ~iv 
          ~pad:Cryptokit.Padding.length Cryptokit.Cipher.Encrypt key |>
        Cryptokit.transform_string (Bytes.to_string plaintext)
    | _ -> ""
end

(* Renegotiation attack patterns *)
module Renegotiation_Attack = struct
  type tls_state = {
    mutable handshake_count: int;
    mutable session_key: bytes option;
    mutable verified_client: bool;
  }
  
  (* Vulnerable: no secure renegotiation extension *)
  let handle_renegotiation state =
    (* Allows renegotiation without binding to previous handshake *)
    state.handshake_count <- state.handshake_count + 1;
    state.session_key <- Some (Mirage_crypto_rng.generate 32);
    (* Client verification state can be injected! *)
    state.verified_client <- false  (* Should preserve auth state! *)
    
  (* Triple handshake attack pattern *)
  let vulnerable_session_resumption ~session_id ~master_secret =
    (* No binding between sessions - allows MitM *)
    let new_session_key = Hash.SHA256.digest 
      (Bytes.of_string (session_id ^ Bytes.to_string master_secret)) in
    new_session_key  (* Vulnerable to triple handshake *)
end

(* Export restrictions and weak crypto *)
module Export_Grade_Crypto = struct
  (* Historically weak "export" crypto *)
  let export_rsa_key_size = 512  (* ALGO004: Weak RSA key *)
  let export_dh_key_size = 512   (* ALGO005: Weak DH parameters *)
  
  let generate_export_grade_key () =
    (* Generates dangerously weak keys *)
    Mirage_crypto_pk.Rsa.generate ~bits:export_rsa_key_size ()
    
  (* Logjam attack - weak DH *)
  let weak_dh_params = 
    Mirage_crypto_pk.Dh.generate ~bits:export_dh_key_size ()
end