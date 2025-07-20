(* Vulnerable Cryptokit patterns based on real CVEs and security research *)

(* CVE-2022-24793: RSA timing attack in Cryptokit < 1.16.1 *)
module Vulnerable_RSA = struct
  open Cryptokit
  
  let private_key = "hardcoded_rsa_private_key_material_here"  (* KEY001: Hardcoded key *)
  
  let decrypt_message ciphertext =
    (* Vulnerable to timing attacks in old Cryptokit versions *)
    let key = RSA.new_key 2048 in
    RSA.decrypt key ciphertext  (* SIDE002: Timing vulnerable *)
    
  let verify_signature msg signature =
    let key = RSA.new_key 2048 in
    (* String comparison vulnerable to timing attacks *)
    let expected = RSA.sign key msg in
    String.equal signature expected  (* SIDE001: Variable-time comparison *)
end

(* Timing vulnerabilities in AES implementation *)
module Timing_Vulnerable_AES = struct
  open Cryptokit
  
  let secret_key = "0123456789abcdef0123456789abcdef"  (* KEY001: Hardcoded 256-bit key *)
  
  let encrypt_user_password password =
    (* Multiple vulnerabilities:
       1. ECB mode (API001)
       2. No MAC (API006)
       3. String-based operations (memory issues)
    *)
    let cipher = Cipher.aes ~mode:Cipher.ECB secret_key Cipher.Encrypt in
    transform_string cipher password
    
  let verify_auth_token token expected_token =
    (* Direct string comparison on cryptographic material *)
    token = expected_token  (* SIDE001: Timing attack *)
end

(* Weak algorithms still supported by Cryptokit *)
module Legacy_Weak_Crypto = struct
  open Cryptokit
  
  (* DES/3DES usage - CVE-2016-2183 (SWEET32) *)
  let encrypt_financial_data ~key ~data =
    let cipher = Cipher.des ~mode:Cipher.CBC ~pad:Padding.length 
                   ~iv:(String.make 8 '\000')  (* KEY002: Predictable IV *)
                   Cipher.Encrypt key in
    transform_string cipher data  (* ALGO001: Weak cipher DES *)
    
  (* MD5 for password hashing - severely broken *)
  let hash_password password salt =
    let hash = Hash.md5 () in  (* ALGO002: Weak hash MD5 *)
    hash#add_string (password ^ salt);
    hash#result
    
  (* SHA1 for digital signatures - SHAttered attack *)
  let sign_document ~key ~document =
    let hash = Hash.sha1 () in  (* ALGO002: Weak hash SHA1 in security context *)
    hash#add_string document;
    let digest = hash#result in
    (* HMAC with SHA1 - still vulnerable *)
    MAC.hmac_sha1 key digest  (* ALGO002: SHA1 in HMAC *)
end

(* Incorrect padding implementation (from Stack Overflow example) *)
module Padding_Vulnerability = struct
  open Cryptokit
  
  let incorrect_3des_decrypt ~key ~ciphertext =
    (* Using bit padding instead of PKCS#5/7 - causes decryption failures *)
    let cipher = Cipher.triple_des ~mode:Cipher.ECB ~pad:Padding.length 
                   Cipher.Decrypt key in  (* ALGO001: 3DES weak *)
    try
      transform_string cipher ciphertext
    with _ -> 
      (* Timing difference reveals padding errors *)
      ""  (* SIDE004: Branch on crypto failure *)
end

(* String-based operations causing memory vulnerabilities *)
module Memory_Unsafe_Crypto = struct
  open Cryptokit
  
  let sensitive_key = ref "super_secret_key_material"
  
  let unsafe_key_derivation password =
    (* Strings remain in memory - can be swapped to disk *)
    let derived = Hash.sha256 () in
    derived#add_string password;
    let key = derived#result in
    (* Key material in immutable string - cannot be zeroed *)
    sensitive_key := key;  (* Memory leak of key material *)
    key
    
  let process_credit_card ~card_number =
    (* Credit card in string memory *)
    let encrypted = Cipher.aes secret_key Cipher.Encrypt |> 
                   transform_string card_number in
    (* Original card_number string still in memory! *)
    encrypted
end

(* Weak randomness for cryptographic operations *)
module Weak_Randomness = struct
  (* Using Random instead of cryptographic RNG *)
  let generate_iv () = 
    (* RAND001: Weak random for crypto *)
    String.init 16 (fun _ -> Char.chr (Random.int 256))
    
  let generate_session_key () =
    (* Predictable seed *)
    Random.init (int_of_float (Unix.time ()));  (* RAND001: Predictable seed *)
    String.init 32 (fun _ -> Char.chr (Random.int 256))
end

(* CBC without proper authentication *)
module CBC_Padding_Oracle = struct
  open Cryptokit
  
  let key = "abcdef0123456789abcdef0123456789"
  
  let vulnerable_decrypt ~iv ~ciphertext =
    (* No MAC verification - padding oracle possible *)
    let cipher = Cipher.aes ~mode:Cipher.CBC ~pad:Padding.length 
                   ~iv Cipher.Decrypt key in
    try
      Some (transform_string cipher ciphertext)  (* API006: CBC without MAC *)
    with 
    | Cryptokit.Error Cryptokit.Bad_padding -> None  (* Padding oracle! *)
    | _ -> None
    
  let encrypt_without_mac ~plaintext =
    let iv = String.make 16 '\000' in  (* KEY002: Zero IV *)
    let cipher = Cipher.aes ~mode:Cipher.CBC ~pad:Padding.length
                   ~iv Cipher.Encrypt key in
    let ciphertext = transform_string cipher plaintext in
    (iv, ciphertext)  (* API006: Missing MAC *)
end

(* Real-world authentication vulnerability pattern *)
module Broken_Authentication = struct
  open Cryptokit
  
  type user_token = {
    user_id: string;
    timestamp: float;
    signature: string;
  }
  
  let token_key = "shared_token_signing_key"  (* KEY001: Hardcoded *)
  
  let create_token user_id =
    let data = Printf.sprintf "%s:%.0f" user_id (Unix.time ()) in
    let hash = Hash.sha1 () in  (* ALGO002: SHA1 for auth *)
    hash#add_string data;
    let signature = hash#result in
    { user_id; timestamp = Unix.time (); signature }
    
  let verify_token token =
    let expected = create_token token.user_id in
    (* Multiple timing leaks *)
    token.signature = expected.signature &&  (* SIDE001: Timing attack *)
    token.timestamp > Unix.time () -. 3600.  (* Token replay possible *)
end