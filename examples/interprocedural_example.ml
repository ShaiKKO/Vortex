(* Example demonstrating interprocedural analysis capabilities *)

module Crypto_utils = struct
  (* Helper function that just encrypts *)
  let encrypt_block ~key ~iv data =
    Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv data
  
  (* Another helper that generates IV *)
  let generate_iv () =
    Mirage_crypto_rng.generate 16
end

module Message_processor = struct
  (* This function encrypts but doesn't add MAC *)
  let encrypt_message key plaintext =
    let iv = Crypto_utils.generate_iv () in
    let ciphertext = Crypto_utils.encrypt_block ~key ~iv plaintext in
    (iv, ciphertext)
  
  (* This function calls encrypt_message but still no MAC *)
  let process_user_data user_key user_data =
    let (iv, encrypted) = encrypt_message user_key user_data in
    (* Store or transmit without authentication *)
    Bytes.cat iv encrypted
end

module Secure_processor = struct
  (* Proper implementation with MAC *)
  let encrypt_and_authenticate enc_key mac_key plaintext =
    let iv = Crypto_utils.generate_iv () in
    let ciphertext = Crypto_utils.encrypt_block ~key:enc_key ~iv plaintext in
    let mac = Mirage_crypto.Hash.SHA256.hmac ~key:mac_key (Bytes.cat iv ciphertext) in
    (iv, ciphertext, mac)
end

(* Complex key reuse scenario *)
module Key_manager = struct
  type keys = {
    master: bytes;
    mutable cached_enc: bytes option;
    mutable cached_mac: bytes option;
  }
  
  let create_manager master = {
    master;
    cached_enc = None;
    cached_mac = None;
  }
  
  (* Problematic: returns same key for different purposes *)
  let get_key manager purpose =
    manager.master  (* Should derive different keys! *)
  
  let encrypt_data manager data =
    let key = get_key manager "encryption" in
    let iv = Crypto_utils.generate_iv () in
    Crypto_utils.encrypt_block ~key ~iv data
  
  let compute_mac manager data =
    let key = get_key manager "mac" in  (* Same key as encryption! *)
    Mirage_crypto.Hash.SHA256.hmac ~key data
end

(* Demonstration of how interprocedural analysis tracks the flow *)
let main () =
  let key = Mirage_crypto_rng.generate 32 in
  
  (* Case 1: CBC without MAC through multiple function calls *)
  let sensitive_data = Bytes.of_string "secret information" in
  let unauth_encrypted = Message_processor.process_user_data key sensitive_data in
  
  (* Case 2: Proper authenticated encryption *)
  let mac_key = Mirage_crypto_rng.generate 32 in
  let (iv, ct, mac) = Secure_processor.encrypt_and_authenticate key mac_key sensitive_data in
  
  (* Case 3: Key reuse across different operations *)
  let km = Key_manager.create_manager key in
  let encrypted = Key_manager.encrypt_data km sensitive_data in
  let mac_value = Key_manager.compute_mac km encrypted in
  
  ()

(* The interprocedural analyzer should detect:
   1. Message_processor.process_user_data -> encrypt_message -> Crypto_utils.encrypt_block
      Results in CBC without MAC across 3 function calls
   
   2. Key_manager uses same key for both encryption and MAC
      Even though get_key is called with different purposes
   
   3. Secure_processor.encrypt_and_authenticate properly uses Encrypt-then-MAC
      This should not trigger warnings
*)