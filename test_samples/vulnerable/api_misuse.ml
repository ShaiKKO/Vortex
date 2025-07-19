(* Test file for API001-API007: API Misuse Patterns *)

open Cryptokit

(* API001: ECB Mode Usage *)
let insecure_ecb_encryption key data =
  (* ECB mode - never use! *)
  let cipher = Cipher.aes ~mode:ECB key in
  cipher#put_string data;
  cipher#get_string

let another_ecb_example key =
  (* Even with padding, ECB is insecure *)
  let cipher = Cipher.aes ~mode:ECB ~pad:Padding.length key in
  cipher

(* API002: CBC Without MAC *)
let vulnerable_cbc_decrypt key iv ciphertext =
  (* CBC decryption without MAC verification *)
  let cipher = Cipher.aes ~mode:CBC ~iv key in
  cipher#put_string ciphertext;
  cipher#get_string  (* No MAC check! *)

let encrypt_without_auth key iv data =
  (* Encryption without authentication *)
  let cipher = Cipher.aes ~mode:CBC ~iv key in
  let encrypted = transform_string cipher data in
  encrypted  (* Returns only ciphertext, no MAC *)

(* API003: Improper IV Generation *)
let bad_iv_generation key data =
  (* Static IV *)
  let iv = String.make 16 '\000' in  (* All zeros! *)
  let cipher = Cipher.aes ~mode:CBC ~iv key in
  cipher#put_string data

let predictable_iv_counter = ref 0
let bad_iv_sequential key data =
  (* Sequential IVs *)
  incr predictable_iv_counter;
  let iv = string_of_int !predictable_iv_counter in
  let iv_padded = (String.make (16 - String.length iv) '\000') ^ iv in
  let cipher = Cipher.aes ~mode:CBC ~iv:iv_padded key in
  cipher#put_string data

(* API004: Missing Padding Validation *)
let decrypt_without_padding_check key iv ciphertext =
  let cipher = Cipher.aes ~mode:CBC ~iv key in
  try
    let plaintext = transform_string cipher ciphertext in
    Some plaintext  (* No explicit padding validation *)
  with
    | _ -> None  (* Swallowing all errors including padding *)

(* API005: Incorrect Random Number Usage *)
let weak_key_generation () =
  (* Using Random module for crypto *)
  Random.self_init ();  (* Weak seeding *)
  let key = Bytes.create 32 in
  Random.fill_bytes key;  (* Not cryptographically secure *)
  Bytes.to_string key

let predictable_nonce () =
  (* Time-based seed *)
  Random.init (int_of_float (Unix.time ()));
  Random.bits ()

let insufficient_entropy () =
  (* Only 30 bits of randomness *)
  let rand = Random.bits () in  (* max 30 bits *)
  string_of_int rand

(* API006: Unverified Certificates *)
module Insecure_TLS = struct
  let no_cert_validation = 
    Ssl.set_verify_mode Ssl.VerifyMode.VerifyNone
  
  let create_insecure_context () =
    let ctx = Ssl.create_context Ssl.TLSv1_2 Ssl.Client_context in
    Ssl.set_verify ctx Ssl.VerifyMode.VerifyNone None;
    ctx
    
  let accept_any_cert = {
    Conduit_lwt_unix.
    verify_mode = Ssl.VerifyMode.VerifyNone;
    cert = None;
    key = None;
  }
end

(* API007: Missing CTR Mode Nonce Increment *)
let vulnerable_ctr_usage key =
  let nonce = String.make 16 '\000' in
  
  let encrypt_multiple messages =
    List.map (fun msg ->
      (* Reusing same counter value! *)
      let cipher = Cipher.aes ~mode:CTR ~iv:nonce key in
      transform_string cipher msg
    ) messages

let static_counter_mode key =
  (* Counter doesn't increment between messages *)
  let make_cipher () = 
    let iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" in
    Cipher.aes ~mode:CTR ~iv key
  in
  
  fun message ->
    let cipher = make_cipher () in  (* Same counter every time *)
    transform_string cipher message