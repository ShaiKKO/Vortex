(* Test file for SIDE001-SIDE005: Side Channel Vulnerabilities *)

(* SIDE001: Variable-Time String Comparison *)
let vulnerable_auth username password =
  (* Direct string comparison - timing leak *)
  if password = "secret123" then
    true
  else
    false

let check_api_key provided expected =
  (* Another timing leak *)
  provided = expected

let verify_token token =
  (* Comparison with stored value *)
  let stored_token = "bearer_token_12345" in
  token = stored_token

let validate_hmac data hmac =
  let computed = Cryptokit.MAC.hmac_sha256 "key" data in
  (* Timing leak in MAC verification *)
  computed = hmac

(* SIDE002: Non-Constant Time Modular Exponentiation *)
let vulnerable_rsa_decrypt ciphertext key =
  (* Variable-time exponentiation *)
  let open Nocrypto.Rsa in
  (* This would use non-constant time operations *)
  decrypt ~key ciphertext

(* SIDE003: Cache Timing in Table Lookups *)
let vulnerable_sbox_lookup index =
  (* S-box table lookup vulnerable to cache timing *)
  let sbox = [|
    0x63; 0x7c; 0x77; 0x7b; 0xf2; 0x6b; 0x6f; 0xc5;
    0x30; 0x01; 0x67; 0x2b; 0xfe; 0xd7; 0xab; 0x76;
    (* ... more values ... *)
  |] in
  sbox.(index)  (* Array access timing depends on cache *)

let aes_subbytes state =
  (* Multiple cache-timing vulnerable lookups *)
  Array.map vulnerable_sbox_lookup state

(* SIDE004: Branch-Based Information Leak *)
let process_secret_data secret =
  (* Branching on secret data *)
  if secret > 128 then
    (* Different execution path based on secret *)
    expensive_operation ()
  else
    cheap_operation ()

let check_password_character c expected =
  (* Early exit on mismatch *)
  if c <> expected then
    raise Invalid_password
  else
    ()

let classify_secret_key key =
  (* Multiple branches based on secret *)
  match key with
  | k when String.length k < 16 -> "weak"
  | k when String.get k 0 = 'A' -> "type_a"
  | k when String.contains k '0' -> "numeric"
  | _ -> "other"

(* SIDE005: Power Analysis Vulnerable Operations *)
let vulnerable_multiplication a b =
  (* Square-and-multiply without blinding *)
  let rec power base exp acc =
    if exp = 0 then acc
    else if exp mod 2 = 0 then
      power (base * base) (exp / 2) acc
    else
      power base (exp - 1) (acc * base)
  in
  power a b 1

let hamming_weight_leak value =
  (* Operations that depend on bit count *)
  let count = ref 0 in
  for i = 0 to 7 do
    if (value lsr i) land 1 = 1 then
      count := !count + 1
  done;
  !count

(* Utility functions referenced above *)
let expensive_operation () = 
  for i = 1 to 1000000 do () done

let cheap_operation () = 
  ()

exception Invalid_password