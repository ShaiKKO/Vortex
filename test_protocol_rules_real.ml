(* Test cases for protocol vulnerability detection *)

(* Test JWT algorithm confusion *)
let decode_jwt_unsafe token =
  (* Simulating JWT decode without algorithm check *)
  let parts = [] in (* String.split_on_char not available in this context *)
  match parts with
  | [header; payload; signature] ->
      (* Decoding without verifying algorithm - VULNERABLE *)
      let decoded = Base64.decode payload in
      print_endline "JWT decoded without algorithm verification"
  | _ -> failwith "Invalid JWT"

(* Test OAuth without state *)
let oauth_authorize client_id redirect_uri =
  (* Building OAuth URL without state parameter - VULNERABLE */
  let auth_url = Printf.sprintf 
    "https://oauth.example.com/authorize?client_id=%s&redirect_uri=%s&response_type=code"
    client_id redirect_uri in
  (* Missing state parameter for CSRF protection *)
  print_endline auth_url

(* Test token in URL *)
let oauth_implicit_flow () =
  let access_token = "secret_token_12345" in
  (* Token exposed in URL - VULNERABLE */
  let callback = Printf.sprintf 
    "https://app.com/callback#access_token=%s"
    access_token in
  print_endline callback (* Logging token! *)

(* Test manual JWT validation *)
let manual_jwt_parse token =
  (* Manual parsing is dangerous *)
  if String.contains token '.' then
    let parts = String.split_on_char '.' token in
    List.iter print_endline parts

(* Test missing expiry check *)
let verify_jwt_no_exp token =
  (* Decode without checking expiration - VULNERABLE */
  let decoded = Base64.decode token in
  if String.length decoded > 0 then
    print_endline "JWT valid"
  else
    print_endline "JWT invalid"