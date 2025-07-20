(* Test file specifically designed to trigger protocol rules *)

(* 1. OAuth without state parameter - should trigger PROTO003 *)
let oauth_authorize client_id =
  (* This URL is missing the state parameter for CSRF protection *)
  let auth_url = "https://oauth.provider.com/authorize?client_id=" ^ client_id ^ "&response_type=code&redirect_uri=https://app.com/callback" in
  print_endline auth_url

(* 2. OAuth implicit flow - should trigger PROTO003 critical *)
let oauth_implicit () =
  let url = "https://provider.com/authorize?response_type=token&client_id=123" in
  print_endline url

(* 3. Token in variable that gets logged - should trigger PROTO004 *)
let process_oauth_response () =
  let access_token = "bearer_token_12345" in
  let refresh_token = "refresh_xyz" in
  (* Logging tokens is dangerous *)
  print_endline access_token;
  Printf.printf "Got refresh token: %s" refresh_token

(* 4. Manual Base64 decoding that might be JWT - should trigger PROTO001 *)
let decode_token token =
  let decoded = Base64.decode token in
  decoded

(* 5. String comparison in crypto context - should trigger existing timing rule *)
let verify_mac computed expected =
  if computed = expected then
    print_endline "MAC valid"
  else
    print_endline "MAC invalid"