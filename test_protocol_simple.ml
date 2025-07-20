(* Simple test for protocol rules *)

(* JWT decode without algorithm check - should trigger PROTO001 *)
let jwt_decode token =
  (* This simulates JWT.decode without algorithm verification *)
  let decoded = Base64.decode token in
  decoded

(* OAuth URL without state - should trigger PROTO003 *) 
let oauth_url client_id =
  let url = "https://oauth.com/authorize?client_id=" ^ client_id ^ "&response_type=code" in
  print_endline url

(* Token in logs - should trigger PROTO004 *)
let log_token () =
  let access_token = "secret123" in
  print_endline access_token

(* Parse before verify pattern *)
let saml_parse response =
  let parsed = response in (* simulate parse *)
  let verified = true in (* simulate verify after parse *)
  if verified then parsed else ""