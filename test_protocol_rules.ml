(* Test case for protocol vulnerability detection *)

(* JWT Algorithm Confusion - should trigger PROTO001 *)
let vulnerable_jwt_decode token =
  (* This accepts 'none' algorithm - CRITICAL vulnerability *)
  Jose.JWT.decode ~allowed_algorithms:["HS256"; "none"] token

(* JWT without replay protection - should trigger PROTO002 *)  
let basic_jwt_verify token key =
  match Jose.JWT.decode token with
  | Ok jwt -> 
      (* Missing exp/jti validation *)
      print_endline "JWT valid"
  | Error _ -> print_endline "JWT invalid"

(* OAuth without state parameter - should trigger PROTO003 *)
let oauth_redirect client_id =
  let auth_url = Printf.sprintf 
    "https://oauth.provider.com/authorize?client_id=%s&response_type=code"
    client_id in
  (* Missing state parameter *)
  redirect_to auth_url

(* OAuth token in URL - should trigger PROTO004 *)
let oauth_implicit_flow () =
  let callback_url = 
    "https://myapp.com/callback#access_token=secret123&token_type=bearer" in
  print_endline callback_url (* Logging token! *)

(* SAML parse before verify - should trigger PROTO005 *)
let vulnerable_saml_handler saml_response =
  let parsed = Saml.parse_response saml_response in (* Parse first - BAD! *)
  match Saml.verify_signature parsed with
  | true -> process_saml parsed
  | false -> failwith "Invalid signature"

(* SAML without replay protection - should trigger PROTO006 *)
let basic_saml_validate assertion =
  (* Missing NotBefore/NotOnOrAfter checks *)
  (* Missing assertion ID caching *)
  validate_signature assertion