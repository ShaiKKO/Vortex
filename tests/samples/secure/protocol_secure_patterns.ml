(* Secure Protocol Implementation Patterns
   Examples of how to properly implement JWT, OAuth, and SAML *)

(* ========================================================================== *)
(* Secure JWT Implementation                                                  *)
(* ========================================================================== *)

module Secure_JWT = struct
  (* Use a proper JWT library with algorithm restrictions *)
  let decode_jwt_secure ~allowed_algorithms token =
    (* SECURE: Explicitly specify allowed algorithms, never 'none' *)
    let allowed = [Jose.JWA.HS256; Jose.JWA.RS256] in
    match Jose.JWT.decode ~allowed_algorithms:allowed token with
    | Ok jwt -> 
        (* Additional validations *)
        validate_timestamps jwt;
        check_jti_not_replayed jwt;
        Ok jwt
    | Error e -> Error e

  (* Comprehensive timestamp validation *)
  let validate_timestamps jwt =
    let now = Unix.time () in
    let clock_skew = 30. in  (* 30 seconds tolerance *)
    
    (* Check expiration *)
    match get_claim jwt "exp" with
    | Some exp when float_of_string exp < now -. clock_skew ->
        failwith "Token expired"
    | _ -> ();
    
    (* Check not-before *)
    match get_claim jwt "nbf" with
    | Some nbf when float_of_string nbf > now +. clock_skew ->
        failwith "Token not yet valid"
    | _ -> ();
    
    (* Validate issued-at for freshness *)
    match get_claim jwt "iat" with
    | Some iat when float_of_string iat > now +. clock_skew ->
        failwith "Token issued in the future"
    | _ -> ()

  (* Replay protection with JTI tracking *)
  module JTI_Cache = struct
    let seen_jtis = Hashtbl.create 1000
    
    let check_and_add jti expiry =
      if Hashtbl.mem seen_jtis jti then
        false  (* Already seen *)
      else begin
        Hashtbl.add seen_jtis jti expiry;
        true
      end
    
    (* Cleanup expired JTIs periodically *)
    let cleanup () =
      let now = Unix.time () in
      Hashtbl.filter_map_inplace (fun _ expiry ->
        if expiry > now then Some expiry else None
      ) seen_jtis
  end

  let check_jti_not_replayed jwt =
    match get_claim jwt "jti", get_claim jwt "exp" with
    | Some jti, Some exp ->
        if not (JTI_Cache.check_and_add jti (float_of_string exp)) then
          failwith "JWT replay detected"
    | _ -> failwith "Missing jti or exp claim"
end

(* ========================================================================== *)
(* Secure OAuth Implementation                                                *)
(* ========================================================================== *)

module Secure_OAuth = struct
  (* Generate cryptographically secure state parameter *)
  let generate_state () =
    (* SECURE: Use crypto-quality randomness *)
    Mirage_crypto_rng.generate 32
    |> Cstruct.to_string
    |> Base64.encode_string

  (* OAuth authorization with CSRF protection *)
  let oauth_authorize ~client_id ~redirect_uri ~session =
    let state = generate_state () in
    
    (* Store state in session for validation *)
    Session.set session "oauth_state" state;
    
    (* SECURE: Include state parameter *)
    let auth_url = Printf.sprintf
      "https://oauth.provider.com/authorize?\
       client_id=%s&\
       redirect_uri=%s&\
       response_type=code&\
       state=%s&\
       code_challenge=%s&\
       code_challenge_method=S256"  (* PKCE for additional security *)
      (Uri.pct_encode client_id)
      (Uri.pct_encode redirect_uri)
      state
      (generate_pkce_challenge ())
    in
    redirect_to auth_url

  (* Validate state on callback *)
  let oauth_callback ~session params =
    let received_state = get_param params "state" in
    let stored_state = Session.get session "oauth_state" in
    
    (* SECURE: Validate state parameter *)
    match stored_state with
    | Some expected when Eqaf.equal expected received_state ->
        let code = get_param params "code" in
        Session.remove session "oauth_state";  (* Use once *)
        exchange_code_for_token code
    | _ ->
        failwith "CSRF detected: Invalid state parameter"

  (* Secure token handling *)
  let handle_oauth_tokens response =
    let access_token = response.access_token in
    let refresh_token = response.refresh_token in
    
    (* SECURE: Never log tokens *)
    Logs.info (fun m -> m "OAuth tokens received for user %s" response.user_id);
    
    (* Store securely (encrypted) *)
    let encrypted_access = encrypt_token access_token in
    let encrypted_refresh = encrypt_token refresh_token in
    
    Token_store.save ~user_id:response.user_id
      ~access:encrypted_access
      ~refresh:encrypted_refresh
      ~expires_in:response.expires_in

  (* Use Authorization header, not URL parameters *)
  let make_api_request ~token endpoint =
    (* SECURE: Token in Authorization header *)
    let headers = [
      ("Authorization", Printf.sprintf "Bearer %s" token);
      ("X-Request-ID", generate_request_id ());
    ] in
    Http_client.get ~headers endpoint
end

(* ========================================================================== *)
(* Secure SAML Implementation                                                 *)
(* ========================================================================== *)

module Secure_SAML = struct
  (* Verify signature BEFORE parsing *)
  let process_saml_response_secure saml_xml =
    (* SECURE: Validate signature on raw XML first *)
    let signature_ref = extract_signature_reference saml_xml in
    
    match verify_xml_signature_raw saml_xml signature_ref with
    | Error e -> Error ("Invalid SAML signature: " ^ e)
    | Ok () ->
        (* Only parse after signature verification *)
        let parsed = Xml.parse_string saml_xml in
        let assertions = extract_verified_assertions parsed in
        Ok (process_assertions assertions)

  (* Proper XML canonicalization *)
  let verify_saml_with_c14n xml_doc =
    (* SECURE: Use exclusive canonicalization *)
    let canonical_xml = Xml_c14n.exclusive_canonicalize xml_doc in
    let signature_value = extract_signature_value xml_doc in
    let signed_info = extract_signed_info_canonical xml_doc in
    
    (* Verify with proper algorithm *)
    match verify_rsa_sha256 signed_info signature_value with
    | true -> Ok ()
    | false -> Error "Signature verification failed"

  (* Comprehensive timestamp validation *)
  let validate_saml_timestamps assertion =
    let now = Unix.time () in
    let clock_skew = 300. in  (* 5 minutes for SAML *)
    
    (* Check NotBefore *)
    match get_saml_time assertion "NotBefore" with
    | Some not_before when not_before > now +. clock_skew ->
        Error "Assertion not yet valid"
    | _ ->
        (* Check NotOnOrAfter *)
        match get_saml_time assertion "NotOnOrAfter" with
        | Some not_after when not_after < now -. clock_skew ->
            Error "Assertion expired"
        | _ -> Ok ()

  (* Assertion replay protection *)
  module Assertion_Cache = struct
    let processed_assertions = Hashtbl.create 1000
    
    let check_and_record assertion_id not_on_or_after =
      if Hashtbl.mem processed_assertions assertion_id then
        Error "SAML assertion replay detected"
      else begin
        Hashtbl.add processed_assertions assertion_id not_on_or_after;
        Ok ()
      end
  end

  (* Validate InResponseTo for SP-initiated SSO *)
  let validate_saml_response response ~expected_request_id =
    let assertion = extract_assertion response in
    
    (* Validate InResponseTo *)
    match get_in_response_to assertion with
    | Some in_response_to when in_response_to = expected_request_id ->
        (* Continue with other validations *)
        validate_saml_timestamps assertion;
        let assertion_id = get_assertion_id assertion in
        let not_after = get_saml_time assertion "NotOnOrAfter" in
        Assertion_Cache.check_and_record assertion_id not_after
    | Some _ -> Error "InResponseTo mismatch"
    | None when expected_request_id <> "" -> 
        Error "Missing InResponseTo for SP-initiated flow"
    | None -> Ok ()  (* IdP-initiated is allowed if no request ID *)
end

(* ========================================================================== *)
(* General Security Utilities                                                 *)
(* ========================================================================== *)

module Security_Utils = struct
  (* Constant-time string comparison *)
  let secure_compare a b =
    Eqaf.equal a b

  (* Secure random generation *)
  let generate_secure_random n =
    Mirage_crypto_rng.generate n |> Cstruct.to_string

  (* Key derivation from password *)
  let derive_key_from_password password salt =
    (* Use proper KDF with sufficient iterations *)
    Pbkdf.pbkdf2 ~password ~salt ~count:100_000 ~dk_len:32

  (* Secure token storage with encryption *)
  let encrypt_token token =
    let key = get_encryption_key () in
    let nonce = generate_secure_random 12 in
    let cipher = Mirage_crypto.AES.GCM.of_secret key in
    let ciphertext = Mirage_crypto.AES.GCM.encrypt ~nonce cipher token in
    Base64.encode_string (nonce ^ ciphertext)

  (* Rate limiting for authentication endpoints *)
  module Rate_Limiter = struct
    let attempts = Hashtbl.create 100
    
    let check_rate_limit client_id =
      let key = Printf.sprintf "%s:%d" client_id (int_of_float (Unix.time () /. 60.)) in
      let count = try Hashtbl.find attempts key with Not_found -> 0 in
      if count >= 10 then  (* 10 attempts per minute *)
        false
      else begin
        Hashtbl.replace attempts key (count + 1);
        true
      end
  end
end

(* Stub functions for examples *)
let get_claim _ _ = Some "1234567890"
let redirect_to _ = ()
let get_param _ _ = "value"
let generate_pkce_challenge () = "challenge"
let exchange_code_for_token _ = {access_token=""; refresh_token=""; user_id=""; expires_in=3600}
let encrypt_token _ = ""
let generate_request_id () = Uuidm.v `V4 |> Uuidm.to_string
let extract_signature_reference _ = ""
let verify_xml_signature_raw _ _ = Ok ()
let extract_verified_assertions _ = []
let process_assertions _ = ()
let extract_signature_value _ = ""
let extract_signed_info_canonical _ = ""
let verify_rsa_sha256 _ _ = true
let get_saml_time _ _ = Some (Unix.time ())
let extract_assertion _ = Obj.magic ()
let get_in_response_to _ = Some "request123"
let get_assertion_id _ = "assertion123"
let get_encryption_key () = Cstruct.of_string "32-byte-encryption-key-goes-here!"

module Session = struct
  let set _ _ _ = ()
  let get _ _ = Some "state"
  let remove _ _ = ()
end

module Token_store = struct
  let save ~user_id:_ ~access:_ ~refresh:_ ~expires_in:_ = ()
end

module Http_client = struct
  let get ~headers:_ _ = ""
end

module Logs = struct
  let info _ = ()
end

module Xml_c14n = struct
  let exclusive_canonicalize _ = ""
end