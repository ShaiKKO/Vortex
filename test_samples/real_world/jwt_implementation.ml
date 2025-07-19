(* Real-world JWT implementation example - mix of good and bad practices *)

module JWT = struct
  open Cryptokit
  
  type algorithm = 
    | HS256 
    | HS512
    | None  (* Dangerous! *)
  
  type token = {
    header: Yojson.Safe.t;
    payload: Yojson.Safe.t;
    signature: string;
  }
  
  (* BAD: Hardcoded secret *)
  let default_secret = "change_me_in_production"  (* KEY001 *)
  
  (* BAD: Weak algorithm support *)
  let sign_none payload =
    (* API misuse - no signature *)
    Base64.encode_string payload  (* Missing authentication *)
  
  (* GOOD: Strong HMAC *)
  let sign_hs256 secret payload =
    let data = payload in
    MAC.hmac_sha256 secret data
  
  (* BAD: Timing attack vulnerability *)
  let verify_signature expected actual =
    expected = actual  (* SIDE001: timing attack *)
  
  (* GOOD: Constant time comparison *)
  let verify_signature_secure expected actual =
    Eqaf.equal expected actual
  
  (* MIXED: Implementation with issues *)
  let create_token ?(algorithm=HS256) ?(secret=default_secret) payload =
    let header = match algorithm with
      | HS256 -> `Assoc [("alg", `String "HS256"); ("typ", `String "JWT")]
      | HS512 -> `Assoc [("alg", `String "HS512"); ("typ", `String "JWT")]
      | None -> `Assoc [("alg", `String "none"); ("typ", `String "JWT")]  (* Dangerous *)
    in
    
    let header_b64 = Base64.encode_string (Yojson.Safe.to_string header) in
    let payload_b64 = Base64.encode_string (Yojson.Safe.to_string payload) in
    let message = header_b64 ^ "." ^ payload_b64 in
    
    let signature = match algorithm with
      | HS256 -> 
          let mac = MAC.hmac_sha256 secret message in
          Base64.encode_string mac
      | HS512 ->
          let mac = MAC.hmac_sha512 secret message in
          Base64.encode_string mac
      | None -> ""  (* No signature! *)
    in
    
    message ^ "." ^ signature
  
  (* BAD: Accepts tokens with no signature *)
  let decode_unsafe token =
    let parts = String.split_on_char '.' token in
    match parts with
    | [header; payload; signature] ->
        (* No signature verification! *)
        let payload_json = Base64.decode_string payload |> Yojson.Safe.from_string in
        Some payload_json
    | _ -> None
  
  (* BETTER: Verify signature *)
  let decode_and_verify ~secret token =
    let parts = String.split_on_char '.' token in
    match parts with
    | [header; payload; signature] ->
        let message = header ^ "." ^ payload in
        let header_json = Base64.decode_string header |> Yojson.Safe.from_string in
        
        (* Check algorithm *)
        let alg = header_json |> Yojson.Safe.Util.member "alg" |> Yojson.Safe.Util.to_string in
        
        let expected_sig = match alg with
          | "HS256" -> Base64.encode_string (MAC.hmac_sha256 secret message)
          | "HS512" -> Base64.encode_string (MAC.hmac_sha512 secret message)
          | "none" -> ""  (* BAD: Accepting 'none' algorithm *)
          | _ -> failwith "Unsupported algorithm"
        in
        
        (* BAD: Still using timing-vulnerable comparison *)
        if signature = expected_sig then  (* SIDE001 *)
          let payload_json = Base64.decode_string payload |> Yojson.Safe.from_string in
          Some payload_json
        else
          None
    | _ -> None
end

(* Example usage showing more issues *)
module JWT_Auth = struct
  (* BAD: Hardcoded key in module *)
  let jwt_signing_key = "super_secret_jwt_key_2023"  (* KEY001 *)
  
  (* BAD: Weak random for session tokens *)
  let generate_session_id () =
    Random.self_init ();  (* API005: weak random *)
    string_of_int (Random.bits ())
  
  (* GOOD: Reading from config *)
  let get_jwt_secret () =
    try 
      Sys.getenv "JWT_SECRET"
    with Not_found ->
      jwt_signing_key  (* BAD: Falls back to hardcoded *)
  
  let create_auth_token user_id =
    let payload = `Assoc [
      ("user_id", `String user_id);
      ("session_id", `String (generate_session_id ()));  (* Using weak random *)
      ("exp", `Int (int_of_float (Unix.time ()) + 3600))
    ] in
    JWT.create_token ~secret:(get_jwt_secret ()) payload
end