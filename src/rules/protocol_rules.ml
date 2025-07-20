(* Protocol Security Rules Implementation
   JWT, OAuth 2.0, and SAML vulnerability detection *)

open Types
open Rule_engine
open Ppxlib
open Utils

(* Protocol detection context *)
module Protocol_Context = struct
  type t = {
    mutable uses_jwt: bool;
    mutable uses_oauth: bool;
    mutable uses_saml: bool;
    mutable jwt_libs: string list;
    mutable oauth_flows: string list;
  }
  
  let create () = {
    uses_jwt = false;
    uses_oauth = false;
    uses_saml = false;
    jwt_libs = [];
    oauth_flows = [];
  }
end

(* PROTO001: JWT Algorithm Confusion Attack *)
let jwt_algorithm_confusion_rule : Rule.t = {
  id = "PROTO001";
  name = "JWT Algorithm Confusion Vulnerability";
  description = "Detects JWT verification that accepts 'none' algorithm or allows algorithm switching";
  severity = Critical;
  tags = ["jwt"; "algorithm-confusion"; "authentication-bypass"; "cwe-347"];
  check = fun ast ->
    let findings = ref [] in
    let ctx = Protocol_Context.create () in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! structure_item item =
        match item.pstr_desc with
        | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
            let module_name = flatten_longident txt |> String.concat "." in
            if List.exists (fun lib -> contains_substring module_name lib) 
                ["Jose"; "Jwt"; "Jose_jwt"] then begin
              ctx.uses_jwt <- true;
              ctx.jwt_libs <- module_name :: ctx.jwt_libs
            end;
            super#structure_item item
        | _ -> super#structure_item item
      
      method! expression expr =
        match expr.pexp_desc with
        (* Detect JWT decode without algorithm verification *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let func_path = flatten_longident txt |> String.concat "." in
            
            (* Check for JWT decode/verify calls - expanded patterns *)
            if (contains_substring func_path "decode" || 
                contains_substring func_path "verify" ||
                contains_substring func_path "parse" ||
                contains_substring func_path "jwt" ||
                contains_substring func_path "JWT" ||
                contains_substring func_path "token") && 
               (ctx.uses_jwt || contains_substring func_path "Base64") then
              let has_algorithm_check = List.exists (fun (label, _) ->
                match label with
                | Asttypes.Labelled l -> 
                    List.mem l ["allowed_algorithms"; "algorithm"; "alg"; "algorithms"]
                | _ -> false
              ) args in
              
              (* Check for dangerous patterns *)
              let accepts_none = List.exists (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_construct ({txt = Lident "None"; _}, _) -> true
                | Pexp_constant (Pconst_string (s, _, _)) ->
                    contains_substring (String.lowercase_ascii s) "none"
                | _ -> false
              ) args in
              
              if not has_algorithm_check || accepts_none then
                findings := {
                  rule_id = "PROTO001";
                  severity = Critical;
                  message = if accepts_none then
                    "JWT verification accepts 'none' algorithm - authentication bypass!"
                  else
                    "JWT decoded without algorithm verification - vulnerable to algorithm confusion";
                  vulnerability = AuthBypass;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some 
                    "Fix JWT algorithm confusion:\n\
                     let allowed_algorithms = [Jose.JWA.RS256; Jose.JWA.ES256] in\n\
                     match Jose.JWT.decode ~allowed_algorithms token with\n\
                     | Ok jwt -> (* safe to use *)\n\
                     | Error _ -> failwith \"Invalid JWT\"\n\
                     NEVER accept 'none' algorithm or decode without verification!";
                  references = [
                    "CWE-347: Improper Verification of Cryptographic Signature";
                    "CVE-2015-2951: JWT libraries algorithm confusion";
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/";
                  ];
                } :: !findings;
            
            (* Check for manual JWT parsing (base64 decode) *)
            else if contains_substring func_path "Base64.decode" then
              (* Look for JWT structure (three dots) *)
              List.iter (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_apply ({pexp_desc = Pexp_ident {txt = Lident "split"; _}; _}, 
                             [(_, {pexp_desc = Pexp_constant (Pconst_char '.'); _}); _]) ->
                    findings := {
                      rule_id = "PROTO001"; 
                      severity = Error;
                      message = "Manual JWT parsing detected - use validated JWT library";
                      vulnerability = ImproperValidation;
                      location = {
                        file = expr.pexp_loc.loc_start.pos_fname;
                        line = expr.pexp_loc.loc_start.pos_lnum;
                        column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                        end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                        end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                      };
                      suggestion = Some "Use jose or another validated JWT library instead of manual parsing";
                      references = ["https://datatracker.ietf.org/doc/html/rfc7519"];
                    } :: !findings
                | _ -> ()
              ) args;
            
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* PROTO002: JWT Replay Attack *)
let jwt_replay_attack_rule : Rule.t = {
  id = "PROTO002";
  name = "JWT Replay Attack Vulnerability";
  description = "Detects JWT validation without replay protection (missing jti/exp/nbf checks)";
  severity = Error;
  tags = ["jwt"; "replay-attack"; "token-reuse"];
  check = fun ast ->
    let findings = ref [] in
    let jwt_validations = ref [] in
    let has_exp_check = ref false in
    let has_jti_check = ref false in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
            let func_path = flatten_longident txt |> String.concat "." in
            
            (* Track JWT validation calls *)
            if contains_substring func_path "JWT.decode" || 
               contains_substring func_path "verify" then
              jwt_validations := expr.pexp_loc :: !jwt_validations;
            
            (* Check for exp/nbf validation *)
            if contains_substring func_path "check_exp" || 
               contains_substring func_path "validate_exp" ||
               contains_substring func_path "expiry" then
              has_exp_check := true;
            
            (* Check for jti tracking *)
            if contains_substring func_path "jti" || 
               contains_substring func_path "jwt_id" ||
               contains_substring func_path "nonce" then
              has_jti_check := true;
            
            super#expression expr
            
        | Pexp_field (_, {txt = Lident field; _}) ->
            (* Check for manual exp/jti field access *)
            if List.mem field ["exp"; "expiry"; "expiration"] then
              has_exp_check := true
            else if List.mem field ["jti"; "jwt_id"; "nonce"] then  
              has_jti_check := true;
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    
    (* Flag if JWT validation found without replay protection *)
    if !jwt_validations <> [] && (not !has_exp_check || not !has_jti_check) then
      List.iter (fun loc ->
        findings := {
          rule_id = "PROTO002";
          severity = Error;
          message = Printf.sprintf "JWT validation missing replay protection: %s"
            (match !has_exp_check, !has_jti_check with
             | false, false -> "no exp or jti validation"
             | true, false -> "no jti tracking for replay prevention"
             | false, true -> "no expiration check"
             | _ -> "");
          vulnerability = ReplayAttack;
          location = {
            file = loc.loc_start.pos_fname;
            line = loc.loc_start.pos_lnum;
            column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
            end_line = Some loc.loc_end.pos_lnum;
            end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
          };
          suggestion = Some 
            "Implement comprehensive JWT replay protection:\n\
             1. Validate exp (expiration) and nbf (not before)\n\
             2. Track jti (JWT ID) to prevent reuse\n\
             3. Implement clock skew tolerance (e.g., 30 seconds)\n\
             Example:\n\
             let validate_jwt_timestamps jwt now =\n\
               match jwt.exp, jwt.nbf with\n\
               | Some exp, Some nbf ->\n\
                   if now < nbf -. clock_skew then Error \"Token not yet valid\"\n\
                   else if now > exp +. clock_skew then Error \"Token expired\"\n\
                   else Ok ()\n\
               | _ -> Error \"Missing required timestamp claims\"";
          references = [
            "RFC 7519 Section 4.1.4-4.1.7";
            "OWASP JWT Security Cheat Sheet";
          ];
        } :: !findings
      ) !jwt_validations;
    
    !findings
}

(* PROTO003: OAuth State Parameter CSRF *)
let oauth_csrf_rule : Rule.t = {
  id = "PROTO003";
  name = "OAuth CSRF via Missing State Parameter";
  description = "Detects OAuth 2.0 flows without proper state parameter validation";
  severity = Error;
  tags = ["oauth"; "csrf"; "state-parameter"; "cwe-352"];
  check = fun ast ->
    let findings = ref [] in
    let ctx = Protocol_Context.create () in
    let oauth_requests = ref [] in
    let has_state_param = ref false in
    let has_state_validation = ref false in
    
    (* Debug: rule is being called *)
    (* Printf.eprintf "PROTO003: OAuth CSRF rule checking...\n"; *)
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_constant (Pconst_string (s, _, _)) ->
            (* Detect OAuth URLs and parameters *)
            if contains_substring s "/authorize" || 
               contains_substring s "response_type=" ||
               contains_substring s "/oauth" ||
               contains_substring s "/auth" ||
               contains_substring s "client_id=" ||
               contains_substring s "redirect_uri=" then begin
              ctx.uses_oauth <- true;
              oauth_requests := expr.pexp_loc :: !oauth_requests;
              
              (* Check for state parameter *)
              if contains_substring s "state=" then
                has_state_param := true;
              
              (* Flag implicit flow as dangerous *)
              if contains_substring s "response_type=token" then
                ctx.oauth_flows <- "implicit" :: ctx.oauth_flows
            end;
            super#expression expr
            
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let func_path = flatten_longident txt |> String.concat "." in
            
            (* Check for state validation in callback *)
            if contains_substring func_path "callback" || 
               contains_substring func_path "oauth_callback" then
              List.iter (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_field (_, {txt = Lident "state"; _}) ->
                    has_state_validation := true
                | _ -> ()
              ) args;
            
            (* Check for secure random generation *)
            if contains_substring func_path "Mirage_crypto_rng.generate" ||
               contains_substring func_path "Random.generate" then
              (* Look for state assignment nearby *)
              has_state_param := true;
            
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    
    (* Flag OAuth flows without proper state handling *)
    if !oauth_requests <> [] && (not !has_state_param || not !has_state_validation) then
      List.iter (fun loc ->
        findings := {
          rule_id = "PROTO003";
          severity = Error;
          message = Printf.sprintf "OAuth flow vulnerable to CSRF: %s"
            (match !has_state_param, !has_state_validation with
             | false, _ -> "missing state parameter"
             | true, false -> "state parameter not validated in callback"
             | _ -> "");
          vulnerability = CSRF;
          location = {
            file = loc.loc_start.pos_fname;
            line = loc.loc_start.pos_lnum;
            column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
            end_line = Some loc.loc_end.pos_lnum;
            end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
          };
          suggestion = Some 
            "Implement OAuth CSRF protection with state parameter:\n\
             1. Generate cryptographic random state:\n\
                let state = Mirage_crypto_rng.generate 32 |> Base64.encode_string\n\
             2. Store in session before redirect\n\
             3. Validate in callback:\n\
                if not (Eqaf.equal session_state received_state) then\n\
                  failwith \"CSRF detected\"\n\
             4. Use PKCE for additional security";
          references = [
            "RFC 6749 Section 10.12";
            "OAuth 2.0 Security Best Practices";
          ];
        } :: !findings
      ) !oauth_requests;
    
    (* Flag implicit flow usage *)
    if List.mem "implicit" ctx.oauth_flows then
      findings := {
        rule_id = "PROTO003";
        severity = Critical;
        message = "OAuth implicit flow detected - deprecated and insecure!";
        vulnerability = InsecureProtocol;
        location = {file = ""; line = 0; column = 0; end_line = None; end_column = None};
        suggestion = Some "Use authorization code flow with PKCE instead of implicit flow";
        references = ["OAuth 2.0 Security BCP: Implicit flow deprecated"];
      } :: !findings;
    
    !findings
}

(* PROTO004: OAuth Token Leakage *)
let oauth_token_leak_rule : Rule.t = {
  id = "PROTO004";
  name = "OAuth Token Exposure Risk";
  description = "Detects OAuth access tokens in URLs, logs, or insecure storage";
  severity = Error;
  tags = ["oauth"; "token-leak"; "access-token"];
  check = fun ast ->
    let findings = ref [] in
    let token_vars = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Track token variables *)
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} ->
                  let lower_name = String.lowercase_ascii name in
                  if contains_substring lower_name "token" ||
                     contains_substring lower_name "access_token" ||
                     contains_substring lower_name "refresh_token" ||
                     contains_substring lower_name "bearer" ||
                     contains_substring lower_name "secret" ||
                     contains_substring lower_name "api_key" ||
                     contains_substring lower_name "auth" then
                    token_vars := name :: !token_vars
              | _ -> ()
            ) bindings;
            super#expression expr
            
        (* Check for tokens in URLs *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let func_path = flatten_longident txt |> String.concat "." in
            
            (* Logging functions - extended list *)
            if List.mem func_path ["print_endline"; "Printf.printf"; "Logs.info"; 
                                   "Logs.debug"; "print_string"; "prerr_endline";
                                   "Printf.fprintf"; "Printf.sprintf"; "Format.printf"] ||
               contains_substring func_path "print" ||
               contains_substring func_path "log" ||
               contains_substring func_path "debug" then
              List.iter (fun (_, arg) ->
                let check_for_token = function
                  | {pexp_desc = Pexp_ident {txt = Lident name; _}; _} ->
                      if List.mem name !token_vars then
                        findings := {
                          rule_id = "PROTO004";
                          severity = Error;
                          message = "OAuth token logged - sensitive data exposure!";
                          vulnerability = InfoDisclosure;
                          location = {
                            file = expr.pexp_loc.loc_start.pos_fname;
                            line = expr.pexp_loc.loc_start.pos_lnum;
                            column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                            end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                            end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                          };
                          suggestion = Some "Never log OAuth tokens. Use token fingerprints or masked values";
                          references = ["OWASP Logging Cheat Sheet"];
                        } :: !findings
                  | _ -> ()
                in
                check_for_token arg
              ) args;
            
            (* URL construction *)
            if contains_substring func_path "sprintf" || 
               contains_substring func_path "concat" then
              List.iter (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_constant (Pconst_string (s, _, _)) ->
                    if contains_substring s "access_token=" ||
                       contains_substring s "#access_token=" then
                      findings := {
                        rule_id = "PROTO004";
                        severity = Critical;
                        message = "OAuth token in URL - will be logged in server/proxy logs!";
                        vulnerability = InfoDisclosure;
                        location = {
                          file = arg.pexp_loc.loc_start.pos_fname;
                          line = arg.pexp_loc.loc_start.pos_lnum;
                          column = arg.pexp_loc.loc_start.pos_cnum - arg.pexp_loc.loc_start.pos_bol;
                          end_line = Some arg.pexp_loc.loc_end.pos_lnum;
                          end_column = Some (arg.pexp_loc.loc_end.pos_cnum - arg.pexp_loc.loc_end.pos_bol);
                        };
                        suggestion = Some 
                          "Never put tokens in URLs:\n\
                           - Use Authorization header: Authorization: Bearer <token>\n\
                           - For SPAs: Use secure httpOnly cookies\n\
                           - Store tokens in memory or secure storage only";
                        references = ["RFC 6750: OAuth 2.0 Bearer Token Usage"];
                      } :: !findings
                | _ -> ()
              ) args;
            
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* PROTO005: SAML XML Signature Wrapping *)
let saml_signature_wrapping_rule : Rule.t = {
  id = "PROTO005";
  name = "SAML XML Signature Wrapping Attack";
  description = "Detects SAML response validation vulnerable to signature wrapping/bypass";
  severity = Critical;
  tags = ["saml"; "xml-signature"; "signature-wrapping"; "cwe-347"];
  check = fun ast ->
    let findings = ref [] in
    let xml_parse_before_verify = ref false in
    let has_canonicalization = ref false in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_sequence (e1, e2) ->
            (* Detect parse-then-verify antipattern *)
            let check_sequence e1 e2 =
              let is_xml_parse e = match e.pexp_desc with
                | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
                    let path = flatten_longident txt |> String.concat "." in
                    contains_substring path "parse" && 
                    (contains_substring path "xml" || contains_substring path "saml")
                | _ -> false
              in
              
              let is_signature_verify e = match e.pexp_desc with
                | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
                    let path = flatten_longident txt |> String.concat "." in
                    contains_substring path "verify" && 
                    (contains_substring path "signature" || contains_substring path "sig")
                | _ -> false
              in
              
              if is_xml_parse e1 && is_signature_verify e2 then
                xml_parse_before_verify := true
            in
            check_sequence e1 e2;
            super#expression expr
            
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let func_path = flatten_longident txt |> String.concat "." in
            
            (* Check for XML parsing functions - expanded patterns *)
            if contains_substring func_path "Xml.parse" ||
               contains_substring func_path "Saml.parse" ||
               contains_substring func_path "Xmlm.make_input" ||
               contains_substring func_path "parse" && contains_substring func_path "xml" ||
               contains_substring func_path "parse" && contains_substring func_path "saml" ||
               contains_substring func_path "DOM" ||
               contains_substring func_path "parseXML" ||
               contains_substring func_path "from_string" then
              (* Check if canonicalization is mentioned *)
              List.iter (fun (label, _) ->
                match label with
                | Asttypes.Labelled l when contains_substring l "canon" ->
                    has_canonicalization := true
                | _ -> ()
              ) args;
            
            (* Check for unsafe XML queries *)
            if contains_substring func_path "xpath" ||
               contains_substring func_path "getElementsBy" then
              findings := {
                rule_id = "PROTO005";
                severity = Warning;
                message = "XML element selection may be vulnerable to wrapping attacks";
                vulnerability = SignatureBypass;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some "Use ID-based references for signed elements, not XPath";
                references = ["SAML Security Considerations"];
              } :: !findings;
            
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    
    (* Flag parse-before-verify antipattern *)
    if !xml_parse_before_verify then
      findings := {
        rule_id = "PROTO005";
        severity = Critical;
        message = "SAML XML parsed before signature verification - signature bypass!";
        vulnerability = SignatureBypass;
        location = {file = ""; line = 0; column = 0; end_line = None; end_column = None};
        suggestion = Some 
          "CRITICAL: Verify XML signature BEFORE parsing:\n\
           1. Extract signed element by ID reference\n\
           2. Verify signature on raw XML\n\
           3. Only parse after successful verification\n\
           4. Use exclusive XML canonicalization (c14n)\n\
           Example:\n\
           let verify_saml_response raw_xml =\n\
             let signed_ref = extract_signature_reference raw_xml in\n\
             match verify_xml_signature raw_xml signed_ref cert with\n\
             | Error _ -> Error \"Invalid signature\"\n\
             | Ok () -> parse_verified_saml raw_xml";
        references = [
          "CWE-347: Improper Verification of Cryptographic Signature";
          "SAML XML Signature Wrapping Attacks";
        ];
      } :: !findings;
    
    !findings
}

(* PROTO006: SAML Replay Attack *)
let saml_replay_rule : Rule.t = {
  id = "PROTO006";
  name = "SAML Assertion Replay Vulnerability";
  description = "Detects SAML validation without replay attack protection";
  severity = Error;
  tags = ["saml"; "replay-attack"; "assertion-reuse"];
  check = fun ast ->
    let findings = ref [] in
    let has_timestamp_check = ref false in
    let has_assertion_cache = ref false in
    let has_inresponseto = ref false in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_field (_, {txt = Lident field; _}) ->
            (* Check for timestamp field access *)
            if List.mem field ["NotBefore"; "NotOnOrAfter"; "IssueInstant"] then
              has_timestamp_check := true
            else if field = "InResponseTo" then
              has_inresponseto := true;
            super#expression expr
            
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
            let func_path = flatten_longident txt |> String.concat "." in
            
            (* Check for assertion ID caching *)
            if contains_substring func_path "cache" && 
               contains_substring func_path "assertion" then
              has_assertion_cache := true;
            
            (* Check for time validation functions *)
            if contains_substring func_path "validate_time" ||
               contains_substring func_path "check_timestamp" then
              has_timestamp_check := true;
            
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    
    (* Flag missing replay protections *)
    if not !has_timestamp_check || not !has_assertion_cache then
      findings := {
        rule_id = "PROTO006";
        severity = Error;
        message = Printf.sprintf "SAML validation missing replay protection: %s"
          (match !has_timestamp_check, !has_assertion_cache, !has_inresponseto with
           | false, false, _ -> "no timestamp validation or assertion caching"
           | true, false, _ -> "no assertion ID cache to prevent replay"
           | false, true, _ -> "no timestamp validation"
           | true, true, false -> "missing InResponseTo validation for SP-initiated"
           | _ -> "");
        vulnerability = ReplayAttack;
        location = {file = ""; line = 0; column = 0; end_line = None; end_column = None};
        suggestion = Some 
          "Implement SAML replay protection:\n\
           1. Validate NotBefore/NotOnOrAfter with clock skew:\n\
              if now < assertion.NotBefore - skew ||\n\
                 now > assertion.NotOnOrAfter + skew then\n\
                Error \"Assertion outside valid time window\"\n\
           2. Cache assertion IDs to prevent reuse:\n\
              if Cache.mem assertion_cache assertion.ID then\n\
                Error \"Assertion replay detected\"\n\
           3. For SP-initiated: validate InResponseTo matches request ID\n\
           4. Validate audience restriction matches SP entity ID";
        references = [
          "SAML 2.0 Security Considerations";
          "OWASP SAML Security Cheat Sheet";
        ];
      } :: !findings;
    
    !findings
}

(* Semgrep integration for enhanced detection *)
module Semgrep_patterns = struct
  let jwt_patterns = [
    {|
    rules:
      - id: jwt-none-algorithm
        pattern-either:
          - pattern: |
              $JWT.decode(..., algorithm="none", ...)
          - pattern: |
              $JWT.verify(..., algorithms=[..., "none", ...], ...)
        message: JWT accepts 'none' algorithm
        severity: ERROR
    |};
    
    {|
    rules:
      - id: jwt-no-expiry-check
        patterns:
          - pattern: $JWT.decode(...)
          - pattern-not-inside: |
              if $EXP < $TIME:
                ...
        message: JWT decoded without expiry check
        severity: WARNING
    |};
  ]
  
  let oauth_patterns = [
    {|
    rules:
      - id: oauth-token-in-url
        pattern-either:
          - pattern: |
              "...access_token=$TOKEN..."
          - pattern: |
              f"...access_token={$TOKEN}..."
        message: OAuth token exposed in URL
        severity: ERROR
    |};
    
    {|
    rules:
      - id: oauth-missing-state
        patterns:
          - pattern: |
              $URL = "...authorize?client_id=..."
          - pattern-not: |
              $URL = "...state=..."
        message: OAuth authorization without state parameter
        severity: WARNING
    |};
  ]
end

(* Register all protocol rules *)
let () =
  Registry.register jwt_algorithm_confusion_rule;
  Registry.register jwt_replay_attack_rule;
  Registry.register oauth_csrf_rule;
  Registry.register oauth_token_leak_rule;
  Registry.register saml_signature_wrapping_rule;
  Registry.register saml_replay_rule