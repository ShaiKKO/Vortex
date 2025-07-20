(* Protocol Security Rules Design
   Based on 2025 threat intelligence research
   Categories: JWT, OAuth 2.0, SAML *)

open Types
open Rule_engine
open Ppxlib
open Utils

(* Rule PROTO001: JWT Algorithm Confusion Attack *)
(* Severity: Critical
   Description: Detects JWT implementations vulnerable to algorithm confusion
   Fix: Explicitly verify algorithm type, never trust alg header blindly *)
let jwt_algorithm_confusion_rule : Rule.t = {
  id = "PROTO001";
  name = "JWT Algorithm Confusion Vulnerability";
  description = "Detects JWT verification that accepts 'none' algorithm or allows algorithm switching";
  severity = Critical;
  tags = ["jwt"; "algorithm-confusion"; "authentication-bypass"];
  check = fun ast ->
    (* Implementation skeleton:
       1. Detect JWT decode/verify functions
       2. Check if algorithm validation is present
       3. Flag if 'none' algorithm is accepted
       4. Flag if algorithm can be switched from RS256 to HS256
       
       Key patterns to detect:
       - Jose.JWT.decode without algorithm verification
       - Custom JWT parsing that reads alg header
       - Missing algorithm whitelist
    *)
    []
}

(* Rule PROTO002: JWT Replay Attack *)
(* Severity: Error
   Description: Detects missing replay protection in JWT implementations
   Fix: Implement jti (JWT ID) tracking and exp/nbf validation *)
let jwt_replay_attack_rule : Rule.t = {
  id = "PROTO002";
  name = "JWT Replay Attack Vulnerability";
  description = "Detects JWT validation without replay protection (missing jti/exp/nbf checks)";
  severity = Error;
  tags = ["jwt"; "replay-attack"; "token-reuse"];
  check = fun ast ->
    (* Implementation skeleton:
       1. Find JWT validation code
       2. Check for exp (expiration) validation
       3. Check for nbf (not before) validation
       4. Check for jti (JWT ID) tracking for replay prevention
       5. Check for clock skew handling
       
       Key patterns:
       - JWT validation without timestamp checks
       - Missing jti blacklist/store
       - No exp/nbf field validation
    *)
    []
}

(* Rule PROTO003: OAuth State Parameter CSRF *)
(* Severity: Error
   Description: Detects OAuth flows missing state parameter validation
   Fix: Generate cryptographically secure state parameter and validate on callback *)
let oauth_csrf_rule : Rule.t = {
  id = "PROTO003";
  name = "OAuth CSRF via Missing State Parameter";
  description = "Detects OAuth 2.0 flows without proper state parameter validation";
  severity = Error;
  tags = ["oauth"; "csrf"; "state-parameter"];
  check = fun ast ->
    (* Implementation skeleton:
       1. Identify OAuth authorization request building
       2. Check if state parameter is generated
       3. Verify state is cryptographically random
       4. Check callback handler validates state
       5. Ensure state is tied to user session
       
       Key patterns:
       - OAuth redirect without state parameter
       - Predictable state values
       - Missing state validation in callback
    *)
    []
}

(* Rule PROTO004: OAuth Token Leakage *)
(* Severity: Error  
   Description: Detects OAuth tokens exposed in URLs or logs
   Fix: Use authorization code flow, never implicit flow, store tokens securely *)
let oauth_token_leak_rule : Rule.t = {
  id = "PROTO004";
  name = "OAuth Token Exposure Risk";
  description = "Detects OAuth access tokens in URLs, logs, or insecure storage";
  severity = Error;
  tags = ["oauth"; "token-leak"; "access-token"];
  check = fun ast ->
    (* Implementation skeleton:
       1. Find OAuth token handling code
       2. Check if tokens appear in URLs (implicit flow)
       3. Detect logging of tokens
       4. Check token storage (should use secure storage)
       5. Verify PKCE is used for public clients
       
       Key patterns:
       - Access tokens in URL fragments
       - Token logging statements
       - Tokens stored in localStorage/cookies without encryption
       - Missing PKCE challenge
    *)
    []
}

(* Rule PROTO005: SAML XML Signature Wrapping *)
(* Severity: Critical
   Description: Detects SAML implementations vulnerable to XML signature wrapping
   Fix: Validate signatures before ANY XML processing, use strict canonicalization *)
let saml_signature_wrapping_rule : Rule.t = {
  id = "PROTO005";
  name = "SAML XML Signature Wrapping Attack";
  description = "Detects SAML response validation vulnerable to signature wrapping/bypass";
  severity = Critical;
  tags = ["saml"; "xml-signature"; "signature-wrapping"];
  check = fun ast ->
    (* Implementation skeleton:
       1. Find SAML response parsing code
       2. Check order: signature validation MUST come first
       3. Verify XML canonicalization method
       4. Check for XPath injection in assertions
       5. Validate signing certificate properly
       
       Key patterns:
       - XML parsing before signature validation
       - Missing canonicalization
       - Weak XPath expressions for signature location
       - Certificate validation bypass
    *)
    []
}

(* Rule PROTO006: SAML Replay Attack *)
(* Severity: Error
   Description: Detects missing replay protection in SAML implementations  
   Fix: Validate SubjectConfirmationData NotOnOrAfter and track assertion IDs *)
let saml_replay_rule : Rule.t = {
  id = "PROTO006";
  name = "SAML Assertion Replay Vulnerability";
  description = "Detects SAML validation without replay attack protection";
  severity = Error;
  tags = ["saml"; "replay-attack"; "assertion-reuse"];
  check = fun ast ->
    (* Implementation skeleton:
       1. Find SAML assertion validation
       2. Check NotBefore/NotOnOrAfter validation
       3. Check InResponseTo matching
       4. Verify assertion ID tracking
       5. Check audience restriction validation
       
       Key patterns:
       - Missing timestamp validation
       - No assertion ID cache/store
       - Missing InResponseTo validation for SP-initiated flow
    *)
    []
}

(* Helper module for protocol detection *)
module Protocol_Context = struct
  type protocol = JWT | OAuth | SAML | Unknown
  
  let detect_protocol_usage ast =
    (* Scan imports and function calls to identify protocol usage *)
    let protocols_found = ref [] in
    
    let visitor = object
      inherit Ast_traverse.iter as super
      
      method! structure_item item =
        match item.pstr_desc with
        | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
            let module_name = flatten_longident txt |> String.concat "." in
            if contains_substring module_name "jose" || 
               contains_substring module_name "jwt" then
              protocols_found := JWT :: !protocols_found
            else if contains_substring module_name "oauth" then
              protocols_found := OAuth :: !protocols_found
            else if contains_substring module_name "saml" then
              protocols_found := SAML :: !protocols_found;
            super#structure_item item
        | _ -> super#structure_item item
    end in
    
    visitor#structure ast;
    !protocols_found
end

(* Common patterns module *)
module Security_Patterns = struct
  (* JWT specific patterns *)
  let jwt_unsafe_patterns = [
    "algorithm.*none";                    (* Accepting 'none' algorithm *)
    "decode.*without.*verify";            (* Decoding without verification *)
    "JSON\\.parse.*header";              (* Manual JWT parsing *)
    "base64.*decode.*split.*\\.";        (* Manual JWT decoding *)
  ]
  
  (* OAuth specific patterns *) 
  let oauth_unsafe_patterns = [
    "response_type=token";                (* Implicit flow *)
    "access_token.*url";                  (* Token in URL *)
    "console\\.log.*token";              (* Logging tokens *)
    "localStorage.*token";               (* Insecure storage *)
  ]
  
  (* SAML specific patterns *)
  let saml_unsafe_patterns = [
    "parseXML.*then.*verify";            (* Parse before verify *)
    "getElementsByTagName.*Assertion";    (* Unsafe XML navigation *)
    "disable.*entity.*expansion.*false";  (* XXE vulnerability *)
  ]
end

(* Suggested fixes module *)
module Remediation = struct
  let jwt_algorithm_fix = "
Example secure JWT validation:
```ocaml
(* Explicitly set allowed algorithms *)
let allowed_algorithms = [Jose.JWA.RS256; Jose.JWA.ES256]

let verify_jwt token key =
  match Jose.JWT.decode ~allowed_algorithms token with
  | Ok jwt ->
      (* Additional validations *)
      validate_expiry jwt.payload;
      validate_issuer jwt.payload;
      check_jti_not_replayed jwt.payload.jti
  | Error _ -> failwith \"Invalid JWT\"
```"

  let oauth_state_fix = "
Example secure OAuth flow:
```ocaml
(* Generate cryptographically secure state *)
let generate_state () =
  Mirage_crypto_rng.generate 32
  |> Base64.encode_string

(* Store state in session *)
let initiate_oauth session =
  let state = generate_state () in
  Session.set session \"oauth_state\" state;
  let auth_url = sprintf \"%s?client_id=%s&state=%s&response_type=code\"
    oauth_endpoint client_id state in
  redirect auth_url

(* Validate state on callback *)  
let oauth_callback session params =
  match Session.get session \"oauth_state\", params.state with
  | Some stored_state, Some received_state when 
      Eqaf.equal stored_state received_state ->
      (* State valid, proceed with token exchange *)
  | _ -> failwith \"CSRF detected: Invalid state parameter\"
```"

  let saml_signature_fix = "
Example secure SAML validation:
```ocaml
(* CRITICAL: Validate signature FIRST *)
let validate_saml_response saml_response =
  (* 1. Validate signature before ANY processing *)
  let signed_element = extract_signed_element saml_response in
  match verify_xml_signature signed_element trusted_cert with
  | Error _ -> failwith \"Invalid SAML signature\"
  | Ok () ->
      (* 2. Only now parse the validated XML *)
      let assertion = parse_saml_assertion signed_element in
      (* 3. Additional security checks *)
      validate_assertion_timestamps assertion;
      validate_audience assertion expected_audience;
      check_assertion_id_not_replayed assertion.id
```"
end

(* Main rule registration *)
let () =
  Registry.register jwt_algorithm_confusion_rule;
  Registry.register jwt_replay_attack_rule;
  Registry.register oauth_csrf_rule;
  Registry.register oauth_token_leak_rule;
  Registry.register saml_signature_wrapping_rule;
  Registry.register saml_replay_rule

(* 
Architecture Integration Notes:
- These rules will be loaded by the main analyzer
- They integrate with existing rule_engine infrastructure
- Severity levels align with existing schema (Critical > Error > Warning > Info)
- Each rule provides specific remediation guidance
- Rules are designed to minimize false positives through context awareness

Next Implementation Steps:
1. Implement actual AST pattern matching logic
2. Add configuration options for rule sensitivity
3. Create test cases for each vulnerability pattern
4. Integrate with Semgrep for enhanced pattern matching
5. Add support for custom protocol validators
*)