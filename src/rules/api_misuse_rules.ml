open Types
open Rule_engine
open Ppxlib

(* API001: ECB Mode Usage *)
let ecb_mode_rule : Rule.t = {
  id = "API001";
  name = "ECB Mode Usage";
  description = "Detects usage of ECB mode which is insecure for encryption";
  severity = Error;
  tags = ["api-misuse"; "ecb"; "block-cipher"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_ident {txt; _} | Pexp_construct ({txt; _}, _) ->
            let path = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            if String.contains_substring path "ecb" then
              findings := {
                rule_id = "API001";
                severity = Error;
                message = "ECB mode is insecure - reveals patterns in plaintext";
                vulnerability = InsecureMode "ECB";
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Never use ECB mode. Replace with:\n\
                   - Authenticated encryption: AES-GCM or ChaCha20-Poly1305\n\
                   - CBC with HMAC (encrypt-then-MAC)\n\
                   - CTR mode with authentication\n\
                   Example: Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce data";
                references = [
                  "https://blog.filippo.io/the-ecb-penguin/";
                  "CWE-327";
                ];
              } :: !findings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* API002: CBC Without MAC *)
let cbc_without_mac_rule : Rule.t = {
  id = "API002";
  name = "CBC Without MAC";
  description = "Detects CBC mode usage without message authentication";
  severity = Error;
  tags = ["api-misuse"; "cbc"; "mac"; "padding-oracle"];
  check = fun ast ->
    let findings = ref [] in
    let cbc_locations = ref [] in
    let mac_locations = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
            let path = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            if String.contains_substring path "cbc" then
              cbc_locations := expr.pexp_loc :: !cbc_locations
            else if List.exists (fun m -> String.contains_substring path m) 
                      ["hmac"; "mac"; "authenticate"; "poly1305"] then
              mac_locations := expr.pexp_loc :: !mac_locations;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    
    (* Check if CBC is used without nearby MAC *)
    List.iter (fun cbc_loc ->
      let has_nearby_mac = List.exists (fun mac_loc ->
        abs (cbc_loc.loc_start.pos_lnum - mac_loc.loc_start.pos_lnum) < 10
      ) !mac_locations in
      
      if not has_nearby_mac then
        findings := {
          rule_id = "API002";
          severity = Error;
          message = "CBC mode without authentication is vulnerable to padding oracle attacks";
          vulnerability = MissingAuthentication;
          location = {
            file = cbc_loc.loc_start.pos_fname;
            line = cbc_loc.loc_start.pos_lnum;
            column = cbc_loc.loc_start.pos_cnum - cbc_loc.loc_start.pos_bol;
            end_line = Some cbc_loc.loc_end.pos_lnum;
            end_column = Some (cbc_loc.loc_end.pos_cnum - cbc_loc.loc_end.pos_bol);
          };
          suggestion = Some 
            "Always authenticate CBC ciphertext:\n\
             - Use encrypt-then-MAC pattern\n\
             - Better: Use authenticated modes (GCM, CCM)\n\
             Example:\n\
             let encrypt_then_mac key data =\n\
               let ciphertext = Cipher.aes ~mode:CBC key data in\n\
               let mac = Hash.hmac_sha256 key ciphertext in\n\
               ciphertext ^ mac";
          references = [
            "CVE-2013-0169 (Lucky13)";
            "https://www.usenix.org/legacy/events/woot10/tech/full_papers/Rizzo.pdf";
          ];
        } :: !findings
    ) !cbc_locations;
    
    !findings
}

(* API003: Improper IV Generation *)
let improper_iv_generation_rule : Rule.t = {
  id = "API003";
  name = "Improper IV Generation";
  description = "Detects incorrect initialization vector generation methods";
  severity = Error;
  tags = ["api-misuse"; "iv"; "initialization-vector"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} when 
                  String.contains_substring (String.lowercase_ascii name) "iv" ||
                  String.contains_substring (String.lowercase_ascii name) "nonce" ->
                  (match vb.pvb_expr.pexp_desc with
                  | Pexp_constant (Pconst_string (_, _, _)) ->
                      findings := {
                        rule_id = "API003";
                        severity = Error;
                        message = "IV/nonce must not be hardcoded";
                        vulnerability = PredictableIV;
                        location = {
                          file = vb.pvb_expr.pexp_loc.loc_start.pos_fname;
                          line = vb.pvb_expr.pexp_loc.loc_start.pos_lnum;
                          column = vb.pvb_expr.pexp_loc.loc_start.pos_cnum - vb.pvb_expr.pexp_loc.loc_start.pos_bol;
                          end_line = Some vb.pvb_expr.pexp_loc.loc_end.pos_lnum;
                          end_column = Some (vb.pvb_expr.pexp_loc.loc_end.pos_cnum - vb.pvb_expr.pexp_loc.loc_end.pos_bol);
                        };
                        suggestion = Some 
                          "Generate IVs properly:\n\
                           - CBC: Random IV for each message\n\
                           - CTR: Sequential/random nonce\n\
                           - GCM: Unique 96-bit nonce\n\
                           Example: let iv = Mirage_crypto_rng.generate 16";
                        references = [
                          "NIST SP 800-38A";
                          "CWE-329";
                        ];
                      } :: !findings
                  | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (Lident "String", "make"); _}; _}, _) ->
                      findings := {
                        rule_id = "API003";
                        severity = Error;
                        message = "IV generated with String.make is predictable";
                        vulnerability = PredictableIV;
                        location = {
                          file = vb.pvb_expr.pexp_loc.loc_start.pos_fname;
                          line = vb.pvb_expr.pexp_loc.loc_start.pos_lnum;
                          column = vb.pvb_expr.pexp_loc.loc_start.pos_cnum - vb.pvb_expr.pexp_loc.loc_start.pos_bol;
                          end_line = Some vb.pvb_expr.pexp_loc.loc_end.pos_lnum;
                          end_column = Some (vb.pvb_expr.pexp_loc.loc_end.pos_cnum - vb.pvb_expr.pexp_loc.loc_end.pos_bol);
                        };
                        suggestion = Some "Use cryptographic random: Mirage_crypto_rng.generate";
                        references = ["CWE-329"];
                      } :: !findings
                  | _ -> ())
              | _ -> ()
            ) bindings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* API004: Missing Padding Validation *)
let missing_padding_validation_rule : Rule.t = {
  id = "API004";
  name = "Missing Padding Validation";
  description = "Detects decryption without proper padding validation";
  severity = Warning;
  tags = ["api-misuse"; "padding"; "validation"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
            let path = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            if String.contains_substring path "decrypt" &&
               (String.contains_substring path "cbc" || 
                String.contains_substring path "ecb") then
              findings := {
                rule_id = "API004";
                severity = Warning;
                message = "Block cipher decryption should validate padding";
                vulnerability = InsecurePadding;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Validate padding after decryption:\n\
                   - Check PKCS#7 padding correctly\n\
                   - Handle padding errors without revealing info\n\
                   - Better: Use authenticated encryption (AEAD)\n\
                   Example:\n\
                   match unpad_pkcs7 decrypted with\n\
                   | Ok data -> process data\n\
                   | Error _ -> constant_time_error_response ()";
                references = [
                  "CVE-2002-20001 (Zombie POODLE)";
                  "https://www.openssl.org/~bodo/ssl-poodle.pdf";
                ];
              } :: !findings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* API005: Incorrect Random Number Usage *)
let incorrect_random_usage_rule : Rule.t = {
  id = "API005";
  name = "Incorrect Random Number Usage";
  description = "Detects improper use of random number generators";
  severity = Error;
  tags = ["api-misuse"; "random"; "entropy"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = Longident.flatten txt |> String.concat "." in
            
            (* Check for Random.self_init in crypto context *)
            if path = "Random.self_init" then
              findings := {
                rule_id = "API005";
                severity = Error;
                message = "Random.self_init uses predictable seed (current time)";
                vulnerability = WeakRandom;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Initialize crypto RNG properly:\n\
                   - Mirage_crypto_rng_unix.initialize ()\n\
                   - Nocrypto_entropy_unix.initialize ()\n\
                   - Never use Random module for crypto";
                references = [
                  "CWE-338";
                  "https://mirage.io/blog/mirage-entropy";
                ];
              } :: !findings
            
            (* Check for insufficient random bytes *)
            else if List.mem path ["Random.int"; "Random.bits"] then
              List.iter (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_constant (Pconst_integer (n, _)) ->
                    let bits = int_of_string n in
                    if bits < 128 then
                      findings := {
                        rule_id = "API005";
                        severity = Warning;
                        message = Printf.sprintf "Only %d bits of randomness - insufficient for crypto" bits;
                        vulnerability = WeakRandom;
                        location = {
                          file = arg.pexp_loc.loc_start.pos_fname;
                          line = arg.pexp_loc.loc_start.pos_lnum;
                          column = arg.pexp_loc.loc_start.pos_cnum - arg.pexp_loc.loc_start.pos_bol;
                          end_line = Some arg.pexp_loc.loc_end.pos_lnum;
                          end_column = Some (arg.pexp_loc.loc_end.pos_cnum - arg.pexp_loc.loc_end.pos_bol);
                        };
                        suggestion = Some "Use at least 128 bits of entropy for crypto operations";
                        references = ["NIST SP 800-90A"];
                      } :: !findings
                | _ -> ()
              ) args;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* API006: Unverified Certificates *)
let unverified_certificates_rule : Rule.t = {
  id = "API006";
  name = "Unverified Certificates";
  description = "Detects TLS/SSL connections without certificate verification";
  severity = Critical;
  tags = ["api-misuse"; "tls"; "certificate"; "verification"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_record (fields, _) ->
            let is_tls_config = List.exists (fun (field, _) ->
              match field.txt with
              | Lident name -> String.contains_substring name "authenticator" ||
                               String.contains_substring name "certificates"
              | _ -> false
            ) fields in
            
            if is_tls_config then
              let has_null_auth = List.exists (fun (field, value) ->
                match field.txt, value.pexp_desc with
                | Lident "authenticator", Pexp_construct ({txt = Lident "None"; _}, _) -> true
                | Lident "authenticator", Pexp_ident {txt = Lident name; _} ->
                    String.contains_substring (String.lowercase_ascii name) "null" ||
                    String.contains_substring (String.lowercase_ascii name) "none"
                | _ -> false
              ) fields in
              
              if has_null_auth then
                findings := {
                  rule_id = "API006";
                  severity = Critical;
                  message = "TLS connection without certificate verification";
                  vulnerability = MissingAuthentication;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some 
                    "Always verify certificates:\n\
                     - Use Ca_certs.authenticator ()\n\
                     - Or X509.Authenticator.chain_of_trust\n\
                     Example:\n\
                     let authenticator = Ca_certs.authenticator () in\n\
                     Tls.Config.client ~authenticator ()";
                  references = [
                    "CWE-295";
                    "https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication";
                  ];
                } :: !findings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* API007: Missing Nonce Increment in CTR Mode *)
let missing_ctr_increment_rule : Rule.t = {
  id = "API007";
  name = "Missing CTR Mode Nonce Increment";
  description = "Detects CTR mode usage without proper counter management";
  severity = Critical;
  tags = ["api-misuse"; "ctr"; "nonce"; "counter"];
  check = fun ast ->
    let findings = ref [] in
    let ctr_nonces = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            if String.contains_substring path "ctr" then
              List.iter (fun (label, arg) ->
                match label with
                | Asttypes.Labelled ("ctr" | "counter" | "nonce") ->
                    (match arg.pexp_desc with
                    | Pexp_ident {txt = Lident name; _} ->
                        if List.mem name !ctr_nonces then
                          findings := {
                            rule_id = "API007";
                            severity = Critical;
                            message = "CTR mode counter reused - destroys security";
                            vulnerability = NonceReuse;
                            location = {
                              file = arg.pexp_loc.loc_start.pos_fname;
                              line = arg.pexp_loc.loc_start.pos_lnum;
                              column = arg.pexp_loc.loc_start.pos_cnum - arg.pexp_loc.loc_start.pos_bol;
                              end_line = Some arg.pexp_loc.loc_end.pos_lnum;
                              end_column = Some (arg.pexp_loc.loc_end.pos_cnum - arg.pexp_loc.loc_end.pos_bol);
                            };
                            suggestion = Some 
                              "Properly manage CTR counters:\n\
                               - Increment after each block\n\
                               - Never reuse counter values\n\
                               - Use stateful counter:\n\
                               type ctr_state = { mutable counter: int64 }\n\
                               let next_ctr state = \n\
                                 let c = state.counter in\n\
                                 state.counter <- Int64.succ c;\n\
                                 c";
                            references = [
                              "NIST SP 800-38A";
                              "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf";
                            ];
                          } :: !findings
                        else
                          ctr_nonces := name :: !ctr_nonces
                    | _ -> ())
                | _ -> ()
              ) args;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

let () =
  Registry.register ecb_mode_rule;
  Registry.register cbc_without_mac_rule;
  Registry.register improper_iv_generation_rule;
  Registry.register missing_padding_validation_rule;
  Registry.register incorrect_random_usage_rule;
  Registry.register unverified_certificates_rule;
  Registry.register missing_ctr_increment_rule