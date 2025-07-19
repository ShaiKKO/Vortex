open Types
open Rule_engine
open Ppxlib

(* KEY001: Hardcoded Cryptographic Keys *)
let hardcoded_key_rule : Rule.t = {
  id = "KEY001";
  name = "Hardcoded Cryptographic Key";
  description = "Detects hardcoded keys, passwords, and secrets in source code";
  severity = Critical;
  tags = ["key-management"; "hardcoded"; "secret"];
  check = fun ast ->
    let findings = ref [] in
    let key_patterns = [
      "key"; "password"; "secret"; "token"; "api_key"; "private_key"; 
      "auth"; "credential"; "passphrase"
    ] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc, vb.pvb_expr.pexp_desc with
              | Ppat_var {txt = name; _}, Pexp_constant (Pconst_string (value, _, _)) ->
                  let lower_name = String.lowercase_ascii name in
                  if List.exists (fun pattern -> 
                    String.contains_substring lower_name pattern
                  ) key_patterns && String.length value >= 8 then
                    findings := {
                      rule_id = "KEY001";
                      severity = Critical;
                      message = Printf.sprintf "Hardcoded %s detected" name;
                      vulnerability = HardcodedKey;
                      location = {
                        file = vb.pvb_expr.pexp_loc.loc_start.pos_fname;
                        line = vb.pvb_expr.pexp_loc.loc_start.pos_lnum;
                        column = vb.pvb_expr.pexp_loc.loc_start.pos_cnum - vb.pvb_expr.pexp_loc.loc_start.pos_bol;
                        end_line = Some vb.pvb_expr.pexp_loc.loc_end.pos_lnum;
                        end_column = Some (vb.pvb_expr.pexp_loc.loc_end.pos_cnum - vb.pvb_expr.pexp_loc.loc_end.pos_bol);
                      };
                      suggestion = Some 
                        "Never hardcode secrets. Use:\n\
                         - Environment variables: Sys.getenv \"MY_SECRET_KEY\"\n\
                         - Configuration files (not in version control)\n\
                         - Key management services (AWS KMS, HashiCorp Vault)\n\
                         - OCaml example: let key = Sys.getenv_opt \"CRYPTO_KEY\" |> Option.get";
                      references = [
                        "CWE-798";
                        "OWASP A07:2021 - Identification and Authentication Failures";
                      ];
                    } :: !findings
              | _ -> ()
            ) bindings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* KEY002: Predictable Key Generation *)
let predictable_key_rule : Rule.t = {
  id = "KEY002";
  name = "Predictable Key Generation";
  description = "Detects weak or predictable methods of generating cryptographic keys";
  severity = Critical;
  tags = ["key-management"; "random"; "predictable"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = Longident.flatten txt |> String.concat "." in
            (* Check for weak random usage in key generation *)
            if (String.contains_substring path "Random" && 
                not (String.contains_substring path "Cryptokit" || 
                     String.contains_substring path "Nocrypto" ||
                     String.contains_substring path "Mirage_crypto")) &&
               List.exists (fun (_, arg) ->
                 match arg.pexp_desc with
                 | Pexp_constant (Pconst_integer (n, _)) ->
                     let size = int_of_string n in
                     size >= 16 (* Likely a key size *)
                 | _ -> false
               ) args then
              findings := {
                rule_id = "KEY002";
                severity = Critical;
                message = "Predictable random number generator used for key generation";
                vulnerability = WeakRandom;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Use cryptographically secure random:\n\
                   - Mirage_crypto_rng.generate size\n\
                   - Cryptokit.Random.string size\n\
                   - Nocrypto.Rng.generate size\n\
                   Example: let key = Mirage_crypto_rng.generate 32";
                references = [
                  "CWE-338";
                  "NIST SP 800-90A Rev. 1";
                ];
              } :: !findings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* KEY003: Nonce Reuse in AEAD *)
let aead_nonce_reuse_rule : Rule.t = {
  id = "KEY003";
  name = "AEAD Nonce Reuse";
  description = "Detects potential nonce reuse in authenticated encryption (GCM, ChaCha20-Poly1305)";
  severity = Critical;
  tags = ["nonce"; "aead"; "gcm"; "chacha20"];
  check = fun ast ->
    let findings = ref [] in
    let nonce_tracking = Hashtbl.create 32 in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} when 
                  String.contains_substring (String.lowercase_ascii name) "nonce" ||
                  String.contains_substring (String.lowercase_ascii name) "iv" ->
                  Hashtbl.add nonce_tracking name vb.pvb_expr
              | _ -> ()
            ) bindings;
            super#expression expr ()
        
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            if (String.contains_substring path "gcm" || 
                String.contains_substring path "chacha20" ||
                String.contains_substring path "authenticate_encrypt") then
              List.iter (fun (label, arg) ->
                match label, arg.pexp_desc with
                | Asttypes.Labelled ("nonce" | "iv"), Pexp_ident {txt = Lident nonce_var; _} ->
                    if Hashtbl.mem nonce_tracking nonce_var then
                      let count = 
                        try (Hashtbl.find_all nonce_tracking nonce_var |> List.length)
                        with Not_found -> 0 in
                      if count > 1 then
                        findings := {
                          rule_id = "KEY003";
                          severity = Critical;
                          message = "AEAD nonce reuse detected - catastrophic for security";
                          vulnerability = NonceReuse;
                          location = {
                            file = arg.pexp_loc.loc_start.pos_fname;
                            line = arg.pexp_loc.loc_start.pos_lnum;
                            column = arg.pexp_loc.loc_start.pos_cnum - arg.pexp_loc.loc_start.pos_bol;
                            end_line = Some arg.pexp_loc.loc_end.pos_lnum;
                            end_column = Some (arg.pexp_loc.loc_end.pos_cnum - arg.pexp_loc.loc_end.pos_bol);
                          };
                          suggestion = Some 
                            "Never reuse nonces in AEAD:\n\
                             - Generate fresh nonce for each encryption\n\
                             - Use counter-based nonces with proper state\n\
                             - Example: let nonce = Mirage_crypto_rng.generate 12\n\
                             - Or use Mirage_crypto.Cipher_block.S.GCM.of_secret with unique nonces";
                          references = [
                            "CVE-2016-0270";
                            "https://github.com/nonce-disrespect/nonce-disrespect";
                          ];
                        } :: !findings
                | _ -> ()
              ) args;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* KEY004: Static IV in Block Ciphers *)
let static_iv_rule : Rule.t = {
  id = "KEY004";
  name = "Static IV in Block Cipher";
  description = "Detects static or predictable initialization vectors";
  severity = Error;
  tags = ["iv"; "initialization-vector"; "block-cipher"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc, vb.pvb_expr.pexp_desc with
              | Ppat_var {txt = name; _}, Pexp_constant (Pconst_string (value, _, _))
                when String.contains_substring (String.lowercase_ascii name) "iv" &&
                     String.for_all (fun c -> c = '\000') value ->
                  findings := {
                    rule_id = "KEY004";
                    severity = Error;
                    message = "Static/zero IV detected in block cipher";
                    vulnerability = PredictableIV;
                    location = {
                      file = vb.pvb_expr.pexp_loc.loc_start.pos_fname;
                      line = vb.pvb_expr.pexp_loc.loc_start.pos_lnum;
                      column = vb.pvb_expr.pexp_loc.loc_start.pos_cnum - vb.pvb_expr.pexp_loc.loc_start.pos_bol;
                      end_line = Some vb.pvb_expr.pexp_loc.loc_end.pos_lnum;
                      end_column = Some (vb.pvb_expr.pexp_loc.loc_end.pos_cnum - vb.pvb_expr.pexp_loc.loc_end.pos_bol);
                    };
                    suggestion = Some 
                      "Generate random IVs for CBC mode:\n\
                       - let iv = Mirage_crypto_rng.generate 16\n\
                       - For CTR: use incrementing counter\n\
                       - For GCM: unique 96-bit nonce\n\
                       - Store/transmit IV with ciphertext";
                    references = [
                      "CWE-329";
                      "NIST SP 800-38A";
                    ];
                  } :: !findings
              | _ -> ()
            ) bindings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* KEY005: Insufficient Key Derivation *)
let weak_kdf_iterations_rule : Rule.t = {
  id = "KEY005";
  name = "Insufficient KDF Iterations";
  description = "Detects weak key derivation function parameters";
  severity = Warning;
  tags = ["kdf"; "pbkdf2"; "scrypt"; "argon2"];
  check = fun ast ->
    let findings = ref [] in
    let min_iterations = [
      ("pbkdf2", 100_000);
      ("scrypt", 16_384); (* N parameter *)
      ("argon2", 3); (* time cost *)
    ] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            List.iter (fun (kdf_name, min_value) ->
              if String.contains_substring path kdf_name then
                List.iter (fun (label, arg) ->
                  match label, arg.pexp_desc with
                  | Asttypes.Labelled ("iterations" | "count" | "n" | "time_cost"), 
                    Pexp_constant (Pconst_integer (n, _)) ->
                      let value = int_of_string n in
                      if value < min_value then
                        findings := {
                          rule_id = "KEY005";
                          severity = Warning;
                          message = Printf.sprintf "%s with %d iterations is too weak" kdf_name value;
                          vulnerability = WeakKDF;
                          location = {
                            file = arg.pexp_loc.loc_start.pos_fname;
                            line = arg.pexp_loc.loc_start.pos_lnum;
                            column = arg.pexp_loc.loc_start.pos_cnum - arg.pexp_loc.loc_start.pos_bol;
                            end_line = Some arg.pexp_loc.loc_end.pos_lnum;
                            end_column = Some (arg.pexp_loc.loc_end.pos_cnum - arg.pexp_loc.loc_end.pos_bol);
                          };
                          suggestion = Some (Printf.sprintf
                            "Use stronger KDF parameters:\n\
                             - PBKDF2: minimum 100,000 iterations (2025 standard)\n\
                             - scrypt: N=16384, r=8, p=1 minimum\n\
                             - Argon2id: time=3, memory=64MB, parallelism=4\n\
                             - Current: %d, Recommended: %d" value min_value);
                          references = [
                            "NIST SP 800-132";
                            "OWASP Password Storage Cheat Sheet";
                          ];
                        } :: !findings
                  | _ -> ()
                ) args
            ) min_iterations;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* KEY006: Key Storage in Plaintext *)
let plaintext_key_storage_rule : Rule.t = {
  id = "KEY006";
  name = "Plaintext Key Storage";
  description = "Detects keys stored or written to files without encryption";
  severity = Error;
  tags = ["key-management"; "storage"; "plaintext"];
  check = fun ast ->
    let findings = ref [] in
    let key_vars = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} when 
                  String.contains_substring (String.lowercase_ascii name) "key" ||
                  String.contains_substring (String.lowercase_ascii name) "secret" ->
                  key_vars := name :: !key_vars
              | _ -> ()
            ) bindings;
            super#expression expr ()
        
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = Longident.flatten txt |> String.concat "." in
            if List.mem path ["Out_channel.output_string"; "output_string"; 
                               "Out_channel.write"; "Stdlib.output"] then
              List.iter (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_ident {txt = Lident var; _} when List.mem var !key_vars ->
                    findings := {
                      rule_id = "KEY006";
                      severity = Error;
                      message = "Key material written to file in plaintext";
                      vulnerability = HardcodedKey;
                      location = {
                        file = expr.pexp_loc.loc_start.pos_fname;
                        line = expr.pexp_loc.loc_start.pos_lnum;
                        column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                        end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                        end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                      };
                      suggestion = Some 
                        "Encrypt keys before storage:\n\
                         - Use key wrapping (AES-KW)\n\
                         - Store in secure key stores\n\
                         - Example: let wrapped = Mirage_crypto.AES.KW.wrap_key ~kek master_key\n\
                         - Use OS keychain APIs when available";
                      references = [
                        "CWE-312";
                        "NIST SP 800-57 Part 1";
                      ];
                    } :: !findings
                | _ -> ()
              ) args;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

let () =
  Registry.register hardcoded_key_rule;
  Registry.register predictable_key_rule;
  Registry.register aead_nonce_reuse_rule;
  Registry.register static_iv_rule;
  Registry.register weak_kdf_iterations_rule;
  Registry.register plaintext_key_storage_rule