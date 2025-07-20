open Types
open Rule_engine
open Ppxlib
open Utils

(* Context-aware analysis module *)
module Algorithm_context = struct
  type usage_context = 
    | Security_critical   (* Signatures, authentication, encryption *)
    | Legacy_compatible   (* Backward compatibility requirement *)
    | Non_security       (* Checksums, version control, etc *)
    | Unknown
  
  let detect_usage_context ast_context var_name =
    let security_patterns = [
      "sign"; "verify"; "encrypt"; "decrypt"; "auth"; "mac"; "hmac";
      "certificate"; "token"; "session"; "credential"
    ] in
    
    let non_security_patterns = [
      "checksum"; "git"; "version"; "cache"; "etag"; "identifier";
      "filename"; "debug"; "log"; "display"
    ] in
    
    let ctx_string = String.lowercase_ascii ast_context in
    let var_lower = String.lowercase_ascii var_name in
    
    if List.exists (fun p -> contains_substring ctx_string p || 
                             contains_substring var_lower p) security_patterns then
      Security_critical
    else if List.exists (fun p -> contains_substring ctx_string p ||
                                  contains_substring var_lower p) non_security_patterns then
      Non_security
    else
      Unknown
end

(* ALGO002: Weak Hash Functions - Context-Aware *)
let weak_hash_rule_v2 : Rule.t = {
  id = "ALGO002";
  name = "Weak Hash Algorithm";
  description = "Detects usage of weak hash functions with context awareness";
  severity = Error;
  tags = ["algorithm"; "hash"; "weak-crypto"; "context-aware"];
  check = fun ast ->
    let weak_hashes = [
      ("md5", "MD5", "CVE-2013-2566", 1);
      ("sha1", "SHA-1", "CVE-2017-15999 (SHAttered)", 2);
      ("md4", "MD4", "CVE-2011-3368", 0);
      ("md2", "MD2", "CVE-2009-2409", 0);
    ] in
    let findings = ref [] in
    let current_context = ref "" in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! structure_item item =
        match item.pstr_desc with
        | Pstr_value (_, bindings) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} -> current_context := name
              | _ -> ()
            ) bindings;
            super#structure_item item
        | _ -> super#structure_item item
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path_str = flatten_longident txt |> String.concat "." |> String.lowercase_ascii in
            
            List.iter (fun (pattern, name, cve, risk_level) ->
              if contains_substring path_str pattern && 
                 contains_substring path_str "hash" then
                let usage_context = Algorithm_context.detect_usage_context !current_context "" in
                
                let (severity, extra_msg) = match usage_context, risk_level with
                  | Algorithm_context.Security_critical, _ -> (Error, " in security-critical context")
                  | Algorithm_context.Non_security, 2 -> (Info, " (acceptable for non-security use)")
                  | Algorithm_context.Non_security, _ -> (Warning, " in non-security context")
                  | Algorithm_context.Legacy_compatible, _ -> (Warning, " for legacy compatibility")
                  | Algorithm_context.Unknown, 0 -> (Error, "")
                  | Algorithm_context.Unknown, 1 -> (Error, "")
                  | Algorithm_context.Unknown, 2 -> (Warning, " (context unclear)")
                  | _ -> (Warning, "")
                in
                
                findings := {
                  rule_id = "ALGO002";
                  severity;
                  message = Printf.sprintf "Weak hash algorithm detected: %s%s" name extra_msg;
                  vulnerability = WeakHash name;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some (
                    match usage_context with
                    | Algorithm_context.Security_critical ->
                        Printf.sprintf 
                          "Critical: Replace %s immediately:\n\
                           - SHA-256/384/512: Mirage_crypto.Hash.SHA256\n\
                           - BLAKE2b: High performance alternative\n\
                           - SHA-3: Future-proof option"
                          name
                    | Algorithm_context.Non_security ->
                        Printf.sprintf 
                          "%s is acceptable for non-security use cases.\n\
                           Consider SHA-256 for future-proofing:\n\
                           - Mirage_crypto.Hash.SHA256.digest"
                          name
                    | _ ->
                        Printf.sprintf 
                          "Replace %s with secure alternatives:\n\
                           - SHA-256: Mirage_crypto.Hash.SHA256\n\
                           - BLAKE2b: Faster than SHA-256\n\
                           - Context detected: %s"
                          name (match usage_context with
                            | Legacy_compatible -> "legacy compatibility"
                            | _ -> "unknown")
                  );
                  references = [
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf";
                    cve;
                  ];
                } :: !findings
            ) weak_hashes;
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* ALGO001: Weak Ciphers - Enhanced with migration paths *)
let weak_cipher_rule_v2 : Rule.t = {
  id = "ALGO001";
  name = "Weak Cipher Algorithm";
  description = "Detects weak ciphers with specific migration guidance";
  severity = Error;
  tags = ["algorithm"; "cipher"; "weak-crypto"; "enhanced"];
  check = fun ast ->
    let weak_ciphers = [
      ("arcfour", "ARC4/RC4", "stream", "ChaCha20-Poly1305");
      ("rc4", "RC4", "stream", "ChaCha20-Poly1305");
      ("des", "DES", "block-64", "AES-256-GCM");
      ("3des", "3DES", "block-64", "AES-256-GCM");
      ("triple_des", "3DES", "block-64", "AES-256-GCM");
      ("blowfish", "Blowfish", "block-64", "AES-256-GCM");
    ] in
    let findings = ref [] in
    let in_legacy_code = ref false in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! structure_item item =
        (* Check for legacy markers in comments *)
        match item.pstr_desc with
        | Pstr_attribute {attr_name = {txt = "deprecated"; _}; _} ->
            in_legacy_code := true
        | _ -> ();
        super#structure_item item
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_ident {txt; _} | Pexp_construct ({txt; _}, _) ->
            let path_str = flatten_longident txt |> String.concat "." |> String.lowercase_ascii in
            
            List.iter (fun (pattern, name, cipher_type, replacement) ->
              if contains_substring path_str pattern then
                let severity = if !in_legacy_code then Warning else Error in
                
                findings := {
                  rule_id = "ALGO001";
                  severity;
                  message = Printf.sprintf "Weak %s cipher detected: %s%s" 
                    cipher_type name
                    (if !in_legacy_code then " in legacy code" else "");
                  vulnerability = WeakCipher name;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some (Printf.sprintf 
                    "Migration guide for %s:\n\
                     1. Immediate replacement: %s\n\
                     2. Implementation:\n%s\n\
                     3. %s"
                    name replacement
                    (match cipher_type with
                     | "stream" -> 
                         "   let key = Mirage_crypto_rng.generate 32 in\n\
                          \   let nonce = Mirage_crypto_rng.generate 12 in\n\
                          \   Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce data"
                     | "block-64" ->
                         "   let key = Mirage_crypto_rng.generate 32 in\n\
                          \   let nonce = Mirage_crypto_rng.generate 12 in\n\
                          \   Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce data"
                     | _ -> "   See documentation for details")
                    (if cipher_type = "block-64" then
                       "Warning: 64-bit block ciphers vulnerable to SWEET32 attack"
                     else
                       "Performance: ChaCha20 is faster on systems without AES-NI"));
                  references = [
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf";
                    if name = "RC4" then "CVE-2015-2808" 
                    else if contains_substring name "DES" then "CVE-2016-2183 (SWEET32)"
                    else "CWE-327";
                  ];
                } :: !findings
            ) weak_ciphers;
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* ALGO003: Insecure ECC Curves - Enhanced with safe curve recommendations *)
let insecure_ecc_curve_rule_v2 : Rule.t = {
  id = "ALGO003";
  name = "Insecure Elliptic Curve";
  description = "Detects weak curves with SafeCurves.cr.yp.to criteria";
  severity = Error;
  tags = ["algorithm"; "ecc"; "curve"; "weak-crypto"; "enhanced"];
  check = fun ast ->
    let curve_analysis = [
      ("secp192r1", "192-bit", Error, "Too small for modern security");
      ("secp224r1", "224-bit", Warning, "Borderline secure until 2030");
      ("secp256r1", "NIST P-256", Info, "Acceptable but consider Curve25519");
      ("secp256k1", "Bitcoin curve", Warning, "Secure but not for general use");
      ("brainpool", "Brainpool", Warning, "Patent concerns, less studied");
      ("curve25519", "Curve25519", Info, "Recommended - meets all SafeCurves criteria");
      ("ed25519", "Ed25519", Info, "Recommended for signatures");
    ] in
    let findings = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_constant (Pconst_string (s, _, _)) 
        | Pexp_construct ({txt = Lident s; _}, _) ->
            let lower = String.lowercase_ascii s in
            
            List.iter (fun (pattern, name, severity, reason) ->
              if contains_substring lower pattern then
                findings := {
                  rule_id = "ALGO003";
                  severity;
                  message = Printf.sprintf "Elliptic curve %s: %s" name reason;
                  vulnerability = WeakCipher (Printf.sprintf "curve-%s" pattern);
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some (
                    match severity with
                    | Error ->
                        "Use SafeCurves-approved curves:\n\
                         - Curve25519: Key exchange (X25519)\n\
                         - Ed25519: Signatures\n\
                         - Implementation: Mirage_crypto_ec.X25519.gen_key ()"
                    | Warning ->
                        Printf.sprintf 
                          "Consider migration to safer curves:\n\
                           - Current: %s\n\
                           - Recommended: Curve25519/Ed25519\n\
                           - Reason to switch: %s"
                          name reason
                    | _ ->
                        Printf.sprintf "%s is acceptable but consider Curve25519 for new systems" name
                  );
                  references = [
                    "https://safecurves.cr.yp.to/";
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf";
                  ];
                } :: !findings
            ) curve_analysis;
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

let () =
  Registry.register weak_hash_rule_v2;
  Registry.register weak_cipher_rule_v2;
  Registry.register insecure_ecc_curve_rule_v2