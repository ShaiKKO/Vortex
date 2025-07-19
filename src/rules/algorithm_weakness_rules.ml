open Types
open Rule_engine
open Ppxlib

(* ALGO001: Weak Ciphers *)
let weak_cipher_rule : Rule.t = {
  id = "ALGO001";
  name = "Weak Cipher Algorithm";
  description = "Detects usage of cryptographically weak ciphers (ARC4, DES, 3DES, Blowfish)";
  severity = Error;
  tags = ["algorithm"; "cipher"; "weak-crypto"];
  check = fun ast ->
    let weak_ciphers = [
      ("arcfour", "ARC4/RC4");
      ("rc4", "RC4");
      ("des", "DES");
      ("3des", "3DES");
      ("triple_des", "3DES");
      ("blowfish", "Blowfish");
    ] in
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_ident {txt; _} | Pexp_construct ({txt; _}, _) ->
            let path_str = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            List.iter (fun (pattern, name) ->
              if String.contains_substring path_str pattern then
                findings := {
                  rule_id = "ALGO001";
                  severity = Error;
                  message = Printf.sprintf "Weak cipher algorithm detected: %s" name;
                  vulnerability = WeakCipher name;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some (Printf.sprintf 
                    "Replace %s with modern alternatives:\n\
                     - For stream ciphers: Use ChaCha20-Poly1305 (Mirage_crypto.Chacha20.authenticate_encrypt)\n\
                     - For block ciphers: Use AES-256-GCM (Mirage_crypto.AES.GCM.authenticate_encrypt)"
                    name);
                  references = [
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf";
                    "CVE-2015-2808 (RC4)"; "CVE-2016-2183 (3DES/SWEET32)";
                  ];
                } :: !findings
            ) weak_ciphers;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* ALGO002: Weak Hash Functions *)
let weak_hash_rule : Rule.t = {
  id = "ALGO002";
  name = "Weak Hash Algorithm";
  description = "Detects usage of cryptographically broken hash functions (MD5, SHA1, MD4)";
  severity = Error;
  tags = ["algorithm"; "hash"; "weak-crypto"];
  check = fun ast ->
    let weak_hashes = [
      ("md5", "MD5", "CVE-2013-2566");
      ("sha1", "SHA-1", "CVE-2017-15999 (SHAttered)");
      ("md4", "MD4", "CVE-2011-3368");
      ("md2", "MD2", "CVE-2009-2409");
    ] in
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
            let path_str = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            List.iter (fun (pattern, name, cve) ->
              if String.contains_substring path_str pattern && 
                 String.contains_substring path_str "hash" then
                findings := {
                  rule_id = "ALGO002";
                  severity = Error;
                  message = Printf.sprintf "Weak hash algorithm detected: %s" name;
                  vulnerability = WeakHash name;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some (Printf.sprintf 
                    "Replace %s with secure alternatives:\n\
                     - For general hashing: SHA-256, SHA-384, SHA-512 (Mirage_crypto.Hash.SHA256)\n\
                     - For passwords: Argon2id, scrypt, or bcrypt\n\
                     - For performance: BLAKE2b (faster than SHA-256)"
                    name);
                  references = [
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf";
                    cve;
                  ];
                } :: !findings
            ) weak_hashes;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* ALGO003: Insecure ECC Curves *)
let insecure_ecc_curve_rule : Rule.t = {
  id = "ALGO003";
  name = "Insecure Elliptic Curve";
  description = "Detects usage of weak or backdoored elliptic curves";
  severity = Error;
  tags = ["algorithm"; "ecc"; "curve"; "weak-crypto"];
  check = fun ast ->
    let weak_curves = [
      ("secp192r1", "192-bit curve (too small)");
      ("secp224r1", "224-bit curve (borderline secure)");
      ("secp256k1", "Bitcoin curve (not recommended for general use)");
      ("brainpool", "Brainpool curves (potential backdoor concerns)");
      ("nist", "NIST curves (use with caution due to NSA involvement)");
    ] in
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_constant (Pconst_string (s, _, _)) 
        | Pexp_construct ({txt = Lident s; _}, _) ->
            let lower = String.lowercase_ascii s in
            List.iter (fun (pattern, reason) ->
              if String.contains_substring lower pattern then
                findings := {
                  rule_id = "ALGO003";
                  severity = Error;
                  message = Printf.sprintf "Potentially insecure elliptic curve: %s" reason;
                  vulnerability = WeakCipher (Printf.sprintf "curve-%s" pattern);
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some 
                    "Use secure curves:\n\
                     - Curve25519 for key exchange (Mirage_crypto_ec.X25519)\n\
                     - Ed25519 for signatures (Mirage_crypto_ec.Ed25519)\n\
                     - P-256, P-384, P-521 if NIST curves required";
                  references = [
                    "https://safecurves.cr.yp.to/";
                    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf";
                  ];
                } :: !findings
            ) weak_curves;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* ALGO004: Small Block Ciphers *)
let small_block_cipher_rule : Rule.t = {
  id = "ALGO004";
  name = "Small Block Size Cipher";
  description = "Detects ciphers with 64-bit blocks vulnerable to birthday attacks";
  severity = Error;
  tags = ["algorithm"; "block-size"; "birthday-attack"];
  check = fun ast ->
    let small_block_ciphers = [
      "des"; "3des"; "triple_des"; "blowfish"; "cast"; "idea"; "rc2"
    ] in
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
            let path_str = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
            if List.exists (fun cipher -> 
              String.contains_substring path_str cipher
            ) small_block_ciphers then
              findings := {
                rule_id = "ALGO004";
                severity = Error;
                message = "Cipher with 64-bit block size is vulnerable to birthday attacks (SWEET32)";
                vulnerability = WeakCipher "64-bit-block";
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Use ciphers with 128-bit blocks or larger:\n\
                   - AES (128-bit blocks): Mirage_crypto.AES\n\
                   - ChaCha20 (stream cipher): Mirage_crypto.Chacha20";
                references = [
                  "CVE-2016-2183 (SWEET32)";
                  "https://sweet32.info/";
                ];
              } :: !findings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* ALGO005: Weak Key Exchange *)
let weak_key_exchange_rule : Rule.t = {
  id = "ALGO005";
  name = "Weak Key Exchange Parameters";
  description = "Detects Diffie-Hellman with parameters < 2048 bits";
  severity = Error;
  tags = ["algorithm"; "key-exchange"; "dh"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) 
          when String.contains_substring (Longident.flatten txt |> String.concat "." |> String.lowercase_ascii) "dh" ->
            List.iter (fun (label, arg) ->
              match label, arg.pexp_desc with
              | Asttypes.Labelled ("bits" | "size" | "modulus_size"), 
                Pexp_constant (Pconst_integer (n, _)) ->
                  let bits = int_of_string n in
                  if bits < 2048 then
                    findings := {
                      rule_id = "ALGO005";
                      severity = Error;
                      message = Printf.sprintf "Diffie-Hellman with %d-bit parameters is too weak" bits;
                      vulnerability = InsecureKeySize bits;
                      location = {
                        file = arg.pexp_loc.loc_start.pos_fname;
                        line = arg.pexp_loc.loc_start.pos_lnum;
                        column = arg.pexp_loc.loc_start.pos_cnum - arg.pexp_loc.loc_start.pos_bol;
                        end_line = Some arg.pexp_loc.loc_end.pos_lnum;
                        end_column = Some (arg.pexp_loc.loc_end.pos_cnum - arg.pexp_loc.loc_end.pos_bol);
                      };
                      suggestion = Some 
                        "Use stronger parameters:\n\
                         - DH: minimum 2048 bits, prefer 3072 or 4096\n\
                         - Better: Use ECDH with Curve25519 (Mirage_crypto_ec.X25519)";
                      references = [
                        "CVE-2015-4000 (Logjam)";
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

(* ALGO006: Legacy SSL/TLS Versions *)
let legacy_tls_rule : Rule.t = {
  id = "ALGO006";
  name = "Legacy SSL/TLS Version";
  description = "Detects usage of deprecated SSL/TLS protocol versions";
  severity = Error;
  tags = ["algorithm"; "tls"; "ssl"; "protocol"];
  check = fun ast ->
    let legacy_versions = [
      ("sslv2", "SSLv2", "completely broken");
      ("sslv3", "SSLv3", "POODLE attack");
      ("tls1.0", "TLS 1.0", "deprecated");
      ("tlsv1.0", "TLS 1.0", "deprecated");
      ("tls1.1", "TLS 1.1", "deprecated");
      ("tlsv1.1", "TLS 1.1", "deprecated");
    ] in
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_constant (Pconst_string (s, _, _)) ->
            let lower = String.lowercase_ascii s in
            List.iter (fun (pattern, name, reason) ->
              if String.contains_substring lower pattern then
                findings := {
                  rule_id = "ALGO006";
                  severity = Error;
                  message = Printf.sprintf "Legacy protocol version %s (%s)" name reason;
                  vulnerability = WeakCipher (Printf.sprintf "protocol-%s" name);
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some 
                    "Use modern TLS versions:\n\
                     - Minimum: TLS 1.2\n\
                     - Recommended: TLS 1.3 (supported in ocaml-tls >= 0.12.0)\n\
                     - Configure: Tls.Config.client ~version:(`TLS_1_2, `TLS_1_3)";
                  references = [
                    "CVE-2014-3566 (POODLE)";
                    "RFC 8996 (TLS 1.0/1.1 deprecation)";
                  ];
                } :: !findings
            ) legacy_versions;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

let () =
  Registry.register weak_cipher_rule;
  Registry.register weak_hash_rule;
  Registry.register insecure_ecc_curve_rule;
  Registry.register small_block_cipher_rule;
  Registry.register weak_key_exchange_rule;
  Registry.register legacy_tls_rule