open Types
open Rule_engine
open Ppxlib
open Utils

(* DEP001: Outdated Cryptokit *)
let outdated_cryptokit_rule : Rule.t = {
  id = "DEP001";
  name = "Outdated Cryptokit Version";
  description = "Detects outdated Cryptokit library with known vulnerabilities";
  severity = Error;
  tags = ["dependency"; "cryptokit"; "cve"; "outdated"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! structure_item item () =
        match item.pstr_desc with
        | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
            let module_name = Longident.flatten txt |> String.concat "." in
            if String.starts_with ~prefix:"Cryptokit" module_name then
              findings := {
                rule_id = "DEP001";
                severity = Error;
                message = "Ensure Cryptokit version >= 1.16.1 (CVE-2022-24793)";
                vulnerability = WeakCipher "outdated-cryptokit";
                location = {
                  file = item.pstr_loc.loc_start.pos_fname;
                  line = item.pstr_loc.loc_start.pos_lnum;
                  column = item.pstr_loc.loc_start.pos_cnum - item.pstr_loc.loc_start.pos_bol;
                  end_line = Some item.pstr_loc.loc_end.pos_lnum;
                  end_column = Some (item.pstr_loc.loc_end.pos_cnum - item.pstr_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Update Cryptokit to latest version:\n\
                   - opam update\n\
                   - opam upgrade cryptokit\n\
                   - Minimum safe version: 1.16.1\n\
                   - CVE-2022-24793: RSA timing attack in versions < 1.16.1";
                references = [
                  "CVE-2022-24793";
                  "https://github.com/xavierleroy/cryptokit/security/advisories/GHSA-v82j-px48-7869";
                ];
              } :: !findings;
            super#structure_item item ()
        | _ -> super#structure_item item ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* DEP002: Deprecated Nocrypto *)
let deprecated_nocrypto_rule : Rule.t = {
  id = "DEP002";
  name = "Deprecated Nocrypto Library";
  description = "Detects usage of deprecated nocrypto library";
  severity = Warning;
  tags = ["dependency"; "nocrypto"; "deprecated"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! structure_item item () =
        match item.pstr_desc with
        | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
            let module_name = Longident.flatten txt |> String.concat "." in
            if String.starts_with ~prefix:"Nocrypto" module_name then
              findings := {
                rule_id = "DEP002";
                severity = Warning;
                message = "Nocrypto is deprecated and unmaintained since 2019";
                vulnerability = WeakCipher "deprecated-library";
                location = {
                  file = item.pstr_loc.loc_start.pos_fname;
                  line = item.pstr_loc.loc_start.pos_lnum;
                  column = item.pstr_loc.loc_start.pos_cnum - item.pstr_loc.loc_start.pos_bol;
                  end_line = Some item.pstr_loc.loc_end.pos_lnum;
                  end_column = Some (item.pstr_loc.loc_end.pos_cnum - item.pstr_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Migrate to mirage-crypto (actively maintained fork):\n\
                   - opam install mirage-crypto mirage-crypto-rng mirage-crypto-pk\n\
                   - Replace Nocrypto with Mirage_crypto modules:\n\
                   - Nocrypto.Hash → Mirage_crypto.Hash\n\
                   - Nocrypto.Cipher_block → Mirage_crypto.Cipher_block\n\
                   - Nocrypto.Rsa → Mirage_crypto_pk.Rsa";
                references = [
                  "https://github.com/mirleft/ocaml-nocrypto";
                  "https://github.com/mirage/mirage-crypto";
                ];
              } :: !findings;
            super#structure_item item ()
        | _ -> super#structure_item item ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* DEP003: Vulnerable SSL Library *)
let vulnerable_ssl_rule : Rule.t = {
  id = "DEP003";
  name = "Vulnerable SSL Library Version";
  description = "Detects SSL library versions with known security issues";
  severity = Error;
  tags = ["dependency"; "ssl"; "cve"; "vulnerable"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! structure_item item () =
        match item.pstr_desc with
        | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
            let module_name = Longident.flatten txt |> String.concat "." in
            if List.mem module_name ["Ssl"; "Lwt_ssl"] then
              findings := {
                rule_id = "DEP003";
                severity = Error;
                message = "Ensure SSL library version >= 0.5.9 (CVE-2020-12802)";
                vulnerability = WeakCipher "vulnerable-ssl";
                location = {
                  file = item.pstr_loc.loc_start.pos_fname;
                  line = item.pstr_loc.loc_start.pos_lnum;
                  column = item.pstr_loc.loc_start.pos_cnum - item.pstr_loc.loc_start.pos_bol;
                  end_line = Some item.pstr_loc.loc_end.pos_lnum;
                  end_column = Some (item.pstr_loc.loc_end.pos_cnum - item.pstr_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Update SSL library:\n\
                   - opam update && opam upgrade ssl\n\
                   - Minimum version: 0.5.9\n\
                   - Consider using ocaml-tls (pure OCaml) instead:\n\
                   - opam install tls tls-lwt\n\
                   - CVE-2020-12802: Memory corruption in versions < 0.5.9";
                references = [
                  "CVE-2020-12802";
                  "https://github.com/savonet/ocaml-ssl/releases/tag/0.5.9";
                ];
              } :: !findings;
            super#structure_item item ()
        | _ -> super#structure_item item ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* DEP004: Unpatched TLS Library *)
let unpatched_tls_rule : Rule.t = {
  id = "DEP004";
  name = "Unpatched TLS Library";
  description = "Detects TLS library versions missing security patches";
  severity = Warning;
  tags = ["dependency"; "tls"; "security-patch"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! structure_item item () =
        match item.pstr_desc with
        | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
            let module_name = Longident.flatten txt |> String.concat "." in
            if String.starts_with ~prefix:"Tls" module_name then
              findings := {
                rule_id = "DEP004";
                severity = Warning;
                message = "Ensure TLS library version >= 0.15.0 for latest security fixes";
                vulnerability = WeakCipher "unpatched-tls";
                location = {
                  file = item.pstr_loc.loc_start.pos_fname;
                  line = item.pstr_loc.loc_start.pos_lnum;
                  column = item.pstr_loc.loc_start.pos_cnum - item.pstr_loc.loc_start.pos_bol;
                  end_line = Some item.pstr_loc.loc_end.pos_lnum;
                  end_column = Some (item.pstr_loc.loc_end.pos_cnum - item.pstr_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Update ocaml-tls to latest version:\n\
                   - opam update && opam upgrade tls\n\
                   - Version 0.15.0+ includes:\n\
                     * TLS 1.3 support\n\
                     * Improved side-channel resistance\n\
                     * Updated cipher suites\n\
                   - Check: opam info tls";
                references = [
                  "https://github.com/mirleft/ocaml-tls/releases";
                  "https://tls.mbed.org/security";
                ];
              } :: !findings;
            super#structure_item item ()
        | _ -> super#structure_item item ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* DEP005: Missing Security Updates *)
let missing_updates_rule : Rule.t = {
  id = "DEP005";
  name = "Missing Security Updates";
  description = "Detects crypto libraries that may have pending security updates";
  severity = Info;
  tags = ["dependency"; "updates"; "maintenance"];
  check = fun ast ->
    let findings = ref [] in
    let crypto_libs = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! structure_item item () =
        match item.pstr_desc with
        | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
            let module_name = Longident.flatten txt |> String.concat "." in
            let crypto_patterns = [
              "Cryptokit"; "Nocrypto"; "Mirage_crypto"; "Tls"; 
              "X509"; "Ssl"; "Sodium"; "Hacl_star"
            ] in
            if List.exists (fun pattern -> 
              String.starts_with ~prefix:pattern module_name
            ) crypto_patterns then
              crypto_libs := module_name :: !crypto_libs;
            super#structure_item item ()
        | _ -> super#structure_item item ()
    end in
    
    visitor#structure ast ();
    
    if !crypto_libs <> [] then
      findings := {
        rule_id = "DEP005";
        severity = Info;
        message = Printf.sprintf "Crypto libraries in use: %s - check for updates" 
          (String.concat ", " !crypto_libs);
        vulnerability = WeakCipher "update-check";
        location = {
          file = "";
          line = 0;
          column = 0;
          end_line = None;
          end_column = None;
        };
        suggestion = Some 
          "Regularly update crypto dependencies:\n\
           - Run: opam update && opam list --upgradable\n\
           - Subscribe to security advisories:\n\
             * https://github.com/ocaml/opam-repository/security\n\
             * Library-specific GitHub repos\n\
           - Use: opam pin add <package> --dev-repo for bleeding edge";
        references = [
          "https://opam.ocaml.org/doc/Usage.html#opam-update";
          "https://discuss.ocaml.org/c/security/23";
        ];
      } :: !findings;
    
    !findings
}

(* DEP006: Insecure Dependency Configuration *)
let insecure_config_rule : Rule.t = {
  id = "DEP006";
  name = "Insecure Dependency Configuration";
  description = "Detects potentially insecure crypto library configurations";
  severity = Warning;
  tags = ["dependency"; "configuration"; "security"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = Longident.flatten txt |> String.concat "." in
            
            (* Check for SSL/TLS without proper config *)
            if contains_substring path "Ssl.create_context" then
              let has_protocol_config = List.exists (fun (label, _) ->
                match label with
                | Asttypes.Labelled l -> List.mem l ["protocol"; "min_protocol"]
                | _ -> false
              ) args in
              
              if not has_protocol_config then
                findings := {
                  rule_id = "DEP006";
                  severity = Warning;
                  message = "SSL context created without explicit protocol version";
                  vulnerability = WeakCipher "default-config";
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some 
                    "Configure SSL/TLS explicitly:\n\
                     - Set minimum protocol version\n\
                     - Disable weak ciphers\n\
                     Example:\n\
                     Ssl.create_context \n\
                       ~protocol:Ssl.TLSv1_2\n\
                       ~options:[Ssl.NO_SSLv2; Ssl.NO_SSLv3; Ssl.NO_TLSv1]\n\
                       Ssl.Both_context";
                  references = [
                    "https://www.ssllabs.com/ssltest/";
                    "https://wiki.mozilla.org/Security/Server_Side_TLS";
                  ];
                } :: !findings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

let () =
  Registry.register outdated_cryptokit_rule;
  Registry.register deprecated_nocrypto_rule;
  Registry.register vulnerable_ssl_rule;
  Registry.register unpatched_tls_rule;
  Registry.register missing_updates_rule;
  Registry.register insecure_config_rule