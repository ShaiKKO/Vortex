open Types
open Rule_engine

(* CVE-2016-2107: OpenSSL AES-NI timing attack *)
let timing_attack_rule : Rule.t = {
  id = "CVE_2016_2107";
  name = "Timing Attack in String Comparison";
  description = "Detects non-constant time string comparisons on sensitive data (CVE-2016-2107)";
  severity = Error;
  tags = ["timing"; "side-channel"; "cve"];
  check = fun ast ->
    let findings = ref [] in
    let sensitive_vars = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ppxlib.Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} ->
                  let lower = String.lowercase_ascii name in
                  if List.exists (fun kw -> String.contains_substring lower kw)
                      ["key"; "password"; "hmac"; "signature"; "mac"] then
                    sensitive_vars := name :: !sensitive_vars
              | _ -> ()
            ) bindings;
            super#expression expr ()
        
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Lident ("=" | "<>" | "String.equal"); _}; _}, args) ->
            let involves_sensitive = List.exists (fun (_, arg) ->
              match arg.pexp_desc with
              | Pexp_ident {txt = Lident name; _} -> List.mem name !sensitive_vars
              | _ -> false
            ) args in
            
            if involves_sensitive then
              findings := {
                rule_id = "CVE_2016_2107";
                severity = Error;
                message = "String comparison vulnerable to timing attacks on sensitive data";
                vulnerability = TimingLeak;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some "Use constant-time comparison: Cryptokit.compare_constant_time or Nocrypto.Uncommon.Cs.ct_eq";
                references = ["CVE-2016-2107"; "https://codahale.com/a-lesson-in-timing-attacks/"];
              } :: !findings;
            super#expression expr ()
        
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* CVE-2013-1443: Weak PBKDF2 iterations *)
let weak_kdf_rule : Rule.t = {
  id = "CVE_2013_1443";
  name = "Weak Key Derivation Function";
  description = "Detects PBKDF with insufficient iterations (CVE-2013-1443)";
  severity = Warning;
  tags = ["kdf"; "pbkdf2"; "cve"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ppxlib.Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (_, "pbkdf2"); _}; _}, args) ->
            List.iter (fun (label, arg) ->
              match label with
              | Asttypes.Labelled ("count" | "iterations" | "iter") ->
                  (match arg.pexp_desc with
                  | Pexp_constant (Pconst_integer (n, _)) ->
                      let iterations = int_of_string n in
                      if iterations < 10000 then
                        findings := {
                          rule_id = "CVE_2013_1443";
                          severity = Warning;
                          message = Printf.sprintf "PBKDF2 with only %d iterations is too weak" iterations;
                          vulnerability = WeakKDF;
                          location = {
                            file = arg.pexp_loc.loc_start.pos_fname;
                            line = arg.pexp_loc.loc_start.pos_lnum;
                            column = arg.pexp_loc.loc_start.pos_cnum - arg.pexp_loc.loc_start.pos_bol;
                            end_line = Some arg.pexp_loc.loc_end.pos_lnum;
                            end_column = Some (arg.pexp_loc.loc_end.pos_cnum - arg.pexp_loc.loc_end.pos_bol);
                          };
                          suggestion = Some "Use at least 10,000 iterations (100,000+ recommended for 2025)";
                          references = ["CVE-2013-1443"; "NIST SP 800-132"];
                        } :: !findings
                  | _ -> ())
              | _ -> ()
            ) args;
            super#expression expr ()
        
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* CVE-2012-4929: Small RSA keys *)
let weak_rsa_key_rule : Rule.t = {
  id = "CVE_2012_4929";
  name = "Weak RSA Key Size";
  description = "Detects RSA keys smaller than 2048 bits (CVE-2012-4929)";
  severity = Error;
  tags = ["rsa"; "key-size"; "cve"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ppxlib.Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (_, ("new_key" | "generate_key")); _}; _}, args) 
          when List.exists (fun (_, arg) ->
            match arg.pexp_desc with
            | Pexp_ident {txt = Ldot (m, _); _} -> 
                String.lowercase_ascii (Longident.flatten m |> String.concat ".") |> fun s ->
                String.contains_substring s "rsa"
            | _ -> false
          ) args ->
            List.iter (fun (label, arg) ->
              match label with
              | Asttypes.Labelled ("size" | "bits" | "keysize" | "key_size") ->
                  (match arg.pexp_desc with
                  | Pexp_constant (Pconst_integer (n, _)) ->
                      let bits = int_of_string n in
                      if bits < 2048 then
                        findings := {
                          rule_id = "CVE_2012_4929";
                          severity = Error;
                          message = Printf.sprintf "RSA key size %d bits is too small" bits;
                          vulnerability = InsecureKeySize bits;
                          location = {
                            file = arg.pexp_loc.loc_start.pos_fname;
                            line = arg.pexp_loc.loc_start.pos_lnum;
                            column = arg.pexp_loc.loc_start.pos_cnum - arg.pexp_loc.loc_start.pos_bol;
                            end_line = Some arg.pexp_loc.loc_end.pos_lnum;
                            end_column = Some (arg.pexp_loc.loc_end.pos_cnum - arg.pexp_loc.loc_end.pos_bol);
                          };
                          suggestion = Some "Use at least 2048-bit RSA keys (3072+ recommended)";
                          references = ["CVE-2012-4929"; "NIST SP 800-57"];
                        } :: !findings
                  | _ -> ())
              | _ -> ()
            ) args;
            super#expression expr ()
        
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* CVE-2013-0169 (Lucky13): CBC without MAC *)
let missing_mac_rule : Rule.t = {
  id = "CVE_2013_0169";
  name = "CBC Mode Without Authentication";
  description = "Detects CBC encryption without MAC (Lucky13 - CVE-2013-0169)";
  severity = Error;
  tags = ["cbc"; "mac"; "padding-oracle"; "cve"];
  check = fun ast ->
    let findings = ref [] in
    let cbc_uses = ref [] in
    let mac_uses = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ppxlib.Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (_, meth); _}; _}, _) ->
            if String.contains_substring (String.lowercase_ascii meth) "cbc" then
              cbc_uses := expr.pexp_loc :: !cbc_uses
            else if List.mem (String.lowercase_ascii meth) ["hmac"; "mac"; "authenticate"] then
              mac_uses := expr.pexp_loc :: !mac_uses;
            super#expression expr ()
        
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    
    (* Simple heuristic: if CBC is used but no MAC in same file *)
    if !cbc_uses <> [] && !mac_uses = [] then
      List.iter (fun loc ->
        findings := {
          rule_id = "CVE_2013_0169";
          severity = Error;
          message = "CBC mode used without message authentication";
          vulnerability = MissingAuthentication;
          location = {
            file = loc.loc_start.pos_fname;
            line = loc.loc_start.pos_lnum;
            column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
            end_line = Some loc.loc_end.pos_lnum;
            end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
          };
          suggestion = Some "Use authenticated encryption (AES-GCM) or add HMAC";
          references = ["CVE-2013-0169"; "https://ieeexplore.ieee.org/document/6547131"];
        } :: !findings
      ) !cbc_uses;
    
    !findings
}

(* CVE-2018-0737: RSA key generation timing *)
let rsa_timing_rule : Rule.t = {
  id = "CVE_2018_0737";
  name = "RSA Private Key Timing Leak";
  description = "Detects RSA operations vulnerable to timing attacks (CVE-2018-0737)";
  severity = Warning;
  tags = ["rsa"; "timing"; "side-channel"; "cve"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ppxlib.Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (m, ("decrypt" | "sign")); _}; _}, _) 
          when String.contains_substring (String.lowercase_ascii (Longident.flatten m |> String.concat ".")) "rsa" ->
            findings := {
              rule_id = "CVE_2018_0737";
              severity = Warning;
              message = "RSA private key operation may be vulnerable to timing attacks";
              vulnerability = TimingLeak;
              location = {
                file = expr.pexp_loc.loc_start.pos_fname;
                line = expr.pexp_loc.loc_start.pos_lnum;
                column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
              };
              suggestion = Some "Ensure RSA implementation uses blinding and constant-time modular exponentiation";
              references = ["CVE-2018-0737"; "https://eprint.iacr.org/2018/367"];
            } :: !findings;
            super#expression expr ()
        
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

let () =
  Registry.register timing_attack_rule;
  Registry.register weak_kdf_rule;
  Registry.register weak_rsa_key_rule;
  Registry.register missing_mac_rule;
  Registry.register rsa_timing_rule