open Types
open Rule_engine
open Ppxlib
open Utils

(* SIDE001: Variable-Time String Comparison *)
let variable_time_comparison_rule : Rule.t = {
  id = "SIDE001";
  name = "Variable-Time String Comparison";
  description = "Detects string comparisons vulnerable to timing attacks";
  severity = Error;
  tags = ["side-channel"; "timing"; "comparison"];
  check = fun ast ->
    let findings = ref [] in
    let sensitive_vars = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} ->
                  let lower = String.lowercase_ascii name in
                  if List.exists (fun kw -> contains_substring lower kw)
                      ["key"; "password"; "token"; "hmac"; "mac"; "signature"; 
                       "hash"; "digest"; "secret"; "auth"] then
                    sensitive_vars := name :: !sensitive_vars
              | _ -> ()
            ) bindings;
            super#expression expr
        
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = op; _}; _}, args) ->
            let op_name = flatten_longident op |> String.concat "." in
            if List.mem op_name ["="; "<>"; "String.equal"; "String.compare"; 
                                 "Bytes.equal"; "compare"] then
              let involves_sensitive = List.exists (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_ident {txt = Lident name; _} -> List.mem name !sensitive_vars
                | _ -> false
              ) args in
              
              if involves_sensitive then
                findings := {
                  rule_id = "SIDE001";
                  severity = Error;
                  message = "Variable-time comparison of sensitive data";
                  vulnerability = TimingLeak;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some 
                    "Use constant-time comparison:\n\
                     - Eqaf.equal for strings/bytes (recommended)\n\
                     - Mirage_crypto.Hash.digest_eq for hash comparisons\n\
                     - Cryptokit: Cryptokit.compare_constant_time\n\
                     - Example: if Eqaf.equal computed_mac expected_mac then ...";
                  references = [
                    "CVE-2016-2107";
                    "https://codahale.com/a-lesson-in-timing-attacks/";
                  ];
                } :: !findings;
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* SIDE002: Non-Constant Time Modular Exponentiation *)
let non_constant_modexp_rule : Rule.t = {
  id = "SIDE002";
  name = "Non-Constant Time Modular Exponentiation";
  description = "Detects potentially vulnerable modular exponentiation";
  severity = Warning;
  tags = ["side-channel"; "timing"; "rsa"; "modexp"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
            let path = flatten_longident txt |> String.concat "." in
            if List.mem path ["Z.powm"; "Big_int.power_big_int_positive_big_int"] ||
               (contains_substring path "pow" && 
                contains_substring path "mod") then
              findings := {
                rule_id = "SIDE002";
                severity = Warning;
                message = "Non-constant time modular exponentiation detected";
                vulnerability = TimingLeak;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Use constant-time modular exponentiation:\n\
                   - Z.powm_sec (constant-time version)\n\
                   - Mirage_crypto_pk.Rsa uses Z.powm_sec internally\n\
                   - Apply blinding: Mirage_crypto_pk.Rsa.decrypt ~blinding:true\n\
                   - Example: Z.powm_sec base exp modulus";
                references = [
                  "CVE-2018-0737";
                  "https://eprint.iacr.org/2018/367";
                ];
              } :: !findings;
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* SIDE003: Cache Timing in Table Lookups *)
let cache_timing_rule : Rule.t = {
  id = "SIDE003";
  name = "Cache Timing in Table Lookups";
  description = "Detects table lookups that may leak information through cache timing";
  severity = Warning;
  tags = ["side-channel"; "cache"; "timing"; "lookup"];
  check = fun ast ->
    let findings = ref [] in
    let sbox_patterns = ["sbox"; "s_box"; "lookup_table"; "substitution"] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Lident "Array.get"; _}; _}, args)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (Lident "Array", "get"); _}; _}, args) ->
            let in_crypto_context = List.exists (fun (_, arg) ->
              match arg.pexp_desc with
              | Pexp_ident {txt = Lident name; _} ->
                  List.exists (fun pattern ->
                    contains_substring (String.lowercase_ascii name) pattern
                  ) sbox_patterns
              | _ -> false
            ) args in
            
            if in_crypto_context then
              findings := {
                rule_id = "SIDE003";
                severity = Warning;
                message = "Table lookup may be vulnerable to cache timing attacks";
                vulnerability = SideChannel;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Mitigate cache timing attacks:\n\
                   - Use bitsliced implementations\n\
                   - Implement cache-oblivious algorithms\n\
                   - Prefetch entire tables\n\
                   - Use constant-time selection: \n\
                     let ct_select idx = Array.fold_left2 (fun acc i v -> \n\
                       if i = idx then v else acc) 0 indices values";
                references = [
                  "CVE-2016-0702 (CacheBleed)";
                  "https://cr.yp.to/antiforgery/cachetiming-20050414.pdf";
                ];
              } :: !findings;
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* SIDE004: Branch-Based Information Leaks *)
let branch_leak_rule : Rule.t = {
  id = "SIDE004";
  name = "Branch-Based Information Leak";
  description = "Detects conditional branches on secret data";
  severity = Warning;
  tags = ["side-channel"; "branch"; "timing"];
  check = fun ast ->
    let findings = ref [] in
    let secret_vars = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} when 
                  List.exists (fun s -> contains_substring (String.lowercase_ascii name) s)
                    ["secret"; "private"; "key"; "nonce"] ->
                  secret_vars := name :: !secret_vars
              | _ -> ()
            ) bindings;
            super#expression expr
        
        | Pexp_ifthenelse (cond, _, _) ->
            let rec contains_secret = function
              | {pexp_desc = Pexp_ident {txt = Lident name; _}; _} ->
                  List.mem name !secret_vars
              | {pexp_desc = Pexp_apply (_, args); _} ->
                  List.exists (fun (_, arg) -> contains_secret arg) args
              | _ -> false
            in
            
            if contains_secret cond then
              findings := {
                rule_id = "SIDE004";
                severity = Warning;
                message = "Conditional branch on secret data may leak information";
                vulnerability = SideChannel;
                location = {
                  file = cond.pexp_loc.loc_start.pos_fname;
                  line = cond.pexp_loc.loc_start.pos_lnum;
                  column = cond.pexp_loc.loc_start.pos_cnum - cond.pexp_loc.loc_start.pos_bol;
                  end_line = Some cond.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (cond.pexp_loc.loc_end.pos_cnum - cond.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Avoid branches on secret data:\n\
                   - Use constant-time conditional selection\n\
                   - Example: let ct_select cond a b = \n\
                     let mask = -cond in (* 0 or -1 *)\n\
                     (a land mask) lor (b land (lnot mask))\n\
                   - Process both branches and select result";
                references = [
                  "https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-doychev.pdf";
                ];
              } :: !findings;
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* SIDE005: Power Analysis Vulnerable Operations *)
let power_analysis_rule : Rule.t = {
  id = "SIDE005";
  name = "Power Analysis Vulnerable Operation";
  description = "Detects operations vulnerable to power analysis attacks";
  severity = Info;
  tags = ["side-channel"; "power-analysis"; "dpa"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = flatten_longident txt |> String.concat "." |> String.lowercase_ascii in
            (* Detect operations with data-dependent power consumption *)
            if (contains_substring path "multiplication" ||
                contains_substring path "mult" ||
                contains_substring path "square") &&
               List.exists (fun (_, arg) ->
                 match arg.pexp_desc with
                 | Pexp_ident {txt = Lident name; _} ->
                     contains_substring (String.lowercase_ascii name) "key" ||
                     contains_substring (String.lowercase_ascii name) "secret"
                 | _ -> false
               ) args then
              findings := {
                rule_id = "SIDE005";
                severity = Info;
                message = "Operation may be vulnerable to power analysis";
                vulnerability = SideChannel;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Mitigate power analysis:\n\
                   - Use masked implementations\n\
                   - Apply algorithmic countermeasures\n\
                   - Example masking: \n\
                     let masked_mult x k = \n\
                       let r = random() in\n\
                       let x' = x lxor r in\n\
                       let result' = mult x' k in\n\
                       result' lxor (mult r k)";
                references = [
                  "https://www.iacr.org/archive/ches2004/31560016/31560016.pdf";
                  "DPA Contest";
                ];
              } :: !findings;
            super#expression expr
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

let () =
  Registry.register variable_time_comparison_rule;
  Registry.register non_constant_modexp_rule;
  Registry.register cache_timing_rule;
  Registry.register branch_leak_rule;
  Registry.register power_analysis_rule