open Types
open Rule_engine
open Ppxlib
open Utils

(* Enhanced context tracking *)
module Context = struct
  type t = {
    mutable in_crypto_module: bool;
    mutable in_test_file: bool;
    mutable crypto_imports: string list;
    mutable dataflow_graph: (string * string list) list;
  }
  
  let create () = {
    in_crypto_module = false;
    in_test_file = false;
    crypto_imports = [];
    dataflow_graph = [];
  }
  
  let is_test_file filename =
    contains_substring filename "_test.ml" ||
    contains_substring filename "test_" ||
    contains_substring filename "/test/"
end

(* SIDE001: Variable-Time String Comparison - Enhanced *)
let variable_time_comparison_rule_v2 : Rule.t = {
  id = "SIDE001";
  name = "Variable-Time String Comparison";
  description = "Detects string comparisons vulnerable to timing attacks with context awareness";
  severity = Error;
  tags = ["side-channel"; "timing"; "comparison"; "enhanced"];
  check = fun ast ->
    let findings = ref [] in
    let ctx = Context.create () in
    let sensitive_vars = ref [] in
    let constant_time_functions = [
      "Eqaf.equal"; "Mirage_crypto.Hash.digest_eq"; 
      "Cryptokit.compare_constant_time"; "ct_eq"
    ] in
    
    (* Check if file is a test file *)
    ctx.in_test_file <- Context.is_test_file (List.hd ast).pstr_loc.loc_start.pos_fname;
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! structure_item item () =
        match item.pstr_desc with
        | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
            let module_name = Longident.flatten txt |> String.concat "." in
            if List.mem module_name ["Cryptokit"; "Nocrypto"; "Mirage_crypto"; 
                                     "Tls"; "Hacl_star"; "Sodium"] then begin
              ctx.in_crypto_module <- true;
              ctx.crypto_imports <- module_name :: ctx.crypto_imports
            end;
            super#structure_item item ()
        | _ -> super#structure_item item ()
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} ->
                  let lower = String.lowercase_ascii name in
                  (* Enhanced detection: check if value comes from crypto operation *)
                  let from_crypto = match vb.pvb_expr.pexp_desc with
                    | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
                        let path = Longident.flatten txt |> String.concat "." in
                        List.exists (fun m -> String.starts_with ~prefix:m path) ctx.crypto_imports
                    | _ -> false
                  in
                  
                  if from_crypto && List.exists (fun kw -> contains_substring lower kw)
                      ["mac"; "hmac"; "signature"; "digest"; "tag"] then
                    sensitive_vars := (name, "crypto_output") :: !sensitive_vars
                  else if List.exists (fun kw -> contains_substring lower kw)
                      ["key"; "password"; "secret"; "token"] then
                    sensitive_vars := (name, "secret_material") :: !sensitive_vars
              | _ -> ()
            ) bindings;
            super#expression expr ()
        
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = op; _}; _}, args) ->
            let op_name = Longident.flatten op |> String.concat "." in
            
            (* Skip if already using constant-time comparison *)
            if List.mem op_name constant_time_functions then
              super#expression expr ()
            else if List.mem op_name ["="; "<>"; "String.equal"; "String.compare"; 
                                      "Bytes.equal"; "compare"] then
              let involves_sensitive = List.exists (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_ident {txt = Lident name; _} -> 
                    List.exists (fun (n, _) -> n = name) !sensitive_vars
                | _ -> false
              ) args in
              
              (* Only flag if in crypto context and not test code *)
              if involves_sensitive && ctx.in_crypto_module && not ctx.in_test_file then
                let sensitive_type = 
                  try List.assoc (match List.find (fun (_, arg) ->
                    match arg.pexp_desc with
                    | Pexp_ident {txt = Lident name; _} -> 
                        List.exists (fun (n, _) -> n = name) !sensitive_vars
                    | _ -> false
                  ) args with (_, {pexp_desc = Pexp_ident {txt = Lident n; _}; _}) -> n | _ -> "") !sensitive_vars
                  with Not_found -> "unknown" in
                
                findings := {
                  rule_id = "SIDE001";
                  severity = if sensitive_type = "crypto_output" then Error else Warning;
                  message = Printf.sprintf "Variable-time comparison of %s" sensitive_type;
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
                     - Detected sensitive type: %s";
                  references = [
                    "CVE-2016-2107";
                    "USENIX Security 2024 - Statistical Timing Analysis";
                  ];
                } :: !findings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* SIDE003: Cache Timing in Table Lookups - Enhanced *)
let cache_timing_rule_v2 : Rule.t = {
  id = "SIDE003";
  name = "Cache Timing in Table Lookups";
  description = "Detects table lookups vulnerable to cache timing with improved context";
  severity = Warning;
  tags = ["side-channel"; "cache"; "timing"; "lookup"; "enhanced"];
  check = fun ast ->
    let findings = ref [] in
    let sbox_patterns = ["sbox"; "s_box"; "lookup_table"; "substitution"] in
    let crypto_context = ref false in
    let table_sizes = Hashtbl.create 16 in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      (* Track array definitions to know their size *)
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc, vb.pvb_expr.pexp_desc with
              | Ppat_var {txt = name; _}, Pexp_array elements ->
                  Hashtbl.add table_sizes name (List.length elements)
              | _ -> ()
            ) bindings;
            super#expression expr ()
            
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let path = Longident.flatten txt |> String.concat "." in
            
            (* Check if we're in crypto code *)
            if contains_substring path "Cipher" || 
               contains_substring path "aes" ||
               contains_substring path "des" then
              crypto_context := true;
            
            (* Array access analysis *)
            match path with
            | "Array.get" | "Array.unsafe_get" ->
                let (array_name, is_crypto_table, table_size) = 
                  match args with
                  | [(_, {pexp_desc = Pexp_ident {txt = Lident name; _}; _}); _] ->
                      let is_crypto = List.exists (fun pattern ->
                        contains_substring (String.lowercase_ascii name) pattern
                      ) sbox_patterns in
                      let size = try Some (Hashtbl.find table_sizes name) with Not_found -> None in
                      (Some name, is_crypto, size)
                  | _ -> (None, false, None)
                in
                
                if is_crypto_table && !crypto_context then
                  let severity = match table_size with
                    | Some s when s <= 256 -> Info  (* Small tables less vulnerable *)
                    | Some s when s <= 4096 -> Warning
                    | _ -> Error
                  in
                  
                  findings := {
                    rule_id = "SIDE003";
                    severity;
                    message = Printf.sprintf "Table lookup may be vulnerable to cache timing attacks%s"
                      (match table_size with 
                       | Some s -> Printf.sprintf " (table size: %d)" s 
                       | None -> "");
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
                       - For small tables (≤256): Consider bitslicing\n\
                       - For large tables: Use scatter-gather or prefetching\n\
                       - Modern CPUs: Check for AES-NI support\n\
                       - Example constant-time lookup for small tables:\n\
                         let ct_lookup table idx =\n\
                           Array.fold_left (fun (i, acc) v ->\n\
                             let mask = -((i = idx) land 1) in\n\
                             (i + 1, acc lor (v land mask))\n\
                           ) (0, 0) table |> snd";
                    references = [
                      "CVE-2016-0702 (CacheBleed)";
                      "USENIX Security 2023 - Cipherfix";
                    ];
                  } :: !findings;
            | _ -> ();
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* SIDE004: Branch-Based Information Leaks - Enhanced with taint tracking *)
let branch_leak_rule_v2 : Rule.t = {
  id = "SIDE004";
  name = "Branch-Based Information Leak";
  description = "Detects conditional branches on secret data with taint analysis";
  severity = Warning;
  tags = ["side-channel"; "branch"; "timing"; "enhanced"];
  check = fun ast ->
    let findings = ref [] in
    let tainted_vars = Hashtbl.create 32 in
    let crypto_sources = [
      "decrypt"; "unwrap"; "derive_key"; "generate"; "random"
    ] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, _) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc, vb.pvb_expr.pexp_desc with
              | Ppat_var {txt = name; _}, Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
                  let path = Longident.flatten txt |> String.concat "." |> String.lowercase_ascii in
                  (* Mark variable as tainted if it comes from crypto operation *)
                  if List.exists (fun src -> contains_substring path src) crypto_sources then
                    Hashtbl.add tainted_vars name "crypto_data"
                  else if contains_substring (String.lowercase_ascii name) "secret" ||
                          contains_substring (String.lowercase_ascii name) "private" then
                    Hashtbl.add tainted_vars name "named_secret"
              | _ -> ()
            ) bindings;
            super#expression expr ()
        
        | Pexp_ifthenelse (cond, then_branch, else_branch) ->
            let rec is_tainted = function
              | {pexp_desc = Pexp_ident {txt = Lident name; _}; _} ->
                  Hashtbl.mem tainted_vars name
              | {pexp_desc = Pexp_apply (_, args); _} as e ->
                  (* Check if it's error handling (common false positive) *)
                  let is_error_check = match e.pexp_desc with
                    | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
                        let path = Longident.flatten txt |> String.concat "." in
                        List.mem path ["Result.is_ok"; "Result.is_error"; "Option.is_some"; "Option.is_none"]
                    | _ -> false
                  in
                  not is_error_check && List.exists (fun (_, arg) -> is_tainted arg) args
              | _ -> false
            in
            
            if is_tainted cond then
              let taint_source = 
                let rec find_tainted_var = function
                  | {pexp_desc = Pexp_ident {txt = Lident name; _}; _} ->
                      (try Some (name, Hashtbl.find tainted_vars name) with Not_found -> None)
                  | {pexp_desc = Pexp_apply (_, args); _} ->
                      List.find_map (fun (_, arg) -> find_tainted_var arg) args
                  | _ -> None
                in
                find_tainted_var cond
              in
              
              let severity = match taint_source with
                | Some (_, "crypto_data") -> Error
                | Some (_, "named_secret") -> Warning
                | _ -> Info
              in
              
              findings := {
                rule_id = "SIDE004";
                severity;
                message = Printf.sprintf "Conditional branch on %s may leak information"
                  (match taint_source with 
                   | Some (name, source) -> Printf.sprintf "%s (%s)" name source
                   | None -> "secret data");
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
                   - Process both branches and select result\n\
                   - For error handling: use constant-time error codes\n\
                   - Example branchless selection:\n\
                     let ct_select cond a b =\n\
                       let mask = -cond in\n\
                       (a land mask) lor (b land (lnot mask))";
                references = [
                  "USENIX Security 2018 - Predicting Secret Keys via Branch Prediction";
                  "https://spectreattack.com/";
                ];
              } :: !findings;
            super#expression expr ()
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

(* Statistical confidence module based on USENIX 2024 paper *)
module Statistical_confidence = struct
  type confidence_level = 
    | High of float    (* > 0.95 confidence *)
    | Medium of float  (* 0.80 - 0.95 *)
    | Low of float     (* < 0.80 *)
  
  let compute_confidence finding context =
    let base_confidence = match finding.severity with
      | Critical -> 0.9
      | Error -> 0.8
      | Warning -> 0.7
      | Info -> 0.6
    in
    
    (* Adjust based on context *)
    let adjusted = 
      if context.Context.in_test_file then base_confidence *. 0.5
      else if context.in_crypto_module then base_confidence *. 1.2
      else base_confidence
    in
    
    match adjusted with
    | c when c > 0.95 -> High c
    | c when c > 0.80 -> Medium c
    | c -> Low c
  
  let add_confidence_to_finding finding confidence =
    let conf_str = match confidence with
      | High c -> Printf.sprintf "High confidence (%.0f%%)" (c *. 100.)
      | Medium c -> Printf.sprintf "Medium confidence (%.0f%%)" (c *. 100.)
      | Low c -> Printf.sprintf "Low confidence (%.0f%%)" (c *. 100.)
    in
    { finding with 
      message = Printf.sprintf "%s [%s]" finding.message conf_str }
end

(* Register enhanced rules *)
let () =
  Registry.register variable_time_comparison_rule_v2;
  Registry.register cache_timing_rule_v2;
  Registry.register branch_leak_rule_v2