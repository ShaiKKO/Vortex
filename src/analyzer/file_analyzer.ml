(* Single file analysis - extracted to avoid circular dependencies *)
open Types
open Ppxlib
open Analyzer_types
open Utils

let rec analyze_single_file state file_path =
  try
    let ic = open_in file_path in
    let lexbuf = Lexing.from_channel ic in
    lexbuf.lex_curr_p <- { lexbuf.lex_curr_p with pos_fname = file_path };
    
    let ast = Parse.implementation lexbuf in
    close_in ic;
    
    (* Phase 1: Import detection *)
    let import_ctx = Import_tracker.analyze_imports ast in
    state.import_context <- import_ctx;
    
    let file_findings = ref [] in
    
    (* Phase 2: Pure OCaml analysis (always run) *)
    if Import_tracker.is_crypto_active import_ctx || state.config.mode = PureOCaml then begin
      (* Basic AST analysis *)
      let ast_findings = Ast_analyzer.analyze_structure ast in
      file_findings := !file_findings @ ast_findings;
      
      (* Activate crypto-specific rules based on imports *)
      let active_rules = Import_tracker.get_active_rules import_ctx in
      let rule_findings = 
        List.concat_map (fun rule_id ->
          match Rule_engine.Registry.get_rule rule_id with
          | Some rule -> rule.Rule_engine.Rule.check ast
          | None -> []
        ) active_rules
      in
      file_findings := !file_findings @ rule_findings;
      
      (* CVE-based rules *)
      let cve_findings = 
        List.concat_map (fun rule ->
          rule.Rule_engine.Rule.check ast
        ) (Rule_engine.Registry.rules_by_tag "cve")
      in
      file_findings := !file_findings @ cve_findings;
      
      (* Protocol security rules *)
      let protocol_findings = 
        List.concat_map (fun rule ->
          rule.Rule_engine.Rule.check ast
        ) (Rule_engine.Registry.rules_by_tag "jwt" @ 
           Rule_engine.Registry.rules_by_tag "oauth" @
           Rule_engine.Registry.rules_by_tag "saml")
      in
      file_findings := !file_findings @ protocol_findings;
      
      (* Dataflow analysis if enabled *)
      if state.config.enable_dataflow then begin
        let dataflow_findings = Dataflow_cfg.analyze_dataflow ast in
        file_findings := !file_findings @ dataflow_findings
      end;
      
      (* Interprocedural analysis if enabled *)
      if state.config.enable_interprocedural then begin
        (* Skip AST conversion - use ast directly *)
        (* Run enhanced API misuse rules with interprocedural analysis *)
        let interprocedural_rules = [
          Api_misuse_rules_v2.cbc_without_mac_rule_v2;
          Api_misuse_rules_v2.encrypt_then_mac_rule_v2;
          Api_misuse_rules_v2.key_reuse_rule_v2;
        ] in
        let interprocedural_findings =
          List.concat_map (fun rule -> rule.Rule_engine.Rule.check ast) interprocedural_rules
        in
        file_findings := !file_findings @ interprocedural_findings
      end
    end;
    
    (* Phase 3: Context-sensitive analysis *)
    if Import_tracker.is_crypto_active import_ctx then begin
      (* Inter-module functor analysis *)
      let functor_findings = analyze_functors ast import_ctx in
      file_findings := !file_findings @ functor_findings;
      
      (* First-class module analysis *)
      let fcm_findings = analyze_first_class_modules ast import_ctx in
      file_findings := !file_findings @ fcm_findings
    end;
    
    (* Phase 4: Optional Semgrep analysis *)
    if state.config.enable_semgrep && state.config.mode <> PureOCaml then begin
      match Lwt_main.run (Semgrep_integration.analyze_with_semgrep file_path) with
      | semgrep_findings -> 
          file_findings := !file_findings @ semgrep_findings
      | exception _ -> ()
    end;
    
    incr state.files_analyzed;
    state.findings := !(state.findings) @ !file_findings;
    !file_findings
    
  with
  | e -> 
    Printf.eprintf "Error analyzing %s: %s\n" file_path (Printexc.to_string e);
    []

and analyze_functors ast import_ctx =
  let findings = ref [] in
  
  let visitor = object(self)
    inherit Ast_traverse.iter as super
    
    method! module_expr mexpr =
      match mexpr.pmod_desc with
      | Pmod_functor (_, body) ->
          (* TODO: Fix functor parameter checking *)
          self#module_expr body
      
      | Pmod_apply (functor_expr, arg_expr) ->
          (* Track functor applications with crypto modules *)
          super#module_expr mexpr
      
      | _ -> super#module_expr mexpr
  end in
  
  visitor#structure ast;
  !findings

and analyze_first_class_modules ast import_ctx =
  let findings = ref [] in
  
  let visitor = object(self)
    inherit Ast_traverse.iter as super
    
    method! expression expr =
      match expr.pexp_desc with
      | Pexp_pack mexpr ->
          (* First-class module packing *)
          self#check_packed_crypto_module mexpr expr.pexp_loc;
          super#expression expr
      
      | Pexp_letmodule (name, mexpr, body) ->
          (* Local module that might be crypto-related *)
          self#check_local_crypto_module name mexpr expr.pexp_loc;
          super#expression expr
      
      | Pexp_constraint (e, {ptyp_desc = Ptyp_package _; _}) ->
          (* Module type constraint *)
          super#expression expr
      
      | _ -> super#expression expr
    
    method private check_packed_crypto_module mexpr loc =
      (* Detect if packing crypto modules *)
      match mexpr.pmod_desc with
      | Pmod_ident {txt; _} ->
          let rec flatten_longident = function
            | Longident.Lident s -> [s]
            | Ldot (lid, s) -> flatten_longident lid @ [s]
            | Lapply (lid1, lid2) -> flatten_longident lid1 @ flatten_longident lid2
          in
          let path = flatten_longident txt |> String.concat "." in
          if Import_tracker.library_of_string path <> None then
            findings := {
              rule_id = "CRYPTO_FCM_001";
              severity = Warning;
              message = "First-class crypto module detected";
              vulnerability = WeakCipher "first-class-module";
              location = {
                file = loc.loc_start.pos_fname;
                line = loc.loc_start.pos_lnum;
                column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
                end_line = Some loc.loc_end.pos_lnum;
                end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
              };
              suggestion = Some "Ensure first-class crypto modules maintain security invariants";
              references = [];
            } :: !findings
      | _ -> ()
    
    method private check_local_crypto_module name mexpr loc =
      match mexpr.pmod_desc with
      | Pmod_ident {txt; _} ->
          let rec flatten_longident = function
            | Longident.Lident s -> [s]
            | Ldot (lid, s) -> flatten_longident lid @ [s]
            | Lapply (lid1, lid2) -> flatten_longident lid1 @ flatten_longident lid2
          in
          let path = flatten_longident txt |> String.concat "." in
          (* Simple substring check *)
          if List.exists (fun import ->
            List.exists (fun m -> contains_substring path m) import.Import_tracker.modules
          ) import_ctx.imports then
            findings := {
              rule_id = "CRYPTO_LOCAL_001";
              severity = Info;
              message = Printf.sprintf "Local crypto module binding: %s" 
                (match name.txt with Some n -> n | None -> "anonymous");
              vulnerability = WeakCipher "local-module";
              location = {
                file = loc.loc_start.pos_fname;
                line = loc.loc_start.pos_lnum;
                column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
                end_line = Some loc.loc_end.pos_lnum;
                end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
              };
              suggestion = Some "Track crypto operations in local module scope";
              references = [];
            } :: !findings
      | _ -> ()
  end in
  
  visitor#structure ast;
  !findings