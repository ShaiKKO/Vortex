(* Interprocedural analysis framework for tracking data flow across functions *)
open Types
open Ppxlib
open Utils

module Function_summary = struct
  type parameter_info = {
    name: string;
    position: int;
    is_output: bool;
    is_sensitive: bool;
  }

  type return_info = {
    returns_sensitive: bool;
    return_type: string option;
  }

  type call_site = {
    callee: string;
    location: Location.t;
    arguments: expression list;
  }

  type t = {
    name: string;
    parameters: parameter_info list;
    return: return_info;
    calls: call_site list;
    performs_crypto: bool;
    crypto_operations: string list;
  }

  let create name = {
    name;
    parameters = [];
    return = { returns_sensitive = false; return_type = None };
    calls = [];
    performs_crypto = false;
    crypto_operations = [];
  }
end

module Call_graph = struct
  type node = {
    function_name: string;
    summary: Function_summary.t;
    callers: string list;
    callees: string list;
  }

  type t = (string, node) Hashtbl.t

  let create () = Hashtbl.create 256

  let add_function graph name summary =
    Hashtbl.replace graph name {
      function_name = name;
      summary;
      callers = [];
      callees = [];
    }

  let add_call graph caller callee =
    match Hashtbl.find_opt graph caller, Hashtbl.find_opt graph callee with
    | Some caller_node, Some callee_node ->
        let caller_node' = { caller_node with callees = callee :: caller_node.callees } in
        let callee_node' = { callee_node with callers = caller :: callee_node.callers } in
        Hashtbl.replace graph caller caller_node';
        Hashtbl.replace graph callee callee_node'
    | _ -> ()

  let get_transitive_callees graph func =
    let rec collect visited func =
      if List.mem func visited then visited
      else
        match Hashtbl.find_opt graph func with
        | Some node ->
            List.fold_left (fun acc callee ->
              collect acc callee
            ) (func :: visited) node.callees
        | None -> visited
    in
    collect [] func
end

module Taint_analysis = struct
  type taint_source =
    | CryptoOperation of string
    | UserInput
    | NetworkData
    | FileData
    | Parameter of int

  type taint_state = {
    variables: (string, taint_source list) Hashtbl.t;
    return_tainted: taint_source list;
  }

  let create () = {
    variables = Hashtbl.create 64;
    return_tainted = [];
  }

  let taint_variable state var sources =
    Hashtbl.replace state.variables var sources

  let is_tainted state var =
    Hashtbl.mem state.variables var

  let get_taint_sources state var =
    Hashtbl.find_opt state.variables var |> Option.value ~default:[]

  let propagate_taint state from_var to_var =
    match Hashtbl.find_opt state.variables from_var with
    | Some sources -> taint_variable state to_var sources
    | None -> ()

  let merge_states state1 state2 =
    let merged = create () in
    (* Merge variables *)
    Hashtbl.iter (fun var sources ->
      Hashtbl.replace merged.variables var sources
    ) state1.variables;
    Hashtbl.iter (fun var sources ->
      match Hashtbl.find_opt merged.variables var with
      | Some existing -> 
          Hashtbl.replace merged.variables var (existing @ sources)
      | None -> 
          Hashtbl.replace merged.variables var sources
    ) state2.variables;
    (* Merge return taint *)
    { merged with return_tainted = state1.return_tainted @ state2.return_tainted }
end

module Interprocedural_analyzer = struct
  type context = {
    call_graph: Call_graph.t;
    mutable current_function: string option;
    taint_states: (string, Taint_analysis.taint_state) Hashtbl.t;
    crypto_patterns: string list;
  }

  let create_context () = {
    call_graph = Call_graph.create ();
    current_function = None;
    taint_states = Hashtbl.create 64;
    crypto_patterns = [
      "encrypt"; "decrypt"; "sign"; "verify"; "hash"; "mac"; "hmac";
      "derive"; "generate"; "random"; "key"; "cipher"; "aes"; "rsa"
    ];
  }

  let is_crypto_operation ctx name =
    let lower = String.lowercase_ascii name in
    List.exists (fun pattern ->
      contains_substring lower pattern
    ) ctx.crypto_patterns

  let analyze_function_call ctx caller_taint callee_name args =
    match Hashtbl.find_opt ctx.call_graph callee_name with
    | Some node ->
        let callee_taint = Taint_analysis.create () in
        
        (* Propagate taint through parameters *)
        List.iteri (fun i arg ->
          match arg.pexp_desc with
          | Pexp_ident {txt = Lident var; _} ->
              if Taint_analysis.is_tainted caller_taint var then
                let sources = Taint_analysis.get_taint_sources caller_taint var in
                List.iter (fun param ->
                  if param.Function_summary.position = i then
                    Taint_analysis.taint_variable callee_taint param.name sources
                ) node.summary.parameters
          | _ -> ()
        ) args;
        
        (* Get callee's taint state if analyzed *)
        begin match Hashtbl.find_opt ctx.taint_states callee_name with
        | Some state -> 
            if state.return_tainted <> [] then
              Some state.return_tainted
            else None
        | None -> None
        end
    | None -> None

  let rec analyze_expression ctx taint expr =
    match expr.pexp_desc with
    | Pexp_let (_, bindings, body) ->
        List.iter (fun vb ->
          match vb.pvb_pat.ppat_desc with
          | Ppat_var {txt = var_name; _} ->
              analyze_expression ctx taint vb.pvb_expr;
              
              (* Check if value comes from crypto operation *)
              begin match vb.pvb_expr.pexp_desc with
              | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
                  let func_name = flatten_longident txt |> String.concat "." in
                  if is_crypto_operation ctx func_name then
                    Taint_analysis.taint_variable taint var_name 
                      [Taint_analysis.CryptoOperation func_name]
                  else
                    (* Check interprocedural taint *)
                    begin match analyze_function_call ctx taint func_name 
                              (List.map snd args) with
                    | Some sources -> 
                        Taint_analysis.taint_variable taint var_name sources
                    | None -> ()
                    end
              | _ -> ()
              end
          | _ -> ()
        ) bindings;
        analyze_expression ctx taint body
        
    | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
        let func_name = flatten_longident txt |> String.concat "." in
        
        (* Record call for current function *)
        begin match ctx.current_function with
        | Some current ->
            let call_site = {
              Function_summary.callee = func_name;
              location = expr.pexp_loc;
              arguments = List.map snd args;
            } in
            begin match Hashtbl.find_opt ctx.call_graph current with
            | Some node ->
                let summary = { node.summary with 
                  calls = call_site :: node.summary.calls 
                } in
                Call_graph.add_function ctx.call_graph current summary
            | None -> ()
            end
        | None -> ()
        end;
        
        List.iter (fun (_, arg) -> analyze_expression ctx taint arg) args
        
    | Pexp_ifthenelse (cond, then_br, else_br) ->
        analyze_expression ctx taint cond;
        analyze_expression ctx taint then_br;
        Option.iter (analyze_expression ctx taint) else_br
        
    | Pexp_sequence (e1, e2) ->
        analyze_expression ctx taint e1;
        analyze_expression ctx taint e2
        
    | _ -> ()

  let analyze_structure_item ctx item =
    match item.pstr_desc with
    | Pstr_value (_, bindings) ->
        List.iter (fun vb ->
          match vb.pvb_pat.ppat_desc with
          | Ppat_var {txt = func_name; _} ->
              (* Create function summary *)
              let summary = Function_summary.create func_name in
              
              (* Extract parameters if it's a function *)
              let params = 
                (* For now, we don't extract parameters from complex function patterns *)
                []
              in
              
              let summary = { summary with parameters = params } in
              Call_graph.add_function ctx.call_graph func_name summary;
              
              (* Analyze function body *)
              let old_func = ctx.current_function in
              ctx.current_function <- Some func_name;
              let taint = Taint_analysis.create () in
              analyze_expression ctx taint vb.pvb_expr;
              Hashtbl.replace ctx.taint_states func_name taint;
              ctx.current_function <- old_func
              
          | _ -> ()
        ) bindings
    | _ -> ()

  let analyze_ast ast =
    let ctx = create_context () in
    List.iter (analyze_structure_item ctx) ast;
    ctx

  let find_pattern ctx pattern_check =
    let findings = ref [] in
    
    Hashtbl.iter (fun func_name node ->
      let taint_state = 
        Hashtbl.find_opt ctx.taint_states func_name 
        |> Option.value ~default:(Taint_analysis.create ())
      in
      
      match pattern_check func_name node taint_state with
      | Some finding -> findings := finding :: !findings
      | None -> ()
    ) ctx.call_graph;
    
    !findings
end

(* Export main analysis function *)
let analyze_interprocedural ast =
  Interprocedural_analyzer.analyze_ast ast