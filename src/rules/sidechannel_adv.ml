(* Advanced Side-Channel Rules Implementation
   Focus: Speculative execution, cache attacks, and constant-time verification
   Reference: AMD TSA vulnerabilities (CVE-2025-36350, CVE-2025-36357) *)

open Types
open Rule_engine
open Ppxlib
open Utils

(* Abstract interpretation context for tracking secret data flow *)
module Abstract_Domain = struct
  type secret_level = 
    | Public
    | Secret of string (* Origin of secret *)
    | Tainted of string * string (* Origin, reason *)
  
  type memory_access_pattern =
    | ConstantAddress
    | SecretDependent of string (* Variable that controls access *)
    | PublicDependent
  
  type context = {
    mutable secret_vars: (string * secret_level) list;
    mutable memory_accesses: (Location.t * memory_access_pattern) list;
    mutable branch_conditions: (Location.t * secret_level) list;
    mutable loop_bounds: (string * secret_level) list;
    mutable speculative_gadgets: location list;
  }
  
  let create () = {
    secret_vars = [];
    memory_accesses = [];
    branch_conditions = [];
    loop_bounds = [];
    speculative_gadgets = [];
  }
  
  let is_secret ctx var =
    List.exists (fun (v, level) -> 
      v = var && level <> Public
    ) ctx.secret_vars
  
  let add_secret ctx var level =
    ctx.secret_vars <- (var, level) :: ctx.secret_vars
  
  let get_secret_level ctx var =
    try 
      List.assoc var ctx.secret_vars
    with Not_found -> Public
end

(* SIDEA001: Speculative Execution Pattern Detection *)
let speculative_execution_rule : Rule.t = {
  id = "SIDEA001";
  name = "Speculative Execution Vulnerability Pattern";
  description = "Detects code patterns vulnerable to Spectre-style attacks";
  severity = Critical;
  tags = ["side-channel"; "speculative-execution"; "spectre"; "cpu"; "advanced"];
  check = fun ast ->
    let findings = ref [] in
    let ctx = Abstract_Domain.create () in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Pattern 1: Bounds check followed by array access (Spectre v1) *)
        | Pexp_ifthenelse (
            {pexp_desc = Pexp_apply ({pexp_desc = Pexp_ident {txt = op; _}; _}, 
                                    [(_, idx); (_, bound)]); _} as cond,
            then_branch,
            _
          ) when List.mem (flatten_longident op |> String.concat ".") ["<"; "<="; "Stdlib.<"; "Stdlib.<="] ->
            (* Check if then branch contains array access with same index *)
            let rec find_array_access expr =
              match expr.pexp_desc with
              | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args)
                when contains_substring (flatten_longident txt |> String.concat ".") "Array.get" ||
                     contains_substring (flatten_longident txt |> String.concat ".") ".(" ->
                (* Check if index matches *)
                List.exists (fun (_, arg) ->
                  match idx.pexp_desc, arg.pexp_desc with
                  | Pexp_ident {txt = Lident idx_name; _}, 
                    Pexp_ident {txt = Lident arg_name; _} -> idx_name = arg_name
                  | _ -> false
                ) args
              | Pexp_sequence (e1, e2) -> find_array_access e1 || find_array_access e2
              | Pexp_let (_, _, body) -> find_array_access body
              | _ -> false
            in
            
            if find_array_access then_branch then begin
              findings := {
                rule_id = "SIDEA001";
                severity = Critical;
                message = "Spectre v1 pattern detected: bounds check bypass vulnerability";
                vulnerability = SideChannel;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Mitigate Spectre v1 vulnerability:\n\
                   1. Use index masking:\n\
                      let safe_idx = idx land (array_bound_mask - 1) in\n\
                      array.(safe_idx)\n\
                   2. Insert speculation barrier:\n\
                      if idx < bound then begin\n\
                        Obj.magic (Sys.opaque_identity ());\n\
                        array.(idx)\n\
                      end\n\
                   3. Use branchless bounds check:\n\
                      let in_bounds = (idx - bound) asr 63 in\n\
                      array.(idx land in_bounds)";
                references = [
                  "CVE-2017-5753 (Spectre v1)";
                  "https://spectreattack.com/";
                  "Intel: Speculative Execution Side Channel Mitigations";
                ];
              } :: !findings;
              ctx.speculative_gadgets <- expr.pexp_loc :: ctx.speculative_gadgets
            end;
            super#expression expr
            
        (* Pattern 2: Indirect function calls (Spectre v2) *)
        | Pexp_apply ({pexp_desc = Pexp_field (_, _) | Pexp_ident _; _} as func, args) ->
            let is_indirect_call = match func.pexp_desc with
              | Pexp_field ({pexp_desc = Pexp_apply (_, _); _}, _) -> true
              | Pexp_field ({pexp_desc = Pexp_ident {txt = Lident table; _}; _}, _) 
                when contains_substring table "table" || 
                     contains_substring table "vtbl" ||
                     contains_substring table "func" -> true
              | _ -> false
            in
            
            if is_indirect_call then
              findings := {
                rule_id = "SIDEA001";
                severity = Error;
                message = "Potential Spectre v2 pattern: indirect branch may be poisoned";
                vulnerability = SideChannel;
                location = {
                  file = func.pexp_loc.loc_start.pos_fname;
                  line = func.pexp_loc.loc_start.pos_lnum;
                  column = func.pexp_loc.loc_start.pos_cnum - func.pexp_loc.loc_start.pos_bol;
                  end_line = Some func.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (func.pexp_loc.loc_end.pos_cnum - func.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Mitigate indirect branch poisoning:\n\
                   1. Use retpoline pattern for indirect calls\n\
                   2. Enable compiler mitigations (-mindirect-branch=thunk)\n\
                   3. Consider using direct calls where possible";
                references = [
                  "CVE-2017-5715 (Spectre v2)";
                  "Retpoline: A Branch Target Injection Mitigation";
                ];
              } :: !findings;
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* SIDEA002: AMD Transient Scheduler Attack Detection *)
let transient_scheduler_rule : Rule.t = {
  id = "SIDEA002";
  name = "AMD Transient Scheduler Attack Pattern";
  description = "Detects patterns vulnerable to AMD TSA (CVE-2025-36350)";
  severity = Error;
  tags = ["side-channel"; "amd-tsa"; "scheduler"; "timing"; "advanced"];
  check = fun ast ->
    let findings = ref [] in
    let in_tight_loop = ref false in
    let memory_ops_in_loop = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Detect tight loops *)
        | Pexp_for (_, start_exp, end_exp, _, body) ->
            in_tight_loop := true;
            memory_ops_in_loop := [];
            self#expression body;
            
            (* Check if loop has port-contention inducing patterns *)
            if List.length !memory_ops_in_loop > 3 then
              findings := {
                rule_id = "SIDEA002";
                severity = Error;
                message = "AMD TSA vulnerability: tight loop with multiple memory operations may leak via scheduler timing";
                vulnerability = SideChannel;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Mitigate AMD Transient Scheduler Attacks:\n\
                   1. Add memory barriers between sensitive operations:\n\
                      Obj.magic (Sys.opaque_identity ())\n\
                   2. Avoid tight loops with alternating loads/stores\n\
                   3. Use constant-time algorithms that don't rely on scheduler behavior\n\
                   4. Update AMD microcode and apply OS mitigations";
                references = [
                  "CVE-2025-36350 (AMD TSA)";
                  "CVE-2025-36357 (AMD Store Queue)";
                  "AMD Security Bulletin: Transient Execution Attacks";
                ];
              } :: !findings;
            
            in_tight_loop := false;
            
        (* Track memory operations in loops *)
        | Pexp_setfield _ | Pexp_field _ ->
            if !in_tight_loop then
              memory_ops_in_loop := expr.pexp_loc :: !memory_ops_in_loop;
            super#expression expr
            
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
            let func_name = flatten_longident txt |> String.concat "." in
            if !in_tight_loop && 
               (contains_substring func_name "Array.set" ||
                contains_substring func_name "Array.get" ||
                contains_substring func_name "Bytes.set" ||
                contains_substring func_name "Bytes.get") then
              memory_ops_in_loop := expr.pexp_loc :: !memory_ops_in_loop;
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* SIDEA003: Store Queue Leakage Detection *)
let store_queue_leakage_rule : Rule.t = {
  id = "SIDEA003";
  name = "Store Queue Side-Channel Leakage";
  description = "Detects store queue timing vulnerabilities";
  severity = Error;
  tags = ["side-channel"; "store-queue"; "memory"; "timing"; "advanced"];
  check = fun ast ->
    let findings = ref [] in
    let recent_stores = ref [] in (* Track recent store operations *)
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Track stores *)
        | Pexp_setfield (obj, field, value) ->
            recent_stores := (obj, field, expr.pexp_loc) :: !recent_stores;
            super#expression expr
            
        (* Check for loads that might alias with recent stores *)
        | Pexp_field (obj, field) ->
            (* Check if this load might alias with a recent store *)
            List.iter (fun (store_obj, store_field, store_loc) ->
              (* Simple aliasing check - could be more sophisticated *)
              let might_alias = match obj.pexp_desc, store_obj.pexp_desc with
                | Pexp_ident {txt = Lident a; _}, Pexp_ident {txt = Lident b; _} -> 
                    a = b || contains_substring a "secret" || contains_substring b "secret"
                | _ -> false
              in
              
              if might_alias && field = store_field then
                findings := {
                  rule_id = "SIDEA003";
                  severity = Error;
                  message = "Store-to-load forwarding may leak timing information";
                  vulnerability = SideChannel;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some 
                    "Prevent store queue timing leaks:\n\
                     1. Insert memory barrier between store and load:\n\
                        obj.field <- secret;\n\
                        Obj.magic (Sys.opaque_identity ());\n\
                        let value = obj.field in\n\
                     2. Use separate memory regions for secret/public data\n\
                     3. Avoid 4K aliasing between secret and attacker-controlled addresses";
                  references = [
                    "Store-to-Load Forwarding Side Channels";
                    "MDS: Microarchitectural Data Sampling";
                  ];
                } :: !findings
            ) !recent_stores;
            
            (* Keep only recent stores (simple heuristic) *)
            if List.length !recent_stores > 10 then
              recent_stores := List.tl !recent_stores;
            
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* SIDEA004: Port Contention Detection *)
let port_contention_rule : Rule.t = {
  id = "SIDEA004";
  name = "Execution Port Contention Side-Channel";
  description = "Detects port contention timing leaks";
  severity = Warning;
  tags = ["side-channel"; "port-contention"; "timing"; "cpu"; "advanced"];
  check = fun ast ->
    let findings = ref [] in
    let ctx = Abstract_Domain.create () in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Detect port-heavy operations *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let op_name = flatten_longident txt |> String.concat "." in
            
            (* Operations that create port pressure *)
            let is_port_heavy = 
              List.exists (fun pattern -> contains_substring op_name pattern) 
                ["mul"; "div"; "mod"; "*/"; "//"; "Int32.mul"; "Int64.mul";
                 "Float.mul"; "Float.div"; "sqrt"; "pow"] in
            
            if is_port_heavy then
              (* Check if any argument is secret *)
              let involves_secret = List.exists (fun (_, arg) ->
                match arg.pexp_desc with
                | Pexp_ident {txt = Lident var; _} -> 
                    Abstract_Domain.is_secret ctx var ||
                    contains_substring var "secret" ||
                    contains_substring var "key"
                | _ -> false
              ) args in
              
              if involves_secret then
                findings := {
                  rule_id = "SIDEA004";
                  severity = Warning;
                  message = Printf.sprintf 
                    "Port-heavy operation '%s' on potentially secret data may leak via timing"
                    op_name;
                  vulnerability = SideChannel;
                  location = {
                    file = expr.pexp_loc.loc_start.pos_fname;
                    line = expr.pexp_loc.loc_start.pos_lnum;
                    column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                    end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                    end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                  };
                  suggestion = Some 
                    "Mitigate port contention timing leaks:\n\
                     1. Use constant-time alternatives:\n\
                        - Replace division with multiplication by inverse\n\
                        - Use Montgomery multiplication for modular ops\n\
                     2. Add dummy operations to balance port usage\n\
                     3. Consider masking sensitive values:\n\
                        let masked = secret lxor random in\n\
                        let result = op masked in\n\
                        unmask result";
                  references = [
                    "PortSmash: Port Contention Side-Channel";
                    "Single-Threaded Contention Attacks";
                  ];
                } :: !findings;
            
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* SIDEA005: Constant-Time Verification using Abstract Interpretation *)
let constant_time_verification_rule : Rule.t = {
  id = "SIDEA005";
  name = "Non-Constant-Time Operation Detection";
  description = "Comprehensive constant-time verification using abstract interpretation";
  severity = Error;
  tags = ["side-channel"; "constant-time"; "verification"; "abstract-interpretation"; "advanced"];
  check = fun ast ->
    let findings = ref [] in
    let ctx = Abstract_Domain.create () in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      (* Track variable bindings and propagate secret tainting *)
      method! expression expr =
        match expr.pexp_desc with
        (* Mark variables as secret based on naming and context *)
        | Pexp_let (_, bindings, body) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} ->
                  (* Heuristics for identifying secrets *)
                  let is_secret_name = 
                    List.exists (fun pattern -> contains_substring (String.lowercase_ascii name) pattern)
                      ["secret"; "key"; "priv"; "password"; "token"; "nonce"; "iv"] in
                  
                  (* Check if assigned from a secret source *)
                  let is_from_secret = match vb.pvb_expr.pexp_desc with
                    | Pexp_ident {txt = Lident src; _} -> 
                        Abstract_Domain.is_secret ctx src
                    | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
                        let func = flatten_longident txt |> String.concat "." in
                        contains_substring func "random" || 
                        contains_substring func "generate_key"
                    | _ -> false
                  in
                  
                  if is_secret_name || is_from_secret then
                    Abstract_Domain.add_secret ctx name (Secret name)
              | _ -> ()
            ) bindings;
            super#expression expr
            
        (* Check for non-constant-time operations on secrets *)
        | Pexp_ifthenelse (cond, _, _) ->
            (* Check if condition depends on secret *)
            let rec check_secret_dependency expr =
              match expr.pexp_desc with
              | Pexp_ident {txt = Lident var; _} -> 
                  Abstract_Domain.is_secret ctx var
              | Pexp_apply ({pexp_desc = Pexp_ident {txt = op; _}; _}, args) ->
                  List.exists (fun (_, arg) -> check_secret_dependency arg) args
              | _ -> false
            in
            
            if check_secret_dependency cond then begin
              findings := {
                rule_id = "SIDEA005";
                severity = Error;
                message = "Non-constant-time branch on secret data";
                vulnerability = SideChannel;
                location = {
                  file = cond.pexp_loc.loc_start.pos_fname;
                  line = cond.pexp_loc.loc_start.pos_lnum;
                  column = cond.pexp_loc.loc_start.pos_cnum - cond.pexp_loc.loc_start.pos_bol;
                  end_line = Some cond.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (cond.pexp_loc.loc_end.pos_cnum - cond.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Ensure constant-time execution:\n\
                   1. Use branchless selection:\n\
                      let ct_select cond a b =\n\
                        let mask = -cond in\n\
                        (a land mask) lor (b land (lnot mask))\n\
                   2. Process both branches and select result:\n\
                      let result_true = compute_true () in\n\
                      let result_false = compute_false () in\n\
                      ct_select condition result_true result_false\n\
                   3. Use constant-time libraries (e.g., Eqaf, hacl-star)";
                references = [
                  "Constant-Time Programming Guide";
                  "FaCT: Flexible and Constant Time Programming";
                ];
              } :: !findings;
              ctx.branch_conditions <- (cond.pexp_loc, Abstract_Domain.get_secret_level ctx "") :: ctx.branch_conditions
            end;
            super#expression expr
            
        (* Variable-time operations *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
            let op_name = flatten_longident txt |> String.concat "." in
            
            (* Non-constant-time operations *)
            let is_variable_time = 
              List.mem op_name ["/"; "mod"; "Int32.div"; "Int32.rem"; 
                               "Int64.div"; "Int64.rem"; "Float.div"] ||
              (List.mem op_name ["="; "<>"; "<"; ">"; "<="; ">="] && 
               List.exists (fun (_, arg) ->
                 match arg.pexp_desc with
                 | Pexp_ident {txt = Lident var; _} -> Abstract_Domain.is_secret ctx var
                 | _ -> false
               ) args) in
            
            if is_variable_time then
              findings := {
                rule_id = "SIDEA005";
                severity = Error;
                message = Printf.sprintf "Variable-time operation '%s' on secret data" op_name;
                vulnerability = SideChannel;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some 
                  "Replace with constant-time operations:\n\
                   - Division: Use multiplication by inverse\n\
                   - Modulo: Use Barrett reduction or Montgomery form\n\
                   - Comparison: Use Eqaf.equal or constant-time compare\n\
                   - Example for comparison:\n\
                     let ct_equal a b = Eqaf.equal a b";
                references = [
                  "BearSSL Constant-Time Crypto";
                  "Cryptographic Implementations Analysis Toolkit";
                ];
              } :: !findings;
            
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* Register all advanced side-channel rules *)
let () =
  Registry.register speculative_execution_rule;
  Registry.register transient_scheduler_rule;
  Registry.register store_queue_leakage_rule;
  Registry.register port_contention_rule;
  Registry.register constant_time_verification_rule