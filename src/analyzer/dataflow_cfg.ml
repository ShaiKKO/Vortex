open Types
open Utils

module Cfg = struct
  type node_id = int
  
  type node_kind =
    | Entry
    | Exit
    | Statement of Parsetree.expression
    | Branch of Parsetree.expression * node_id * node_id option
    | Join
  
  type node = {
    id: node_id;
    kind: node_kind;
    mutable preds: node_id list;
    mutable succs: node_id list;
    mutable dom: node_id option;
    mutable df: node_id list;
  }
  
  type t = {
    nodes: (node_id, node) Hashtbl.t;
    entry: node_id;
    exit: node_id;
    mutable next_id: int;
  }
  
  let create () = {
    nodes = Hashtbl.create 256;
    entry = 0;
    exit = 1;
    next_id = 2;
  }
  
  let add_node cfg kind =
    let id = cfg.next_id in
    cfg.next_id <- cfg.next_id + 1;
    let node = {
      id;
      kind;
      preds = [];
      succs = [];
      dom = None;
      df = [];
    } in
    Hashtbl.add cfg.nodes id node;
    id
  
  let add_edge cfg from_id to_id =
    let from_node = Hashtbl.find cfg.nodes from_id in
    let to_node = Hashtbl.find cfg.nodes to_id in
    from_node.succs <- to_id :: from_node.succs;
    to_node.preds <- from_id :: to_node.preds
  
  let compute_dominators cfg =
    let rec intersect doms b1 b2 =
      let rec finger1 = ref b1 in
      let rec finger2 = ref b2 in
      while !finger1 <> !finger2 do
        while !finger1 > !finger2 do
          finger1 := doms.(!finger1)
        done;
        while !finger2 > !finger1 do
          finger2 := doms.(!finger2)
        done
      done;
      !finger1
    in
    
    let n = Hashtbl.length cfg.nodes in
    let doms = Array.make n (-1) in
    doms.(cfg.entry) <- cfg.entry;
    
    let changed = ref true in
    while !changed do
      changed := false;
      Hashtbl.iter (fun id node ->
        if id <> cfg.entry then
          let new_dom = 
            List.fold_left (fun acc pred ->
              if doms.(pred) >= 0 then
                if acc = -1 then pred
                else intersect doms acc pred
              else acc
            ) (-1) node.preds
          in
          if doms.(id) <> new_dom then begin
            doms.(id) <- new_dom;
            changed := true
          end
      ) cfg.nodes
    done;
    
    Hashtbl.iter (fun id node ->
      node.dom <- if doms.(id) >= 0 then Some doms.(id) else None
    ) cfg.nodes
end

module Dataflow = struct
  type lattice_value =
    | Bot
    | Value of crypto_state
    | Top
  
  and crypto_state = {
    nonces: (string * usage_state) list;
    keys: (string * key_state) list;
    randoms: (string * random_state) list;
  }
  
  and usage_state = Fresh | Used | Unknown
  and key_state = Literal of string | Derived | External | Unknown
  and random_state = CryptoSecure | PseudoRandom | Unknown
  
  let join v1 v2 =
    match v1, v2 with
    | Bot, v | v, Bot -> v
    | Top, _ | _, Top -> Top
    | Value s1, Value s2 ->
        let join_usage u1 u2 =
          match u1, u2 with
          | Fresh, Fresh -> Fresh
          | Used, _ | _, Used -> Used
          | _ -> Unknown
        in
        let join_key k1 k2 =
          match k1, k2 with
          | Literal s1, Literal s2 when s1 = s2 -> Literal s1
          | Derived, Derived -> Derived
          | External, External -> External
          | _ -> Unknown
        in
        Value {
          nonces = List.map2 (fun (n1, u1) (n2, u2) ->
            (n1, join_usage u1 u2)
          ) s1.nonces s2.nonces;
          keys = List.map2 (fun (k1, s1) (k2, s2) ->
            (k1, join_key s1 s2)
          ) s1.keys s2.keys;
          randoms = s1.randoms;
        }
  
  let analyze_node node state =
    match node.Cfg.kind with
    | Statement expr ->
        analyze_expr expr state
    | Branch (cond, _, _) ->
        analyze_expr cond state
    | _ -> state
  
  and analyze_expr expr state =
    let open Parsetree in
    match expr.pexp_desc with
    | Pexp_let (_, bindings, body) ->
        let state' = List.fold_left analyze_binding state bindings in
        analyze_expr body state'
    
    | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (_, "encrypt"); _}; _}, args) ->
        check_nonce_usage args state
    
    | _ -> state
  
  and analyze_binding state vb =
    match vb.pvb_pat.ppat_desc with
    | Ppat_var {txt = name; _} when contains_substring name "nonce" ->
        match state with
        | Value s -> Value {s with nonces = (name, Fresh) :: s.nonces}
        | _ -> state
    | _ -> state
  
  and check_nonce_usage args state =
    List.iter (fun (label, arg) ->
      match label, arg with
      | Asttypes.Labelled "nonce", {pexp_desc = Pexp_ident {txt = Lident name; _}; _} ->
          (match state with
          | Value s ->
              let nonces' = List.map (fun (n, u) ->
                if n = name then (n, Used) else (n, u)
              ) s.nonces in
              Value {s with nonces = nonces'}
          | _ -> state)
      | _ -> ()
    ) args;
    state
  
  let worklist_algorithm cfg initial_state =
    let states = Hashtbl.create (Hashtbl.length cfg.Cfg.nodes) in
    Hashtbl.iter (fun id _ ->
      Hashtbl.add states id (if id = cfg.entry then initial_state else Bot)
    ) cfg.nodes;
    
    let worklist = Queue.create () in
    Queue.add cfg.entry worklist;
    
    while not (Queue.is_empty worklist) do
      let node_id = Queue.take worklist in
      let node = Hashtbl.find cfg.nodes node_id in
      
      let input_state = 
        List.fold_left (fun acc pred_id ->
          let pred_state = Hashtbl.find states pred_id in
          join acc pred_state
        ) Bot node.preds
      in
      
      let output_state = analyze_node node input_state in
      
      if output_state <> Hashtbl.find states node_id then begin
        Hashtbl.replace states node_id output_state;
        List.iter (fun succ_id ->
          if not (Queue.mem succ_id worklist) then
            Queue.add succ_id worklist
        ) node.succs
      end
    done;
    
    states
end

let build_cfg_from_ast ast =
  let cfg = Cfg.create () in
  
  let rec visit_expr parent_id expr =
    match expr.Parsetree.pexp_desc with
    | Pexp_sequence (e1, e2) ->
        let mid_id = visit_expr parent_id e1 in
        visit_expr mid_id e2
    
    | Pexp_ifthenelse (cond, then_e, else_opt) ->
        let branch_id = Cfg.add_node cfg (Branch (cond, 0, None)) in
        Cfg.add_edge cfg parent_id branch_id;
        
        let then_id = visit_expr branch_id then_e in
        let else_id = match else_opt with
          | Some else_e -> visit_expr branch_id else_e
          | None -> branch_id
        in
        
        let join_id = Cfg.add_node cfg Join in
        Cfg.add_edge cfg then_id join_id;
        Cfg.add_edge cfg else_id join_id;
        join_id
    
    | Pexp_let (_, bindings, body) ->
        let stmt_id = Cfg.add_node cfg (Statement expr) in
        Cfg.add_edge cfg parent_id stmt_id;
        visit_expr stmt_id body
    
    | _ ->
        let stmt_id = Cfg.add_node cfg (Statement expr) in
        Cfg.add_edge cfg parent_id stmt_id;
        stmt_id
  in
  
  let entry_node = {
    Cfg.id = cfg.entry;
    kind = Entry;
    preds = [];
    succs = [];
    dom = None;
    df = [];
  } in
  Hashtbl.add cfg.nodes cfg.entry entry_node;
  
  let exit_node = {
    Cfg.id = cfg.exit;
    kind = Exit;
    preds = [];
    succs = [];
    dom = None;
    df = [];
  } in
  Hashtbl.add cfg.nodes cfg.exit exit_node;
  
  List.fold_left (fun parent_id item ->
    match item.Parsetree.pstr_desc with
    | Pstr_eval (expr, _) -> visit_expr parent_id expr
    | _ -> parent_id
  ) cfg.entry ast;
  
  Cfg.compute_dominators cfg;
  cfg

let analyze_dataflow ast =
  let cfg = build_cfg_from_ast ast in
  let initial_state = Dataflow.Value {
    nonces = [];
    keys = [];
    randoms = [];
  } in
  let final_states = Dataflow.worklist_algorithm cfg initial_state in
  
  let findings = ref [] in
  
  Hashtbl.iter (fun node_id state ->
    match state with
    | Dataflow.Value s ->
        List.iter (fun (name, usage) ->
          match usage with
          | Dataflow.Used ->
              (* Check if this nonce was used before *)
              findings := {
                rule_id = "CRYPTO_FLOW_001";
                severity = Critical;
                message = Printf.sprintf "Nonce '%s' may be reused" name;
                vulnerability = NonceReuse;
                location = {
                  file = "";
                  line = 0;
                  column = 0;
                  end_line = None;
                  end_column = None;
                };
                suggestion = Some "Ensure nonces are used only once";
                references = ["CVE-2016-0270"];
              } :: !findings
          | _ -> ()
        ) s.nonces
    | _ -> ()
  ) final_states;
  
  !findings