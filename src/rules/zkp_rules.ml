(* Zero-Knowledge Proof Vulnerability Rules Implementation
   Detects SNARK circuit bugs, verifier issues, and side-channels *)

module T = Types
open Rule_engine  
open Ppxlib
open Utils

(* Convert location helper *)
let convert_location (loc : Ppxlib.Location.t) : T.location =
  {
    T.file = loc.loc_start.pos_fname;
    T.line = loc.loc_start.pos_lnum;
    T.column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
    T.end_line = Some loc.loc_end.pos_lnum;
    T.end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
  }

(* Helper to create findings *)
let make_finding ~rule_id ~severity ~message ~location ~suggestion ~references =
  {
    T.rule_id;
    T.severity;
    T.message;
    T.vulnerability = T.SupplyChain; (* TODO: Add ZKP vulnerability type *)
    T.location;
    T.suggestion;
    T.references;
  }

(* ZKP library detection *)
module ZKP_Detection = struct
  (* Common ZKP library patterns *)
  let zkp_modules = [
    "Bellman"; "Groth16"; "ConstraintSystem"; "LinearCombination";
    "Snarky"; "Snark"; "Field"; "Boolean";
    "Bulletproof"; "RangeProof"; 
    "PLONK"; "PlonkCircuit";
    "Circom"; "witness"; "signal";
  ]
  
  let is_zkp_code ast =
    let found = ref false in
    let visitor = object
      inherit Ast_traverse.iter as super
      method! expression expr =
        match expr.pexp_desc with
        | Pexp_ident {txt = Longident.Lident name; _}
        | Pexp_ident {txt = Longident.Ldot(_, name); _} ->
            if List.mem name zkp_modules then found := true;
            super#expression expr
        | _ -> super#expression expr
    end in
    visitor#structure ast;
    !found
    
  (* Track witness/signal declarations *)
  let find_witness_vars ast =
    let witnesses = ref [] in
    let visitor = object
      inherit Ast_traverse.iter as super
      method! expression expr =
        match expr.pexp_desc with
        (* Field.var () or similar *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Ldot(_, ("var" | "witness" | "signal")); _}; _}, _) ->
            witnesses := expr.pexp_loc :: !witnesses;
            super#expression expr
        (* let witness = ... *)
        | Pexp_let (_, bindings, _) ->
            List.iter (fun binding ->
              match binding.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} when 
                  contains_substring name "witness" || 
                  contains_substring name "private" ||
                  contains_substring name "secret" ->
                  witnesses := binding.pvb_expr.pexp_loc :: !witnesses
              | _ -> ()
            ) bindings;
            super#expression expr
        | _ -> super#expression expr
    end in
    visitor#structure ast;
    !witnesses
end

(* ZKP001: Under-Constrained Circuits - 96% of bugs *)
let under_constrained_circuit_rule : Rule.t = {
  id = "ZKP001";
  name = "Under-Constrained ZKP Circuit";
  description = "Detects circuits with missing constraints (96% of SNARK bugs)";
  severity = T.Critical;
  tags = ["zkp"; "circuit"; "constraint"; "security"; "soundness"];
  check = fun ast ->
    let findings = ref [] in
    
    if not (ZKP_Detection.is_zkp_code ast) then !findings
    else begin
      (* Track constraints and witnesses *)
      let witnesses = ref [] in
      let constraints = ref [] in
      let unconstrained = ref [] in
      
      let visitor = object(self)
        inherit Ast_traverse.iter as super
        
        method! expression expr =
          match expr.pexp_desc with
          (* Witness/variable declarations *)
          | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Ldot(_, "var"); _}; _}, _) ->
              witnesses := expr.pexp_loc :: !witnesses;
              super#expression expr
              
          (* Look for constraint patterns *)
          | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Lident name; _}; _}, args) 
            when List.mem name ["assert_r1cs"; "assert_equal"; "enforce"; "constrain"] ->
              constraints := expr.pexp_loc :: !constraints;
              super#expression expr
              
          (* Detect unconstrained operations *)
          | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Lident op; _}; _}, 
                       [(_, left); (_, right)]) when List.mem op ["*"; "+"; "-"] ->
              (* Check if result is assigned but not constrained *)
              unconstrained := expr.pexp_loc :: !unconstrained;
              super#expression expr
              
          (* Array access without bounds check *)
          | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Lident "Array.get"; _}; _}, 
                       [(_, _arr); (_, index)]) ->
              findings := 
                make_finding
                  ~rule_id:"ZKP001"
                  ~severity:T.Critical
                  ~message:"Unconstrained array index in circuit - allows out-of-bounds access"
                  ~location:(convert_location expr.pexp_loc)
                  ~suggestion:(Some 
                    "Add range constraint for array index:\n\
                     assert_r1cs (index >= 0);\n\
                     assert_r1cs (index < array_length);")
                  ~references:[
                    "https://en.wikipedia.org/wiki/Zero-knowledge_proof";
                    "2024 SoK: 96% of circuit vulnerabilities";
                  ]
                :: !findings;
              super#expression expr
              
          | _ -> super#expression expr
        
        method! structure_item item =
          match item.pstr_desc with
          (* Check for missing constraints in functions *)
          | Pstr_value (_, bindings) ->
              List.iter (fun binding ->
                match binding.pvb_pat.ppat_desc with
                | Ppat_var {txt = fname; _} when contains_substring fname "circuit" ->
                    (* Circuit function should have constraints *)
                    let has_constraints = ref false in
                    let check_visitor = object
                      inherit Ast_traverse.iter
                      method! expression e =
                        match e.pexp_desc with
                        | Pexp_ident {txt = Longident.Lident name; _}
                          when List.mem name ["assert_r1cs"; "enforce"; "constrain"] ->
                            has_constraints := true
                        | _ -> ()
                    end in
                    check_visitor#expression binding.pvb_expr;
                    
                    if not !has_constraints then
                      findings := 
                        make_finding
                          ~rule_id:"ZKP001"
                          ~severity:T.Critical
                          ~message:(Printf.sprintf 
                            "Circuit function '%s' has no constraints - allows arbitrary proofs"
                            fname)
                          ~location:(convert_location binding.pvb_loc)
                          ~suggestion:(Some 
                            "Add constraints to enforce circuit logic:\n\
                             - Use assert_r1cs for R1CS constraints\n\
                             - Use assert_equal for equality constraints\n\
                             - Ensure all witnesses are constrained")
                          ~references:["2024 SoK: Under-constrained circuits"]
                        :: !findings
                | _ -> ()
              ) bindings;
              super#structure_item item
          | _ -> super#structure_item item
      end in
      
      visitor#structure ast;
      !findings
    end
}

(* ZKP002: Verifier Soundness Bugs *)
let verifier_soundness_rule : Rule.t = {
  id = "ZKP002";
  name = "Proof Verifier Soundness Bug";
  description = "Detects vulnerabilities that allow false proof acceptance";
  severity = T.Error;
  tags = ["zkp"; "verifier"; "soundness"; "fiat-shamir"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Weak Fiat-Shamir challenge *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Lident "hash"; _}; _}, args) ->
            let has_all_inputs = ref false in
            List.iter (fun (_, arg) ->
              match arg.pexp_desc with
              | Pexp_tuple elems when List.length elems >= 3 -> 
                  has_all_inputs := true
              | _ -> ()
            ) args;
            
            if not !has_all_inputs then
              findings := 
                make_finding
                  ~rule_id:"ZKP002"
                  ~severity:T.Error
                  ~message:"Incomplete Fiat-Shamir challenge - missing transcript elements"
                  ~location:(convert_location expr.pexp_loc)
                  ~suggestion:(Some 
                    "Include all public values in challenge hash:\n\
                     let challenge = hash(protocol_id || commitments || public_inputs || round_messages)")
                  ~references:[
                    "https://arxiv.org/html/2402.15293v3";
                    "Malformed Fiat-Shamir challenges";
                  ]
                :: !findings;
            super#expression expr
            
        (* Missing error handling in verification *)
        | Pexp_try (verify_expr, exception_cases) ->
            let has_proper_handling = List.exists (fun case ->
              match case.pc_rhs.pexp_desc with
              | Pexp_construct ({txt = Longident.Lident "false"; _}, _) -> true
              | _ -> false
            ) exception_cases in
            
            if not has_proper_handling && contains_substring (Pprintast.string_of_expression verify_expr) "verify" then
              findings := 
                make_finding
                  ~rule_id:"ZKP002"
                  ~severity:T.Error
                  ~message:"Proof verification with unsafe error handling"
                  ~location:(convert_location expr.pexp_loc)
                  ~suggestion:(Some 
                    "Return false on verification errors:\n\
                     try verify_proof proof with _ -> false")
                  ~references:["Soundness bug allowing invalid proofs"]
                :: !findings;
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* ZKP003: Witness Generation Side-Channels (MTZK 2025) *)
let witness_sidechannel_rule : Rule.t = {
  id = "ZKP003";
  name = "Witness Generation Side-Channel Leak";
  description = "Detects timing/power leakage during witness computation";
  severity = T.Warning;
  tags = ["zkp"; "witness"; "timing"; "side-channel"];
  check = fun ast ->
    let findings = ref [] in
    
    let in_witness_context = ref false in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Track witness generation context *)
        | Pexp_let (_, bindings, body) ->
            List.iter (fun binding ->
              match binding.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} when 
                  contains_substring name "witness" || 
                  contains_substring name "private" ->
                  in_witness_context := true
              | _ -> ()
            ) bindings;
            super#expression expr;
            in_witness_context := false
            
        (* Conditional on witness value *)
        | Pexp_ifthenelse (cond, _, _) when !in_witness_context ->
            findings := 
              make_finding
                ~rule_id:"ZKP003"
                ~severity:T.Warning
                ~message:"Conditional branch on witness value - timing side-channel"
                ~location:(convert_location expr.pexp_loc)
                ~suggestion:(Some 
                  "Use constant-time operations:\n\
                   - Replace conditionals with arithmetic\n\
                   - Use Field.if_then_else for constant-time selection\n\
                   - Balance operations across branches")
                ~references:[
                  "https://www.ndss-symposium.org/wp-content/uploads/2025-530-paper.pdf";
                  "MTZK 2025: Timing leaks in ZK compilers";
                ]
              :: !findings;
            super#expression expr
            
        (* Array access with witness index *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Lident "Array.get"; _}; _}, 
                     [(_, _); (_, index)]) when !in_witness_context ->
            findings := 
              make_finding
                ~rule_id:"ZKP003"
                ~severity:T.Warning
                ~message:"Array access with witness-dependent index - cache timing leak"
                ~location:(convert_location expr.pexp_loc)
                ~suggestion:(Some 
                  "Use constant-time array access:\n\
                   - Access all elements and select with multiplexer\n\
                   - Use oblivious RAM techniques\n\
                   - Mask array indices")
                ~references:["Cache timing attacks on witness generation"]
              :: !findings;
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* ZKP004: Trusted Setup Vulnerabilities *)
let trusted_setup_rule : Rule.t = {
  id = "ZKP004";
  name = "Trusted Setup Security Issues";
  description = "Detects vulnerabilities in trusted setup handling";
  severity = T.Critical;
  tags = ["zkp"; "trusted-setup"; "toxic-waste"; "parameters"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Hardcoded values that look like setup params *)
        | Pexp_constant (Pconst_string (s, _, _)) 
          when String.length s > 64 && contains_substring s "0x" ->
            findings := 
              make_finding
                ~rule_id:"ZKP004"
                ~severity:T.Critical
                ~message:"Possible hardcoded trusted setup parameter"
                ~location:(convert_location expr.pexp_loc)
                ~suggestion:(Some 
                  "Never hardcode setup parameters:\n\
                   - Load from external ceremony files\n\
                   - Verify parameter integrity\n\
                   - Use circuit-specific ceremonies")
                ~references:["Trusted setup compromise risks"]
              :: !findings;
            super#expression expr
            
        (* Loading params without verification *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Lident ("load_params" | "read_setup"); _}; _}, args) ->
            (* Check if followed by verification *)
            findings := 
              make_finding
                ~rule_id:"ZKP004"
                ~severity:T.Error
                ~message:"Loading trusted setup without verification"
                ~location:(convert_location expr.pexp_loc)
                ~suggestion:(Some 
                  "Verify setup parameters:\n\
                   let params = load_params file in\n\
                   assert (verify_params_checksum params expected_hash);")
                ~references:["Parameter substitution attacks"]
              :: !findings;
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* ZKP005: Commitment and Randomness Issues *)
let commitment_randomness_rule : Rule.t = {
  id = "ZKP005";
  name = "Weak ZKP Commitments and Randomness";
  description = "Detects insufficient entropy in commitments";
  severity = T.Error;
  tags = ["zkp"; "randomness"; "commitment"; "entropy"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Weak random sources *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Ldot(Longident.Lident "Random", _); _}; _}, _) ->
            findings := 
              make_finding
                ~rule_id:"ZKP005"
                ~severity:T.Error
                ~message:"Using non-cryptographic randomness for ZKP"
                ~location:(convert_location expr.pexp_loc)
                ~suggestion:(Some 
                  "Use cryptographic randomness:\n\
                   let r = Mirage_crypto_rng.generate 32")
                ~references:["Weak randomness in commitments"]
              :: !findings;
            super#expression expr
            
        (* Small random values *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Lident "random_int"; _}; _}, 
                     [(_, {pexp_desc = Pexp_constant (Pconst_integer (n, _)); _})]) ->
            (try
              let max_val = int_of_string n in
              if max_val < 1_000_000 then
                findings := 
                  make_finding
                    ~rule_id:"ZKP005"
                    ~severity:T.Error
                    ~message:(Printf.sprintf "Insufficient randomness: only %d possible values" max_val)
                    ~location:(convert_location expr.pexp_loc)
                    ~suggestion:(Some 
                      "Use at least 128 bits of entropy:\n\
                       let r = Mirage_crypto_rng.generate 16 (* 128 bits *)")
                    ~references:["Brute-forceable commitments"]
                  :: !findings
            with _ -> ());
            super#expression expr
            
        | _ -> super#expression expr
    end in
    
    visitor#structure ast;
    !findings
}

(* Register all ZKP rules *)
let () =
  Registry.register under_constrained_circuit_rule;
  Registry.register verifier_soundness_rule;
  Registry.register witness_sidechannel_rule;
  Registry.register trusted_setup_rule;
  Registry.register commitment_randomness_rule