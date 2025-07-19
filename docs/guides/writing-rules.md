# Writing Custom Rules

This guide explains how to create custom security rules for OCaml Crypto Linter.

## Rule Structure

Each rule implements the `Rule.t` type:

```ocaml
type t = {
  id: string;               (* Unique identifier like "CUSTOM001" *)
  name: string;             (* Human-readable name *)
  severity: severity;       (* Critical | Error | Warning | Info *)
  tags: string list;        (* Categories like ["crypto", "key-management"] *)
  check: Ppxlib.structure -> finding list;  (* The analysis function *)
}
```

## Basic Rule Template

Create a new file `src/rules/my_custom_rules.ml`:

```ocaml
open Ppxlib
open Ocaml_crypto_linter.Types

let rule_hardcoded_api_key = {
  Rule.id = "CUSTOM001";
  name = "Hardcoded API Key";
  severity = Critical;
  tags = ["security", "secrets"];
  check = fun structure ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_constant (Pconst_string (value, _, _)) ->
            (* Check if string looks like an API key *)
            if String.length value > 20 && 
               String.contains_substring value "api_key" ||
               String.contains_substring value "secret_" then
              findings := {
                rule_id = "CUSTOM001";
                severity = Critical;
                message = "Hardcoded API key detected";
                vulnerability = HardcodedKey;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some "Store API keys in environment variables or secure vaults";
                references = ["https://cwe.mitre.org/data/definitions/798.html"];
              } :: !findings
        | _ -> ()
        
        super#expression expr ()
    end in
    
    visitor#structure structure ();
    !findings
}

(* Register the rule *)
let () = Rule_engine.Registry.register rule_hardcoded_api_key
```

## Advanced Pattern Matching

### Detecting Function Calls

```ocaml
let rule_weak_random_seed = {
  Rule.id = "CUSTOM002";
  name = "Weak Random Seed";
  severity = Error;
  tags = ["crypto", "randomness"];
  check = fun structure ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        (* Random.init with predictable seed *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Ldot (Lident "Random", "init"); _}; _},
                     [(_, seed_expr)]) ->
            (match seed_expr.pexp_desc with
            | Pexp_constant (Pconst_integer _) ->
                findings := make_finding 
                  ~rule_id:"CUSTOM002"
                  ~message:"Random.init called with constant seed"
                  ~location:(location_of_expression expr)
                  ~suggestion:"Use Random.self_init() or cryptographically secure random"
                  :: !findings
            | _ -> ())
        | _ -> ()
        
        super#expression expr ()
    end in
    
    visitor#structure structure ();
    !findings
}
```

### Context-Aware Analysis

```ocaml
let rule_unencrypted_storage = {
  Rule.id = "CUSTOM003";
  name = "Unencrypted Sensitive Data Storage";
  severity = Error;
  tags = ["storage", "encryption"];
  check = fun structure ->
    let findings = ref [] in
    let sensitive_vars = Hashtbl.create 10 in
    
    (* First pass: identify sensitive variables *)
    let identifier_visitor = object
      inherit [unit] Ast_traverse.iter as super
      
      method! value_binding vb () =
        match vb.pvb_pat.ppat_desc with
        | Ppat_var {txt; _} when 
            List.exists (fun pattern -> String.contains_substring (String.lowercase_ascii txt) pattern)
              ["password"; "secret"; "key"; "token"; "credential"] ->
            Hashtbl.add sensitive_vars txt vb.pvb_loc
        | _ -> ()
        
        super#value_binding vb ()
    end in
    
    (* Second pass: check if sensitive data is written to files *)
    let storage_visitor = object
      inherit [unit] Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Longident.Ldot (Lident "Out_channel", "write_string"); _}; _},
                     [_; (_, {pexp_desc = Pexp_ident {txt = Lident var; _}; _})]) ->
            if Hashtbl.mem sensitive_vars var then
              findings := make_finding
                ~rule_id:"CUSTOM003"
                ~message:(Printf.sprintf "Sensitive variable '%s' written to file without encryption" var)
                ~location:(location_of_expression expr)
                ~suggestion:"Encrypt sensitive data before storage"
                :: !findings
        | _ -> ()
        
        super#expression expr ()
    end in
    
    identifier_visitor#structure structure ();
    storage_visitor#structure structure ();
    !findings
}
```

## Helper Functions

Create utility functions for common patterns:

```ocaml
(* utils.ml *)
let location_of_expression expr = {
  file = expr.pexp_loc.loc_start.pos_fname;
  line = expr.pexp_loc.loc_start.pos_lnum;
  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
}

let make_finding ~rule_id ~message ~location ?(severity=Error) ?(suggestion=None) ?(references=[]) () = {
  rule_id;
  severity;
  message;
  vulnerability = HardcodedKey; (* Adjust based on rule *)
  location;
  suggestion;
  references;
}

let is_crypto_function = function
  | Longident.Ldot (Lident "Cryptokit", _) -> true
  | Longident.Ldot (Lident "Nocrypto", _) -> true
  | Longident.Ldot (Lident "Mirage_crypto", _) -> true
  | _ -> false

let extract_string_constant = function
  | {pexp_desc = Pexp_constant (Pconst_string (s, _, _)); _} -> Some s
  | _ -> None
```

## Testing Your Rules

Create test cases in `test/test_custom_rules.ml`:

```ocaml
open Alcotest

let test_hardcoded_api_key () =
  let code = {|
    let api_key = "sk_live_abcd1234567890"
    let config = {
      endpoint = "https://api.example.com";
      key = api_key;
    }
  |} in
  
  let ast = Ppxlib.Parse.implementation (Lexing.from_string code) in
  let findings = My_custom_rules.rule_hardcoded_api_key.check ast in
  
  check int "should find one hardcoded key" 1 (List.length findings);
  check string "should have correct rule ID" "CUSTOM001" 
    (List.hd findings).rule_id

let test_weak_random_seed () =
  let code = {|
    let () = Random.init 42
    let token = Random.bits ()
  |} in
  
  let ast = Ppxlib.Parse.implementation (Lexing.from_string code) in
  let findings = My_custom_rules.rule_weak_random_seed.check ast in
  
  check int "should find weak seed" 1 (List.length findings)

let () =
  run "Custom Rules" [
    "hardcoded_api_key", [
      test_case "detects API keys" `Quick test_hardcoded_api_key;
    ];
    "weak_random", [
      test_case "detects weak seeds" `Quick test_weak_random_seed;
    ];
  ]
```

## Registering Rules

Add to `src/rules/dune`:

```dune
(library
 (name ocaml_crypto_linter_rules)
 (public_name ocaml-crypto-linter.rules)
 (modules
  rule_engine
  algorithm_weakness_rules
  key_nonce_rules
  side_channel_rules
  api_misuse_rules
  my_custom_rules)  ; Add your module
 (libraries
  ocaml_crypto_linter.types
  ppxlib))
```

Register in `rule_engine.ml`:

```ocaml
module Registry = struct
  let rules = ref []
  
  let register rule =
    rules := rule :: !rules
    
  let all_rules () = !rules
  
  let get_rule id =
    List.find_opt (fun r -> r.Rule.id = id) !rules
end

(* Auto-registration *)
let () =
  (* Existing rules *)
  List.iter Registry.register Algorithm_weakness_rules.all_rules;
  List.iter Registry.register Key_nonce_rules.all_rules;
  
  (* Custom rules *)
  Registry.register My_custom_rules.rule_hardcoded_api_key;
  Registry.register My_custom_rules.rule_weak_random_seed
```

## Advanced Techniques

### Inter-procedural Analysis

```ocaml
let analyze_interprocedural structure =
  let call_graph = ref StringMap.empty in
  let sensitive_functions = ref StringSet.empty in
  
  (* Build call graph *)
  let build_visitor = object
    inherit [unit] Ast_traverse.iter as super
    
    method! expression expr () =
      match expr.pexp_desc with
      | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
          (* Track function calls *)
          let caller = get_current_function () in
          let callee = Longident.flatten txt |> String.concat "." in
          (* Update call graph *)
      | _ -> ()
  end in
  
  (* Analyze data flow through call graph *)
  (* ... *)
```

### Pattern Matching with metaquot

```ocaml
let detect_pattern structure =
  let pattern = [%expr Hashtbl.find [%e? _] [%e? key]] in
  
  match structure with
  | [%expr Hashtbl.find [%e? table] [%e? key]] ->
      (* Matched! Analyze table and key *)
  | _ -> ()
```

### Custom Vulnerability Types

```ocaml
type custom_vulnerability =
  | InsecureDeserialization
  | SQLInjection
  | CommandInjection
  | XXE
  | InsecureFileUpload

let vulnerability_to_json = function
  | InsecureDeserialization -> 
      `Assoc [("type", `String "insecure_deserialization")]
  (* ... *)
```

## Best Practices

1. **Use Clear Rule IDs**: Follow naming convention (CUSTOM001, SEC001, etc.)
2. **Provide Actionable Messages**: Tell users how to fix issues
3. **Include References**: Link to CWEs, CVEs, or documentation
4. **Test Thoroughly**: Both positive and negative cases
5. **Consider Context**: Reduce false positives with context analysis
6. **Document Rules**: Add comments explaining what you're detecting and why

## Distribution

### As OPAM Package

```yaml
opam-version: "2.0"
name: "my-crypto-rules"
depends: ["ocaml-crypto-linter" {>= "0.1.0"}]
```

### As Plugin

```ocaml
(* plugin.ml *)
let init () =
  My_custom_rules.register_all ()

let () = 
  Ocaml_crypto_linter.Plugin.register "my-rules" init
```

## Examples Repository

Find more examples at:
- Basic rules: `examples/rules/basic/`
- Advanced rules: `examples/rules/advanced/`
- Domain-specific: `examples/rules/domain/`