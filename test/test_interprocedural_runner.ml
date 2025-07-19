(* Test runner for interprocedural analysis *)
open Ocaml_crypto_linter

let test_file = "test_interprocedural.ml"

let run_tests () =
  Printf.printf "Testing interprocedural analysis...\n\n";
  
  (* Parse the test file *)
  let ast = 
    try
      let ic = open_in test_file in
      let lexbuf = Lexing.from_channel ic in
      lexbuf.lex_curr_p <- { lexbuf.lex_curr_p with pos_fname = test_file };
      let structure = Parse.implementation lexbuf in
      close_in ic;
      Ppxlib_ast.Selected_ast.Of_ocaml.copy_structure structure
    with e ->
      Printf.eprintf "Failed to parse test file: %s\n" (Printexc.to_string e);
      exit 1
  in
  
  (* Run the enhanced API misuse rules *)
  let rules = [
    Api_misuse_rules_v2.cbc_without_mac_rule_v2;
    Api_misuse_rules_v2.encrypt_then_mac_rule_v2;
    Api_misuse_rules_v2.key_reuse_rule_v2;
  ] in
  
  List.iter (fun rule ->
    Printf.printf "Running rule: %s (%s)\n" rule.id rule.name;
    let findings = rule.check ast in
    
    if findings = [] then
      Printf.printf "  No issues found.\n"
    else
      List.iter (fun finding ->
        Printf.printf "  [%s] %s at line %d\n"
          (match finding.severity with
           | Critical -> "CRITICAL"
           | Error -> "ERROR"
           | Warning -> "WARNING"
           | Info -> "INFO")
          finding.message
          finding.location.line;
        
        match finding.suggestion with
        | Some sugg -> Printf.printf "    Suggestion: %s\n" sugg
        | None -> ()
      ) findings;
    
    Printf.printf "\n"
  ) rules;
  
  Printf.printf "Interprocedural analysis test complete.\n"

let () = run_tests ()