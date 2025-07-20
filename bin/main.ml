open Cmdliner
open Ocaml_crypto_linter
open Ocaml_crypto_linter.Types

(* Force loading of all rules by explicitly referencing the Rules module *)
module Rules = Ocaml_crypto_linter.Rules
let () = ignore Rules.rule_statistics

let analyze_files files output_format output_file enable_semgrep =
  let start_time = Unix.gettimeofday () in
  let all_findings = ref [] in
  let errors = ref [] in
  let files_analyzed = ref 0 in
  
  List.iter (fun file ->
    try
      let ic = open_in file in
      let lexbuf = Lexing.from_channel ic in
      lexbuf.lex_curr_p <- { lexbuf.lex_curr_p with pos_fname = file };
      
      let structure = Ppxlib.Parse.implementation lexbuf in
      close_in ic;
      
      (* Run AST-based analysis *)
      let ast_findings = Ast_analyzer.analyze_structure structure in
      
      (* Run registered rules *)
      let all_rules = Rules.Registry.all_rules () in
      let rule_findings = List.concat_map (fun rule ->
        rule.Rule_engine.Rule.check structure
      ) all_rules in
      
      all_findings := !all_findings @ ast_findings @ rule_findings;
      incr files_analyzed
      
    with
    | Syntaxerr.Error _ as e ->
        errors := (file, Printexc.to_string e) :: !errors
    | e ->
        errors := (file, Printexc.to_string e) :: !errors
  ) files;
  
  (* Run Semgrep analysis if enabled *)
  let final_findings = 
    if enable_semgrep then
      match Lwt_main.run (Semgrep_integration.analyze_with_semgrep ".") with
      | semgrep_findings -> !all_findings @ semgrep_findings
      | exception _ -> !all_findings
    else !all_findings
  in
  
  let result = {
    Types.findings = final_findings;
    files_analyzed = !files_analyzed;
    analysis_time = Unix.gettimeofday () -. start_time;
    errors = !errors;
  } in
  
  match output_format with
  | "json" ->
      (match output_file with
       | Some file -> Json_reporter.write_report ~output_file:file result
       | None -> Yojson.Safe.pretty_to_channel stdout (Json_reporter.report_to_json result))
  | "sarif" ->
      (match output_file with
       | Some file -> Sarif_reporter.write_sarif_report ~output_file:file result
       | None -> Sarif_reporter.print_sarif result)
  | "text" | _ ->
      Json_reporter.print_summary result;
      List.iter (fun finding ->
        Printf.printf "\n[%s] %s\n" finding.rule_id finding.message;
        Printf.printf "  File: %s:%d:%d\n" 
          finding.location.file 
          finding.location.line 
          finding.location.column;
        Printf.printf "  Severity: %s\n" 
          (match finding.severity with
           | Info -> "INFO"
           | Warning -> "WARNING"
           | Error -> "ERROR"
           | Critical -> "CRITICAL");
        (match finding.suggestion with
         | Some s -> Printf.printf "  Suggestion: %s\n" s
         | None -> ())
      ) result.findings

let files_arg =
  Arg.(non_empty & pos_all file [] & info [] ~docv:"FILE" ~doc:"OCaml source files to analyze")

let output_format_arg =
  Arg.(value & opt string "text" & info ["f"; "format"] ~docv:"FORMAT" 
    ~doc:"Output format (text, json, or sarif)")

let output_file_arg =
  Arg.(value & opt (some string) None & info ["o"; "output"] ~docv:"FILE"
    ~doc:"Output file (stdout if not specified)")

let semgrep_arg =
  Arg.(value & flag & info ["semgrep"] ~doc:"Enable Semgrep integration for additional checks")

let analyze_cmd =
  let doc = "Analyze OCaml code for cryptographic vulnerabilities" in
  let man = [
    `S Manpage.s_description;
    `P "ocaml-crypto-linter is a static analysis tool that detects common cryptographic misuses and vulnerabilities in OCaml codebases.";
    `P "It supports both AST-based analysis and Semgrep rules for comprehensive coverage.";
    `S Manpage.s_examples;
    `P "Analyze a single file:";
    `Pre "  ocaml-crypto-linter src/crypto.ml";
    `P "Analyze multiple files with JSON output:";
    `Pre "  ocaml-crypto-linter -f json -o report.json src/*.ml";
    `P "Generate SARIF report for GitHub:";
    `Pre "  ocaml-crypto-linter -f sarif -o report.sarif src/*.ml";
    `P "Enable Semgrep integration:";
    `Pre "  ocaml-crypto-linter --semgrep src/";
  ] in
  let info = Cmd.info "ocaml-crypto-linter" ~version:"0.1.0" ~doc ~man in
  Cmd.v info Term.(const analyze_files $ files_arg $ output_format_arg $ output_file_arg $ semgrep_arg)

let () = exit (Cmd.eval analyze_cmd)