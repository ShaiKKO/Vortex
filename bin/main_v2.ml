(* Enhanced CLI with confidence scoring and priority filtering *)
open Cmdliner
open Ocaml_crypto_linter

let analyze_cmd confidence_threshold priority_threshold files =
  let start_time = Unix.gettimeofday () in
  
  (* Configure analyzer *)
  let config = {
    Analyzer.default_config with
    enable_interprocedural = true;
  } in
  
  (* Run analysis *)
  let result = Analyzer.analyze_files ~config files in
  let analysis_time = Unix.gettimeofday () -. start_time in
  let result = { result with analysis_time } in
  
  (* Apply confidence and priority filtering *)
  let enhanced_findings = Confidence_scoring.enhance_findings result.findings in
  let filtered = List.filter (fun e ->
    let conf_score = match e.Confidence_scoring.Enhanced_finding.confidence with
      | VeryHigh s | High s | Medium s | Low s | VeryLow s -> s
    in
    conf_score >= confidence_threshold && 
    e.Confidence_scoring.Enhanced_finding.priority >= priority_threshold
  ) enhanced_findings in
  
  (* Convert back to regular findings for compatibility *)
  let filtered_findings = List.map (fun e -> 
    e.Confidence_scoring.Enhanced_finding.finding
  ) filtered in
  
  let filtered_result = { result with findings = filtered_findings } in
  
  (* Print enhanced summary *)
  Json_reporter_v2.print_enhanced_summary filtered_result;
  
  (* Write detailed report *)
  Json_reporter_v2.write_report_v2 ~output_file:"crypto_lint_report.json" result;
  Json_reporter_v2.write_text_report_v2 ~output_file:"crypto_lint_report.txt" result;
  
  Printf.printf "\nDetailed reports written to:\n";
  Printf.printf "  - crypto_lint_report.json (JSON with confidence scores)\n";
  Printf.printf "  - crypto_lint_report.txt (Human-readable with priorities)\n";
  
  (* Exit with appropriate code *)
  if List.exists (fun e -> 
    e.Confidence_scoring.Enhanced_finding.priority >= 8
  ) enhanced_findings then
    exit 1
  else
    exit 0

let confidence_arg =
  let doc = "Minimum confidence threshold (0.0-1.0)" in
  Arg.(value & opt float 0.0 & info ["c"; "confidence"] ~docv:"THRESHOLD" ~doc)

let priority_arg =
  let doc = "Minimum priority level (1-10)" in
  Arg.(value & opt int 1 & info ["p"; "priority"] ~docv:"LEVEL" ~doc)

let files_arg =
  let doc = "OCaml source files to analyze" in
  Arg.(non_empty & pos_all file [] & info [] ~docv:"FILE" ~doc)

let analyze_term =
  Term.(const analyze_cmd $ confidence_arg $ priority_arg $ files_arg)

let info =
  let doc = "OCaml cryptographic vulnerability linter with confidence scoring" in
  let man = [
    `S Manpage.s_description;
    `P "Analyzes OCaml code for cryptographic vulnerabilities with statistical confidence scoring.";
    `P "Features:";
    `P "- Context-aware analysis reduces false positives";
    `P "- Interprocedural analysis detects complex patterns";
    `P "- Confidence scoring helps prioritize fixes";
    `P "- Risk-based priority ranking (P1-P10)";
    `S Manpage.s_examples;
    `P "Analyze all ML files:";
    `Pre "  ocaml-crypto-linter src/**/*.ml";
    `P "Show only high confidence findings:";
    `Pre "  ocaml-crypto-linter -c 0.8 src/**/*.ml";
    `P "Focus on critical issues (P7+):";
    `Pre "  ocaml-crypto-linter -p 7 src/**/*.ml";
  ] in
  Cmd.info "ocaml-crypto-linter" ~version:"0.2.0" ~doc ~man

let cmd = Cmd.v info analyze_term

let () = exit (Cmd.eval cmd)