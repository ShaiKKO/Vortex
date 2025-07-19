open Types
open Ppxlib
open Analyzer_types

module Analyzer = struct
  
  let analyze_single_file = File_analyzer.analyze_single_file
  
  
  let analyze_files ?(config = default_config) files =
    let state = create_state config in
    
    (* Always use sequential analysis to avoid circular dependency *)
    List.iter (fun file ->
      let _ = analyze_single_file state file in ()
    ) files;
    
    {
      findings = !(state.findings);
      files_analyzed = !(state.files_analyzed);
      analysis_time = 0.0;
      errors = [];
    }
  
  let analyze_with_semgrep_deps project_root =
    (* Scan for dependency vulnerabilities *)
    let deps_file = Filename.concat project_root "opam" in
    if Sys.file_exists deps_file then
      let semgrep_rules = [
        {
          Semgrep_integration.Semgrep.id = "ocaml.deps.outdated-crypto";
          pattern = {|
            depends: [
              ...
              "$CRYPTO" {$CONSTRAINT}
              ...
            ]
          |};
          message = "Check crypto library version for known vulnerabilities";
          severity = "WARNING";
          languages = ["yaml"];
        };
      ] in
      
      match Lwt_main.run (
        let open Lwt.Syntax in
        let* () = Semgrep_integration.Semgrep.write_rules_file semgrep_rules in
        Semgrep_integration.Semgrep.run_semgrep deps_file
      ) with
      | findings -> findings
      | exception _ -> []
    else []
end