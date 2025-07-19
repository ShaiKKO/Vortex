open Types
open Types.Json_conv

let report_to_json result =
  let findings_json = `List (List.map finding_to_json result.findings) in
  let summary = `Assoc [
    ("total_findings", `Int (List.length result.findings));
    ("critical", `Int (List.length (List.filter (fun f -> f.severity = Critical) result.findings)));
    ("errors", `Int (List.length (List.filter (fun f -> f.severity = Error) result.findings)));
    ("warnings", `Int (List.length (List.filter (fun f -> f.severity = Warning) result.findings)));
    ("info", `Int (List.length (List.filter (fun f -> f.severity = Info) result.findings)));
  ] in
  
  let errors_json = `List (List.map (fun (file, msg) -> 
    `Assoc [("file", `String file); ("error", `String msg)]
  ) result.errors) in
  
  `Assoc [
    ("findings", findings_json);
    ("summary", summary);
    ("metadata", `Assoc [
      ("files_analyzed", `Int result.files_analyzed);
      ("analysis_time", `Float result.analysis_time);
      ("tool_version", `String "0.1.0");
      ("timestamp", `String (Unix.time () |> Unix.gmtime |> fun tm ->
        Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ"
          (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
          tm.tm_hour tm.tm_min tm.tm_sec));
    ]);
    ("errors", errors_json);
  ]

let write_report ~output_file result =
  let json = report_to_json result in
  let out_chan = open_out output_file in
  Yojson.Safe.pretty_to_channel out_chan json;
  close_out out_chan

let print_summary result =
  Printf.printf "\n=== OCaml Crypto Linter Summary ===\n";
  Printf.printf "Files analyzed: %d\n" result.files_analyzed;
  Printf.printf "Analysis time: %.2fs\n" result.analysis_time;
  Printf.printf "\nFindings:\n";
  Printf.printf "  Critical: %d\n" (List.length (List.filter (fun f -> f.severity = Critical) result.findings));
  Printf.printf "  Errors: %d\n" (List.length (List.filter (fun f -> f.severity = Error) result.findings));
  Printf.printf "  Warnings: %d\n" (List.length (List.filter (fun f -> f.severity = Warning) result.findings));
  Printf.printf "  Info: %d\n" (List.length (List.filter (fun f -> f.severity = Info) result.findings));
  Printf.printf "  Total: %d\n" (List.length result.findings);
  
  if result.errors <> [] then begin
    Printf.printf "\nAnalysis errors:\n";
    List.iter (fun (file, msg) ->
      Printf.printf "  %s: %s\n" file msg
    ) result.errors
  end