(* Enhanced JSON reporter with confidence scoring *)
open Types
open Types.Json_conv
open Confidence_scoring

let enhanced_finding_to_json enhanced =
  Enhanced_finding.to_json enhanced

let report_to_json_v2 result =
  (* Enhance findings with confidence scores *)
  let enhanced_findings = enhance_findings result.findings in
  
  (* Group by priority for better visualization *)
  let by_priority = List.fold_left (fun acc enhanced ->
    let priority = enhanced.Enhanced_finding.priority in
    let current = 
      try List.assoc priority acc 
      with Not_found -> []
    in
    (priority, enhanced :: current) :: 
    (List.remove_assoc priority acc)
  ) [] enhanced_findings in
  
  let findings_by_priority = 
    List.sort (fun (p1, _) (p2, _) -> compare p2 p1) by_priority
    |> List.map (fun (priority, findings) ->
      `Assoc [
        ("priority", `Int priority);
        ("count", `Int (List.length findings));
        ("findings", `List (List.map enhanced_finding_to_json findings));
      ]
    )
  in
  
  (* Calculate risk statistics *)
  let total_risk = List.fold_left (fun acc e -> 
    acc +. e.Enhanced_finding.risk_score
  ) 0.0 enhanced_findings in
  
  let avg_confidence = 
    if enhanced_findings = [] then 0.0
    else
      let total_conf = List.fold_left (fun acc e ->
        match e.Enhanced_finding.confidence with
        | VeryHigh s | High s | Medium s | Low s | VeryLow s -> acc +. s
      ) 0.0 enhanced_findings in
      total_conf /. float_of_int (List.length enhanced_findings)
  in
  
  let confidence_distribution = 
    let counts = List.fold_left (fun acc e ->
      let key = match e.Enhanced_finding.confidence with
        | VeryHigh _ -> "very_high"
        | High _ -> "high"
        | Medium _ -> "medium"
        | Low _ -> "low"
        | VeryLow _ -> "very_low"
      in
      let current = try List.assoc key acc with Not_found -> 0 in
      (key, current + 1) :: (List.remove_assoc key acc)
    ) ["very_high", 0; "high", 0; "medium", 0; "low", 0; "very_low", 0] enhanced_findings
    in
    `Assoc (List.map (fun (k, v) -> (k, `Int v)) counts)
  in
  
  let summary = `Assoc [
    ("total_findings", `Int (List.length result.findings));
    ("critical", `Int (List.length (List.filter (fun f -> f.severity = Critical) result.findings)));
    ("errors", `Int (List.length (List.filter (fun f -> f.severity = Error) result.findings)));
    ("warnings", `Int (List.length (List.filter (fun f -> f.severity = Warning) result.findings)));
    ("info", `Int (List.length (List.filter (fun f -> f.severity = Info) result.findings)));
    ("total_risk_score", `Float total_risk);
    ("average_confidence", `Float avg_confidence);
    ("confidence_distribution", confidence_distribution);
  ] in
  
  let errors_json = `List (List.map (fun (file, msg) -> 
    `Assoc [("file", `String file); ("error", `String msg)]
  ) result.errors) in
  
  `Assoc [
    ("findings_by_priority", `List findings_by_priority);
    ("summary", summary);
    ("metadata", `Assoc [
      ("files_analyzed", `Int result.files_analyzed);
      ("analysis_time", `Float result.analysis_time);
      ("tool_version", `String "0.2.0");
      ("features", `List [
        `String "confidence_scoring";
        `String "priority_ranking";
        `String "risk_assessment";
      ]);
      ("timestamp", `String (Unix.time () |> Unix.gmtime |> fun tm ->
        Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ"
          (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
          tm.tm_hour tm.tm_min tm.tm_sec));
    ]);
    ("errors", errors_json);
  ]

let write_report_v2 ~output_file result =
  let json = report_to_json_v2 result in
  let out_chan = open_out output_file in
  Yojson.Safe.pretty_to_channel out_chan json;
  close_out out_chan

let print_enhanced_summary result =
  let enhanced_findings = enhance_findings result.findings in
  
  Printf.printf "\n=== OCaml Crypto Linter Summary (Enhanced) ===\n";
  Printf.printf "Files analyzed: %d\n" result.files_analyzed;
  Printf.printf "Analysis time: %.2fs\n" result.analysis_time;
  
  (* Priority breakdown *)
  Printf.printf "\nFindings by Priority:\n";
  let by_priority = List.fold_left (fun acc e ->
    let p = e.Enhanced_finding.priority in
    let current = try List.assoc p acc with Not_found -> 0 in
    (p, current + 1) :: (List.remove_assoc p acc)
  ) (List.init 10 (fun i -> (10 - i, 0))) enhanced_findings in
  
  List.iter (fun (priority, count) ->
    if count > 0 then
      Printf.printf "  P%d: %d findings\n" priority count
  ) (List.sort (fun (p1, _) (p2, _) -> compare p2 p1) by_priority);
  
  (* Confidence breakdown *)
  Printf.printf "\nConfidence Distribution:\n";
  let conf_counts = List.fold_left (fun (vh, h, m, l, vl) e ->
    match e.Enhanced_finding.confidence with
    | VeryHigh _ -> (vh + 1, h, m, l, vl)
    | High _ -> (vh, h + 1, m, l, vl)
    | Medium _ -> (vh, h, m + 1, l, vl)
    | Low _ -> (vh, h, m, l + 1, vl)
    | VeryLow _ -> (vh, h, m, l, vl + 1)
  ) (0, 0, 0, 0, 0) enhanced_findings in
  
  let (vh, h, m, l, vl) = conf_counts in
  if vh > 0 then Printf.printf "  Very High: %d\n" vh;
  if h > 0 then Printf.printf "  High: %d\n" h;
  if m > 0 then Printf.printf "  Medium: %d\n" m;
  if l > 0 then Printf.printf "  Low: %d\n" l;
  if vl > 0 then Printf.printf "  Very Low: %d\n" vl;
  
  (* Top risks *)
  Printf.printf "\nTop 5 Risks:\n";
  let top_risks = 
    List.sort Enhanced_finding.compare enhanced_findings
    |> (fun l -> List.filteri (fun i _ -> i < 5) l)
  in
  
  List.iter (fun e ->
    Enhanced_finding.format_enhanced Format.std_formatter e
  ) top_risks;
  
  (* Risk score *)
  let total_risk = List.fold_left (fun acc e -> 
    acc +. e.Enhanced_finding.risk_score
  ) 0.0 enhanced_findings in
  
  Printf.printf "\nOverall Risk Score: %.1f\n" total_risk;
  
  if result.errors <> [] then begin
    Printf.printf "\nAnalysis errors:\n";
    List.iter (fun (file, msg) ->
      Printf.printf "  %s: %s\n" file msg
    ) result.errors
  end

(* Text report with confidence *)
let write_text_report_v2 ~output_file result =
  let enhanced_findings = enhance_findings result.findings in
  let out_chan = open_out output_file in
  let fmt = Format.formatter_of_out_channel out_chan in
  
  Format.fprintf fmt "OCaml Crypto Linter Report\n";
  Format.fprintf fmt "==========================\n\n";
  Format.fprintf fmt "Generated: %s\n" 
    (Unix.time () |> Unix.gmtime |> fun tm ->
      Printf.sprintf "%04d-%02d-%02d %02d:%02d:%02d UTC"
        (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
        tm.tm_hour tm.tm_min tm.tm_sec);
  Format.fprintf fmt "Files analyzed: %d\n" result.files_analyzed;
  Format.fprintf fmt "Total findings: %d\n\n" (List.length enhanced_findings);
  
  (* Group by file *)
  let by_file = List.fold_left (fun acc e ->
    let file = e.Enhanced_finding.finding.location.file in
    let current = try List.assoc file acc with Not_found -> [] in
    (file, e :: current) :: (List.remove_assoc file acc)
  ) [] enhanced_findings in
  
  List.iter (fun (file, findings) ->
    Format.fprintf fmt "\nFile: %s\n" file;
    Format.fprintf fmt "%s\n" (String.make (String.length file + 6) '-');
    
    let sorted = List.sort Enhanced_finding.compare findings in
    List.iter (fun e ->
      Format.fprintf fmt "\n";
      Enhanced_finding.format_enhanced fmt e;
      
      match e.Enhanced_finding.finding.suggestion with
      | Some sugg -> Format.fprintf fmt "  Suggestion: %s\n" sugg
      | None -> ();
      
      if e.Enhanced_finding.finding.references <> [] then begin
        Format.fprintf fmt "  References:\n";
        List.iter (fun ref -> Format.fprintf fmt "    - %s\n" ref) 
          e.Enhanced_finding.finding.references
      end
    ) sorted
  ) (List.sort (fun (f1, _) (f2, _) -> String.compare f1 f2) by_file);
  
  Format.pp_print_flush fmt ();
  close_out out_chan