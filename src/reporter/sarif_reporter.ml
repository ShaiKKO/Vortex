open Types

module Sarif = struct
  type sarif_level = Note | Warning | Error
  
  let severity_to_sarif = function
    | Info -> Note
    | Warning -> Warning
    | Error | Critical -> Error
  
  let sarif_level_to_string = function
    | Note -> "note"
    | Warning -> "warning"
    | Error -> "error"
  
  let vulnerability_to_tags = function
    | WeakCipher _ -> ["security", "cryptography", "CWE-327"]
    | InsecureKeySize _ -> ["security", "cryptography", "CWE-326"]
    | HardcodedKey -> ["security", "cryptography", "CWE-798"]
    | PredictableIV -> ["security", "cryptography", "CWE-329"]
    | WeakRandom -> ["security", "cryptography", "CWE-338"]
    | NonceReuse -> ["security", "cryptography", "CWE-323"]
    | WeakHash _ -> ["security", "cryptography", "CWE-328"]
    | InsecurePadding -> ["security", "cryptography", "CWE-310"]
    | TimingLeak -> ["security", "cryptography", "CWE-208"]
    | SideChannel -> ["security", "cryptography", "CWE-203"]
    | KeyReuse -> ["security", "cryptography", "CWE-323"]
    | MacMissing -> ["security", "cryptography", "CWE-353"]
    | MissingAuthentication -> ["security", "cryptography", "CWE-353"]
    | WeakKDF -> ["security", "cryptography", "CWE-916"]
    | InsecureMode _ -> ["security", "cryptography", "CWE-327"]
  
  let create_rule finding =
    `Assoc [
      ("id", `String finding.rule_id);
      ("name", `String finding.rule_id);
      ("shortDescription", `Assoc [
        ("text", `String finding.message)
      ]);
      ("fullDescription", `Assoc [
        ("text", `String finding.message)
      ]);
      ("defaultConfiguration", `Assoc [
        ("level", `String (sarif_level_to_string (severity_to_sarif finding.severity)))
      ]);
      ("properties", `Assoc [
        ("tags", `List (List.map (fun t -> `String t) (vulnerability_to_tags finding.vulnerability)));
        ("security-severity", `String (match finding.severity with
          | Critical -> "9.0"
          | Error -> "7.0"
          | Warning -> "4.0"
          | Info -> "2.0"))
      ]);
      ("help", `Assoc [
        ("text", `String (match finding.suggestion with Some s -> s | None -> ""));
        ("markdown", `String (
          let refs = String.concat "\n" (List.map (fun r -> "- " ^ r) finding.references) in
          Printf.sprintf "%s\n\n## References\n%s"
            (match finding.suggestion with Some s -> s | None -> "")
            refs
        ))
      ])
    ]
  
  let create_result finding rule_index =
    let region = `Assoc [
      ("startLine", `Int finding.location.line);
      ("startColumn", `Int finding.location.column);
      ("endLine", `Int (match finding.location.end_line with Some l -> l | None -> finding.location.line));
      ("endColumn", `Int (match finding.location.end_column with Some c -> c | None -> finding.location.column));
    ] in
    
    `Assoc [
      ("ruleId", `String finding.rule_id);
      ("ruleIndex", `Int rule_index);
      ("level", `String (sarif_level_to_string (severity_to_sarif finding.severity)));
      ("message", `Assoc [
        ("text", `String finding.message)
      ]);
      ("locations", `List [
        `Assoc [
          ("physicalLocation", `Assoc [
            ("artifactLocation", `Assoc [
              ("uri", `String finding.location.file);
              ("uriBaseId", `String "%SRCROOT%")
            ]);
            ("region", region)
          ])
        ]
      ]);
      ("properties", `Assoc [
        ("vulnerability-type", `String (match finding.vulnerability with
          | WeakCipher name -> "weak-cipher:" ^ name
          | InsecureKeySize size -> Printf.sprintf "key-size:%d" size
          | HardcodedKey -> "hardcoded-key"
          | PredictableIV -> "predictable-iv"
          | WeakRandom -> "weak-random"
          | NonceReuse -> "nonce-reuse"
          | WeakHash name -> "weak-hash:" ^ name
          | InsecurePadding -> "insecure-padding"
          | TimingLeak -> "timing-leak"
          | SideChannel -> "side-channel"
          | KeyReuse -> "key-reuse"
          | MacMissing -> "mac-missing"
          | MissingAuthentication -> "missing-auth"
          | WeakKDF -> "weak-kdf"
          | InsecureMode mode -> "insecure-mode:" ^ mode))
      ]);
      ("fixes", match finding.suggestion with
        | Some suggestion -> `List [
            `Assoc [
              ("description", `Assoc [
                ("text", `String suggestion)
              ])
            ]
          ]
        | None -> `List [])
    ]
  
  let create_sarif_report result : Yojson.Safe.t =
    (* Deduplicate rules *)
    let rules = 
      List.fold_left (fun acc finding ->
        if List.exists (fun r -> 
          match r with `Assoc fields -> 
            (match List.assoc_opt "id" fields with
            | Some (`String id) -> id = finding.rule_id
            | _ -> false)
          | _ -> false
        ) acc then acc
        else create_rule finding :: acc
      ) [] result.findings |> List.rev
    in
    
    (* Create rule index map *)
    let rule_indices = 
      List.mapi (fun i rule ->
        match rule with
        | `Assoc fields ->
            (match List.assoc_opt "id" fields with
            | Some (`String id) -> (id, i)
            | _ -> ("", i))
        | _ -> ("", i)
      ) rules
    in
    
    (* Create results with rule indices *)
    let results = List.map (fun finding ->
      let rule_index = 
        try List.assoc finding.rule_id rule_indices
        with Not_found -> 0
      in
      create_result finding rule_index
    ) result.findings in
    
    `Assoc [
      ("$schema", `String "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
      ("version", `String "2.1.0");
      ("runs", `List [
        `Assoc [
          ("tool", `Assoc [
            ("driver", `Assoc [
              ("name", `String "ocaml-crypto-linter");
              ("version", `String "0.1.0");
              ("informationUri", `String "https://github.com/your-username/ocaml-crypto-linter");
              ("rules", `List rules);
              ("supportedTaxonomies", `List [
                `Assoc [
                  ("name", `String "CWE");
                  ("index", `Int 0);
                  ("guid", `String "2582E80E-4B80-46C0-BECE-5F0FE91D6A8C")
                ]
              ])
            ])
          ]);
          ("results", `List results);
          ("taxonomies", `List [
            `Assoc [
              ("name", `String "CWE");
              ("version", `String "4.12");
              ("releaseDateUtc", `String "2023-06-29");
              ("informationUri", `String "https://cwe.mitre.org/");
              ("downloadUri", `String "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip");
              ("organization", `String "MITRE");
              ("shortDescription", `Assoc [
                ("text", `String "The MITRE Common Weakness Enumeration")
              ])
            ]
          ]);
          ("invocations", `List [
            `Assoc [
              ("executionSuccessful", `Bool (result.errors = []));
              ("commandLine", `String "ocaml-crypto-linter");
              ("arguments", `List []);
              ("workingDirectory", `Assoc [
                ("uri", `String (Sys.getcwd ()))
              ]);
              ("startTimeUtc", `String (
                Unix.time () -. result.analysis_time |> Unix.gmtime |> fun tm ->
                Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02d.000Z"
                  (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
                  tm.tm_hour tm.tm_min tm.tm_sec
              ));
              ("endTimeUtc", `String (
                Unix.time () |> Unix.gmtime |> fun tm ->
                Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02d.000Z"
                  (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
                  tm.tm_hour tm.tm_min tm.tm_sec
              ));
              ("exitCode", `Int (if result.errors = [] then 0 else 1));
              ("toolExecutionNotifications", `List (
                List.map (fun (file, msg) ->
                  `Assoc [
                    ("level", `String "error");
                    ("message", `Assoc [
                      ("text", `String (Printf.sprintf "Failed to analyze %s: %s" file msg))
                    ])
                  ]
                ) result.errors
              ))
            ]
          ]);
          ("properties", `Assoc [
            ("metrics", `Assoc [
              ("filesAnalyzed", `Int result.files_analyzed);
              ("analysisTime", `Float result.analysis_time);
              ("findingsBySeverity", `Assoc [
                ("critical", `Int (List.length (List.filter (fun f -> f.severity = Critical) result.findings)));
                ("error", `Int (List.length (List.filter (fun f -> f.severity = Error) result.findings)));
                ("warning", `Int (List.length (List.filter (fun f -> f.severity = Warning) result.findings)));
                ("note", `Int (List.length (List.filter (fun f -> f.severity = Info) result.findings)));
              ])
            ])
          ])
        ]
      ])
    ]
end

let write_sarif_report ~output_file result =
  let sarif = Sarif.create_sarif_report result in
  let out_chan = open_out output_file in
  Yojson.Safe.pretty_to_channel out_chan sarif;
  close_out out_chan

let print_sarif result =
  let sarif = Sarif.create_sarif_report result in
  Yojson.Safe.pretty_to_channel stdout sarif