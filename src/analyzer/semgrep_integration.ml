open Types
open Lwt.Syntax

module Semgrep = struct
  type rule = {
    id: string;
    pattern: string;
    message: string;
    severity: string;
    languages: string list;
  }
  
  let crypto_rules = [
    {
      id = "ocaml.crypto.hardcoded-key";
      pattern = {|
        $KEY = "..."
        ...
        $CRYPTO.$METHOD(..., $KEY, ...)
      |};
      message = "Hardcoded cryptographic key detected";
      severity = "ERROR";
      languages = ["ocaml"];
    };
    {
      id = "ocaml.crypto.weak-hash";
      pattern = {|
        $HASH.($MD5 | $SHA1 | $MD4)(...)
      |};
      message = "Weak hash algorithm detected";
      severity = "WARNING";
      languages = ["ocaml"];
    };
    {
      id = "ocaml.crypto.ecb-mode";
      pattern = {|
        Cipher.$ALG.ecb(...)
      |};
      message = "ECB mode is insecure for encryption";
      severity = "ERROR";
      languages = ["ocaml"];
    };
  ]
  
  let dependency_rules = [
    {
      id = "ocaml.deps.cryptokit-cve";
      pattern = {|
        depends: [
          ...
          "cryptokit" {< "1.16.1"}
          ...
        ]
      |};
      message = "Cryptokit < 1.16.1 has CVE-2022-24793 (timing attack in RSA)";
      severity = "ERROR";
      languages = ["generic"];
    };
    {
      id = "ocaml.deps.nocrypto-deprecated";
      pattern = {|
        depends: [
          ...
          "nocrypto"
          ...
        ]
      |};
      message = "Nocrypto is unmaintained since 2019, migrate to mirage-crypto";
      severity = "WARNING";
      languages = ["generic"];
    };
    {
      id = "ocaml.deps.ssl-cve";
      pattern = {|
        depends: [
          ...
          "ssl" {< "0.5.9"}
          ...
        ]
      |};
      message = "SSL < 0.5.9 vulnerable to CVE-2020-12802";
      severity = "ERROR";
      languages = ["generic"];
    };
    {
      id = "ocaml.deps.tls-cve";
      pattern = {|
        depends: [
          ...
          "tls" {< "0.15.0"}
          ...
        ]
      |};
      message = "TLS < 0.15.0 has known security issues";
      severity = "WARNING";
      languages = ["generic"];
    };
    {
      id = "ocaml.deps.x509-cve";
      pattern = {|
        depends: [
          ...
          "x509" {< "0.16.0"}
          ...
        ]
      |};
      message = "X509 < 0.16.0 has certificate validation vulnerabilities";
      severity = "ERROR";
      languages = ["generic"];
    };
  ]
  
  let write_rules_file rules =
    let yaml_rules = List.map (fun r ->
      Printf.sprintf {|
  - id: %s
    patterns:
      - pattern: |
          %s
    message: %s
    severity: %s
    languages: %s
|} r.id r.pattern r.message r.severity 
       (Printf.sprintf "[%s]" (String.concat ", " r.languages))
    ) rules in
    
    let content = Printf.sprintf {|rules:
%s|} (String.concat "\n" yaml_rules) in
    
    let* out_chan = Lwt_io.open_file ~mode:Lwt_io.output ".semgrep-crypto-rules.yml" in
    let* () = Lwt_io.write out_chan content in
    Lwt_io.close out_chan
  
  let run_semgrep target_path =
    let cmd = Printf.sprintf "semgrep --config=.semgrep-crypto-rules.yml --json %s" target_path in
    let process_in = Lwt_process.open_process_in (Lwt_process.shell cmd) in
    let* output = Lwt_io.read (Lwt_process.process_in_channel process_in) in
    let* status = Lwt_process.close process_in in
    
    try
      let json = Yojson.Safe.from_string output in
      let results = Yojson.Safe.Util.(json |> member "results" |> to_list) in
      
      let findings = List.map (fun result ->
        let open Yojson.Safe.Util in
        let check_id = result |> member "check_id" |> to_string in
        let path = result |> member "path" |> to_string in
        let start = result |> member "start" in
        let end_ = result |> member "end" in
        
        let vulnerability = 
          if String.contains check_id "hardcoded-key" then HardcodedKey
          else if String.contains check_id "weak-hash" then WeakHash "detected"
          else if String.contains check_id "ecb-mode" then InsecureMode "ECB"
          else WeakCipher "unknown"
        in
        
        {
          rule_id = check_id;
          severity = Error;
          message = result |> member "extra" |> member "message" |> to_string;
          vulnerability;
          location = {
            file = path;
            line = start |> member "line" |> to_int;
            column = start |> member "col" |> to_int;
            end_line = Some (end_ |> member "line" |> to_int);
            end_column = Some (end_ |> member "col" |> to_int);
          };
          suggestion = None;
          references = [];
        }
      ) results in
      
      Lwt.return findings
    with
    | Yojson.Json_error msg ->
        Printf.eprintf "Failed to parse Semgrep output: %s\n" msg;
        Lwt.return []
    | e ->
        Printf.eprintf "Semgrep execution failed: %s\n" (Printexc.to_string e);
        Lwt.return []
end

let analyze_with_semgrep target_path =
  let* () = Semgrep.write_rules_file Semgrep.crypto_rules in
  Semgrep.run_semgrep target_path

let analyze_dependencies project_root =
  let dep_files = [
    Filename.concat project_root "dune-project";
    Filename.concat project_root ".opam";
  ] @ (try
    Sys.readdir project_root
    |> Array.to_list
    |> List.filter (fun f -> Filename.check_suffix f ".opam")
    |> List.map (fun f -> Filename.concat project_root f)
  with _ -> [])
  in
  
  let existing_files = List.filter Sys.file_exists dep_files in
  
  if existing_files = [] then
    Lwt.return []
  else
    let* () = Semgrep.write_rules_file Semgrep.dependency_rules in
    let* findings_lists = Lwt_list.map_p (fun file ->
      Semgrep.run_semgrep file
    ) existing_files in
    
    Lwt.return (List.concat findings_lists)