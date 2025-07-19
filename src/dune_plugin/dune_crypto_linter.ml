open Dune_engine
open Stdune
open Dune_rules

let crypto_linter_alias = Alias.Name.of_string "crypto-lint"
let crypto_linter_check_alias = Alias.Name.of_string "crypto-check"

type linter_config = {
  enabled: bool;
  fail_on_error: bool;
  parallel: bool;
  custom_rules: string list;
  excluded_paths: string list;
}

let default_config = {
  enabled = true;
  fail_on_error = false;
  parallel = true;
  custom_rules = [];
  excluded_paths = ["_build"; "test"; "bench"];
}

let read_config ~dir =
  let config_file = Path.relative dir ".crypto-linter.json" in
  if Path.exists config_file then
    try
      let json = 
        Io.read_file config_file
        |> Yojson.Safe.from_string
      in
      let open Yojson.Safe.Util in
      {
        enabled = json |> member "enabled" |> to_bool_option |> Option.value ~default:true;
        fail_on_error = json |> member "fail_on_error" |> to_bool_option |> Option.value ~default:false;
        parallel = json |> member "parallel" |> to_bool_option |> Option.value ~default:true;
        custom_rules = json |> member "custom_rules" |> to_list |> List.map to_string;
        excluded_paths = json |> member "excluded_paths" |> to_list |> List.map to_string;
      }
    with _ -> default_config
  else default_config

let should_analyze config file =
  not (List.exists (fun excluded ->
    String.is_prefix file ~prefix:excluded
  ) config.excluded_paths)

let gen_rules sctx ~dir =
  let open Action_builder.O in
  let config = read_config ~dir:(Path.build dir) in
  
  if not config.enabled then
    Action_builder.return []
  else
    let* context = Action_builder.return (Super_context.context sctx) in
    let build_dir = Context.build_dir context in
    
    let* source_files = 
      Source_tree.find_dir (Super_context.source_tree sctx) dir
      |> Option.value ~default:(Source_tree.Dir.empty dir)
      |> Source_tree.Dir.filenames
      |> Filename.Set.to_list
      |> List.filter (fun f -> 
          String.is_suffix f ~suffix:".ml" || String.is_suffix f ~suffix:".mli")
      |> List.filter (should_analyze config)
      |> Action_builder.return
    in
    
    if List.is_empty source_files then
      Action_builder.return []
    else
      let linter_exe = 
        Path.relative build_dir "install/default/bin/ocaml-crypto-linter"
      in
      
      (* Generate report file *)
      let report_file = Path.relative (Path.build dir) ".crypto-linter-report.json" in
      
      (* Build command arguments *)
      let args = 
        [ "-f"; "json"
        ; "-o"; Path.to_string report_file ]
        @ (if config.parallel then ["--parallel"] else [])
        @ (List.concat_map (fun rule -> ["--rule"; rule]) config.custom_rules)
        @ List.map (fun f -> Path.to_string (Path.relative (Path.build dir) f)) source_files
      in
      
      let action =
        let open Action_builder.With_targets.O in
        Action_builder.with_no_targets
          (Action_builder.progn
            [ (* Run linter *)
              Action.run
                ~dir:(Path.build dir)
                linter_exe
                args
            ; (* Check results if fail_on_error *)
              if config.fail_on_error then
                Action.bash
                  (Printf.sprintf
                    {|if [ -f "%s" ]; then
                        errors=$(jq '.summary.errors + .summary.critical' "%s")
                        if [ "$errors" -gt 0 ]; then
                          echo "Crypto linter found $errors critical issues"
                          exit 1
                        fi
                      fi|}
                    (Path.to_string report_file)
                    (Path.to_string report_file))
              else
                Action.no_op
            ])
      in
      
      (* Create rules for both aliases *)
      let* () = Action_builder.alias crypto_linter_alias ~dir in
      let* () = Action_builder.alias crypto_linter_check_alias ~dir in
      
      [ Rule.make
          ~info:(Rule.Info.of_string "crypto-linter")
          ~targets:(Targets.empty)
          action ]

let setup_semgrep_integration sctx =
  let open Action_builder.O in
  let* context = Action_builder.return (Super_context.context sctx) in
  let root_dir = Context.build_dir context |> Path.parent_exn in
  
  (* Check for dependency vulnerabilities *)
  let opam_files = 
    [ "*.opam"
    ; "dune-project"
    ; "opam"
    ; ".opam"
    ]
  in
  
  let semgrep_config = Path.relative root_dir ".semgrep-crypto-deps.yml" in
  let semgrep_rules = {|
rules:
  - id: outdated-cryptokit
    patterns:
      - pattern: |
          depends: [
            ...
            "cryptokit" {< "1.19"}
            ...
          ]
    message: "Outdated Cryptokit version with known vulnerabilities"
    severity: ERROR
    languages: [generic]
    
  - id: vulnerable-nocrypto
    patterns:
      - pattern: |
          depends: [
            ...
            "nocrypto" {$VERSION}
            ...
          ]
    message: "Nocrypto is deprecated, use mirage-crypto instead"
    severity: WARNING
    languages: [generic]
    
  - id: ssl-version
    patterns:
      - pattern: |
          depends: [
            ...
            "ssl" {< "0.5.13"}
            ...
          ]
    message: "Old SSL version with security issues"
    severity: ERROR
    languages: [generic]
|} in
  
  let write_semgrep_config =
    Action.write_file semgrep_config semgrep_rules
  in
  
  let run_semgrep =
    Action.run
      ~dir:(Path.build root_dir)
      (Path.of_string "semgrep")
      [ "--config"; Path.to_string semgrep_config
      ; "--json"
      ; "-o"; ".crypto-deps-report.json"
      ; "." ]
  in
  
  Action_builder.with_no_targets
    (Action_builder.progn [write_semgrep_config; run_semgrep])

let setup () =
  let module M = struct
    type stanza = unit
    
    type Stanzas.t += T of stanza
    
    let name = "crypto-linter"
    
    let desc = "OCaml cryptographic vulnerability linter"
    
    let parse info sexps =
      match sexps with
      | [] -> T ()
      | _ -> User_error.raise ~loc:(Dune_lang.Ast.loc info) 
              [ Pp.text "crypto-linter takes no arguments" ]
    
    let gen_rules _ ~sctx ~dir:_ ~scope:_ ~source_dir:dir () =
      gen_rules sctx ~dir
    
    let () =
      Dune_rules.Stanza.add name
        ~desc
        (fun info sexps ->
          let stanza = parse info sexps in
          (stanza, []))
  end in
  ()

(* Hook into dune build process *)
let () =
  setup ();
  (* Register as a formatting tool *)
  let open Dune_rules in
  Format_rules.register_tool
    ~name:"crypto-linter"
    ~run:(fun ~dir ->
      Action.run
        ~dir
        (Path.of_string "ocaml-crypto-linter")
        ["--check"; "."])