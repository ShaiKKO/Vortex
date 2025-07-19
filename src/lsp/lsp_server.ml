open Lwt.Syntax
open Types

module Lsp = struct
  module Protocol = struct
    type message_type = Request | Notification | Response
    
    type request_id = 
      | IntId of int
      | StringId of string
    
    type position = {
      line: int;
      character: int;
    }
    
    type range = {
      start: position;
      end_: position;
    }
    
    type diagnostic_severity = Error | Warning | Information | Hint
    
    type diagnostic = {
      range: range;
      severity: diagnostic_severity option;
      code: string option;
      source: string option;
      message: string;
      tags: int list option;
      relatedInformation: related_info list option;
    }
    
    and related_info = {
      location: location;
      message: string;
    }
    
    and location = {
      uri: string;
      range: range;
    }
    
    let severity_to_lsp = function
      | Types.Critical -> Error
      | Types.Error -> Error
      | Types.Warning -> Warning
      | Types.Info -> Information
    
    let finding_to_diagnostic (f: finding) : diagnostic = {
      range = {
        start = {
          line = f.location.line - 1;
          character = f.location.column;
        };
        end_ = {
          line = (match f.location.end_line with Some l -> l - 1 | None -> f.location.line - 1);
          character = (match f.location.end_column with Some c -> c | None -> f.location.column + 10);
        };
      };
      severity = Some (severity_to_lsp f.severity);
      code = Some f.rule_id;
      source = Some "ocaml-crypto-linter";
      message = f.message;
      tags = None;
      relatedInformation = 
        if f.references = [] then None
        else Some (List.map (fun ref -> {
          location = {uri = ref; range = {start = {line = 0; character = 0}; end_ = {line = 0; character = 0}}};
          message = "Reference";
        }) f.references);
    }
  end
  
  module Server = struct
    type state = {
      mutable initialized: bool;
      mutable root_uri: string option;
      mutable open_documents: (string, string) Hashtbl.t;
      mutable diagnostics: (string, Protocol.diagnostic list) Hashtbl.t;
    }
    
    let create () = {
      initialized = false;
      root_uri = None;
      open_documents = Hashtbl.create 32;
      diagnostics = Hashtbl.create 32;
    }
    
    let analyze_document state uri content =
      try
        let lexbuf = Lexing.from_string content in
        lexbuf.lex_curr_p <- { lexbuf.lex_curr_p with pos_fname = uri };
        
        let structure = Ppxlib.Parse.implementation lexbuf in
        
        (* Run all analyses *)
        let ast_findings = Ast_analyzer.analyze_structure structure in
        let rule_findings = List.concat_map (fun rule ->
          rule.Rule_engine.Rule.check structure
        ) (Rule_engine.Registry.all_rules ()) in
        let dataflow_findings = Dataflow_cfg.analyze_dataflow structure in
        
        let all_findings = ast_findings @ rule_findings @ dataflow_findings in
        let diagnostics = List.map Protocol.finding_to_diagnostic all_findings in
        
        Hashtbl.replace state.diagnostics uri diagnostics;
        diagnostics
      with
      | e ->
        Printf.eprintf "Analysis error: %s\n" (Printexc.to_string e);
        []
    
    let handle_initialize state params =
      let root_uri = 
        try Some (Yojson.Safe.Util.(params |> member "rootUri" |> to_string))
        with _ -> None
      in
      state.root_uri <- root_uri;
      state.initialized <- true;
      
      let capabilities = `Assoc [
        ("textDocumentSync", `Int 1);
        ("diagnosticProvider", `Assoc [
          ("interFileDependencies", `Bool false);
          ("workspaceDiagnostics", `Bool false);
        ]);
      ] in
      
      `Assoc [
        ("capabilities", capabilities);
        ("serverInfo", `Assoc [
          ("name", `String "ocaml-crypto-linter");
          ("version", `String "0.1.0");
        ]);
      ]
    
    let handle_text_document_did_open state params =
      let open Yojson.Safe.Util in
      let text_document = params |> member "textDocument" in
      let uri = text_document |> member "uri" |> to_string in
      let text = text_document |> member "text" |> to_string in
      
      Hashtbl.add state.open_documents uri text;
      let diagnostics = analyze_document state uri text in
      
      (* Send diagnostics notification *)
      let notification = `Assoc [
        ("jsonrpc", `String "2.0");
        ("method", `String "textDocument/publishDiagnostics");
        ("params", `Assoc [
          ("uri", `String uri);
          ("diagnostics", `List (List.map (fun d ->
            `Assoc [
              ("range", `Assoc [
                ("start", `Assoc [
                  ("line", `Int d.Protocol.range.start.line);
                  ("character", `Int d.Protocol.range.start.character);
                ]);
                ("end", `Assoc [
                  ("line", `Int d.Protocol.range.end_.line);
                  ("character", `Int d.Protocol.range.end_.character);
                ]);
              ]);
              ("severity", match d.severity with 
                | Some Protocol.Error -> `Int 1
                | Some Warning -> `Int 2
                | Some Information -> `Int 3
                | Some Hint -> `Int 4
                | None -> `Null);
              ("code", match d.code with Some c -> `String c | None -> `Null);
              ("source", match d.source with Some s -> `String s | None -> `Null);
              ("message", `String d.message);
            ]
          ) diagnostics));
        ]);
      ] in
      
      Some notification
    
    let handle_text_document_did_change state params =
      let open Yojson.Safe.Util in
      let text_document = params |> member "textDocument" in
      let uri = text_document |> member "uri" |> to_string in
      let changes = params |> member "contentChanges" |> to_list in
      
      match changes with
      | change :: _ ->
          let text = change |> member "text" |> to_string in
          Hashtbl.replace state.open_documents uri text;
          let diagnostics = analyze_document state uri text in
          
          let notification = `Assoc [
            ("jsonrpc", `String "2.0");
            ("method", `String "textDocument/publishDiagnostics");
            ("params", `Assoc [
              ("uri", `String uri);
              ("diagnostics", `List (List.map (fun d ->
                `Assoc [
                  ("range", `Assoc [
                    ("start", `Assoc [
                      ("line", `Int d.Protocol.range.start.line);
                      ("character", `Int d.Protocol.range.start.character);
                    ]);
                    ("end", `Assoc [
                      ("line", `Int d.Protocol.range.end_.line);
                      ("character", `Int d.Protocol.range.end_.character);
                    ]);
                  ]);
                  ("severity", match d.severity with 
                    | Some Protocol.Error -> `Int 1
                    | Some Warning -> `Int 2
                    | Some Information -> `Int 3
                    | Some Hint -> `Int 4
                    | None -> `Null);
                  ("code", match d.code with Some c -> `String c | None -> `Null);
                  ("source", match d.source with Some s -> `String s | None -> `Null);
                  ("message", `String d.message);
                ]
              ) diagnostics));
            ]);
          ] in
          
          Some notification
      | [] -> None
    
    let handle_request state id method_ params =
      match method_ with
      | "initialize" ->
          let result = handle_initialize state params in
          `Assoc [
            ("jsonrpc", `String "2.0");
            ("id", id);
            ("result", result);
          ]
      
      | _ ->
          `Assoc [
            ("jsonrpc", `String "2.0");
            ("id", id);
            ("error", `Assoc [
              ("code", `Int (-32601));
              ("message", `String "Method not found");
            ]);
          ]
    
    let handle_notification state method_ params =
      match method_ with
      | "initialized" -> None
      | "textDocument/didOpen" -> handle_text_document_did_open state params
      | "textDocument/didChange" -> handle_text_document_did_change state params
      | "textDocument/didClose" ->
          let uri = Yojson.Safe.Util.(params |> member "textDocument" |> member "uri" |> to_string) in
          Hashtbl.remove state.open_documents uri;
          Hashtbl.remove state.diagnostics uri;
          None
      | _ -> None
  end
  
  let start_server () =
    let state = Server.create () in
    
    let rec loop () =
      let* line = Lwt_io.read_line Lwt_io.stdin in
      
      (* Parse Content-Length header *)
      if String.starts_with ~prefix:"Content-Length:" line then
        let len = 
          Scanf.sscanf line "Content-Length: %d" (fun x -> x) in
        
        (* Skip empty line *)
        let* _ = Lwt_io.read_line Lwt_io.stdin in
        
        (* Read message body *)
        let buf = Bytes.create len in
        let* _ = Lwt_io.read_into_exactly Lwt_io.stdin buf 0 len in
        let body = Bytes.to_string buf in
        
        try
          let json = Yojson.Safe.from_string body in
          let open Yojson.Safe.Util in
          
          let response = 
            match member "id" json with
            | `Null ->
                (* Notification *)
                let method_ = json |> member "method" |> to_string in
                let params = json |> member "params" in
                Server.handle_notification state method_ params
            
            | id ->
                (* Request *)
                let method_ = json |> member "method" |> to_string in
                let params = json |> member "params" in
                Some (Server.handle_request state id method_ params)
          in
          
          (match response with
          | Some resp ->
              let resp_str = Yojson.Safe.to_string resp in
              let* () = Lwt_io.printf "Content-Length: %d\r\n\r\n%s" 
                (String.length resp_str) resp_str in
              Lwt_io.flush Lwt_io.stdout
          | None -> Lwt.return_unit)
          >>= loop
          
        with
        | e ->
          Printf.eprintf "LSP error: %s\n" (Printexc.to_string e);
          loop ()
      else
        loop ()
    in
    
    loop ()
end

let () =
  match Sys.argv with
  | [| _; "--lsp" |] ->
      Printf.eprintf "Starting OCaml Crypto Linter LSP server...\n";
      Lwt_main.run (Lsp.start_server ())
  | _ -> ()