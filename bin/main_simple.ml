(* Simplified main for testing - avoids circular dependencies *)
open Cmdliner
open Ppxlib

(* Helper function for substring search *)
let contains_substring s sub =
  let len_s = String.length s in
  let len_sub = String.length sub in
  let rec check i =
    if i + len_sub > len_s then false
    else if String.sub s i len_sub = sub then true
    else check (i + 1)
  in
  check 0

let analyze_file filename =
  Printf.printf "Analyzing %s...\n" filename;
  
  try
    let ic = open_in filename in
    let lexbuf = Lexing.from_channel ic in
    lexbuf.lex_curr_p <- { lexbuf.lex_curr_p with pos_fname = filename };
    
    let structure = Parse.implementation lexbuf in
    close_in ic;
    
    (* Just check for basic patterns *)
    let findings = ref [] in
    
    let visitor = object
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        match expr.pexp_desc with
        (* Check for hardcoded strings that look like keys *)
        | Pexp_constant (Pconst_string (value, _, _)) ->
            if String.length value > 10 && 
               (contains_substring value "key" || 
                contains_substring value "secret" ||
                contains_substring value "password") then
              findings := ("KEY001", expr.pexp_loc) :: !findings
        
        (* Check for weak algorithms *)
        | Pexp_ident {txt = Longident.Ldot (Lident "Digest", "string"); _} ->
            findings := ("ALGO002", expr.pexp_loc) :: !findings
            
        | Pexp_ident {txt = Longident.Ldot (Longident.Ldot (Lident "Cryptokit", "Cipher"), "des"); _} ->
            findings := ("ALGO001", expr.pexp_loc) :: !findings
            
        | Pexp_ident {txt = Longident.Ldot (Longident.Ldot (Lident "Cryptokit", "Hash"), "md5"); _} ->
            findings := ("ALGO002", expr.pexp_loc) :: !findings
            
        (* Check for timing attacks *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Lident "="; _}; _}, 
                     [(_, left); (_, right)]) ->
            (* Simple heuristic: if comparing strings/variables *)
            (match left.pexp_desc, right.pexp_desc with
            | Pexp_ident _, Pexp_ident _ 
            | Pexp_ident _, Pexp_constant (Pconst_string _)
            | Pexp_constant (Pconst_string _), Pexp_ident _ ->
                findings := ("SIDE001", expr.pexp_loc) :: !findings
            | _ -> ())
            
        | _ -> ();
        
        super#expression expr
    end in
    
    visitor#structure structure;
    
    (* Print findings *)
    List.iter (fun (rule, loc) ->
      Printf.printf "[%s] Found issue at %s:%d:%d\n" 
        rule 
        loc.loc_start.pos_fname
        loc.loc_start.pos_lnum
        (loc.loc_start.pos_cnum - loc.loc_start.pos_bol)
    ) (List.rev !findings);
    
    List.length !findings
    
  with e ->
    Printf.eprintf "Error analyzing %s: %s\n" filename (Printexc.to_string e);
    0


let files_arg =
  Arg.(non_empty & pos_all file [] & info [] ~docv:"FILE" ~doc:"OCaml source files to analyze")

let format_arg =
  Arg.(value & opt string "text" & info ["f"; "format"] ~docv:"FORMAT" 
    ~doc:"Output format (text or json)")

let output_arg =
  Arg.(value & opt (some string) None & info ["o"; "output"] ~docv:"FILE"
    ~doc:"Output file")

let analyze_cmd =
  let analyze files format _output =
    let total_findings = ref 0 in
    
    if format = "json" then begin
      Printf.printf "{\n  \"findings\": [\n";
    end;
    
    List.iter (fun file ->
      let findings = analyze_file file in
      total_findings := !total_findings + findings
    ) files;
    
    if format = "json" then begin
      Printf.printf "  ],\n  \"summary\": {\n";
      Printf.printf "    \"total_findings\": %d,\n" !total_findings;
      Printf.printf "    \"files_analyzed\": %d\n" (List.length files);
      Printf.printf "  }\n}\n";
    end else begin
      Printf.printf "\nTotal findings: %d\n" !total_findings;
    end;
    
    `Ok 0
  in
  
  let doc = "Analyze OCaml code for cryptographic vulnerabilities (simplified)" in
  let info = Cmd.info "ocaml-crypto-linter-simple" ~version:"0.1.0" ~doc in
  Cmd.v info Term.(ret (const analyze $ files_arg $ format_arg $ output_arg))

let () = exit (Cmd.eval' analyze_cmd)