#!/usr/bin/env -S opam exec -- ocaml
(* Standalone OCaml script for testing crypto patterns *)

#use "topfind";;
#require "ppxlib";;

open Ppxlib

(* Helper function to flatten Longident *)
let rec flatten_longident = function
  | Longident.Lident s -> [s]
  | Ldot (lid, s) -> flatten_longident lid @ [s]
  | Lapply (lid1, lid2) -> flatten_longident lid1 @ flatten_longident lid2

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

(* Simple pattern detection *)
let detect_patterns filename =
  Printf.printf "\n=== Analyzing %s ===\n" filename;
  
  try
    let ic = open_in filename in
    let lexbuf = Lexing.from_channel ic in
    lexbuf.lex_curr_p <- { lexbuf.lex_curr_p with pos_fname = filename };
    
    let structure = Parse.implementation lexbuf in
    close_in ic;
    
    let findings = ref [] in
    
    let visitor = object
      inherit Ast_traverse.iter as super
      
      method! expression expr =
        (match expr.pexp_desc with
        (* Hardcoded keys *)
        | Pexp_constant (Pconst_string (value, _, _)) ->
            if String.length value > 8 && 
               (contains_substring (String.lowercase_ascii value) "key" || 
                contains_substring (String.lowercase_ascii value) "secret" ||
                contains_substring (String.lowercase_ascii value) "password" ||
                contains_substring value "sk_" ||
                contains_substring value "pk_") then
              findings := ("KEY001", "Hardcoded key", expr.pexp_loc) :: !findings
        
        (* Weak algorithms *)
        | Pexp_ident {txt; _} ->
            let path = flatten_longident txt |> String.concat "." in
            (* MD5 via Digest *)
            if path = "Digest.string" || path = "Digest.file" then
              findings := ("ALGO002", "Weak hash MD5", expr.pexp_loc) :: !findings
            (* DES cipher *)
            else if contains_substring path "Cipher.des" || 
                    contains_substring path "Cipher.triple_des" then
              findings := ("ALGO001", "Weak cipher DES", expr.pexp_loc) :: !findings
            (* RC4 *)
            else if contains_substring path "Cipher.arcfour" then
              findings := ("ALGO001", "Weak cipher RC4", expr.pexp_loc) :: !findings
            (* SHA1 *)
            else if contains_substring path "Hash.sha1" then
              findings := ("ALGO002", "Weak hash SHA-1", expr.pexp_loc) :: !findings
            (* MD5 *)
            else if contains_substring path "Hash.md5" then
              findings := ("ALGO002", "Weak hash MD5", expr.pexp_loc) :: !findings
        
        (* String equality - potential timing attack *)
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Lident "="; _}; _}, args) ->
            (match args with
            | [(_, left); (_, right)] ->
                let is_sensitive_var e = match e.pexp_desc with
                  | Pexp_ident {txt = Lident name; _} ->
                      contains_substring name "password" ||
                      contains_substring name "token" ||
                      contains_substring name "key" ||
                      contains_substring name "secret" ||
                      contains_substring name "mac" ||
                      contains_substring name "hmac"
                  | _ -> false
                in
                if is_sensitive_var left || is_sensitive_var right then
                  findings := ("SIDE001", "Timing attack vulnerability", expr.pexp_loc) :: !findings
            | _ -> ())
            
        (* ECB mode *)
        | Pexp_apply (_, args) ->
            List.iter (fun (_, arg) ->
              match arg.pexp_desc with
              | Pexp_ident {txt; _} ->
                  let path = flatten_longident txt |> String.concat "." in
                  if path = "ECB" then
                    findings := ("API001", "ECB mode usage", arg.pexp_loc) :: !findings
              | _ -> ()
            ) args
            
        | _ -> ());
        
        super#expression expr
    end in
    
    visitor#structure structure;
    
    (* Print findings *)
    Printf.printf "Found %d issues:\n" (List.length !findings);
    List.iter (fun (rule, desc, loc) ->
      Printf.printf "  [%s] %s at line %d, col %d\n" 
        rule desc
        loc.loc_start.pos_lnum
        (loc.loc_start.pos_cnum - loc.loc_start.pos_bol)
    ) (List.rev !findings);
    
    List.length !findings
    
  with e ->
    Printf.eprintf "Error: %s\n" (Printexc.to_string e);
    0

(* Test files *)
let test_files = [
  "test_samples/vulnerable/hardcoded_keys.ml";
  "test_samples/vulnerable/weak_algorithms.ml";
  "test_samples/vulnerable/timing_attacks.ml";
  "test_samples/vulnerable/api_misuse.ml";
  "test_samples/secure/good_crypto.ml";
]

(* Run tests *)
let () =
  let total = ref 0 in
  List.iter (fun file ->
    if Sys.file_exists file then
      let count = detect_patterns file in
      total := !total + count
    else
      Printf.printf "File not found: %s\n" file
  ) test_files;
  
  Printf.printf "\n=== Summary ===\n";
  Printf.printf "Total findings: %d\n" !total