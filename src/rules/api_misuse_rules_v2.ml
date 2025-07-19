(* Enhanced API misuse rules with interprocedural analysis *)
open Types
open Rule_engine
open Ppxlib
open Interprocedural

(* API006: CBC Without MAC - Enhanced with interprocedural analysis *)
let cbc_without_mac_rule_v2 : Rule.t = {
  id = "API006";
  name = "CBC Mode Without Authentication";
  description = "Detects CBC encryption without MAC using interprocedural analysis";
  severity = Error;
  tags = ["api-misuse"; "cbc"; "mac"; "authentication"; "interprocedural"];
  check = fun ast ->
    let ctx = Interprocedural_analyzer.analyze_ast ast in
    
    (* Pattern: Function that encrypts with CBC but no MAC in same or called functions *)
    let check_cbc_without_mac func_name node taint_state =
      let has_cbc_encrypt = List.exists (fun call ->
        let callee_lower = String.lowercase_ascii call.Function_summary.callee in
        String.contains_substring callee_lower "cbc" && 
        (String.contains_substring callee_lower "encrypt" ||
         String.contains_substring callee_lower "cipher")
      ) node.summary.calls in
      
      if not has_cbc_encrypt then None
      else
        (* Check for MAC in same function or transitively called functions *)
        let all_callees = Call_graph.get_transitive_callees ctx.call_graph func_name in
        let has_mac = List.exists (fun callee ->
          match Hashtbl.find_opt ctx.call_graph callee with
          | Some callee_node ->
              List.exists (fun call ->
                let name = String.lowercase_ascii call.Function_summary.callee in
                String.contains_substring name "mac" ||
                String.contains_substring name "hmac" ||
                String.contains_substring name "authenticate" ||
                String.contains_substring name "tag"
              ) callee_node.summary.calls
          | None -> false
        ) all_callees in
        
        if has_mac then None
        else
          (* Find the CBC call location *)
          let cbc_call = List.find (fun call ->
            let callee_lower = String.lowercase_ascii call.Function_summary.callee in
            String.contains_substring callee_lower "cbc" && 
            String.contains_substring callee_lower "encrypt"
          ) node.summary.calls in
          
          Some {
            rule_id = "API006";
            severity = Error;
            message = Printf.sprintf 
              "CBC encryption without authentication detected in function '%s'" 
              func_name;
            vulnerability = MacMissing;
            location = {
              file = cbc_call.location.loc_start.pos_fname;
              line = cbc_call.location.loc_start.pos_lnum;
              column = cbc_call.location.loc_start.pos_cnum - 
                      cbc_call.location.loc_start.pos_bol;
              end_line = Some cbc_call.location.loc_end.pos_lnum;
              end_column = Some (cbc_call.location.loc_end.pos_cnum - 
                               cbc_call.location.loc_end.pos_bol);
            };
            suggestion = Some (
              "CBC mode is vulnerable to padding oracle attacks without authentication:\n" ^
              "1. Add HMAC after encryption (Encrypt-then-MAC):\n" ^
              "   let encrypted = Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv data in\n" ^
              "   let mac = Mirage_crypto.Hash.SHA256.hmac ~key:mac_key encrypted in\n" ^
              "   (encrypted, mac)\n" ^
              "2. Or switch to authenticated encryption:\n" ^
              "   Mirage_crypto.Cipher_block.AES.GCM.authenticate_encrypt ~key ~nonce data"
            );
            references = [
              "CVE-2013-0169 (Lucky Thirteen)";
              "CVE-2014-3566 (POODLE)";
              "https://tools.ietf.org/html/rfc7366";
            ];
          }
    in
    
    Interprocedural_analyzer.find_pattern ctx check_cbc_without_mac
}

(* API002: Encrypt-then-MAC Order - Enhanced with cross-function tracking *)
let encrypt_then_mac_rule_v2 : Rule.t = {
  id = "API002";
  name = "MAC-then-Encrypt Pattern";
  description = "Detects incorrect MAC-then-encrypt order across functions";
  severity = Error;
  tags = ["api-misuse"; "mac"; "order"; "interprocedural"];
  check = fun ast ->
    let ctx = Interprocedural_analyzer.analyze_ast ast in
    let findings = ref [] in
    
    (* Track encryption and MAC operations across function boundaries *)
    let analyze_mac_order func_name node =
      let operations = ref [] in
      
      (* Collect operations in order *)
      let rec collect_ops calls =
        List.iter (fun call ->
          let name = String.lowercase_ascii call.Function_summary.callee in
          if String.contains_substring name "encrypt" then
            operations := ("encrypt", call.location) :: !operations
          else if String.contains_substring name "mac" || 
                  String.contains_substring name "hmac" then
            operations := ("mac", call.location) :: !operations
          else
            (* Recursively check called functions *)
            match Hashtbl.find_opt ctx.call_graph call.Function_summary.callee with
            | Some callee_node -> collect_ops callee_node.summary.calls
            | None -> ()
        ) calls
      in
      
      collect_ops node.summary.calls;
      
      (* Check order - MAC should come after encrypt *)
      let rec check_order = function
        | [] | [_] -> ()
        | (op1, loc1) :: (op2, loc2) :: rest ->
            if op1 = "mac" && op2 = "encrypt" then
              findings := {
                rule_id = "API002";
                severity = Error;
                message = "MAC-then-Encrypt pattern detected (should be Encrypt-then-MAC)";
                vulnerability = ApiMisuse;
                location = {
                  file = loc1.loc_start.pos_fname;
                  line = loc1.loc_start.pos_lnum;
                  column = loc1.loc_start.pos_cnum - loc1.loc_start.pos_bol;
                  end_line = Some loc2.loc_end.pos_lnum;
                  end_column = Some (loc2.loc_end.pos_cnum - loc2.loc_end.pos_bol);
                };
                suggestion = Some (
                  "Use Encrypt-then-MAC pattern for security:\n" ^
                  "1. First encrypt the plaintext\n" ^
                  "2. Then compute MAC over the ciphertext\n" ^
                  "3. This prevents padding oracle attacks\n\n" ^
                  "Example:\n" ^
                  "let encrypt_then_mac key mac_key plaintext =\n" ^
                  "  let iv = Mirage_crypto_rng.generate 16 in\n" ^
                  "  let ciphertext = AES.CBC.encrypt ~key ~iv plaintext in\n" ^
                  "  let mac = Hash.SHA256.hmac ~key:mac_key (iv ^ ciphertext) in\n" ^
                  "  (iv, ciphertext, mac)"
                );
                references = [
                  "https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html";
                  "CVE-2016-0270";
                ];
              } :: !findings;
            check_order ((op2, loc2) :: rest)
      in
      
      check_order (List.rev !operations)
    in
    
    Hashtbl.iter (fun func_name node ->
      analyze_mac_order func_name node
    ) ctx.call_graph;
    
    !findings
}

(* API003: Key Reuse Detection - Enhanced with data flow tracking *)
let key_reuse_rule_v2 : Rule.t = {
  id = "API003";
  name = "Cryptographic Key Reuse";
  description = "Detects key reuse across different algorithms using data flow";
  severity = Warning;
  tags = ["api-misuse"; "key-reuse"; "interprocedural"];
  check = fun ast ->
    let ctx = Interprocedural_analyzer.analyze_ast ast in
    let findings = ref [] in
    let key_usage = Hashtbl.create 32 in
    
    (* Track key usage across functions *)
    Hashtbl.iter (fun func_name node ->
      match Hashtbl.find_opt ctx.taint_states func_name with
      | Some taint_state ->
          (* Find variables that are used as keys *)
          Hashtbl.iter (fun var sources ->
            if List.exists (function
              | Taint_analysis.CryptoOperation op -> 
                  String.contains_substring (String.lowercase_ascii op) "key" ||
                  String.contains_substring (String.lowercase_ascii op) "derive"
              | _ -> false
            ) sources then
              (* Track where this key is used *)
              List.iter (fun call ->
                let is_crypto_use = 
                  String.contains_substring 
                    (String.lowercase_ascii call.Function_summary.callee) "encrypt" ||
                  String.contains_substring 
                    (String.lowercase_ascii call.Function_summary.callee) "sign" ||
                  String.contains_substring 
                    (String.lowercase_ascii call.Function_summary.callee) "mac"
                in
                
                if is_crypto_use then
                  (* Check if key variable is used in this call *)
                  List.iter (fun arg ->
                    match arg.pexp_desc with
                    | Pexp_ident {txt = Lident arg_var; _} when arg_var = var ->
                        let usage = (call.Function_summary.callee, call.location) in
                        begin match Hashtbl.find_opt key_usage var with
                        | Some usages -> 
                            Hashtbl.replace key_usage var (usage :: usages)
                        | None -> 
                            Hashtbl.replace key_usage var [usage]
                        end
                    | _ -> ()
                  ) call.arguments
              ) node.summary.calls
          ) taint_state.variables
      | None -> ()
    ) ctx.call_graph;
    
    (* Check for key reuse across different algorithms *)
    Hashtbl.iter (fun key_var usages ->
      let unique_algorithms = 
        List.map (fun (callee, _) ->
          let lower = String.lowercase_ascii callee in
          if String.contains_substring lower "aes" then "AES"
          else if String.contains_substring lower "rsa" then "RSA"
          else if String.contains_substring lower "hmac" then "HMAC"
          else if String.contains_substring lower "sign" then "Signature"
          else "Unknown"
        ) usages
        |> List.sort_uniq String.compare
      in
      
      if List.length unique_algorithms > 1 then
        let (_, first_loc) = List.hd usages in
        findings := {
          rule_id = "API003";
          severity = Warning;
          message = Printf.sprintf 
            "Key '%s' reused across different algorithms: %s" 
            key_var (String.concat ", " unique_algorithms);
          vulnerability = KeyReuse;
          location = {
            file = first_loc.loc_start.pos_fname;
            line = first_loc.loc_start.pos_lnum;
            column = first_loc.loc_start.pos_cnum - first_loc.loc_start.pos_bol;
            end_line = Some first_loc.loc_end.pos_lnum;
            end_column = Some (first_loc.loc_end.pos_cnum - first_loc.loc_end.pos_bol);
          };
          suggestion = Some (
            "Use separate keys for different cryptographic operations:\n" ^
            "1. Derive purpose-specific keys from a master key:\n" ^
            "   let kdf key purpose = \n" ^
            "     Mirage_crypto.Hash.SHA256.hmac ~key \n" ^
            "       (Bytes.of_string purpose)\n\n" ^
            "2. Use different keys for:\n" ^
            "   - Encryption: let enc_key = kdf master_key \"encryption\"\n" ^
            "   - Authentication: let mac_key = kdf master_key \"mac\"\n" ^
            "   - Signing: let sign_key = kdf master_key \"signing\""
          );
          references = [
            "NIST SP 800-57";
            "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf";
          ];
        } :: !findings
    ) key_usage;
    
    !findings
}

(* Register enhanced rules *)
let () =
  Registry.register cbc_without_mac_rule_v2;
  Registry.register encrypt_then_mac_rule_v2;
  Registry.register key_reuse_rule_v2