open Types
open Utils

module Rule = struct
  type t = {
    id: string;
    name: string;
    description: string;
    severity: severity;
    tags: string list;
    check: Ppxlib.structure -> finding list;
  }
end

module Registry = struct
  let rules : (string, Rule.t) Hashtbl.t = Hashtbl.create 32
  
  let register rule =
    Hashtbl.replace rules rule.Rule.id rule
  
  let get_rule id = Hashtbl.find_opt rules id
  
  let all_rules () = 
    Hashtbl.fold (fun _ rule acc -> rule :: acc) rules []
  
  let rules_by_tag tag =
    Hashtbl.fold (fun _ rule acc ->
      if List.mem tag rule.Rule.tags then rule :: acc else acc
    ) rules []
end

let nonce_reuse_rule : Rule.t = {
  id = "CRYPTO005";
  name = "Nonce Reuse Detection";
  description = "Detects potential nonce reuse in cryptographic operations";
  severity = Critical;
  tags = ["nonce"; "iv"; "encryption"];
  check = fun ast ->
    let nonce_vars = Hashtbl.create 16 in
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ppxlib.Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_let (_, bindings, body) ->
            List.iter (fun vb ->
              match vb.pvb_pat.ppat_desc with
              | Ppat_var {txt = name; _} when 
                  String.lowercase_ascii name |> fun n ->
                  List.exists (fun s -> contains_substring n s) ["nonce"; "iv"] ->
                  Hashtbl.add nonce_vars name vb.pvb_expr.pexp_loc
              | _ -> ()
            ) bindings;
            super#expression expr ()
        
        | Pexp_ident {txt = Lident name; _} when Hashtbl.mem nonce_vars name ->
            let uses = try Hashtbl.find_all nonce_vars name with Not_found -> [] in
            if List.length uses > 1 then
              findings := {
                rule_id = "CRYPTO005";
                severity = Critical;
                message = Printf.sprintf "Nonce '%s' appears to be reused" name;
                vulnerability = NonceReuse;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some "Generate a fresh nonce for each encryption operation";
                references = ["https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf"];
              } :: !findings
        
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

let weak_random_rule : Rule.t = {
  id = "CRYPTO006";
  name = "Weak Random Number Generator";
  description = "Detects use of weak random number generators for cryptographic purposes";
  severity = Error;
  tags = ["random"; "prng"; "entropy"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ppxlib.Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_ident {txt = Ldot (Lident "Random", _); _} ->
            findings := {
              rule_id = "CRYPTO006";
              severity = Error;
              message = "Using OCaml's Random module for cryptographic purposes is insecure";
              vulnerability = WeakRandom;
              location = {
                file = expr.pexp_loc.loc_start.pos_fname;
                line = expr.pexp_loc.loc_start.pos_lnum;
                column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
              };
              suggestion = Some "Use Cryptokit.Random or Nocrypto.Rng for cryptographic randomness";
              references = ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation"];
            } :: !findings
        
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

let timing_attack_rule : Rule.t = {
  id = "CRYPTO007";
  name = "Timing Attack Vulnerability";
  description = "Detects string comparisons that may be vulnerable to timing attacks";
  severity = Warning;
  tags = ["timing"; "side-channel"; "comparison"];
  check = fun ast ->
    let findings = ref [] in
    
    let visitor = object(self)
      inherit [unit] Ppxlib.Ast_traverse.iter as super
      
      method! expression expr () =
        match expr.pexp_desc with
        | Pexp_apply ({pexp_desc = Pexp_ident {txt = Lident ("=" | "<>" | "String.equal"); _}; _}, args) ->
            let is_crypto_context = true in (* TODO: improve context detection *)
            if is_crypto_context then
              findings := {
                rule_id = "CRYPTO007";
                severity = Warning;
                message = "String comparison may be vulnerable to timing attacks";
                vulnerability = TimingLeak;
                location = {
                  file = expr.pexp_loc.loc_start.pos_fname;
                  line = expr.pexp_loc.loc_start.pos_lnum;
                  column = expr.pexp_loc.loc_start.pos_cnum - expr.pexp_loc.loc_start.pos_bol;
                  end_line = Some expr.pexp_loc.loc_end.pos_lnum;
                  end_column = Some (expr.pexp_loc.loc_end.pos_cnum - expr.pexp_loc.loc_end.pos_bol);
                };
                suggestion = Some "Use constant-time comparison functions for cryptographic data";
                references = ["https://codahale.com/a-lesson-in-timing-attacks/"];
              } :: !findings
        
        | _ -> super#expression expr ()
    end in
    
    visitor#structure ast ();
    !findings
}

let () =
  Registry.register nonce_reuse_rule;
  Registry.register weak_random_rule;
  Registry.register timing_attack_rule