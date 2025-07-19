open Ppxlib
open Types

module Crypto_patterns = struct
  let cryptokit_modules = ["Cipher"; "Hash"; "Random"; "RSA"; "DH"; "Padding"]
  let nocrypto_modules = ["Rsa"; "Dsa"; "Dh"; "Hash"; "Cipher_block"; "Cipher_stream"]
  
  let weak_ciphers = ["DES"; "3DES"; "RC4"; "RC2"; "Blowfish"]
  let weak_hashes = ["MD5"; "SHA1"; "MD4"; "MD2"]
  let secure_key_sizes = [
    ("AES", 128);
    ("AES", 192);
    ("AES", 256);
    ("RSA", 2048);
    ("RSA", 3072);
    ("RSA", 4096);
    ("DSA", 2048);
    ("DSA", 3072);
  ]
  
  let is_crypto_module path =
    match path with
    | Lident name -> List.mem name (cryptokit_modules @ nocrypto_modules)
    | Ldot (Lident "Cryptokit", name) -> List.mem name cryptokit_modules
    | Ldot (Lident "Nocrypto", name) -> List.mem name nocrypto_modules
    | _ -> false
end

class crypto_visitor = object(self)
  inherit [finding list] Ast_traverse.fold as super
  
  method! expression expr findings =
    let open Ast_helper in
    let loc = expr.pexp_loc in
    match expr.pexp_desc with
    | Pexp_construct ({txt = Lident name; _}, _) when List.mem name Crypto_patterns.weak_ciphers ->
        let finding = {
          rule_id = "CRYPTO001";
          severity = Error;
          message = Printf.sprintf "Use of weak cipher: %s" name;
          vulnerability = WeakCipher name;
          location = {
            file = loc.loc_start.pos_fname;
            line = loc.loc_start.pos_lnum;
            column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
            end_line = Some loc.loc_end.pos_lnum;
            end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
          };
          suggestion = Some "Use AES-256-GCM or ChaCha20-Poly1305 instead";
          references = ["https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf"];
        } in
        finding :: findings
    
    | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (_, "string_to_key"); _}; _}, args) ->
        let finding = {
          rule_id = "CRYPTO002";
          severity = Critical;
          message = "Potential hardcoded cryptographic key";
          vulnerability = HardcodedKey;
          location = {
            file = loc.loc_start.pos_fname;
            line = loc.loc_start.pos_lnum;
            column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
            end_line = Some loc.loc_end.pos_lnum;
            end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
          };
          suggestion = Some "Load keys from secure configuration or use key derivation functions";
          references = ["https://cwe.mitre.org/data/definitions/798.html"];
        } in
        finding :: findings
    
    | Pexp_apply ({pexp_desc = Pexp_ident {txt = Ldot (_, hash_fn); _}; _}, _) 
      when List.mem hash_fn Crypto_patterns.weak_hashes ->
        let finding = {
          rule_id = "CRYPTO003";
          severity = Warning;
          message = Printf.sprintf "Use of weak hash function: %s" hash_fn;
          vulnerability = WeakHash hash_fn;
          location = {
            file = loc.loc_start.pos_fname;
            line = loc.loc_start.pos_lnum;
            column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
            end_line = Some loc.loc_end.pos_lnum;
            end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
          };
          suggestion = Some "Use SHA-256, SHA-384, SHA-512, or BLAKE2";
          references = ["https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf"];
        } in
        finding :: findings
    
    | Pexp_constant (Pconst_string (s, _, _)) when String.length s >= 16 && String.length s <= 64 ->
        (* Heuristic: strings of certain lengths might be keys *)
        let is_hex = String.for_all (fun c -> 
          (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
        ) s in
        if is_hex then
          let finding = {
            rule_id = "CRYPTO004";
            severity = Warning;
            message = "Possible hardcoded key or secret detected";
            vulnerability = HardcodedKey;
            location = {
              file = loc.loc_start.pos_fname;
              line = loc.loc_start.pos_lnum;
              column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
              end_line = Some loc.loc_end.pos_lnum;
              end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
            };
            suggestion = Some "Store secrets in environment variables or secure vaults";
            references = ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"];
          } in
          finding :: findings
        else findings
    
    | _ -> super#expression expr findings
  
  method! pattern pat findings =
    match pat.ppat_desc with
    | Ppat_var {txt = name; _} when 
        List.exists (fun prefix -> 
          String.lowercase_ascii name |> fun n -> 
          String.starts_with ~prefix n
        ) ["key"; "password"; "secret"; "token"; "iv"; "nonce"] ->
        (* Track variable names that might contain sensitive data *)
        findings
    | _ -> super#pattern pat findings
end

let analyze_structure str =
  let visitor = new crypto_visitor in
  visitor#structure str []

let analyze_signature sg =
  let visitor = new crypto_visitor in
  visitor#signature sg []