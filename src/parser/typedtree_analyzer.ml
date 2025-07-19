module Linter_types = Types
open Utils
open Typedtree

type crypto_api_call = {
  func_path: Path.t;
  location: Location.t;
  args: (Asttypes.arg_label * Typedtree.expression) list;
}

type security_context = {
  mutable crypto_calls: crypto_api_call list;
  mutable key_flows: (Ident.t * Location.t list) list;
  mutable iv_usage: (Ident.t, int) Hashtbl.t;
  mutable tainted_values: Ident.t list;
}

let create_context () = {
  crypto_calls = [];
  key_flows = [];
  iv_usage = Hashtbl.create 32;
  tainted_values = [];
}

class typedtree_visitor (ctx: security_context) = object(self)
  inherit Tast_iterator.iter as super
  
  method! expr expr =
    match expr.exp_desc with
    | Texp_apply (func, args) ->
        self#analyze_application func args expr.exp_loc;
        super#expr expr
    
    | Texp_let (_, bindings, body) ->
        List.iter self#analyze_binding bindings;
        super#expr expr
    
    | Texp_ident (path, _, _) ->
        self#track_identifier path expr.exp_loc;
        super#expr expr
    
    | _ -> super#expr expr
  
  method private analyze_application func args loc =
    match func.exp_desc with
    | Texp_ident (path, _, _) ->
        let path_str = Path.name path in
        if self#is_crypto_function path_str then begin
          ctx.crypto_calls <- {
            func_path = path;
            location = loc;
            args = args;
          } :: ctx.crypto_calls;
          
          self#check_crypto_parameters path_str args loc
        end
    | _ -> ()
  
  method private analyze_binding vb =
    match vb.vb_pat.pat_desc with
    | Tpat_var (id, _) ->
        let name = Ident.name id in
        if self#is_sensitive_name name then
          ctx.tainted_values <- id :: ctx.tainted_values;
        
        (match vb.vb_expr.exp_desc with
        | Texp_constant (Const_string _) when self#is_key_like name ->
            self#report_hardcoded_key vb.vb_expr.exp_loc name
        | _ -> ())
    | _ -> ()
  
  method private is_crypto_function path =
    List.exists (fun prefix ->
      String.starts_with ~prefix path
    ) ["Cryptokit."; "Nocrypto."; "Mirage_crypto."; 
       "Hacl_star."; "Sodium."; "Tls."]
  
  method private is_sensitive_name name =
    let lower = String.lowercase_ascii name in
    List.exists (fun keyword ->
      contains_substring lower keyword
    ) ["key"; "password"; "secret"; "token"; "nonce"; "iv"; "salt"]
  
  method private is_key_like name =
    let lower = String.lowercase_ascii name in
    contains_substring lower "key" || 
    contains_substring lower "password"
  
  method private check_crypto_parameters func_name args loc =
    match func_name with
    | "Cryptokit.Cipher.aes" ->
        self#check_aes_key_size args loc
    
    | "Nocrypto.Cipher_block.AES.GCM.encrypt" ->
        self#check_gcm_nonce args loc
    
    | path when contains_substring path "Hash.md5" ||
                contains_substring path "Hash.sha1" ->
        self#report_weak_hash path loc
    
    | _ -> ()
  
  method private check_aes_key_size args loc =
    List.iter (fun (label, arg) ->
      match label with
      | Asttypes.Labelled "key" ->
          (match arg.exp_desc with
          | Texp_constant (Const_string (key, _, _)) ->
              let key_bits = String.length key * 8 in
              if key_bits < 128 then
                self#report_weak_key_size key_bits loc
          | _ -> ())
      | _ -> ()
    ) args
  
  method private check_gcm_nonce args loc =
    List.iter (fun (label, arg) ->
      match label with
      | Asttypes.Labelled "nonce" ->
          (match arg.exp_desc with
          | Texp_ident (Path.Pident id, _, _) ->
              let count = 
                try Hashtbl.find ctx.iv_usage id + 1
                with Not_found -> 1 in
              Hashtbl.replace ctx.iv_usage id count;
              if count > 1 then
                self#report_nonce_reuse (Ident.name id) loc
          | _ -> ())
      | _ -> ()
    ) args
  
  method private track_identifier path loc =
    match path with
    | Path.Pident id when List.mem id ctx.tainted_values ->
        ctx.key_flows <- 
          (id, loc :: (try List.assoc id ctx.key_flows with Not_found -> [])) 
          :: List.remove_assoc id ctx.key_flows
    | _ -> ()
  
  method private report_hardcoded_key loc name =
    let finding = {
      rule_id = "CRYPTO_TYPED_001";
      severity = Linter_types.Critical;
      message = Printf.sprintf "Hardcoded %s detected in typed AST" name;
      vulnerability = Linter_types.HardcodedKey;
      location = {
        file = loc.loc_start.pos_fname;
        line = loc.loc_start.pos_lnum;
        column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
        end_line = Some loc.loc_end.pos_lnum;
        end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
      };
      suggestion = Some "Use environment variables or secure key management";
      references = ["CWE-798"; "NIST SP 800-57"];
    } in
    (* Store finding in context or report immediately *)
    ()
  
  method private report_weak_hash algo loc =
    let finding = {
      rule_id = "CRYPTO_TYPED_002";
      severity = Linter_types.Error;
      message = Printf.sprintf "Weak hash algorithm %s detected" algo;
      vulnerability = Linter_types.WeakHash (if String.contains algo "md5" then "MD5" else "SHA1");
      location = {
        file = loc.loc_start.pos_fname;
        line = loc.loc_start.pos_lnum;
        column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
        end_line = Some loc.loc_end.pos_lnum;
        end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
      };
      suggestion = Some "Use SHA-256, SHA-384, SHA-512, or BLAKE2";
      references = ["CVE-2017-15999"; "NIST SP 800-131A"];
    } in
    ()
  
  method private report_weak_key_size bits loc =
    let finding = {
      rule_id = "CRYPTO_TYPED_003";
      severity = Linter_types.Error;
      message = Printf.sprintf "Weak key size: %d bits" bits;
      vulnerability = Linter_types.InsecureKeySize bits;
      location = {
        file = loc.loc_start.pos_fname;
        line = loc.loc_start.pos_lnum;
        column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
        end_line = Some loc.loc_end.pos_lnum;
        end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
      };
      suggestion = Some "Use at least 128-bit keys for AES";
      references = ["NIST SP 800-131A"];
    } in
    ()
  
  method private report_nonce_reuse name loc =
    let finding = {
      rule_id = "CRYPTO_TYPED_004";
      severity = Linter_types.Critical;
      message = Printf.sprintf "Nonce '%s' is reused in GCM mode" name;
      vulnerability = Linter_types.NonceReuse;
      location = {
        file = loc.loc_start.pos_fname;
        line = loc.loc_start.pos_lnum;
        column = loc.loc_start.pos_cnum - loc.loc_start.pos_bol;
        end_line = Some loc.loc_end.pos_lnum;
        end_column = Some (loc.loc_end.pos_cnum - loc.loc_end.pos_bol);
      };
      suggestion = Some "Generate a unique nonce for each encryption";
      references = ["CVE-2016-0270"; "NIST SP 800-38D"];
    } in
    ()
end

let analyze_typed_tree tree =
  let ctx = create_context () in
  let visitor = new typedtree_visitor ctx in
  visitor#structure tree;
  
  (* Return analysis results *)
  {
    crypto_calls = ctx.crypto_calls;
    tainted_flows = ctx.key_flows;
    nonce_reuse_count = 
      Hashtbl.fold (fun _ count acc -> 
        if count > 1 then acc + 1 else acc
      ) ctx.iv_usage 0;
  }