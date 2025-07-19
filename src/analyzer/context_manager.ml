open Types
open Utils

module Context_manager = struct
  type module_info = {
    name: string;
    file: string;
    exports: (string * value_kind) list;
    imports: string list;
    crypto_operations: crypto_operation list;
  }
  
  and value_kind =
    | Function of function_sig
    | Value of value_type
    | Module of module_type
    | Type of type_info
  
  and function_sig = {
    params: string list;
    return_type: string option;
    is_crypto: bool;
    tainted: bool;
  }
  
  and value_type =
    | CryptoKey
    | Nonce
    | Hash
    | Ciphertext
    | Plaintext
    | Unknown
  
  and module_type =
    | CryptoModule of Import_tracker.crypto_library
    | RegularModule
    | FunctorModule of string list
  
  and type_info = {
    kind: type_kind;
    params: string list;
  }
  
  and type_kind =
    | Abstract
    | Variant
    | Record
    | Alias of string
  
  and crypto_operation = {
    op_type: operation_type;
    location: Location.t;
    inputs: string list;
    outputs: string list;
    context: operation_context;
  }
  
  and operation_type =
    | Encryption of string
    | Decryption of string
    | Hashing of string
    | KeyGeneration
    | KeyDerivation
    | Signing
    | Verification
    | RandomGeneration
  
  and operation_context = {
    in_functor: bool;
    in_first_class_module: bool;
    module_path: string list;
  }
  
  type global_context = {
    modules: (string, module_info) Hashtbl.t;
    dependencies: (string * string) list;
    crypto_flows: crypto_flow list;
    taint_propagation: (string, taint_info) Hashtbl.t;
  }
  
  and crypto_flow = {
    source: flow_point;
    sink: flow_point;
    flow_type: flow_type;
    severity: severity;
  }
  
  and flow_point = {
    module_name: string;
    value_name: string;
    location: Location.t;
  }
  
  and flow_type =
    | KeyFlow
    | NonceFlow
    | PlaintextFlow
    | HashFlow
  
  and taint_info = {
    origin: string;
    taint_type: value_type;
    propagated_to: string list;
  }
  
  let create_context () = {
    modules = Hashtbl.create 64;
    dependencies = [];
    crypto_flows = [];
    taint_propagation = Hashtbl.create 128;
  }
  
  class module_analyzer ctx module_name = object(self)
    inherit [module_info] Ppxlib.Ast_traverse.fold as super
    
    val mutable current_module = {
      name = module_name;
      file = "";
      exports = [];
      imports = [];
      crypto_operations = [];
    }
    
    method! structure_item item info =
      match item.pstr_desc with
      | Pstr_value (_, bindings) ->
          List.fold_left (fun info binding ->
            self#analyze_value_binding binding info
          ) info bindings
      
      | Pstr_module {pmb_name; pmb_expr; _} ->
          let sub_module = self#analyze_module pmb_name.txt pmb_expr in
          { info with exports = (pmb_name.txt, Module RegularModule) :: info.exports }
      
      | Pstr_type (_, type_decls) ->
          List.fold_left (fun info decl ->
            self#analyze_type_decl decl info
          ) info type_decls
      
      | Pstr_open {popen_expr; _} ->
          let import = self#extract_module_path popen_expr in
          { info with imports = import :: info.imports }
      
      | _ -> super#structure_item item info
    
    method private analyze_value_binding binding info =
      match binding.pvb_pat.ppat_desc with
      | Ppat_var {txt = name; _} ->
          let value_type = self#infer_value_type binding.pvb_expr in
          let is_crypto = self#is_crypto_related binding.pvb_expr in
          
          if is_crypto then begin
            let op = self#extract_crypto_operation name binding.pvb_expr in
            match op with
            | Some operation ->
                { info with 
                  exports = (name, Value value_type) :: info.exports;
                  crypto_operations = operation :: info.crypto_operations }
            | None ->
                { info with exports = (name, Value value_type) :: info.exports }
          end else
            { info with exports = (name, Value value_type) :: info.exports }
      
      | _ -> info
    
    method private analyze_module name expr =
      match expr.pmod_desc with
      | Pmod_structure items ->
          let sub_analyzer = new module_analyzer ctx name in
          let empty_info = {
            name;
            file = current_module.file;
            exports = [];
            imports = [];
            crypto_operations = [];
          } in
          List.fold_left (fun info item ->
            sub_analyzer#structure_item item info
          ) empty_info items
      
      | Pmod_functor _ ->
          { current_module with 
            exports = [(name, Module (FunctorModule []))] }
      
      | _ -> current_module
    
    method private analyze_type_decl decl info =
      let type_info = {
        kind = (match decl.ptype_kind with
          | Ptype_abstract -> Abstract
          | Ptype_variant _ -> Variant
          | Ptype_record _ -> Record
          | _ -> Abstract);
        params = List.map (fun (tp, _) -> 
          match tp.ptyp_desc with
          | Ptyp_var s -> s
          | _ -> "_"
        ) decl.ptype_params;
      } in
      { info with exports = (decl.ptype_name.txt, Type type_info) :: info.exports }
    
    method private infer_value_type expr =
      match expr.pexp_desc with
      | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
          let path = Longident.flatten txt |> String.concat "." in
          if contains_substring path "key" then CryptoKey
          else if contains_substring path "nonce" || 
                  contains_substring path "iv" then Nonce
          else if contains_substring path "hash" then Hash
          else if contains_substring path "encrypt" then Ciphertext
          else if contains_substring path "decrypt" then Plaintext
          else Unknown
      | _ -> Unknown
    
    method private is_crypto_related expr =
      match expr.pexp_desc with
      | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, _) ->
          let path = Longident.flatten txt |> String.concat "." in
          List.exists (fun pattern ->
            contains_substring (String.lowercase_ascii path) pattern
          ) ["crypto"; "cipher"; "hash"; "sign"; "encrypt"; "decrypt"; 
             "key"; "nonce"; "random"; "hmac"; "aes"; "rsa"]
      | _ -> false
    
    method private extract_crypto_operation name expr =
      match expr.pexp_desc with
      | Pexp_apply ({pexp_desc = Pexp_ident {txt; _}; _}, args) ->
          let path = Longident.flatten txt |> String.concat "." in
          let op_type = 
            if contains_substring path "encrypt" then 
              Some (Encryption path)
            else if contains_substring path "decrypt" then 
              Some (Decryption path)
            else if contains_substring path "hash" then 
              Some (Hashing path)
            else if contains_substring path "sign" then 
              Some Signing
            else if contains_substring path "verify" then 
              Some Verification
            else if contains_substring path "random" then 
              Some RandomGeneration
            else if contains_substring path "derive" then 
              Some KeyDerivation
            else None
          in
          
          (match op_type with
          | Some op ->
              Some {
                op_type = op;
                location = expr.pexp_loc;
                inputs = self#extract_arg_names args;
                outputs = [name];
                context = {
                  in_functor = false;
                  in_first_class_module = false;
                  module_path = [current_module.name];
                };
              }
          | None -> None)
      | _ -> None
    
    method private extract_arg_names args =
      List.filter_map (fun (_, arg) ->
        match arg.pexp_desc with
        | Pexp_ident {txt = Lident name; _} -> Some name
        | _ -> None
      ) args
    
    method private extract_module_path expr =
      match expr.pmod_desc with
      | Pmod_ident {txt; _} ->
          Longident.flatten txt |> String.concat "."
      | _ -> "unknown"
  end
  
  let analyze_module ctx name ast =
    let analyzer = new module_analyzer ctx name in
    let module_info = List.fold_left (fun info item ->
      analyzer#structure_item item info
    ) { name; file = ""; exports = []; imports = []; crypto_operations = [] } ast in
    
    Hashtbl.add ctx.modules name module_info;
    module_info
  
  let analyze_inter_module_flows ctx =
    let flows = ref [] in
    
    (* Build dependency graph *)
    Hashtbl.iter (fun name info ->
      List.iter (fun import ->
        ctx.dependencies <- (name, import) :: ctx.dependencies
      ) info.imports
    ) ctx.modules;
    
    (* Trace crypto flows *)
    Hashtbl.iter (fun module_name module_info ->
      List.iter (fun op ->
        (* Check if outputs flow to other modules *)
        List.iter (fun output ->
          Hashtbl.iter (fun other_name other_info ->
            if other_name <> module_name then
              List.iter (fun (import_name, _) ->
                if import_name = output then
                  flows := {
                    source = {
                      module_name;
                      value_name = output;
                      location = op.location;
                    };
                    sink = {
                      module_name = other_name;
                      value_name = import_name;
                      location = op.location;
                    };
                    flow_type = (match op.op_type with
                      | Encryption _ -> PlaintextFlow
                      | KeyGeneration | KeyDerivation -> KeyFlow
                      | Hashing _ -> HashFlow
                      | _ -> PlaintextFlow);
                    severity = Info;
                  } :: !flows
              ) other_info.exports
          ) ctx.modules
        ) op.outputs
      ) module_info.crypto_operations
    ) ctx.modules;
    
    ctx.crypto_flows <- !flows;
    !flows
  
  let check_crypto_anti_patterns ctx =
    let findings = ref [] in
    
    (* Check for key reuse across modules *)
    let key_usage = Hashtbl.create 32 in
    Hashtbl.iter (fun module_name info ->
      List.iter (fun (name, kind) ->
        match kind with
        | Value CryptoKey ->
            if Hashtbl.mem key_usage name then
              findings := {
                rule_id = "INTER_MODULE_001";
                severity = Error;
                message = Printf.sprintf "Crypto key '%s' used across multiple modules" name;
                vulnerability = HardcodedKey;
                location = {
                  file = info.file;
                  line = 0;
                  column = 0;
                  end_line = None;
                  end_column = None;
                };
                suggestion = Some "Use separate keys for different modules";
                references = [];
              } :: !findings
            else
              Hashtbl.add key_usage name module_name
        | _ -> ()
      ) info.exports
    ) ctx.modules;
    
    (* Check for plaintext flows to untrusted modules *)
    List.iter (fun flow ->
      if flow.flow_type = PlaintextFlow then
        findings := {
          rule_id = "INTER_MODULE_002";
          severity = Warning;
          message = Printf.sprintf "Plaintext flows from %s.%s to %s.%s" 
            flow.source.module_name flow.source.value_name
            flow.sink.module_name flow.sink.value_name;
          vulnerability = MissingAuthentication;
          location = flow.source.location;
          suggestion = Some "Ensure plaintext is encrypted before module boundaries";
          references = [];
        } :: !findings
    ) ctx.crypto_flows;
    
    !findings
  
  let get_module_crypto_summary ctx module_name =
    match Hashtbl.find_opt ctx.modules module_name with
    | Some info ->
        let crypto_exports = List.filter (fun (_, kind) ->
          match kind with
          | Value (CryptoKey | Nonce | Hash | Ciphertext) -> true
          | Function {is_crypto = true; _} -> true
          | Module (CryptoModule _) -> true
          | _ -> false
        ) info.exports in
        
        Some {
          total_exports = List.length info.exports;
          crypto_exports = List.length crypto_exports;
          crypto_operations = List.length info.crypto_operations;
          imports_crypto = List.exists (fun imp ->
            List.exists (fun lib ->
              contains_substring imp 
                (Import_tracker.get_crypto_modules lib |> List.hd)
            ) [Import_tracker.Cryptokit; Import_tracker.Nocrypto; Import_tracker.Mirage_crypto]
          ) info.imports;
        }
    | None -> None
end