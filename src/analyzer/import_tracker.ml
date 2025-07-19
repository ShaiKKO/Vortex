open Ppxlib

type crypto_library = 
  | Cryptokit
  | Nocrypto
  | Mirage_crypto
  | Hacl_star
  | Sodium
  | Tls
  | X509
  | Ssl
  | Custom of string

type import_info = {
  library: crypto_library;
  modules: string list;
  location: Location.t;
  is_open: bool;
}

type crypto_context = {
  mutable imports: import_info list;
  mutable active_libraries: crypto_library list;
  mutable crypto_mode_enabled: bool;
  mutable custom_patterns: (string * crypto_library) list;
}

let create_context () = {
  imports = [];
  active_libraries = [];
  crypto_mode_enabled = false;
  custom_patterns = [];
}

let library_of_string = function
  | "Cryptokit" -> Some Cryptokit
  | "Nocrypto" -> Some Nocrypto
  | "Mirage_crypto" -> Some Mirage_crypto
  | "Hacl_star" | "Hacl" -> Some Hacl_star
  | "Sodium" -> Some Sodium
  | "Tls" -> Some Tls
  | "X509" -> Some X509
  | "Ssl" | "Lwt_ssl" -> Some Ssl
  | s when String.starts_with ~prefix:"Cryptokit." s -> Some Cryptokit
  | s when String.starts_with ~prefix:"Nocrypto." s -> Some Nocrypto
  | s when String.starts_with ~prefix:"Mirage_crypto." s -> Some Mirage_crypto
  | _ -> None

let get_crypto_modules = function
  | Cryptokit -> ["Cipher"; "Hash"; "Random"; "RSA"; "DH"; "Padding"; "Base64"]
  | Nocrypto -> ["Rsa"; "Dsa"; "Dh"; "Hash"; "Cipher_block"; "Cipher_stream"; "Rng"]
  | Mirage_crypto -> ["AES"; "DES"; "Hash"; "Cipher_block"; "Cipher_stream"; "Rng"; "Pk"]
  | Hacl_star -> ["Ed25519"; "Curve25519"; "Chacha20_Poly1305"; "SHA2_256"; "SHA2_512"]
  | Sodium -> ["Random"; "Box"; "Sign"; "Hash"; "Auth"; "Stream"]
  | Tls -> ["Engine"; "Config"; "X509"; "Ciphersuite"]
  | X509 -> ["Certificate"; "Signing_request"; "Public_key"; "Private_key"]
  | Ssl -> ["ssl_connect"; "ssl_accept"; "ssl_shutdown"]
  | Custom name -> [name]

class import_tracker ctx = object(self)
  inherit [unit] Ast_traverse.iter as super
  
  method! structure_item item () =
    match item.pstr_desc with
    | Pstr_open {popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _} ->
        self#track_open txt item.pstr_loc;
        super#structure_item item ()
    
    | Pstr_module {pmb_expr = {pmod_desc = Pmod_ident {txt; _}; _}; pmb_name; _} ->
        self#track_module_alias pmb_name.txt txt item.pstr_loc;
        super#structure_item item ()
    
    | _ -> super#structure_item item ()
  
  method! expression expr () =
    match expr.pexp_desc with
    | Pexp_ident {txt; _} ->
        self#check_crypto_usage txt expr.pexp_loc;
        super#expression expr ()
    
    | Pexp_open ({popen_expr = {pmod_desc = Pmod_ident {txt; _}; _}; _}, e) ->
        self#track_local_open txt expr.pexp_loc;
        self#expression e ();
    
    | _ -> super#expression expr ()
  
  method private track_open lid loc =
    let module_path = Longident.flatten lid |> String.concat "." in
    match library_of_string module_path with
    | Some lib ->
        ctx.imports <- {
          library = lib;
          modules = get_crypto_modules lib;
          location = loc;
          is_open = true;
        } :: ctx.imports;
        
        if not (List.mem lib ctx.active_libraries) then
          ctx.active_libraries <- lib :: ctx.active_libraries;
        
        ctx.crypto_mode_enabled <- true;
        
    | None ->
        (* Check custom patterns *)
        List.iter (fun (pattern, lib) ->
          if String.starts_with ~prefix:pattern module_path then begin
            ctx.imports <- {
              library = lib;
              modules = [module_path];
              location = loc;
              is_open = true;
            } :: ctx.imports;
            ctx.crypto_mode_enabled <- true
          end
        ) ctx.custom_patterns
  
  method private track_module_alias name lid loc =
    let module_path = Longident.flatten lid |> String.concat "." in
    match library_of_string module_path with
    | Some lib ->
        ctx.imports <- {
          library = lib;
          modules = [name];
          location = loc;
          is_open = false;
        } :: ctx.imports;
        
        if not (List.mem lib ctx.active_libraries) then
          ctx.active_libraries <- lib :: ctx.active_libraries;
        
        ctx.crypto_mode_enabled <- true
    | None -> ()
  
  method private track_local_open lid loc =
    self#track_open lid loc
  
  method private check_crypto_usage lid loc =
    let path = Longident.flatten lid |> String.concat "." in
    
    (* Direct crypto library usage *)
    if library_of_string path <> None then
      ctx.crypto_mode_enabled <- true;
    
    (* Check if using imported crypto modules *)
    List.iter (fun import ->
      List.iter (fun modname ->
        if String.starts_with ~prefix:modname path then
          ctx.crypto_mode_enabled <- true
      ) import.modules
    ) ctx.imports
end

let analyze_imports ast =
  let ctx = create_context () in
  let tracker = new import_tracker ctx in
  tracker#structure ast ();
  ctx

let get_active_rules ctx =
  let rules = ref [] in
  
  List.iter (fun lib ->
    match lib with
    | Cryptokit ->
        rules := !rules @ [
          "weak-cipher-cryptokit";
          "hardcoded-key-cryptokit";
          "weak-hash-cryptokit";
          "insecure-random-cryptokit";
        ]
    
    | Nocrypto ->
        rules := !rules @ [
          "weak-cipher-nocrypto";
          "nonce-reuse-nocrypto";
          "timing-attack-nocrypto";
          "rsa-padding-nocrypto";
        ]
    
    | Mirage_crypto ->
        rules := !rules @ [
          "gcm-nonce-reuse";
          "cbc-padding-oracle";
          "weak-kdf-mirage";
          "missing-auth-mirage";
        ]
    
    | Hacl_star ->
        rules := !rules @ [
          "curve25519-validation";
          "ed25519-nonce";
          "chacha20-counter";
        ]
    
    | Sodium ->
        rules := !rules @ [
          "sodium-init-check";
          "sodium-memleak";
          "sodium-nonce-increment";
        ]
    
    | Tls ->
        rules := !rules @ [
          "tls-version-check";
          "cipher-suite-strength";
          "certificate-validation";
        ]
    
    | X509 ->
        rules := !rules @ [
          "cert-chain-validation";
          "key-usage-check";
          "signature-algorithm";
        ]
    
    | Ssl ->
        rules := !rules @ [
          "ssl-version-deprecated";
          "ssl-cert-verify";
          "ssl-session-reuse";
        ]
    
    | Custom name ->
        rules := !rules @ [
          Printf.sprintf "custom-%s" (String.lowercase_ascii name);
        ]
  ) ctx.active_libraries;
  
  !rules

let add_custom_pattern ctx pattern library_name =
  ctx.custom_patterns <- (pattern, Custom library_name) :: ctx.custom_patterns

let is_crypto_active ctx = ctx.crypto_mode_enabled

let get_import_locations ctx =
  List.map (fun import -> import.location) ctx.imports