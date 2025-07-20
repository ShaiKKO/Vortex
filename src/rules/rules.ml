(* Main rules module that aggregates all rule categories *)

(* Export the main registry first *)
module Registry = Rule_engine.Registry

(* Load all rule modules - this forces their initialization *)
module Algorithm_rules = Algorithm_weakness_rules
module Key_rules = Key_nonce_rules  
module Side_channel = Side_channel_rules
module Api_rules = Api_misuse_rules
module Dependency = Dependency_rules
module Cve = Cve_rules
module Protocol = Protocol_rules
module Sidechannel_advanced = Sidechannel_adv
module Sidechannel_enhanced = Sidechannel_enhanced

(* Force protocol rules module to load by accessing a value *)
let _ = Protocol_rules.jwt_algorithm_confusion_rule
(* Force advanced side-channel rules to load *)
let _ = Sidechannel_adv.speculative_execution_rule
(* Force enhanced side-channel rules to load *)
let _ = Sidechannel_enhanced.enhanced_speculative_rule

(* Summary statistics *)
let rule_statistics () =
  let all_rules = Registry.all_rules () in
  let by_category = Hashtbl.create 5 in
  
  List.iter (fun rule ->
    List.iter (fun tag ->
      let count = 
        try Hashtbl.find by_category tag + 1
        with Not_found -> 1 in
      Hashtbl.replace by_category tag count
    ) rule.Rule_engine.Rule.tags
  ) all_rules;
  
  Printf.printf "OCaml Crypto Linter - Rule Summary\n";
  Printf.printf "==================================\n";
  Printf.printf "Total rules: %d\n\n" (List.length all_rules);
  
  Printf.printf "By Category:\n";
  Hashtbl.iter (fun category count ->
    Printf.printf "  %-20s: %d rules\n" category count
  ) by_category;
  
  Printf.printf "\nBy Severity:\n";
  let severities = Hashtbl.create 4 in
  List.iter (fun rule ->
    let sev = match rule.Rule_engine.Rule.severity with
      | Critical -> "Critical"
      | Error -> "Error"
      | Warning -> "Warning"
      | Info -> "Info"
    in
    let count = try Hashtbl.find severities sev + 1 with Not_found -> 1 in
    Hashtbl.replace severities sev count
  ) all_rules;
  
  Hashtbl.iter (fun sev count ->
    Printf.printf "  %-20s: %d rules\n" sev count
  ) severities

(* Priority ranking based on real-world prevalence *)
let high_priority_rules = [
  "ALGO001";  (* Weak ciphers - very common *)
  "ALGO002";  (* Weak hashes - extremely common *)
  "KEY001";   (* Hardcoded keys - critical and common *)
  "API001";   (* ECB mode - common mistake *)
  "SIDE001";  (* Timing attacks - subtle but prevalent *)
  "DEP002";   (* Deprecated nocrypto - migration needed *)
]

let medium_priority_rules = [
  "KEY003";   (* AEAD nonce reuse *)
  "API002";   (* CBC without MAC *)
  "API006";   (* Unverified certificates *)
  "ALGO006";  (* Legacy TLS versions *)
  "KEY002";   (* Predictable key generation *)
]

let get_rules_by_priority priority =
  let priority_list = match priority with
    | "high" -> high_priority_rules
    | "medium" -> medium_priority_rules
    | _ -> []
  in
  List.filter_map (fun id ->
    Registry.get_rule id
  ) priority_list

(* Example-driven documentation *)
let rule_examples = [
  ("ALGO001", 
   "Weak Cipher",
   "let cipher = Cryptokit.Cipher.des key",
   "let cipher = Mirage_crypto.AES.GCM.of_secret key");
  
  ("ALGO002",
   "Weak Hash", 
   "let hash = Cryptokit.Hash.md5 ()",
   "let hash = Mirage_crypto.Hash.SHA256.digest");
  
  ("KEY001",
   "Hardcoded Key",
   "let key = \"my_secret_key_123\"",
   "let key = Sys.getenv \"CRYPTO_KEY\"");
  
  ("KEY003",
   "Nonce Reuse",
   "let nonce = String.make 12 '\\000'",
   "let nonce = Mirage_crypto_rng.generate 12");
  
  ("SIDE001",
   "Timing Attack",
   "if computed_mac = expected_mac then",
   "if Eqaf.equal computed_mac expected_mac then");
  
  ("API001",
   "ECB Mode",
   "Cipher.aes ~mode:`ECB key",
   "Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce");
]

let print_examples () =
  Printf.printf "\nCommon Vulnerability Examples\n";
  Printf.printf "=============================\n\n";
  
  List.iter (fun (rule_id, name, bad, good) ->
    Printf.printf "%s - %s\n" rule_id name;
    Printf.printf "  ❌ Bad:  %s\n" bad;
    Printf.printf "  ✅ Good: %s\n\n" good;
  ) rule_examples