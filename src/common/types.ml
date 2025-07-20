type severity = Info | Warning | Error | Critical

type location = {
  file: string;
  line: int;
  column: int;
  end_line: int option;
  end_column: int option;
}

type crypto_vulnerability = 
  | WeakCipher of string
  | InsecureKeySize of int
  | HardcodedKey
  | PredictableIV
  | WeakRandom
  | NonceReuse
  | WeakHash of string
  | InsecurePadding
  | TimingLeak
  | SideChannel
  | KeyReuse
  | MacMissing
  | MissingAuthentication
  | WeakKDF
  | InsecureMode of string
  (* Protocol vulnerabilities *)
  | AuthBypass
  | ReplayAttack
  | CSRF
  | InfoDisclosure
  | InsecureProtocol
  | SignatureBypass
  | ImproperValidation

type finding = {
  rule_id: string;
  severity: severity;
  message: string;
  vulnerability: crypto_vulnerability;
  location: location;
  suggestion: string option;
  references: string list;
}

type analysis_result = {
  findings: finding list;
  files_analyzed: int;
  analysis_time: float;
  errors: (string * string) list;
}

module Json_conv = struct
  
  let severity_to_json = function
    | Info -> `String "info"
    | Warning -> `String "warning"
    | Error -> `String "error"
    | Critical -> `String "critical"
  
  let location_to_json loc = 
    `Assoc [
      ("file", `String loc.file);
      ("line", `Int loc.line);
      ("column", `Int loc.column);
      ("end_line", match loc.end_line with Some l -> `Int l | None -> `Null);
      ("end_column", match loc.end_column with Some c -> `Int c | None -> `Null);
    ]
  
  let vulnerability_to_json = function
    | WeakCipher name -> `Assoc [("type", `String "weak_cipher"); ("details", `String name)]
    | InsecureKeySize size -> `Assoc [("type", `String "insecure_key_size"); ("size", `Int size)]
    | HardcodedKey -> `Assoc [("type", `String "hardcoded_key")]
    | PredictableIV -> `Assoc [("type", `String "predictable_iv")]
    | WeakRandom -> `Assoc [("type", `String "weak_random")]
    | NonceReuse -> `Assoc [("type", `String "nonce_reuse")]
    | WeakHash name -> `Assoc [("type", `String "weak_hash"); ("algorithm", `String name)]
    | InsecurePadding -> `Assoc [("type", `String "insecure_padding")]
    | TimingLeak -> `Assoc [("type", `String "timing_leak")]
    | SideChannel -> `Assoc [("type", `String "side_channel")]
    | KeyReuse -> `Assoc [("type", `String "key_reuse")]
    | MacMissing -> `Assoc [("type", `String "mac_missing")]
    | MissingAuthentication -> `Assoc [("type", `String "missing_authentication")]
    | WeakKDF -> `Assoc [("type", `String "weak_kdf")]
    | InsecureMode mode -> `Assoc [("type", `String "insecure_mode"); ("mode", `String mode)]
    (* Protocol vulnerabilities *)
    | AuthBypass -> `Assoc [("type", `String "auth_bypass")]
    | ReplayAttack -> `Assoc [("type", `String "replay_attack")]
    | CSRF -> `Assoc [("type", `String "csrf")]
    | InfoDisclosure -> `Assoc [("type", `String "info_disclosure")]
    | InsecureProtocol -> `Assoc [("type", `String "insecure_protocol")]
    | SignatureBypass -> `Assoc [("type", `String "signature_bypass")]
    | ImproperValidation -> `Assoc [("type", `String "improper_validation")]
  
  let finding_to_json f =
    `Assoc [
      ("rule_id", `String f.rule_id);
      ("severity", severity_to_json f.severity);
      ("message", `String f.message);
      ("vulnerability", vulnerability_to_json f.vulnerability);
      ("location", location_to_json f.location);
      ("suggestion", match f.suggestion with Some s -> `String s | None -> `Null);
      ("references", `List (List.map (fun r -> `String r) f.references));
    ]
end