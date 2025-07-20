(* Test file for enhanced supply chain rules 
   Tests false positive fixes and new detections *)

(* These should NOT be flagged (false positive fixes) *)
let legitimate_variants = 
  depends "mirage-crypto" ;      (* Main package - legitimate *)
  depends "mirage-crypto-rng" ;  (* Legitimate variant *)
  depends "mirage-crypto-pk" ;   (* Legitimate variant *)
  depends "mirage-crypto-ec" ;   (* Legitimate variant *)
  depends "cohttp-lwt" ;         (* Legitimate variant *)
  depends "cohttp-async" ;       (* Legitimate variant *)
  depends "lwt_ppx" ;            (* Legitimate variant *)
  depends "lwt_react"            (* Legitimate variant *)

(* SUPPLY001: Known vulnerabilities - enhanced *)
let vulnerable_packages = 
  depends "nocrypto" ;           (* Deprecated - should show migration guide *)
  depends "ssl" ;                (* Obsolete SSL bindings *)
  depends "cryptopp" ;           (* CVE-2025-10234 *)
  depends "jose" ;               (* Has CVE if old version *)
  depends "cryptokit"            (* Check for timing attack CVE *)

(* SUPPLY002: Typosquatting - enhanced detection *)
let typosquatting_attempts =
  depends "yojsonn" ;            (* Extra 'n' - distance 1 *)
  depends "cryptkit" ;           (* Missing 'o' - distance 1 *)
  depends "lwtw" ;               (* Extra 'w' - distance 1 *)
  depends "c0http" ;             (* '0' instead of 'o' *)
  depends "base_64" ;            (* Underscore pattern *)
  depends "zarithh" ;            (* Doubled last char *)
  depends "ppx-deriving" ;       (* Hyphen instead of underscore *)
  depends "mirage_crypto"        (* Underscore instead of hyphen - but should NOT flag as it's whitelisted *)

(* SUPPLY004: Outdated dependency checks *)
let version_checks = 
  depends "lwt" ;                (* Should mention 5.9.1 *)
  depends "tls" ;                (* Should mention 0.17.3 *)
  depends "dune" ;               (* Should mention 3.16.0 *)
  depends "zarith" ;             (* Should mention 1.14 *)
  depends "ppxlib"               (* Should mention 0.33.0 *)

(* SUPPLY007: Known backdoors *)
let critical_backdoors =
  depends "malicious-pkg" ;      (* Cryptominer backdoor *)
  depends "fake-jose"            (* Credential stealer *)

(* Additional packages to test edge cases *)
let edge_cases = 
  depends "async" ;              (* Normal package *)
  depends "core" ;               (* Normal package *)
  depends "batteries" ;          (* Normal package *)
  depends "cmdliner" ;           (* Normal package *)
  depends "fmt"                  (* Normal package *)