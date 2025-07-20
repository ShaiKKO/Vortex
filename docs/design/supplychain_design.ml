(* Supply Chain Security Rules Design
   Focus: Dependency vulnerabilities, typosquatting, version pinning
   Reference: 2025 threat intelligence showing 49% of orgs vulnerable *)

open Types
open Rule_engine

(* Supply chain threat model *)
module Supply_Chain_Threats = struct
  type dependency_source = 
    | Opam of string
    | Npm of string  
    | System of string
    | Git of string * string (* url * commit *)
    | Local of string
    
  type vulnerability = {
    cve_id: string option;
    description: string;
    severity: severity;
    fixed_version: string option;
    published_date: string;
  }
  
  type dependency_info = {
    name: string;
    version: string;
    source: dependency_source;
    dependencies: string list; (* transitive *)
    vulnerabilities: vulnerability list;
    last_updated: float option;
  }
  
  type supply_chain_risk =
    | KnownVulnerability of vulnerability
    | Typosquatting of string * string (* suspected typo of legitimate package *)
    | Unpinned of string (* floating version *)
    | Outdated of string * string (* current * latest *)
    | SuspiciousSource of string (* unusual source *)
    | MismatchedSource (* GitHub vs package repo *)
end

(* ========================================================================== *)
(* SUPPLY001: Known Vulnerability Detection                                   *)
(* ========================================================================== *)

(* Design: Cross-reference dependencies against CVE database
   - Parse opam/dune-project files
   - Extract all dependencies with versions
   - Check against vulnerability database
   - Flag packages with known CVEs *)

let known_vulnerability_rule = {
  id = "SUPPLY001";
  name = "Known Vulnerability in Dependencies";
  description = "Detects dependencies with published CVEs or security advisories";
  severity = Critical;
  tags = ["supply-chain"; "cve"; "vulnerability"; "dependency"];
  
  vulnerability_sources = [
    "NVD (National Vulnerability Database)";
    "OSV (Open Source Vulnerabilities)";
    "GitHub Security Advisories";
    "Opam Security Advisories";
  ];
  
  detection_approach = "
    1. Parse dune-project and *.opam files
    2. Extract dependency list with version constraints
    3. Resolve actual versions (from opam switch or lock files)
    4. Query vulnerability databases for each package@version
    5. Report any matches with severity and remediation
  ";
  
  example_vulnerabilities = [
    ("cryptokit", "< 1.16.1", "CVE-2022-24793", "Timing attack in RSA decryption");
    ("jose", "< 0.6.0", "CVE-2021-41184", "Algorithm confusion vulnerability");
    ("tls", "< 0.15.0", "CVE-2021-32650", "Certificate verification bypass");
  ];
}

(* ========================================================================== *)
(* SUPPLY002: Typosquatting Detection                                         *)
(* ========================================================================== *)

(* Design: Detect potential typosquatting attacks
   - Compare package names against known good packages
   - Use edit distance algorithms
   - Check for common typo patterns
   - Flag suspicious similarities *)

let typosquatting_detection_rule = {
  id = "SUPPLY002";
  name = "Potential Typosquatting Attack";
  description = "Detects dependencies that may be typosquatted versions of legitimate packages";
  severity = High;
  tags = ["supply-chain"; "typosquatting"; "security"; "malicious"];
  
  detection_methods = [
    "Levenshtein distance (< 3 for package names)";
    "Common typo patterns (doubled letters, transpositions)";
    "Homoglyph attacks (visual similarity)";
    "Popular package targeting (high download count targets)";
  ];
  
  legitimate_packages = [
    (* Popular OCaml packages that might be targeted *)
    "lwt"; "core"; "async"; "batteries"; "cryptokit"; "tls"; "cohttp";
    "yojson"; "ppx_deriving"; "dune"; "cmdliner"; "logs"; "fmt";
    "mirage-crypto"; "zarith"; "digestif"; "x509"; "jose";
  ];
  
  typo_patterns = [
    ("doubling", "core" -> "coree");
    ("transposition", "async" -> "asncy");
    ("omission", "cryptokit" -> "cryptkit");
    ("homoglyph", "core" -> "соrе"); (* Cyrillic 'о' *)
    ("separator", "mirage-crypto" -> "mirage_crypto");
  ];
  
  risk_factors = [
    "Recently published package (< 30 days)";
    "Similar name to popular package";
    "No GitHub repository";
    "Minimal documentation";
    "Requests network access or filesystem permissions";
  ];
}

(* ========================================================================== *)
(* SUPPLY003: Unpinned Dependencies                                           *)
(* ========================================================================== *)

(* Design: Detect floating version constraints
   - Flag dependencies without exact pins
   - Identify wildcard constraints
   - Check for missing lock files
   - Assess update risks *)

let unpinned_dependencies_rule = {
  id = "SUPPLY003";
  name = "Unpinned Dependency Versions";
  description = "Detects dependencies without exact version pins, risking unexpected updates";
  severity = Warning;
  tags = ["supply-chain"; "versioning"; "reproducibility"; "best-practice"];
  
  risky_constraints = [
    ">= 1.0.0";    (* Any future version *)
    "~> 1.0";      (* Pessimistic constraint *)
    "*";           (* Wildcard *)
    "";            (* No constraint *)
    ">= 0";        (* Effectively no constraint *)
  ];
  
  safe_patterns = [
    "= 1.2.3";     (* Exact pin *)
    "1.2.3";       (* Exact version *)
    ">= 1.2.3 & < 1.3.0"; (* Tight range *)
  ];
  
  recommendations = [
    "Use opam lock files for reproducible builds";
    "Pin exact versions in production";
    "Use version ranges only for libraries";
    "Regularly audit and update pinned versions";
  ];
}

(* ========================================================================== *)
(* SUPPLY004: Outdated Dependencies                                           *)
(* ========================================================================== *)

(* Design: Identify severely outdated packages
   - Compare installed vs latest versions
   - Calculate version age
   - Check for security updates
   - Prioritize critical updates *)

let outdated_dependencies_rule = {
  id = "SUPPLY004";
  name = "Severely Outdated Dependencies";
  description = "Detects dependencies that are significantly behind latest versions";
  severity = Info;
  tags = ["supply-chain"; "maintenance"; "updates"; "security"];
  
  outdated_thresholds = [
    ("major_versions_behind", 2, Error);      (* 2+ major versions *)
    ("years_old", 2.0, Warning);              (* 2+ years *)
    ("security_updates", 1, Critical);        (* Any security update *)
  ];
  
  check_criteria = "
    1. Determine current version from opam switch or lock file
    2. Query opam repository for latest version
    3. Parse version numbers and compare
    4. Check if newer versions contain security fixes
    5. Calculate time since current version release
  ";
  
  exceptions = [
    "Intentionally held back for compatibility";
    "Latest version has breaking changes";
    "No security implications in updates";
  ];
}

(* ========================================================================== *)
(* SUPPLY005: Suspicious Package Sources                                      *)
(* ========================================================================== *)

(* Design: Detect unusual or risky package sources
   - Check for non-standard repositories
   - Identify local/git dependencies in production
   - Verify package signatures
   - Detect source mismatches *)

let suspicious_sources_rule = {
  id = "SUPPLY005";
  name = "Suspicious Package Source";
  description = "Detects dependencies from unusual or potentially compromised sources";
  severity = Error;
  tags = ["supply-chain"; "integrity"; "source-verification"; "trust"];
  
  trusted_sources = [
    "https://opam.ocaml.org";
    "https://github.com/ocaml/opam-repository";
  ];
  
  suspicious_patterns = [
    "Git dependency without commit pin";
    "HTTP (non-HTTPS) source";
    "Local file path in production";
    "Unknown opam repository";
    "Direct URL downloads";
    "Fork of popular package";
  ];
  
  source_verification = "
    1. Check if package source matches official repository
    2. Verify HTTPS for all remote sources
    3. Ensure git dependencies are pinned to commits
    4. Check package signatures if available
    5. Compare GitHub repo with package contents
  ";
  
  mismatch_detection = [
    "Package name doesn't match GitHub repo";
    "Different maintainer on GitHub vs opam";
    "Code on package repo differs from GitHub";
    "Missing source repository link";
  ];
}

(* ========================================================================== *)
(* Integration with build systems                                             *)
(* ========================================================================== *)

module Build_System_Integration = struct
  (* Parse dune-project *)
  let parse_dune_project path =
    (* Extract:
       - depends stanza
       - pin-depends stanza
       - x-opam-pins (if any)
    *)
    ()
    
  (* Parse opam files *)
  let parse_opam_file path =
    (* Extract:
       - depends field
       - pin-depends field
       - dev-repo
       - upstream repository
    *)
    ()
    
  (* Query opam *)
  let query_opam_info package =
    (* Get:
       - Latest version
       - All versions
       - Dependencies
       - Repository source
    *)
    ()
end

(* ========================================================================== *)
(* Vulnerability Database Integration                                         *)
(* ========================================================================== *)

module Vulnerability_DB = struct
  type db_source = 
    | LocalCache of string
    | OnlineAPI of string
    | OfflineDB of string
    
  (* CVE/Advisory database schema *)
  type advisory = {
    id: string;
    package: string;
    versions_affected: string list;
    severity: severity;
    description: string;
    cwe: string list;
    references: string list;
    fixed_in: string option;
  }
  
  (* Update strategies *)
  let update_strategies = [
    "Daily automated updates";
    "On-demand before analysis";
    "Cached with TTL";
    "Offline snapshots for air-gapped";
  ]
end

(* ========================================================================== *)
(* Remediation Suggestions                                                    *)
(* ========================================================================== *)

module Remediation = struct
  let suggest_fix = function
    | KnownVulnerability vuln ->
        Printf.sprintf "Update %s to version %s or later to fix %s"
          vuln.package
          (Option.value vuln.fixed_version ~default:"latest")
          (Option.value vuln.cve_id ~default:"vulnerability")
    
    | Typosquatting (typo, legitimate) ->
        Printf.sprintf "Replace '%s' with '%s' - possible typosquatting attack"
          typo legitimate
    
    | Unpinned pkg ->
        Printf.sprintf "Pin %s to exact version: %s = \"x.y.z\""
          pkg pkg
    
    | Outdated (pkg, latest) ->
        Printf.sprintf "Update %s to latest version %s"
          pkg latest
    
    | SuspiciousSource source ->
        Printf.sprintf "Verify package source: %s. Use official opam repository when possible"
          source
end

(* Rule registration *)
let rules = [
  known_vulnerability_rule;
  typosquatting_detection_rule;
  unpinned_dependencies_rule;
  outdated_dependencies_rule;
  suspicious_sources_rule;
]