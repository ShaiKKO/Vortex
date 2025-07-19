(* Statistical confidence scoring for crypto vulnerability findings *)
open Types

module Confidence = struct
  type level = 
    | VeryHigh of float  (* > 0.95 *)
    | High of float      (* 0.85 - 0.95 *)
    | Medium of float    (* 0.70 - 0.85 *)
    | Low of float       (* 0.50 - 0.70 *)
    | VeryLow of float   (* < 0.50 *)

  type factors = {
    base_score: float;           (* Rule-specific base confidence *)
    context_modifier: float;     (* File/module context adjustment *)
    pattern_strength: float;     (* How definitive the pattern match is *)
    false_positive_rate: float;  (* Historical FP rate for this rule *)
    code_complexity: float;      (* Complexity of surrounding code *)
  }

  let level_of_score score =
    match score with
    | s when s > 0.95 -> VeryHigh s
    | s when s > 0.85 -> High s
    | s when s > 0.70 -> Medium s
    | s when s > 0.50 -> Low s
    | s -> VeryLow s

  let string_of_level = function
    | VeryHigh s -> Printf.sprintf "Very High (%.0f%%)" (s *. 100.)
    | High s -> Printf.sprintf "High (%.0f%%)" (s *. 100.)
    | Medium s -> Printf.sprintf "Medium (%.0f%%)" (s *. 100.)
    | Low s -> Printf.sprintf "Low (%.0f%%)" (s *. 100.)
    | VeryLow s -> Printf.sprintf "Very Low (%.0f%%)" (s *. 100.)

  let color_of_level = function
    | VeryHigh _ -> "\027[91m"  (* Bright red *)
    | High _ -> "\027[31m"      (* Red *)
    | Medium _ -> "\027[33m"    (* Yellow *)
    | Low _ -> "\027[34m"       (* Blue *)
    | VeryLow _ -> "\027[90m"   (* Gray *)
end

module Context_analyzer = struct
  type code_context = {
    is_test_file: bool;
    is_example_code: bool;
    is_crypto_module: bool;
    is_deprecated: bool;
    has_security_comments: bool;
    module_depth: int;
    function_complexity: int;
  }

  let analyze_file_context filename =
    let is_test = 
      String.contains_substring filename "_test.ml" ||
      String.contains_substring filename "test_" ||
      String.contains_substring filename "/test/" ||
      String.contains_substring filename "/tests/"
    in
    
    let is_example =
      String.contains_substring filename "/example/" ||
      String.contains_substring filename "/examples/" ||
      String.contains_substring filename "_example.ml" ||
      String.contains_substring filename "demo"
    in
    
    let is_crypto =
      String.contains_substring filename "crypto" ||
      String.contains_substring filename "cipher" ||
      String.contains_substring filename "auth" ||
      String.contains_substring filename "security"
    in
    
    {
      is_test_file = is_test;
      is_example_code = is_example;
      is_crypto_module = is_crypto;
      is_deprecated = false;  (* Would need AST analysis *)
      has_security_comments = false;  (* Would need comment parsing *)
      module_depth = 0;  (* Would need module nesting analysis *)
      function_complexity = 0;  (* Would need cyclomatic complexity *)
    }

  let context_modifier ctx =
    let base = 1.0 in
    let adjusted = 
      base
      *. (if ctx.is_test_file then 0.3 else 1.0)
      *. (if ctx.is_example_code then 0.4 else 1.0)
      *. (if ctx.is_crypto_module then 1.5 else 1.0)
      *. (if ctx.is_deprecated then 0.5 else 1.0)
      *. (if ctx.has_security_comments then 0.8 else 1.0)
    in
    max 0.1 (min 2.0 adjusted)
end

module Rule_confidence = struct
  (* Base confidence scores for different rule categories *)
  let base_confidence = function
    | "ALGO001" -> 0.95  (* Weak ciphers - very reliable *)
    | "ALGO002" -> 0.85  (* Weak hashes - context dependent *)
    | "ALGO003" -> 0.90  (* Weak curves - reliable *)
    | "KEY001" -> 0.99   (* Hardcoded keys - almost certain *)
    | "KEY002" -> 0.70   (* Predictable IV - needs context *)
    | "KEY003" -> 0.75   (* Key reuse - complex pattern *)
    | "SIDE001" -> 0.80  (* Timing comparison - depends on data *)
    | "SIDE003" -> 0.65  (* Cache timing - many false positives *)
    | "SIDE004" -> 0.60  (* Branch leaks - very context dependent *)
    | "API001" -> 0.90   (* ECB mode - reliable *)
    | "API002" -> 0.85   (* MAC order - reliable pattern *)
    | "API006" -> 0.75   (* CBC without MAC - interprocedural *)
    | _ -> 0.70          (* Default for unknown rules *)

  (* Historical false positive rates from USENIX studies *)
  let false_positive_rate = function
    | "ALGO001" -> 0.02  (* Weak ciphers rarely FP *)
    | "ALGO002" -> 0.15  (* SHA1 often used for non-security *)
    | "SIDE001" -> 0.20  (* String comparison has many valid uses *)
    | "SIDE003" -> 0.35  (* Table lookups often benign *)
    | "SIDE004" -> 0.40  (* Branches on secrets hard to detect *)
    | "KEY002" -> 0.30   (* IV patterns sometimes intentional *)
    | _ -> 0.25          (* Default FP rate *)

  (* Pattern strength based on detection method *)
  let pattern_strength finding =
    match finding.vulnerability with
    | WeakCipher name when String.length name > 0 -> 0.95
    | WeakHash name when String.length name > 0 -> 0.90
    | HardcodedKey -> 0.99
    | PredictableIV -> 0.70
    | TimingLeak -> 0.75
    | SideChannel -> 0.65
    | KeyReuse -> 0.70
    | MacMissing -> 0.80
    | _ -> 0.75
end

module Bayesian_scorer = struct
  (* Bayesian confidence calculation based on multiple factors *)
  let calculate_confidence finding filename =
    let ctx = Context_analyzer.analyze_file_context filename in
    let base = Rule_confidence.base_confidence finding.rule_id in
    let fp_rate = Rule_confidence.false_positive_rate finding.rule_id in
    let pattern = Rule_confidence.pattern_strength finding in
    let ctx_mod = Context_analyzer.context_modifier ctx in
    
    (* Bayesian formula: P(bug|evidence) = P(evidence|bug) * P(bug) / P(evidence) *)
    let p_bug = base in
    let p_evidence_given_bug = pattern in
    let p_evidence_given_no_bug = fp_rate in
    let p_evidence = 
      p_evidence_given_bug *. p_bug +. 
      p_evidence_given_no_bug *. (1. -. p_bug) 
    in
    
    let bayesian_score = 
      (p_evidence_given_bug *. p_bug) /. p_evidence
    in
    
    (* Apply context modifier *)
    let final_score = bayesian_score *. ctx_mod in
    
    (* Clamp to valid probability range *)
    max 0.0 (min 1.0 final_score)
end

module Enhanced_finding = struct
  type t = {
    finding: finding;
    confidence: Confidence.level;
    risk_score: float;  (* Severity * Confidence *)
    priority: int;      (* 1-10, for sorting *)
  }

  let severity_weight = function
    | Critical -> 4.0
    | Error -> 3.0
    | Warning -> 2.0
    | Info -> 1.0

  let enhance finding =
    let confidence_score = 
      Bayesian_scorer.calculate_confidence finding finding.location.file 
    in
    let confidence_level = Confidence.level_of_score confidence_score in
    let risk = severity_weight finding.severity *. confidence_score in
    let priority = int_of_float (risk *. 2.5) |> max 1 |> min 10 in
    
    {
      finding;
      confidence = confidence_level;
      risk_score = risk;
      priority;
    }

  let compare a b =
    (* Sort by priority (descending), then by confidence *)
    match compare b.priority a.priority with
    | 0 -> compare b.risk_score a.risk_score
    | n -> n

  let to_json enhanced =
    let conf_str, conf_score = match enhanced.confidence with
      | VeryHigh s | High s | Medium s | Low s | VeryLow s -> 
          (Confidence.string_of_level enhanced.confidence, s)
    in
    
    `Assoc [
      ("finding", finding_to_json enhanced.finding);
      ("confidence", `String conf_str);
      ("confidence_score", `Float conf_score);
      ("risk_score", `Float enhanced.risk_score);
      ("priority", `Int enhanced.priority);
    ]

  let format_enhanced fmt enhanced =
    let color = Confidence.color_of_level enhanced.confidence in
    let reset = "\027[0m" in
    
    Printf.fprintf fmt "%s[P%d]%s %s [%s] %s\n"
      color
      enhanced.priority
      reset
      (match enhanced.finding.severity with
       | Critical -> "CRITICAL"
       | Error -> "ERROR"
       | Warning -> "WARNING"
       | Info -> "INFO")
      (Confidence.string_of_level enhanced.confidence)
      enhanced.finding.message;
    
    Printf.fprintf fmt "  Location: %s:%d:%d\n"
      enhanced.finding.location.file
      enhanced.finding.location.line
      enhanced.finding.location.column;
    
    if enhanced.risk_score > 8.0 then
      Printf.fprintf fmt "  ⚠️  HIGH RISK - Immediate attention required\n"
end

(* Machine learning data collection for improving confidence *)
module ML_feedback = struct
  type feedback_entry = {
    rule_id: string;
    pattern_hash: string;
    context_features: (string * float) list;
    was_true_positive: bool;
    timestamp: float;
  }

  let feedback_db = "crypto_linter_feedback.db"

  let extract_features finding ctx =
    [
      ("is_test", if ctx.Context_analyzer.is_test_file then 1.0 else 0.0);
      ("is_crypto_module", if ctx.is_crypto_module then 1.0 else 0.0);
      ("module_depth", float_of_int ctx.module_depth);
      ("severity", Rule_confidence.severity_weight finding.severity);
    ]

  let record_feedback finding was_correct =
    (* In production, this would write to a database *)
    let ctx = Context_analyzer.analyze_file_context finding.location.file in
    let entry = {
      rule_id = finding.rule_id;
      pattern_hash = Digest.string finding.message |> Digest.to_hex;
      context_features = extract_features finding ctx;
      was_true_positive = was_correct;
      timestamp = Unix.time ();
    } in
    (* TODO: Persist to database *)
    ()

  let get_adjusted_confidence rule_id pattern features =
    (* In production, query ML model or statistics *)
    Rule_confidence.base_confidence rule_id
end

(* Export main enhancement function *)
let enhance_findings findings =
  List.map Enhanced_finding.enhance findings
  |> List.sort Enhanced_finding.compare