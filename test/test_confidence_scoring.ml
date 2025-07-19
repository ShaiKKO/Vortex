(* Unit tests for confidence scoring *)
open Ocaml_crypto_linter
open Types
open Confidence_scoring

let test_context_detection () =
  Printf.printf "Testing context detection...\n";
  
  let test_files = [
    ("src/crypto.ml", false, true);
    ("test/test_crypto.ml", true, false);
    ("examples/demo.ml", true, false);
    ("src/auth/cipher.ml", false, true);
    ("tests/integration/test_api.ml", true, false);
  ] in
  
  List.iter (fun (filename, expected_test, expected_crypto) ->
    let ctx = Context_analyzer.analyze_file_context filename in
    assert (ctx.is_test_file = expected_test);
    assert (ctx.is_crypto_module = expected_crypto);
    Printf.printf "  ✓ %s: test=%b crypto=%b\n" 
      filename ctx.is_test_file ctx.is_crypto_module
  ) test_files

let test_confidence_calculation () =
  Printf.printf "\nTesting confidence calculation...\n";
  
  (* Create test findings *)
  let make_finding rule_id severity message vulnerability file =
    {
      rule_id;
      severity;
      message;
      vulnerability;
      location = {
        file;
        line = 10;
        column = 5;
        end_line = Some 10;
        end_column = Some 20;
      };
      suggestion = None;
      references = [];
    }
  in
  
  let test_cases = [
    (* Rule, Severity, Vulnerability, File, Expected range *)
    ("ALGO001", Error, WeakCipher "DES", "src/crypto.ml", (0.9, 1.0));
    ("ALGO001", Error, WeakCipher "DES", "test/test.ml", (0.2, 0.4));
    ("ALGO002", Error, WeakHash "SHA1", "src/auth.ml", (0.8, 0.95));
    ("ALGO002", Error, WeakHash "SHA1", "examples/git.ml", (0.3, 0.5));
    ("KEY001", Critical, HardcodedKey, "src/main.ml", (0.95, 1.0));
    ("SIDE003", Warning, SideChannel, "src/cipher.ml", (0.5, 0.7));
  ] in
  
  List.iter (fun (rule_id, sev, vuln, file, (min_conf, max_conf)) ->
    let finding = make_finding rule_id sev "Test" vuln file in
    let score = Bayesian_scorer.calculate_confidence finding file in
    
    Printf.printf "  %s in %s: %.2f%% (expected %.0f%%-%.0f%%)\n"
      rule_id file (score *. 100.) (min_conf *. 100.) (max_conf *. 100.);
    
    assert (score >= min_conf && score <= max_conf)
  ) test_cases

let test_priority_ranking () =
  Printf.printf "\nTesting priority ranking...\n";
  
  let findings = [
    {
      rule_id = "KEY001";
      severity = Critical;
      message = "Hardcoded key";
      vulnerability = HardcodedKey;
      location = {file = "src/main.ml"; line = 1; column = 1; 
                  end_line = None; end_column = None};
      suggestion = None;
      references = [];
    };
    {
      rule_id = "ALGO002";
      severity = Warning;
      message = "SHA1 hash";
      vulnerability = WeakHash "SHA1";
      location = {file = "test/test.ml"; line = 1; column = 1; 
                  end_line = None; end_column = None};
      suggestion = None;
      references = [];
    };
  ] in
  
  let enhanced = enhance_findings findings in
  let sorted = List.sort Enhanced_finding.compare enhanced in
  
  (* First should be hardcoded key (higher priority) *)
  match sorted with
  | first :: second :: _ ->
      assert (first.Enhanced_finding.finding.rule_id = "KEY001");
      assert (second.Enhanced_finding.finding.rule_id = "ALGO002");
      Printf.printf "  ✓ Priority ordering correct\n";
      Printf.printf "    P%d: %s\n" 
        first.Enhanced_finding.priority 
        first.Enhanced_finding.finding.message;
      Printf.printf "    P%d: %s\n" 
        second.Enhanced_finding.priority 
        second.Enhanced_finding.finding.message
  | _ -> assert false

let test_risk_scoring () =
  Printf.printf "\nTesting risk scoring...\n";
  
  let critical_high_conf = {
    rule_id = "KEY001";
    severity = Critical;
    message = "Critical issue";
    vulnerability = HardcodedKey;
    location = {file = "src/crypto.ml"; line = 1; column = 1; 
                end_line = None; end_column = None};
    suggestion = None;
    references = [];
  } in
  
  let info_low_conf = {
    rule_id = "SIDE004";
    severity = Info;
    message = "Info issue";
    vulnerability = SideChannel;
    location = {file = "test/test.ml"; line = 1; column = 1; 
                end_line = None; end_column = None};
    suggestion = None;
    references = [];
  } in
  
  let e1 = Enhanced_finding.enhance critical_high_conf in
  let e2 = Enhanced_finding.enhance info_low_conf in
  
  assert (e1.Enhanced_finding.risk_score > e2.Enhanced_finding.risk_score);
  Printf.printf "  ✓ Risk scores: Critical=%.1f > Info=%.1f\n"
    e1.Enhanced_finding.risk_score
    e2.Enhanced_finding.risk_score

let () =
  Printf.printf "Running confidence scoring tests...\n\n";
  test_context_detection ();
  test_confidence_calculation ();
  test_priority_ranking ();
  test_risk_scoring ();
  Printf.printf "\nAll tests passed! ✨\n"