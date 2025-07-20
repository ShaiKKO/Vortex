(* Zero-Knowledge Proof Vulnerability Rules Design
   Focus: SNARK circuit constraints, proof verification, trusted setup
   Reference: 96% of SNARK bugs from under-constrained circuits (2024)
   Additional: MTZK 2025 findings on witness timing leaks, soundness bugs *)

open Types
open Rule_engine

(* ZKP threat model based on 2024-2025 research *)
module ZKP_Threats = struct
  type zkp_system = 
    | Groth16
    | PLONK
    | Bulletproofs
    | STARKs
    | Marlin
    | Sonic
    | Circom      (* Added based on MTZK 2025 *)
    | SnarkJS     (* Common with Circom *)
    | Custom of string
    
  type circuit_element =
    | PublicInput of string
    | PrivateWitness of string
    | Constraint of string
    | Gate of string
    | Wire of string
    | Signal of string  (* Circom signals *)
    
  type zkp_vulnerability =
    | UnderConstrained of string list (* 96% of circuit bugs - Critical *)
    | SoundnessBug of string (* Malformed Fiat-Shamir - High *)
    | WitnessTimingLeak of string (* MTZK 2025 - Medium *)
    | WitnessPowerLeak (* Power analysis during generation *)
    | WeakFiatShamir (* bad challenge generation *)
    | TrustedSetupLeak (* toxic waste exposure *)
    | NonceReuse (* randomness reuse *)
    | MalleableProof (* proof can be modified *)
    | CircuitSoundness (* allows false proofs *)
end

(* Common ZKP libraries in OCaml ecosystem *)
module ZKP_Libraries = struct
  (* Bellman-ocaml: Groth16 implementation *)
  let bellman_patterns = [
    "Bellman";
    "Groth16";
    "ConstraintSystem";
    "LinearCombination";
  ]
  
  (* Snarky: Higher-level ZKP DSL *)
  let snarky_patterns = [
    "Snarky";
    "Snark";
    "Field";
    "Boolean";
    "assert_equal";
    "assert_r1cs";
  ]
  
  (* Circom/SnarkJS bindings (if any) *)
  let circom_patterns = [
    "circom";
    "snarkjs";
    "witness";
    "signal";
    "component";
    "template";
    "<==";  (* Circom constraint operator *)
    "==>";  (* Circom assignment *)
  ]
  
  (* Bulletproofs implementations *)
  let bulletproofs_patterns = [
    "Bulletproof";
    "RangeProof";
    "InnerProduct";
    "Pedersen";
  ]
  
  (* PLONK implementations *)
  let plonk_patterns = [
    "PLONK";
    "PlonkCircuit";
    "PlonkProof";
    "PlonkVerifier";
    "custom_gates";
    "lookup_tables";
  ]
end

(* ========================================================================== *)
(* ZKP001: Under-Constrained Circuits (96% of bugs)                           *)
(* ========================================================================== *)

(* Design: Detect missing constraints in ZKP circuits
   - Check for private witnesses without constraints
   - Detect public inputs not properly constrained
   - Flag circuits with insufficient R1CS constraints
   - Identify missing range proofs
   - Special attention to Circom <== vs === operators *)

let under_constrained_circuit_rule = {
  id = "ZKP001";
  name = "Under-Constrained ZKP Circuit";
  description = "Detects circuits with missing constraints (96% of SNARK bugs per 2024 SoK)";
  severity = Critical;
  tags = ["zkp"; "circuit"; "constraint"; "security"; "soundness"];
  
  patterns_to_detect = [
    (* Private witness without constraint *)
    "let witness = Field.var () in ... (* no constraint on witness *)";
    
    (* Public input not verified *)
    "let public_input = ... in (* used but not constrained *)";
    
    (* Missing range constraints *)
    "assert (x > 0) (* but no circuit constraint enforcing this *)";
    
    (* Unconstrained intermediate values *)
    "let intermediate = witness1 * witness2 (* result not constrained *)";
    
    (* Circom-specific: using === instead of <== *)
    "signal output result;\nresult === computed; (* not a constraint! *)";
    
    (* Missing nullifier constraints *)
    "nullifier = hash(secret) (* but nullifier uniqueness not enforced *)";
    
    (* Unconstrained array access *)
    "arr[index] (* index bounds not checked in circuit *)";
  ];
  
  detection_logic = "
    1. Track all witness/private variable declarations
    2. Check each witness has at least one constraint
    3. Verify public inputs are properly constrained
    4. Ensure intermediate calculations are constrained
    5. Check for range proofs where needed
    6. For Circom: ensure <== used for constraints, not ===
    7. Verify array indices are constrained
    8. Check nullifiers have uniqueness constraints
  ";
  
  fix_suggestions = [
    "Add explicit constraints for all witnesses";
    "Use assert_r1cs or assert_equal for constraints";
    "In Circom: use <== for constraints, not ===";
    "Implement range proofs for bounded values";
    "Add array bounds checking in circuit";
    "Review circuit completeness with formal verification";
  ];
  
  references = [
    "https://en.wikipedia.org/wiki/Zero-knowledge_proof";
    "2024 SoK: 96% of circuit vulnerabilities";
  ];
}

(* ========================================================================== *)
(* ZKP002: Verifier Soundness Bugs                                            *)
(* ========================================================================== *)

(* Design: Detect soundness issues in proof verification
   - Malformed Fiat-Shamir challenges
   - Missing verification steps
   - Incorrect challenge space
   - Weak verifier implementations *)

let verifier_soundness_rule = {
  id = "ZKP002";
  name = "Proof Verifier Soundness Bug";
  description = "Detects vulnerabilities that allow false proof acceptance";
  severity = High;
  tags = ["zkp"; "verifier"; "soundness"; "fiat-shamir"];
  
  vulnerable_patterns = [
    (* Malformed Fiat-Shamir challenge *)
    "let challenge = hash(commitment) mod small_prime (* challenge space too small *)";
    
    (* Missing verification steps *)
    "verify_proof proof (* but skips pairing check *)";
    
    (* Incorrect challenge computation *)
    "let c = H(g^r) (* missing public statement in hash *)";
    
    (* Accepting malformed proofs *)
    "try verify proof with _ -> true (* accepts invalid proofs! *)";
    
    (* Wrong curve operations *)
    "pairing(a, b) = pairing(c, d) (* but doesn't check point validity *)";
    
    (* Missing proof element validation *)
    "let (a, b, c) = proof in (* no validation of group elements *)";
  ];
  
  secure_verification = "
    let verify_proof_soundly proof public_inputs =
      (* 1. Validate all proof elements are in correct groups *)
      let (pi_a, pi_b, pi_c) = proof in
      assert (is_in_g1 pi_a && is_in_g2 pi_b && is_in_g1 pi_c);
      
      (* 2. Compute challenge with full transcript *)
      let challenge = hash_transcript(
        protocol_id ^ serialize(public_inputs) ^ 
        serialize(pi_a) ^ serialize(pi_b) ^ serialize(pi_c)
      ) in
      
      (* 3. Verify pairing equation *)
      let vk_x = compute_vk_x public_inputs verification_key in
      pairing(pi_a, pi_b) = 
        pairing(alpha, beta) * 
        pairing(vk_x, gamma) * 
        pairing(pi_c, delta)
  ";
  
  references = [
    "https://arxiv.org/html/2402.15293v3";
    "Study on malformed Fiat-Shamir challenges";
  ];
}

(* ========================================================================== *)
(* ZKP003: Witness Generation Side-Channels (MTZK 2025)                       *)
(* ========================================================================== *)

(* Design: Detect timing and power leaks during witness generation
   - Variable-time operations on witnesses
   - Branch conditions dependent on witness
   - Non-constant memory access patterns
   - Cache timing vulnerabilities *)

let witness_sidechannel_rule = {
  id = "ZKP003";
  name = "Witness Generation Side-Channel Leak";
  description = "Detects timing/power leakage during witness computation (MTZK 2025)";
  severity = Medium;
  tags = ["zkp"; "witness"; "timing"; "side-channel"; "circom"];
  
  timing_leak_patterns = [
    (* Variable-time operations *)
    "if witness > 0 then expensive_op() else cheap_op()";
    
    (* Early returns based on witness *)
    "if private_input = target then return proof (* timing leak *)";
    
    (* Non-constant array access *)
    "memory[witness_value] (* cache timing attack *)";
    
    (* Variable loop bounds *)
    "for i = 0 to witness_bits do (* iteration count leaks witness *)";
    
    (* Circom-specific timing leaks *)
    "component selector = Multiplexer(n);\nselector.index <== secret_index; (* timing varies *)";
    
    (* BigInt operations with variable time *)
    "witness_bigint.mod(prime) (* time depends on value *)";
    
    (* Conditional assertions *)
    "if (check_enabled) { assert(witness_valid); } (* leaks check_enabled *)";
  ];
  
  constant_time_practices = [
    "Use constant-time comparisons (Eqaf module)";
    "Avoid branching on secret values";
    "Use masking for array accesses";
    "Implement dummy operations for balance";
    "Use constant-time modular arithmetic";
    "Pre-compute all possible paths";
  ];
  
  circom_specific = "
    (* For Circom circuits *)
    - Avoid Multiplexer components with secret indices
    - Use QuinSelector for constant-time selection
    - Implement IsZero carefully to avoid leaks
    - Balance constraint counts across branches
    - Use deterministic witness generation order
  ";
  
  references = [
    "https://www.ndss-symposium.org/wp-content/uploads/2025-530-paper.pdf";
    "MTZK: Testing ZK Compiler Bugs (NDSS 2025)";
  ];
}

(* ========================================================================== *)
(* ZKP004: Trusted Setup Vulnerabilities                                      *)
(* ========================================================================== *)

(* Design: Detect issues with trusted setup ceremonies
   - Check for hardcoded toxic waste
   - Verify setup parameters are properly loaded
   - Detect reuse of setup across incompatible circuits
   - Identify missing setup verification *)

let trusted_setup_rule = {
  id = "ZKP004";
  name = "Trusted Setup Security Issues";
  description = "Detects vulnerabilities in trusted setup handling";
  severity = Critical;
  tags = ["zkp"; "trusted-setup"; "toxic-waste"; "parameters"];
  
  vulnerable_patterns = [
    (* Hardcoded setup parameters *)
    "let tau = \"0x1234...\" (* hardcoded toxic waste! *)";
    
    (* No verification of setup *)
    "let params = load_params file (* no integrity check *)";
    
    (* Reusing setup incorrectly *)
    "let proof = prove circuit witness universal_setup (* wrong ceremony *)";
    
    (* Exposed toxic waste *)
    "let generate_setup () = let tau = random () in (params(tau), tau) (* returns tau! *)";
    
    (* Deterministic setup *)
    "Random.init 42; let tau = Random.bits() (* predictable! *)";
    
    (* Setup without contribution verification *)
    "let final_params = contribute(params, entropy) (* no proof of contribution *)";
  ];
  
  secure_handling = [
    "Use MPC ceremonies for setup generation";
    "Verify setup parameters with checksums";
    "Never expose toxic waste values";
    "Use circuit-specific ceremonies";
    "Implement setup attestation";
    "Verify all contributions in ceremony";
    "Use perpetual powers of tau when applicable";
  ];
}

(* ========================================================================== *)
(* ZKP005: Commitment and Randomness Issues                                   *)
(* ========================================================================== *)

(* Design: Detect weak commitments and randomness reuse
   - Insufficient commitment randomness
   - Deterministic proof generation
   - Weak random sources
   - Commitment malleability *)

let commitment_randomness_rule = {
  id = "ZKP005";
  name = "Weak ZKP Commitments and Randomness";
  description = "Detects insufficient entropy in commitments and proof randomization";
  severity = High;
  tags = ["zkp"; "randomness"; "commitment"; "entropy"];
  
  weak_patterns = [
    (* Insufficient randomness *)
    "let r = Random.int 1000 (* only 10 bits of entropy! *)";
    
    (* Reused randomness *)
    "let r = derive_from_seed seed (* same r for multiple proofs *)";
    
    (* No blinding in commitments *)
    "let commitment = g^witness (* should be g^witness * h^r *)";
    
    (* Weak PRNG for crypto *)
    "Random.self_init() (* not cryptographically secure *)";
    
    (* Deterministic \"randomness\" *)
    "let r = hash(witness) (* randomness depends on witness! *)";
    
    (* Small randomness space *)
    "let blinding = random_byte() (* only 256 possibilities *)";
  ];
  
  secure_randomness = "
    (* Use cryptographically secure randomness *)
    let generate_blinding_factor () =
      Mirage_crypto_rng.generate 32  (* 256 bits *)
    
    (* Pedersen commitment with proper blinding *)  
    let commit witness =
      let r = Mirage_crypto_rng.generate 32 in
      let commitment = G.add
        (G.mul g witness)
        (G.mul h r) in
      (commitment, r)  (* save r for opening *)
    
    (* Fresh randomness for each proof *)
    let prove_with_randomization circuit witness =
      let r = Mirage_crypto_rng.generate 32 in
      create_proof circuit witness r
  ";
}

(* ========================================================================== *)
(* Integration Patterns and Library-Specific Checks                           *)
(* ========================================================================== *)

module Library_Integration = struct
  (* Bellman-ocaml specific *)
  let bellman_checks = {
    constraint_completeness = [
      "Verify all LinearCombination results are constrained";
      "Check ConstraintSystem has expected number of constraints";
      "Validate witness assignment matches circuit structure";
      "Ensure no unallocated variables";
    ];
    
    code_pattern = "
      (* Proper constraint in Bellman *)
      let proper_constraint cs witness =
        let lc = LinearCombination.zero() in
        let lc = LinearCombination.add_term lc witness Scalar.one in
        ConstraintSystem.enforce cs lc lc output_lc
        (* NOT just: let _ = witness * witness *)
    ";
  }
  
  (* Snarky specific *)
  let snarky_checks = {
    witness_handling = [
      "Check Field.t values used in constraints";
      "Verify Boolean.Assert actually constrains";
      "Audit as_prover blocks for leaks";
      "Validate run_checked completeness";
    ];
    
    leak_prevention = "
      (* Avoid witness leaks in Snarky *)
      let no_leak_example () =
        let%bind witness = exists Field.typ ~compute:(fun () ->
          Field.Constant.of_int 42
        ) in
        (* DON'T: printf !\"%{sexp: Field.t}\" witness *)
        (* DO: generic error handling *)
        let%bind () = Field.Assert.equal witness expected in
        ...
    ";
  }
  
  (* Circom/SnarkJS patterns *)
  let circom_checks = {
    constraint_operators = [
      "Use <== for constraints, not ===";
      "Avoid <-- without subsequent constraints";
      "Check all signals have constraints";
      "Verify component inputs/outputs constrained";
    ];
    
    timing_safety = [
      "Avoid variable-index array access";
      "Use QuinSelector over Multiplexer for secrets";
      "Balance constraints across conditions";
      "Careful with IsZero on secrets";
    ];
  }
end

(* ========================================================================== *)
(* Severity Classification and Remediation                                    *)
(* ========================================================================== *)

module Severity_Guide = struct
  let classify = function
    | UnderConstrained _ -> Critical  (* Can prove false statements *)
    | SoundnessBug _ -> Critical      (* Breaks security *)
    | TrustedSetupLeak -> Critical    (* Breaks all proofs *)
    | CircuitSoundness -> Critical    (* Allows forgery *)
    | WeakFiatShamir -> High         (* May allow forgery *)
    | NonceReuse -> High             (* Breaks uniqueness *)
    | MalleableProof -> High         (* Allows modifications *)
    | WitnessTimingLeak _ -> Medium  (* Requires local access *)
    | WitnessPowerLeak -> Medium     (* Requires physical access *)
    
  let remediation_priority = [
    "1. Fix all under-constrained circuits first";
    "2. Address soundness bugs in verifiers";
    "3. Secure trusted setup handling";
    "4. Implement constant-time witness generation";
    "5. Add proper randomness and commitments";
  ]
end

(* Rule registration *)
let rules = [
  under_constrained_circuit_rule;
  verifier_soundness_rule;
  witness_sidechannel_rule;
  trusted_setup_rule;
  commitment_randomness_rule;
]