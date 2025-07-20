(* Advanced Side-Channel Rules Design
   Focus: Speculative execution, cache attacks, and constant-time verification
   Reference: AMD TSA vulnerabilities (CVE-2025-36350, CVE-2025-36357) *)

open Types
open Rule_engine

(* Abstract interpretation context for tracking secret data flow *)
module Abstract_Domain = struct
  type secret_level = 
    | Public
    | Secret
    | Tainted of string (* Tainted with specific secret source *)
  
  type memory_access_pattern =
    | Sequential
    | DataDependent of string (* Variable that controls access *)
    | Random
  
  type execution_context = {
    secret_vars: (string * secret_level) list;
    memory_accesses: (location * memory_access_pattern) list;
    branch_conditions: (expression * secret_level) list;
    speculative_depth: int;
  }
end

(* ========================================================================== *)
(* SIDEA001: Speculative Execution Pattern Detection                          *)
(* ========================================================================== *)

(* Design: Detect code patterns vulnerable to speculative execution attacks
   - Bounds checks followed by memory access
   - Indirect branches with attacker-controlled targets
   - Conditional branches that guard sensitive operations *)

let speculative_execution_rule = {
  id = "SIDEA001";
  name = "Speculative Execution Vulnerability Pattern";
  description = "Detects code patterns vulnerable to Spectre-style attacks";
  severity = Critical;
  tags = ["side-channel"; "speculative-execution"; "spectre"; "cpu"];
  
  (* Pattern examples to detect:
     1. if (x < array_size) then array.(x) else ... 
        -> Speculative OOB read
     2. if (untrusted_idx < limit) then 
          secret_array.(untrusted_idx)
        -> Spectre v1 pattern
     3. let f = function_table.(user_input) in f ()
        -> Spectre v2 (indirect branch) *)
  
  detection_patterns = [
    "Bounds check bypass (Spectre v1)";
    "Indirect branch poisoning (Spectre v2)";
    "Return stack buffer pollution";
    "Store-to-load forwarding gadgets";
  ];
  
  mitigations = [
    "Insert speculation barriers (lfence/csdb)";
    "Use array_index_mask_nospec for bounds checks";
    "Implement retpoline for indirect calls";
    "Apply SLH (Speculative Load Hardening)";
  ];
}

(* ========================================================================== *)
(* SIDEA002: Transient Scheduler Attack Patterns (AMD TSA)                    *)
(* ========================================================================== *)

(* Design: Detect patterns vulnerable to AMD Transient Scheduler Attacks
   - Focus on single-threaded contention scenarios
   - Port contention timing channels
   - Store queue timing dependencies *)

let transient_scheduler_rule = {
  id = "SIDEA002";
  name = "AMD Transient Scheduler Attack Pattern";
  description = "Detects patterns vulnerable to AMD TSA (CVE-2025-36350)";
  severity = High;
  tags = ["side-channel"; "amd-tsa"; "scheduler"; "timing"];
  
  (* Vulnerable patterns:
     1. Tight loops with memory operations that could cause port contention
     2. Interleaved loads/stores that create timing dependencies
     3. Code that relies on CPU scheduling for security boundaries *)
  
  vulnerable_patterns = [
    "Memory operations in tight loops";
    "Alternating load/store sequences";
    "Port-heavy cryptographic operations";
    "Timing-sensitive security checks";
  ];
  
  amd_specific_checks = [
    "Detect EPYC/Ryzen specific instructions";
    "Flag single-threaded performance critical sections";
    "Identify store queue pressure points";
  ];
}

(* ========================================================================== *)
(* SIDEA003: Store Queue Leakage Detection                                    *)
(* ========================================================================== *)

(* Design: Detect store-to-load forwarding vulnerabilities
   - Store queue timing attacks
   - Memory disambiguation failures
   - L1D timing side channels *)

let store_queue_leakage_rule = {
  id = "SIDEA003";
  name = "Store Queue Side-Channel Leakage";
  description = "Detects store queue timing vulnerabilities";
  severity = High;
  tags = ["side-channel"; "store-queue"; "memory"; "timing"];
  
  (* Patterns to detect:
     1. Stores of secret data followed by predictable loads
     2. Aliasing between secret and public memory locations
     3. Store-load pairs that could leak via timing *)
  
  detection_logic = "
    - Track stores of secret data
    - Identify subsequent loads that may alias
    - Flag timing-observable dependencies
    - Detect 4K aliasing vulnerabilities
  ";
  
  mitigations = [
    "Avoid aliasing between secret and public data";
    "Insert memory barriers between sensitive operations";
    "Use separate memory regions for secrets";
    "Apply store queue flushing";
  ];
}

(* ========================================================================== *)
(* SIDEA004: Port Contention Side-Channel Detection                           *)
(* ========================================================================== *)

(* Design: Detect operations that leak via execution port contention
   - Identify port-heavy operations on secret data
   - Flag timing-observable resource conflicts *)

let port_contention_rule = {
  id = "SIDEA004";
  name = "Execution Port Contention Side-Channel";
  description = "Detects port contention timing leaks (Spectre-STC)";
  severity = Medium;
  tags = ["side-channel"; "port-contention"; "timing"; "cpu"];
  
  (* Vulnerable operations:
     1. Integer multiplication/division on secrets
     2. SIMD operations with secret-dependent patterns
     3. Branch-heavy code with secret conditions *)
  
  port_pressure_operations = [
    "Integer multiplication chains";
    "Division operations";
    "SIMD shuffle with secret masks";
    "Cryptographic permutations";
  ];
  
  detection_approach = "
    Abstract interpretation to track:
    - Operations that map to specific execution ports
    - Secret data flow into port-heavy operations
    - Timing-observable operation sequences
  ";
}

(* ========================================================================== *)
(* SIDEA005: Abstract Interpretation for Constant-Time Verification           *)
(* ========================================================================== *)

(* Design: Use abstract interpretation to verify constant-time properties
   - Track secret data propagation through the program
   - Identify all non-constant-time operations on secrets
   - Provide correctness proofs where possible *)

let constant_time_verification_rule = {
  id = "SIDEA005";
  name = "Non-Constant-Time Operation Detection";
  description = "Comprehensive constant-time verification using abstract interpretation";
  severity = Error;
  tags = ["side-channel"; "constant-time"; "verification"; "abstract-interpretation"];
  
  abstract_domains = [
    "Secret-level tracking (public/secret/tainted)";
    "Timing-observable operations";
    "Memory access patterns";
    "Control flow dependencies";
  ];
  
  non_constant_operations = [
    "Variable-time comparisons";
    "Secret-dependent branches";
    "Secret-dependent memory access";
    "Non-constant-time arithmetic (div/mod)";
    "Early termination on secret data";
  ];
  
  verification_approach = "
    1. Initialize abstract state with marked secrets
    2. Propagate secret tainting through operations
    3. Flag any timing-observable operation on secrets
    4. Track implicit flows through control dependencies
    5. Generate proof obligations for constant-time claims
  ";
  
  suggested_fixes = [
    "Replace with constant-time primitives";
    "Use branchless algorithms";
    "Apply constant-time selection";
    "Implement masking countermeasures";
  ];
}

(* ========================================================================== *)
(* Integration with existing framework                                        *)
(* ========================================================================== *)

module Advanced_Side_Channel_Rules = struct
  (* Abstract interpretation engine *)
  module Abstract_Interpreter = struct
    open Abstract_Domain
    
    (* Initialize analysis context *)
    let create_context () = {
      secret_vars = [];
      memory_accesses = [];
      branch_conditions = [];
      speculative_depth = 0;
    }
    
    (* Track secret data flow *)
    let propagate_secret ctx expr =
      (* Implementation will track how secrets flow through:
         - Assignments
         - Function calls
         - Binary operations
         - Memory operations *)
      ctx
    
    (* Detect timing-observable operations *)
    let is_timing_observable = function
      | Comparison (secret, _)
      | Branch_on secret
      | Array_access (_, secret_index)
      | Division (secret, _)
      | Modulo (secret, _) -> true
      | _ -> false
  end
  
  (* Pattern matching for specific vulnerabilities *)
  module Pattern_Detector = struct
    (* Spectre v1 pattern: if (x < len) then arr[x] *)
    let is_spectre_v1_pattern = function
      | If_then_else (
          Comparison (idx, bound),
          Array_access (arr, idx'),
          _
        ) when idx = idx' -> true
      | _ -> false
    
    (* AMD TSA pattern: tight loop with memory ops *)
    let is_tsa_vulnerable_loop = function
      | For_loop (_, _, body) ->
          has_memory_operations body && 
          loop_iteration_count_is_secret body
      | _ -> false
  end
  
  (* Suggested mitigations *)
  module Mitigations = struct
    let speculative_barrier = "
      (* Insert speculation barrier *)
      let barrier () = 
        (* Architecture-specific barrier *)
        match Sys.backend_type with
        | Native -> Ocaml_speculative_barrier.fence ()
        | Bytecode -> ()
    "
    
    let constant_time_select = "
      (* Constant-time selection *)
      let ct_select cond a b =
        let mask = -cond in (* 0 or -1 *)
        (a land mask) lor (b land (lnot mask))
    "
    
    let masked_table_lookup = "
      (* Masked table lookup to prevent cache attacks *)
      let masked_lookup table idx =
        Array.fold_left2 (fun acc i v ->
          let mask = ct_equal i idx in
          acc lor (v land mask)
        ) 0 (Array.init (Array.length table) (fun i -> i)) table
    "
  end
end

(* Rule registration *)
let rules = [
  speculative_execution_rule;
  transient_scheduler_rule;
  store_queue_leakage_rule;
  port_contention_rule;
  constant_time_verification_rule;
]