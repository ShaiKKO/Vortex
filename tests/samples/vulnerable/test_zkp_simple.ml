(* Simple ZKP vulnerability test cases *)

(* ZKP library simulation *)
module Field = struct
  type t = int
  let var () = 0
  let constant x = x
end

module ConstraintSystem = struct
  type t = unit
  let create () = ()
  let assert_r1cs _ _ _ = ()
  let assert_equal _ _ = ()
end

(* Test case 1: Under-constrained circuit *)
let vulnerable_circuit_missing_constraints cs =
  let witness = Field.var () in
  let public_output = Field.var () in
  (* BUG: No constraint between witness and output *)
  public_output

(* Test case 2: Weak Fiat-Shamir *)
let weak_fiat_shamir commitment =
  (* BUG: Missing public inputs in hash *)
  let challenge = Digest.string commitment in
  challenge

(* Test case 3: Timing side-channel *)
let timing_leak_witness private_input =
  let witness = Field.var () in
  (* BUG: Conditional on witness value *)
  if witness > 100 then
    print_endline "Large witness"
  else
    print_endline "Small witness"

(* Test case 4: Weak randomness *)
let weak_randomness () =
  (* BUG: Using Random module for crypto *)
  let r = Random.int 1000 in
  r

(* Test case 5: Array access without bounds *)
let unconstrained_array_access arr index =
  (* BUG: No bounds check on index *)
  Array.get arr index

(* Test case 6: Hardcoded setup *)
let hardcoded_setup () =
  (* BUG: Looks like hardcoded parameter *)
  let param = "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed" in
  param

(* Good examples *)
let secure_circuit cs =
  let witness = Field.var () in
  let expected = Field.constant 42 in
  (* GOOD: Proper constraint *)
  ConstraintSystem.assert_equal witness expected;
  witness

let secure_randomness () =
  (* GOOD: Would use Mirage_crypto_rng *)
  42  (* Placeholder *)