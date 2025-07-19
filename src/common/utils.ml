(* Common utility functions *)

(* String utilities *)
let contains_substring s sub =
  let len_s = String.length s in
  let len_sub = String.length sub in
  let rec check i =
    if i + len_sub > len_s then false
    else if String.sub s i len_sub = sub then true
    else check (i + 1)
  in
  check 0

(* Longident utilities *)
let rec flatten_longident = function
  | Longident.Lident s -> [s]
  | Ldot (lid, s) -> flatten_longident lid @ [s]
  | Lapply (lid1, lid2) -> flatten_longident lid1 @ flatten_longident lid2

(* String check utilities *)
let string_ends_with ~suffix s =
  let len_s = String.length s in
  let len_suffix = String.length suffix in
  len_s >= len_suffix &&
  String.sub s (len_s - len_suffix) len_suffix = suffix

let string_starts_with ~prefix s =
  let len_s = String.length s in
  let len_prefix = String.length prefix in
  len_s >= len_prefix &&
  String.sub s 0 len_prefix = prefix

let string_contains s sub =
  contains_substring s sub