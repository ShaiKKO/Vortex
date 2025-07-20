(* Test existing crypto rules *)
open Cryptokit

(* Should trigger weak cipher rule *)
let encrypt_des key data =
  let cipher = Cipher.des key Cipher.Encrypt in
  transform_string cipher data

(* Should trigger weak hash rule *)  
let hash_md5 data =
  let hash = Hash.md5 () in
  hash_string hash data