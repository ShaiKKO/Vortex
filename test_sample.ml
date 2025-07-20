(* Test sample with various crypto vulnerabilities *)

(* Hardcoded key - should trigger KEY001 *)
let secret_key = "my_super_secret_key_12345"

(* Weak hash - should trigger ALGO002 *)
let hash_password pwd =
  Cryptokit.hash_string (Cryptokit.Hash.md5 ()) pwd

(* Weak cipher - should trigger ALGO001 *)
let encrypt_data data =
  let cipher = Cryptokit.Cipher.des ~mode:Cryptokit.Cipher.ECB in
  cipher#put_string data;
  cipher#finish

(* Static IV - should trigger KEY004 *)
let static_iv = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"

(* Timing vulnerable comparison - should trigger CVE_2016_2107 *)
let verify_signature sig1 sig2 =
  sig1 = sig2  (* Non-constant time comparison *)

(* Weak KDF - should trigger CVE_2013_1443 and KEY005 *)
let derive_key password salt =
  Cryptokit.pbkdf2 ~count:1000 ~dk_len:32 password salt

(* Small RSA key - should trigger CVE_2012_4929 *)
let generate_weak_rsa () =
  Cryptokit.RSA.new_key 1024

(* CBC without MAC - should trigger API006 *)
let encrypt_cbc data key iv =
  let cipher = Cryptokit.Cipher.aes ~mode:Cryptokit.Cipher.CBC key in
  cipher#put_string data;
  cipher#finish
  (* No MAC applied! *)

(* Nonce reuse - should trigger KEY003 *)
let nonce = Cryptokit.Random.string 12
let encrypt_gcm1 data = Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce data
let encrypt_gcm2 data = Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce data (* Reused nonce! *)