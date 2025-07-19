(* Test cases for interprocedural analysis *)

(* Test 1: CBC without MAC across functions *)
let encrypt_data key iv data =
  Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv data

let process_message key data =
  let iv = Mirage_crypto_rng.generate 16 in
  let encrypted = encrypt_data key iv data in
  (* Missing MAC! *)
  (iv, encrypted)

(* Test 2: Proper CBC with MAC *)
let encrypt_with_mac key mac_key data =
  let iv = Mirage_crypto_rng.generate 16 in
  let encrypted = Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv data in
  let mac = Mirage_crypto.Hash.SHA256.hmac ~key:mac_key encrypted in
  (iv, encrypted, mac)

(* Test 3: MAC-then-Encrypt (wrong order) *)
let mac_plaintext key data =
  Mirage_crypto.Hash.SHA256.hmac ~key data

let wrong_order_crypto key mac_key plaintext =
  let mac = mac_plaintext mac_key plaintext in
  let iv = Mirage_crypto_rng.generate 16 in
  let to_encrypt = Bytes.cat plaintext mac in
  Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv to_encrypt

(* Test 4: Key reuse across algorithms *)
let shared_key = Mirage_crypto_rng.generate 32

let encrypt_with_shared_key data =
  let iv = Mirage_crypto_rng.generate 16 in
  Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key:shared_key ~iv data

let sign_with_shared_key data =
  (* Reusing encryption key for signing - bad! *)
  Mirage_crypto.Hash.SHA256.hmac ~key:shared_key data

(* Test 5: Complex interprocedural case *)
let derive_key master purpose =
  Mirage_crypto.Hash.SHA256.hmac ~key:master (Bytes.of_string purpose)

let complex_encrypt master_key data =
  let enc_key = derive_key master_key "encryption" in
  let iv = Mirage_crypto_rng.generate 16 in
  let encrypted = Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key:enc_key ~iv data in
  (iv, encrypted)

let complex_sign master_key data =
  let sign_key = derive_key master_key "signing" in
  Mirage_crypto.Hash.SHA256.hmac ~key:sign_key data

let secure_process master_key data =
  let (iv, encrypted) = complex_encrypt master_key data in
  let mac_key = derive_key master_key "mac" in
  let mac = Mirage_crypto.Hash.SHA256.hmac ~key:mac_key encrypted in
  (iv, encrypted, mac)

(* Test 6: Nested function calls *)
let inner_encrypt key iv data =
  Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv data

let middle_layer key data =
  let iv = Mirage_crypto_rng.generate 16 in
  inner_encrypt key iv data

let outer_layer key data =
  let encrypted = middle_layer key data in
  (* No MAC across 3 levels of calls *)
  encrypted