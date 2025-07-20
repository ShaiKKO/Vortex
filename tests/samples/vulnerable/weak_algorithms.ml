(* Test file for ALGO001-ALGO006: Weak Algorithm Detection *)

open Cryptokit
open Nocrypto

(* ALGO001: Weak Cipher Algorithms *)
let weak_ciphers () =
  (* DES - 56-bit key *)
  let des_cipher = Cipher.des "12345678" in
  
  (* Triple DES *)
  let triple_des = Cipher.triple_des "123456781234567812345678" in
  
  (* RC4/ARC4 *)
  let rc4_cipher = Cipher.arcfour "some_key" in
  
  (* Blowfish - 64-bit blocks *)
  let blowfish = Cipher.blowfish "blowfish_key" in
  
  (* Using Nocrypto *)
  let des_block = Nocrypto.Cipher_block.DES.of_secret (Cstruct.of_string "12345678") in
  
  (* All should trigger ALGO001 *)
  ()

(* ALGO002: Weak Hash Algorithms *)
let weak_hashes data =
  (* MD5 via Digest module *)
  let md5_hash = Digest.string data in
  let md5_file = Digest.file "somefile.txt" in
  
  (* MD5 via Cryptokit *)
  let md5 = Hash.md5 () in
  md5#add_string data;
  let result = md5#result in
  
  (* SHA-1 *)
  let sha1 = Hash.sha1 () in
  sha1#add_string data;
  
  (* MD4 - even worse *)
  let md4 = Hash.md4 () in
  
  (* MD2 - ancient *)
  let md2 = Hash.md2 () in
  
  (* Using Nocrypto *)
  let sha1_nocrypto = Nocrypto.Hash.SHA1.digest (Cstruct.of_string data) in
  let md5_nocrypto = Nocrypto.Hash.MD5.digest (Cstruct.of_string data) in
  
  result

(* ALGO003: Insecure Elliptic Curves *)
let weak_curves () =
  (* Weak P-192 curve *)
  let p192_key = Nocrypto.Ec.P192.generate () in
  
  (* Weak P-224 curve *)
  let p224_key = Nocrypto.Ec.P224.generate () in
  
  (* Named weak curves *)
  let secp192r1 = Nocrypto.Ec.P192.params in
  let secp224r1 = Nocrypto.Ec.P224.params in
  
  (* All should trigger ALGO003 *)
  ()

(* ALGO004: Small Block Size Cipher *)
let small_block_ciphers () =
  (* 64-bit block ciphers vulnerable to SWEET32 *)
  let des = Cipher.des "key12345" in          (* 64-bit blocks *)
  let triple_des = Cipher.triple_des "key" in (* 64-bit blocks *)
  let blowfish = Cipher.blowfish "key" in     (* 64-bit blocks *)
  let cast5 = Cipher.cast128 "key1234567890123456" in (* 64-bit blocks *)
  ()

(* ALGO005: Weak Key Exchange Parameters *)
let weak_key_exchange () =
  (* Weak RSA key size *)
  let weak_rsa = Nocrypto.Rsa.generate ~bits:1024 in  (* Too small *)
  let weak_rsa_512 = Nocrypto.Rsa.generate ~bits:512 in  (* Extremely weak *)
  
  (* Weak DH parameters *)
  let weak_dh = Nocrypto.Dh.generate_parameters ~bits:1024 in
  
  (* Weak DSA *)
  (* let weak_dsa = Cryptokit.DSA.generate_key ~bits:1024 in *)
  
  ()

(* ALGO006: Legacy SSL/TLS Versions *)
module TLS_Config = struct
  (* SSLv2 - completely broken *)
  let sslv2_config = Ssl.{
    protocol = SSLv2;
    certificates = [];
    ciphers = "ALL";
  }
  
  (* SSLv3 - POODLE attack *)
  let sslv3_config = Ssl.{
    protocol = SSLv3;
    certificates = [];
    ciphers = "ALL";
  }
  
  (* TLS 1.0 - BEAST attack *)
  let tls10_config = Ssl.{
    protocol = TLSv1;
    certificates = [];
    ciphers = "ALL";
  }
  
  (* TLS 1.1 - deprecated *)
  let tls11_config = Ssl.{
    protocol = TLSv1_1;
    certificates = [];
    ciphers = "ALL";
  }
end