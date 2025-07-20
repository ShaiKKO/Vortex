(* Test file for KEY001: Hardcoded Cryptographic Key *)

(* Direct hardcoded keys - should trigger KEY001 *)
let api_key = "sk_live_4242424242424242"
let secret_key = "my_super_secret_encryption_key_12345"
let private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."

(* Keys in different contexts *)
module Config = struct
  let database_key = "db_encryption_key_prod_2023"
  let jwt_secret = "jwt_secret_key_do_not_share"
end

(* Keys in functions *)
let encrypt_data data =
  let key = "hardcoded_aes_key_256_bits_long!" in
  Cryptokit.Cipher.aes key

(* Base64 encoded but still hardcoded *)
let encoded_secret = "bXlfc2VjcmV0X3Bhc3N3b3JkXzEyMw=="

(* Keys in records *)
type config = {
  endpoint: string;
  api_key: string;
  secret: string;
}

let prod_config = {
  endpoint = "https://api.example.com";
  api_key = "prod_api_key_a1b2c3d4e5f6";
  secret = "webhook_secret_key_xyz789";
}

(* Keys in arrays/lists *)
let key_rotation_list = [
  "old_key_2021_q1";
  "old_key_2021_q2";
  "current_key_2021_q3";
]

(* Environment variable names that look like they contain keys *)
let suspicious_env_var = "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"