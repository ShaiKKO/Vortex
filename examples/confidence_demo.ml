(* Demonstration of confidence scoring reducing false positives *)

(* Case 1: SHA1 in security context - High confidence finding *)
module Auth_token = struct
  let generate_token user_id secret =
    (* SHA1 used for authentication - BAD! *)
    let data = Printf.sprintf "%s:%s:%f" user_id secret (Unix.time ()) in
    Cryptokit.Hash.sha1 () |> fun h ->
    h#add_string data;
    h#result
    
  let verify_token token secret =
    (* String comparison on auth token - timing attack *)
    String.equal token (generate_token "user" secret)
end

(* Case 2: SHA1 in non-security context - Low confidence *)
module Git_utils = struct
  let compute_object_hash content =
    (* SHA1 for git objects - this is fine, git still uses SHA1 *)
    let header = Printf.sprintf "blob %d\000" (String.length content) in
    Cryptokit.Hash.sha1 () |> fun h ->
    h#add_string header;
    h#add_string content;
    h#result
    
  let get_commit_id changes =
    (* Not security critical *)
    List.map compute_object_hash changes
end

(* Case 3: Test file - Very low confidence *)
module Test_crypto = struct
  (* File: test_crypto.ml *)
  let test_weak_cipher () =
    (* DES in test code - low priority *)
    let key = "testkey!" in
    let cipher = Cryptokit.Cipher.des ~pad:Cryptokit.Padding.length 
                   Cryptokit.Cipher.Encrypt key in
    cipher#put_string "test data";
    cipher#finish
end

(* Case 4: Complex interprocedural with high confidence *)
module Payment_processor = struct
  let encrypt_card_number key card_number =
    (* CBC without MAC - but detected across functions *)
    let iv = String.make 16 '0' in  (* Also predictable IV! *)
    Cryptokit.Cipher.aes ~mode:Cryptokit.Cipher.CBC ~pad:Cryptokit.Padding.length
      ~iv:iv Cryptokit.Cipher.Encrypt key |> fun cipher ->
    cipher#put_string card_number;
    cipher#finish
    
  let process_payment key card_data amount =
    let encrypted = encrypt_card_number key card_data.number in
    (* No MAC on sensitive payment data! *)
    send_to_payment_gateway encrypted amount
    
  and send_to_payment_gateway encrypted_card amount =
    (* Network transmission without authentication *)
    Http_client.post "/api/payment" 
      (encrypted_card ^ ":" ^ string_of_float amount)
end

(* Case 5: Key reuse with medium confidence *)
module Multi_purpose_crypto = struct
  let master_key = Bytes.of_string "this-is-32-bytes-long-master-key"
  
  (* Same key used for different purposes *)
  let encrypt_user_data data =
    Mirage_crypto.Cipher_block.AES.ECB.encrypt ~key:master_key data
    
  let sign_api_request request =
    (* Key reuse - but might be intentional design *)
    Mirage_crypto.Hash.SHA256.hmac ~key:master_key request
end

(* Expected confidence scores:
   
   1. Auth_token.generate_token - SHA1 for auth
      - Confidence: High (90%+) 
      - Priority: P9
      - Clear security context
      
   2. Git_utils.compute_object_hash - SHA1 for git
      - Confidence: Low (40%)
      - Priority: P2
      - Non-security use case
      
   3. Test_crypto.test_weak_cipher - DES in tests
      - Confidence: Very Low (15%)
      - Priority: P1
      - Test file context
      
   4. Payment_processor - Multiple issues
      - CBC without MAC: High (85%)
      - Predictable IV: Very High (95%)
      - Priority: P10
      - Financial data = critical
      
   5. Multi_purpose_crypto - Key reuse
      - Confidence: Medium (70%)
      - Priority: P6
      - Could be intentional pattern
      
   The confidence scoring helps developers focus on:
   - Real security issues (Auth_token, Payment_processor)
   - While filtering out non-issues (Git_utils, Test_crypto)
   - And flagging "maybe" issues for review (Multi_purpose_crypto)
*)