(* Hash collision DoS vulnerabilities and high-risk patterns *)

(* Hash collision attacks on hash tables *)
module Hash_Table_DoS = struct
  (* Vulnerable: Using MD5 for hash table keys with user input *)
  module MD5_Hash_Table = struct
    let table = Hashtbl.create 1024
    
    (* ALGO002 + DoS: MD5 hash collisions can cause O(n) lookup *)
    let hash_key input =
      let hash = Cryptokit.Hash.md5 () in
      hash#add_string input;
      hash#result
      
    let add_user_data ~key ~value =
      (* User can craft colliding keys! *)
      let hashed = hash_key key in
      Hashtbl.add table hashed value  (* DoS: Collision causes chain *)
      
    (* Collision example: These produce same MD5 hash (collision attack) *)
    let collision_1 = "\x4d\xc9\x68\xff\x0e\xe3\x5c\x20\x95\x72\xd4\x77\x7b\x72\x15\x87"
    let collision_2 = "\x4d\xc9\x68\xff\x0e\xe3\x5c\x20\x95\x72\xd4\x77\x7b\x72\x15\x88"
  end
  
  (* SHA1 hash tables - SHAttered collision attack *)
  module SHA1_Hash_DoS = struct
    (* ALGO002: SHA1 has practical collisions *)
    let compute_sha1_hash data =
      Cryptokit.Hash.sha1 () |> fun h ->
      h#add_string data;
      h#result
      
    (* Vulnerable pattern: user content addressed by SHA1 *)
    let content_cache = Hashtbl.create 10000
    
    let store_user_content content =
      let hash = compute_sha1_hash content in
      Hashtbl.add content_cache hash content  (* SHA1 collision = DoS *)
  end
  
  (* Predictable hash function DoS *)
  module Predictable_Hash_DoS = struct
    (* RAND001: Using non-crypto hash with predictable seed *)
    let weak_hash str =
      let hash = ref 0 in
      String.iter (fun c -> 
        hash := !hash * 31 + Char.code c  (* Predictable pattern *)
      ) str;
      !hash
      
    let user_sessions = Hashtbl.create 1000
    
    let create_session ~session_id ~data =
      let hash = weak_hash session_id in
      (* Attacker can predict hash values and cause collisions *)
      Hashtbl.add user_sessions hash data
  end
end

(* Large file hashing without chunking - resource exhaustion *)
module Resource_Exhaustion = struct
  (* Vulnerable: Loading entire file into memory *)
  let hash_large_file_vulnerable filename =
    let ic = open_in_bin filename in
    let size = in_channel_length ic in
    (* DoS: Attacker uploads 10GB file = OOM *)
    let content = really_input_string ic size in  (* Memory exhaustion! *)
    close_in ic;
    
    (* Even worse with multiple hash computations *)
    let md5 = Cryptokit.Hash.md5 () in
    let sha1 = Cryptokit.Hash.sha1 () in
    let sha256 = Cryptokit.Hash.sha256 () in
    
    md5#add_string content;     (* 3x memory usage *)
    sha1#add_string content;
    sha256#add_string content;
    
    (md5#result, sha1#result, sha256#result)
    
  (* Vulnerable: Unlimited decompression *)
  let decompress_user_data compressed =
    (* Zip bomb: 42KB -> 4.5PB *)
    try
      Zlib.uncompress compressed  (* No size limits! *)
    with _ -> ""
end

(* Algorithmic complexity attacks *)
module Algorithmic_Complexity_DoS = struct
  (* Vulnerable: Exponential regex *)
  let validate_email email =
    (* ReDoS: Catastrophic backtracking *)
    let regex = Str.regexp "^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\\.com$" in
    Str.string_match regex email 0  (* DoS with "aaaa...a@" *)
    
  (* Vulnerable: Recursive parsing without depth limit *)
  let rec parse_nested_json json depth =
    (* No depth limit - stack overflow *)
    match json with
    | `Assoc items ->
        List.map (fun (k, v) -> (k, parse_nested_json v (depth + 1))) items
    | `List items ->
        List.map (fun item -> parse_nested_json item (depth + 1)) items
    | _ -> []
    
  (* Vulnerable: Quadratic string concatenation *)
  let build_response items =
    List.fold_left (fun acc item ->
      acc ^ (process_item item)  (* O(n²) complexity *)
    ) "" items
end

(* Collision attacks on crypto constructs *)
module Crypto_Collision_Attacks = struct
  (* Birthday attack on small MACs *)
  let weak_mac_truncation ~key ~message =
    let mac = Cryptokit.MAC.hmac_sha256 key in
    mac#add_string message;
    let full_mac = mac#result in
    (* Truncating MAC enables birthday attacks *)
    String.sub full_mac 0 4  (* 32-bit MAC = 2^16 collision! *)
    
  (* Weak nonce generation allows collisions *)
  let generate_weak_nonce () =
    (* RAND001: Only 32-bit nonce space *)
    Random.int32 Int32.max_int |> Int32.to_string  (* Birthday paradox *)
    
  (* Length extension attack pattern *)
  let vulnerable_mac ~secret ~user_data =
    (* ALGO002: SHA1/SHA256 vulnerable to length extension *)
    let to_hash = secret ^ user_data in
    Cryptokit.Hash.sha256 () |> fun h ->
    h#add_string to_hash;
    h#result  (* Not HMAC - length extension possible! *)
end

(* XML/JSON bomb attacks *)
module Parser_Bomb_Attacks = struct
  (* Billion laughs attack *)
  let parse_xml_unsafe xml_string =
    (* No entity expansion limits *)
    let parser = Xml.parse_string xml_string in
    (* <!ENTITY lol "lol">
       <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
       ... exponential expansion *)
    parser
    
  (* JSON deep nesting attack *)
  let parse_json_unsafe json_string =
    (* No depth/size limits *)
    Yojson.Safe.from_string json_string  (* Stack overflow possible *)
end

(* Certificate validation DoS *)
module Certificate_DoS = struct
  (* Expensive signature verification *)
  let verify_certificate_chain chain =
    (* No limit on chain length *)
    List.iter (fun cert ->
      (* Each verification is expensive *)
      verify_rsa_signature cert.signature cert.data  (* CPU DoS *)
    ) chain
    
  (* Pathological certificate names *)
  let match_wildcard_cert pattern hostname =
    (* Exponential regex matching *)
    let regex = Str.regexp (
      String.map (function
        | '*' -> ".*"
        | '?' -> "."
        | c -> Str.quote (String.make 1 c)
      ) pattern
    ) in
    Str.string_match regex hostname 0  (* ReDoS possible *)
end

(* Rate limiting bypass *)
module Rate_Limit_Bypass = struct
  (* Weak rate limit key *)
  let rate_limit_key request =
    (* Using only IP - can be spoofed/shared *)
    request.client_ip  (* Multiple users behind NAT *)
    
  (* Time-based race condition *)
  let check_rate_limit key =
    let current_count = get_count key in
    if current_count < max_requests then begin
      (* TOCTOU race: Multiple threads can pass check *)
      increment_count key;  (* Not atomic! *)
      true
    end else false
end