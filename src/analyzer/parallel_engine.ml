open Types
open Analyzer_types

module Parallel_engine = struct
  type work_item = {
    file_path: string;
    priority: int;
  }
  
  type worker_result = {
    file: string;
    findings: finding list;
    error: string option;
  }
  
  let chunk_size = 50
  let max_domains = 8
  
  let create_work_queue files =
    let queue = Queue.create () in
    List.iter (fun file ->
      Queue.add { file_path = file; priority = 1 } queue
    ) files;
    queue
  
  let worker_task analyzer_state work_queue results_queue =
    let rec process_files () =
      match 
        try Some (Queue.take work_queue)
        with Queue.Empty -> None
      with
      | None -> ()
      | Some work_item ->
          let result = 
            try
              let findings = File_analyzer.analyze_single_file analyzer_state work_item.file_path in
              { file = work_item.file_path; findings; error = None }
            with e ->
              { file = work_item.file_path; 
                findings = []; 
                error = Some (Printexc.to_string e) }
          in
          Queue.add result results_queue;
          process_files ()
    in
    process_files ()
  
  let analyze_files_parallel analyzer_state files =
    if not (Domain.is_main_domain ()) then
      failwith "Parallel analysis must be called from main domain";
    
    let num_files = List.length files in
    let num_domains = min max_domains ((num_files / chunk_size) + 1) in
    
    if num_domains <= 1 then
      (* Fall back to sequential *)
      List.iter (fun file ->
        let _ = File_analyzer.analyze_single_file analyzer_state file in ()
      ) files
    else begin
      let work_queue = create_work_queue files in
      let results_queue = Queue.create () in
      
      (* Spawn worker domains *)
      let domains = Array.init (num_domains - 1) (fun _ ->
        Domain.spawn (fun () ->
          worker_task analyzer_state work_queue results_queue
        )
      ) in
      
      (* Main domain also works *)
      worker_task analyzer_state work_queue results_queue;
      
      (* Wait for all domains to complete *)
      Array.iter Domain.join domains;
      
      (* Collect results *)
      let all_findings = ref [] in
      let errors = ref [] in
      
      Queue.iter (fun result ->
        all_findings := !all_findings @ result.findings;
        match result.error with
        | Some err -> errors := (result.file, err) :: !errors
        | None -> ()
      ) results_queue;
      
      analyzer_state.findings := !(analyzer_state.findings) @ !all_findings;
      
      (* Handle errors *)
      List.iter (fun (file, err) ->
        Printf.eprintf "Error in parallel analysis of %s: %s\n" file err
      ) !errors
    end
  
  module Advanced = struct
    (* Work-stealing implementation for better load balancing *)
    module Work_stealing = struct
      type 'a stealer = {
        mutable items: 'a list;
        mutex: Mutex.t;
      }
      
      let create_stealer () = {
        items = [];
        mutex = Mutex.create ();
      }
      
      let steal stealer =
        Mutex.lock stealer.mutex;
        let result = 
          match stealer.items with
          | [] -> None
          | h :: t ->
              stealer.items <- t;
              Some h
        in
        Mutex.unlock stealer.mutex;
        result
      
      let add_work stealer work =
        Mutex.lock stealer.mutex;
        stealer.items <- work :: stealer.items;
        Mutex.unlock stealer.mutex
    end
    
    (* Memory-mapped file processing *)
    module Mmap_processor = struct
      external mmap_file : string -> int -> int -> bytes = "ocaml_crypto_linter_mmap"
      
      let process_large_file file_path =
        let fd = Unix.openfile file_path [Unix.O_RDONLY] 0 in
        let stats = Unix.fstat fd in
        let size = stats.st_size in
        
        if size > 1_000_000 then begin
          (* Use mmap for files > 1MB *)
          let mapped = mmap_file file_path 0 size in
          let content = Bytes.to_string mapped in
          Unix.close fd;
          
          (* Process in chunks to avoid memory pressure *)
          let chunk_size = 100_000 in
          let chunks = size / chunk_size + 1 in
          
          let findings = ref [] in
          for i = 0 to chunks - 1 do
            let start = i * chunk_size in
            let len = min chunk_size (size - start) in
            let chunk = String.sub content start len in
            
            (* Analyze chunk *)
            let lexbuf = Lexing.from_string chunk in
            try
              let ast = Parse.implementation lexbuf in
              let chunk_findings = Ast_analyzer.analyze_structure ast in
              findings := !findings @ chunk_findings
            with _ -> ()
          done;
          
          !findings
        end else begin
          Unix.close fd;
          []
        end
    end
    
    (* Priority-based scheduling *)
    module Priority_scheduler = struct
      type priority = High | Medium | Low
      
      type scheduled_file = {
        path: string;
        priority: priority;
        size: int;
      }
      
      let prioritize_files files =
        List.map (fun file ->
          let priority = 
            if String.ends_with ~suffix:"_test.ml" file then Low
            else if String.contains file "crypto" || 
                    String.contains file "auth" ||
                    String.contains file "security" then High
            else Medium
          in
          
          let size = 
            try (Unix.stat file).st_size
            with _ -> 0
          in
          
          { path = file; priority; size }
        ) files
        |> List.sort (fun a b ->
          (* Sort by priority, then by size (smaller first) *)
          match compare a.priority b.priority with
          | 0 -> compare a.size b.size
          | n -> n
        )
    end
    
    (* Incremental analysis with caching *)
    module Incremental = struct
      type cache_entry = {
        mtime: float;
        checksum: string;
        findings: finding list;
      }
      
      let cache : (string, cache_entry) Hashtbl.t = Hashtbl.create 1024
      
      let compute_checksum content =
        Digest.string content |> Digest.to_hex
      
      let should_analyze file_path =
        try
          let stats = Unix.stat file_path in
          match Hashtbl.find_opt cache file_path with
          | None -> true
          | Some entry -> stats.st_mtime > entry.mtime
        with _ -> true
      
      let cache_results file_path findings =
        try
          let stats = Unix.stat file_path in
          let content = 
            let ic = open_in file_path in
            let content = really_input_string ic (in_channel_length ic) in
            close_in ic;
            content
          in
          
          let entry = {
            mtime = stats.st_mtime;
            checksum = compute_checksum content;
            findings;
          } in
          
          Hashtbl.replace cache file_path entry
        with _ -> ()
      
      let get_cached_findings file_path =
        match Hashtbl.find_opt cache file_path with
        | Some entry -> Some entry.findings
        | None -> None
    end
  end
  
  let analyze_with_advanced_features analyzer_state files =
    (* Use priority scheduling *)
    let scheduled = Advanced.Priority_scheduler.prioritize_files files in
    
    (* Filter using incremental cache *)
    let files_to_analyze = List.filter (fun sf ->
      Advanced.Incremental.should_analyze sf.Advanced.Priority_scheduler.path
    ) scheduled in
    
    Printf.printf "Analyzing %d/%d files (using cache)\n" 
      (List.length files_to_analyze) (List.length files);
    
    (* Create work stealers for better load balancing *)
    let num_domains = min max_domains ((List.length files_to_analyze / 10) + 1) in
    let stealers = Array.init num_domains (fun _ ->
      Advanced.Work_stealing.create_stealer ()
    ) in
    
    (* Distribute work *)
    List.iteri (fun i sf ->
      let domain_idx = i mod num_domains in
      Advanced.Work_stealing.add_work stealers.(domain_idx) sf.path
    ) files_to_analyze;
    
    (* Spawn domains with work stealing *)
    let domains = Array.init (num_domains - 1) (fun idx ->
      Domain.spawn (fun () ->
        let my_stealer = stealers.(idx + 1) in
        let all_stealers = Array.to_list stealers in
        
        let rec process () =
          match Advanced.Work_stealing.steal my_stealer with
          | Some file ->
              let findings = Analyzer.analyze_single_file analyzer_state file in
              Advanced.Incremental.cache_results file findings;
              process ()
          | None ->
              (* Try stealing from others *)
              let rec try_steal = function
                | [] -> ()
                | s :: rest ->
                    if s != my_stealer then
                      match Advanced.Work_stealing.steal s with
                      | Some file ->
                          let findings = Analyzer.analyze_single_file analyzer_state file in
                          Advanced.Incremental.cache_results file findings;
                          process ()
                      | None -> try_steal rest
                    else try_steal rest
              in
              try_steal all_stealers
        in
        process ()
      )
    ) in
    
    (* Main domain works too *)
    let my_stealer = stealers.(0) in
    let rec process () =
      match Advanced.Work_stealing.steal my_stealer with
      | Some file ->
          let findings = Analyzer.analyze_single_file analyzer_state file in
          Advanced.Incremental.cache_results file findings;
          process ()
      | None -> ()
    in
    process ();
    
    (* Join all domains *)
    Array.iter Domain.join domains;
    
    (* Add cached findings for files not analyzed *)
    List.iter (fun file ->
      if not (List.exists (fun sf -> 
        sf.Advanced.Priority_scheduler.path = file
      ) files_to_analyze) then
        match Advanced.Incremental.get_cached_findings file with
        | Some findings ->
            analyzer_state.findings := !(analyzer_state.findings) @ findings
        | None -> ()
    ) files
end

let analyze_files_parallel = Parallel_engine.analyze_files_parallel
let analyze_with_advanced_features = Parallel_engine.analyze_with_advanced_features