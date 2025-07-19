(* Shared types for analyzer to avoid circular dependencies *)
open Types

type analysis_mode = 
  | PureOCaml
  | Hybrid
  | SemgrepOnly

type analyzer_config = {
  mode: analysis_mode;
  parallel_threshold: int;
  enable_semgrep: bool;
  enable_dataflow: bool;
  enable_typedtree: bool;
  enable_interprocedural: bool;
  custom_rules: string list;
}

let default_config = {
  mode = Hybrid;
  parallel_threshold = 10;
  enable_semgrep = true;
  enable_dataflow = true;
  enable_typedtree = false;
  enable_interprocedural = true;
  custom_rules = [];
}

type analysis_state = {
  mutable import_context: Import_tracker.crypto_context;
  findings: finding list ref;
  files_analyzed: int ref;
  config: analyzer_config;
}

let create_state config = {
  import_context = Import_tracker.create_context ();
  findings = ref [];
  files_analyzed = ref 0;
  config;
}