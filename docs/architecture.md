# OCaml Crypto Linter - Architecture Analysis

## Component Specification Table

| Component | Technology Stack | Purpose | Input | Output |
|-----------|-----------------|---------|-------|--------|
| **Parser** | compiler-libs.common, ppxlib, Parsetree | AST extraction & traversal | .ml/.mli files | Typed AST, crypto API calls |
| **Analyzer** | Semgrep, Multicore OCaml (Domainslib), Lwt | Parallel vulnerability analysis | AST, source code | Finding records |
| **Rules Engine** | Pure OCaml, pattern matching | Pluggable crypto checks | AST nodes, context | Vulnerabilities |
| **Reporter** | Yojson, Format, LSP protocol | Multi-format output | Finding records | JSON/SARIF/text |
| **CLI** | Cmdliner, Dune | User interface | Command args | Exit codes, reports |
| **Semgrep Bridge** | YAML generation, process spawning | External analysis | Rule patterns | JSON findings |

## Data Flow Analysis

| Stage | Data Structure | Transformation | Concurrency |
|-------|---------------|----------------|-------------|
| 1. **File Reading** | `string list` (paths) | → Lexing.lexbuf | Sequential |
| 2. **Parsing** | Lexing.lexbuf | → Parsetree.structure | Per-file parallel |
| 3. **Type Analysis** | Parsetree | → Typedtree (optional) | Sequential |
| 4. **Rule Execution** | AST nodes | → finding list | Domain-parallel |
| 5. **Semgrep Run** | YAML rules | → JSON results | Process-parallel |
| 6. **Aggregation** | finding list list | → analysis_result | Reduction |
| 7. **Reporting** | analysis_result | → JSON/text output | Sequential |

## Technology Stack Details

### Core Dependencies
- **OCaml 4.14+**: Multicore support
- **ppxlib 0.32+**: AST manipulation, metaquot
- **compiler-libs**: Typedtree, Path, Ident modules
- **Domainslib**: Work-stealing parallelism
- **Semgrep 1.45+**: Pattern-based analysis
- **Lwt**: Async I/O for external processes

### Analysis Libraries
- **Salto** (planned): Abstract interpretation for dataflow
- **pfff**: Code navigation, semantic grep
- **Alcotest/QCheck**: Property-based testing

## UML-Style Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        OCaml Crypto Linter Pipeline                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────┐     ┌──────────┐     ┌────────────┐                 │
│  │  Files  │────▶│  Lexer   │────▶│   Parser   │                 │
│  │ .ml/.mli│     │ (Lexing) │     │ (Ppxlib)   │                 │
│  └─────────┘     └──────────┘     └─────┬──────┘                 │
│                                          │                         │
│                                          ▼                         │
│                                   ┌──────────────┐                 │
│                                   │     AST      │                 │
│                                   │ (Parsetree)  │                 │
│                                   └──────┬───────┘                 │
│                                          │                         │
│                    ┌─────────────────────┴─────────────────┐      │
│                    ▼                                       ▼      │
│           ┌─────────────────┐                   ┌──────────────┐  │
│           │  Type Analyzer  │                   │   Semgrep    │  │
│           │ (compiler-libs) │                   │  Bridge      │  │
│           └────────┬────────┘                   └──────┬───────┘  │
│                    │                                    │          │
│                    ▼                                    ▼          │
│         ┌───────────────────────────────────────────────────┐     │
│         │            Parallel Analysis Engine               │     │
│         │  ┌─────────┐  ┌─────────┐  ┌─────────┐         │     │
│         │  │ Domain 1│  │ Domain 2│  │ Domain N│         │     │
│         │  │ Rules   │  │ Rules   │  │ Rules   │         │     │
│         │  └─────────┘  └─────────┘  └─────────┘         │     │
│         │         (Domainslib work-stealing)              │     │
│         └──────────────────┬───────────────────────────────┘     │
│                            │                                      │
│                            ▼                                      │
│                   ┌─────────────────┐                            │
│                   │   Aggregator    │                            │
│                   │ (Finding merge) │                            │
│                   └────────┬────────┘                            │
│                            │                                      │
│                            ▼                                      │
│               ┌────────────────────────┐                         │
│               │      Reporter          │                         │
│               ├────────────────────────┤                         │
│               │ • JSON (CI/CD)        │                         │
│               │ • SARIF (GitHub)      │                         │
│               │ • LSP (Editor)        │                         │
│               │ • Text (Terminal)     │                         │
│               └────────────────────────┘                         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

```

## Crypto Vulnerability Rules Taxonomy

| Rule ID | Category | Description | Severity | CVE References |
|---------|----------|-------------|----------|----------------|
| CRYPTO001 | Weak Cipher | DES, 3DES, RC4, Blowfish usage | HIGH | CVE-2016-2183 (SWEET32) |
| CRYPTO002 | Hardcoded Key | String literals as crypto keys | CRITICAL | CWE-798 |
| CRYPTO003 | Weak Hash | MD5, SHA1 for security | MEDIUM | CVE-2017-15999 (SHAttered) |
| CRYPTO004 | Key Detection | Hex string heuristics | LOW | CWE-798 |
| CRYPTO005 | Nonce Reuse | IV/nonce variable reuse | CRITICAL | CVE-2016-0270 |
| CRYPTO006 | Weak PRNG | OCaml Random for crypto | HIGH | CWE-338 |
| CRYPTO007 | Timing Attack | Non-constant comparisons | MEDIUM | CVE-2016-2107 |
| CRYPTO008 | ECB Mode | Block cipher ECB usage | HIGH | CWE-327 |
| CRYPTO009 | Small RSA Key | RSA < 2048 bits | HIGH | CVE-2012-4929 |
| CRYPTO010 | NULL Cipher | Disabled encryption | CRITICAL | CWE-327 |
| CRYPTO011 | Weak KDF | PBKDF iterations < 10000 | MEDIUM | NIST SP 800-132 |
| CRYPTO012 | Missing MAC | Encryption without auth | HIGH | CWE-353 |

## Implementation Phases

### Phase 1: Core Parser (Week 1-2)
- [x] Basic AST traversal with ppxlib
- [x] Crypto library detection (Cryptokit, Nocrypto, Mirage-crypto)
- [ ] Typedtree integration for deeper analysis
- [ ] Control flow graph construction

### Phase 2: Rule Development (Week 3-4)
- [x] Weak cipher detection
- [x] Hardcoded key patterns
- [x] Hash function analysis
- [ ] Advanced dataflow for nonce tracking
- [ ] Taint analysis for key material

### Phase 3: Parallel Analyzer (Week 5-6)
- [ ] Domainslib integration
- [ ] Work-stealing scheduler
- [ ] Incremental analysis cache
- [ ] Memory-mapped file processing

### Phase 4: External Integration (Week 7-8)
- [x] Semgrep YAML generation
- [ ] Salto abstract interpretation
- [ ] LSP server implementation
- [ ] SARIF output format

### Phase 5: Advanced Features (Week 9-10)
- [ ] Machine learning for pattern detection
- [ ] Crypto library version checking
- [ ] Fix suggestions with diffs
- [ ] IDE plugin development

## Performance Targets

| Metric | Target | Current | Method |
|--------|--------|---------|--------|
| Files/second | 100+ | ~50 | Parallel parsing |
| Memory usage | <1GB/1K files | ~500MB | Streaming analysis |
| Rule execution | <10ms/rule | ~15ms | Domain parallelism |
| Semgrep overhead | <2x native | ~3x | Process pooling |

## Security Considerations

1. **Supply Chain**: Verify Semgrep binary integrity
2. **Resource Limits**: Prevent DoS via complex patterns
3. **Sandboxing**: Isolate untrusted code analysis
4. **Privacy**: No telemetry without consent