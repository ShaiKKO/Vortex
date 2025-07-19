(lang dune 3.15)

(name ocaml_crypto_linter)

(generate_opam_files true)

(source
 (github ShaiKKO/Vortex))

(authors "Shaiiko" "OCaml Crypto Linter Contributors")

(maintainers "shaiiko@proton.me")

(license MIT)

(documentation https://shaikko.github.io/Vortex/ocaml-crypto-linter/)

(package
 (name ocaml-crypto-linter)
 (synopsis "Static analysis tool for cryptographic vulnerabilities in OCaml code")
 (description "A modular linter that detects common cryptographic misuses and vulnerabilities in OCaml codebases, with support for Semgrep rules and abstract interpretation")
 (depends
  (ocaml (>= 4.14.0))
  (dune (>= 3.15))
  (ppxlib (>= 0.32.0))
  (cmdliner (>= 1.2.0))
  (yojson (>= 2.0.0))
  (lwt (>= 5.6.0))
  (eqaf (>= 0.9))
  (mirage-crypto (>= 0.11.0))
  (domainslib (>= 0.5.0))
  (odoc :with-doc)
  (alcotest (and :with-test (>= 1.7.0)))
  (cryptokit (and :with-test (>= 1.19)))
  (nocrypto (and :with-test (>= 0.5.4))))
 (tags
  (topics cryptography security static-analysis linter)))

(package
 (name ocaml-crypto-linter-rules)
 (synopsis "Pluggable cryptographic vulnerability rules for ocaml-crypto-linter")
 (depends
  ocaml-crypto-linter))