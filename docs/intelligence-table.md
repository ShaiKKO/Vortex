2025 Cryptographic Security Threats Intelligence Table

     1. JWT/OAuth/SAML Protocol Vulnerabilities

     | Threat                        | Examples                                                   | Sources                           | Severity |
     |-------------------------------|------------------------------------------------------------|-----------------------------------|----------|
     | Algorithm Confusion           | Auth0 alg:none re-bug (2024), JWT header manipulation      | CVE-2024-10318, Auth0 incidents   | Critical |
     | None Algorithm Bypass         | JWT libraries accepting "none" algorithm without signature | Multiple JWT libraries affected   | Critical |
     | Weak Secret Keys              | Hardcoded/predictable JWT secrets in source code           | wallarm/jwt-secrets database      | High     |
     | OAuth State Parameter CSRF    | Missing/improper state parameter validation                | OAuth 2.0 spec ambiguities (2025) | High     |
     | SAML XML Signature Wrapping   | XSW attacks resurfaced in 2024                             | XML-based authentication systems  | High     |
     | Signature Verification Bypass | Using decode() instead of verify() methods                 | Common implementation error       | Critical |

     2. Advanced Side-Channel Attacks

     | Threat                      | Examples                                              | Sources                             | Severity |
     |-----------------------------|-------------------------------------------------------|-------------------------------------|----------|
     | Transient Scheduler Attacks | AMD TSA vulnerabilities (July 2025)                   | CVE-2025-36350, CVE-2025-36357      | High     |
     | Spectre-STC Variant         | Single-threaded contention attacks (2020-ongoing)     | TU Kaiserslautern research          | Medium   |
     | Store Queue Leakage         | AMD EPYC/Ryzen processor vulnerabilities              | AMD Security Bulletin 2025          | High     |
     | L1 Data Queue Timing        | Authenticated local privilege escalation              | AMD Critical Information Disclosure | High     |
     | Port Contention Attacks     | Shared resource exploitation in single-threaded cores | Spectre variant research            | Medium   |

     3. Supply Chain Attacks

     | Threat                 | Examples                                  | Sources                      | Severity |
     |------------------------|-------------------------------------------|------------------------------|----------|
     | Dependency Confusion   | 49% of organizations vulnerable (2025)    | Orca Security research       | Critical |
     | Typosquatting          | bitcoinlib-dev, aiocpa attacks            | PyPI/npm incidents 2024-2025 | High     |
     | Malicious Updates      | react-native-aria compromise (June 2025)  | npm security advisories      | Critical |
     | Trust Building Attacks | Polished READMEs with backdoors           | cappership PyPI campaign     | High     |
     | Repository Mismatch    | Clean GitHub, malicious PyPI/npm packages | Multiple 2025 incidents      | High     |
     | Crypto Key Theft       | Solana private key stealing packages      | 23 crypto campaigns (2025)   | Critical |

     4. Zero-Knowledge Proof Vulnerabilities

     | Threat                     | Examples                                       | Sources                          | Severity |
     |----------------------------|------------------------------------------------|----------------------------------|----------|
     | Under-Constrained Circuits | 96% of SNARK bugs (2024 study)                 | eprint.iacr.org/2024/514         | Critical |
     | Trusted Setup Compromise   | Zcash Sapling circuit flaw (historical)        | ZKP audit findings               | Critical |
     | Fiat-Shamir Implementation | Improper challenge generation                  | Semaphore contract vulnerability | High     |
     | Witness Leakage            | Information disclosure during proof generation | ZKP security audits              | High     |
     | Side-Channel Leaks         | Timing/power analysis during proof computation | Academic research 2024           | Medium   |
     | Commitment Randomness      | Insufficient entropy in commitments            | Circuit design errors            | High     |

     5. HSM Integration Vulnerabilities

     | Threat                  | Examples                                   | Sources                        | Severity |
     |-------------------------|--------------------------------------------|--------------------------------|----------|
     | PKCS#11 Buffer Overflow | Remote code execution via PKCS#11 commands | BlackHat 2019 (still relevant) | Critical |
     | Firmware Backdoors      | Persistent backdoors surviving updates     | Ledger HSM research            | Critical |
     | Key Extraction          | Remote retrieval of all HSM secrets        | HSM vendor vulnerabilities     | Critical |
     | Weak Key Wrapping       | Improper key export protection             | PKCS#11 implementation flaws   | High     |
     | Session Management      | Improper session handling in HSMaaS        | CSA HSM best practices 2024    | Medium   |
     | Access Control Bypass   | Override via firmware manipulation         | Multiple HSM vendors           | Critical |

     Key Insights for Implementation:

     1. Protocol Vulnerabilities: Focus on JWT/OAuth implementation validation, especially algorithm confusion and signature verification
     2. Side-Channels: New AMD vulnerabilities show ongoing CPU-level risks requiring OS/firmware patches
     3. Supply Chain: Dependency confusion affects nearly half of organizations; need strong package verification
     4. ZKP: Circuit constraints are the primary vulnerability source; formal verification is critical
     5. HSM: Despite being "secure hardware," HSMs have exploitable software interfaces requiring careful integration

     This intelligence will guide the implementation of new security rules for the OCaml Crypto Linter, with each category requiring specific detection patterns and remediation
     guidance.
