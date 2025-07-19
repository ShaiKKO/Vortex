---
name: Security rule proposal
about: Propose a new cryptographic vulnerability detection rule
title: '[RULE] '
labels: rule-proposal
assignees: ''

---

**Rule Information**
- **Category**: (ALGO/KEY/SIDE/API/DEP/RAND/DOS)
- **Proposed ID**: 
- **Severity**: (Critical/Error/Warning/Info)
- **Name**: 

**Vulnerability Description**
Describe the cryptographic vulnerability this rule would detect.

**Vulnerable Pattern**
```ocaml
(* Example of vulnerable code that should be detected *)
```

**Secure Alternative**
```ocaml
(* Example of secure code that should be recommended *)
```

**Detection Logic**
Describe how the rule would detect this pattern:
- AST patterns to match
- Data flow requirements
- Context considerations

**False Positive Considerations**
How can we minimize false positives for this rule?

**References**
- CVE IDs:
- Research papers:
- Best practices guides:

**Test Cases**
Provide examples of code that should and shouldn't trigger this rule:
```ocaml
(* Should trigger *)

(* Should NOT trigger *)
```