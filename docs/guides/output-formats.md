# Output Formats Guide

OCaml Crypto Linter supports multiple output formats for different use cases.

## Text Format (Default)

Human-readable output for terminal display.

### Example Output

```
OCaml Crypto Linter v0.1.0
========================

Analyzing 15 files...

Files analyzed: 15
Time taken: 0.23s
Total findings: 4
Critical: 1, Errors: 2, Warnings: 1, Info: 0

[KEY001] Hardcoded Cryptographic Key
  File: src/auth.ml:23:13
  Severity: CRITICAL
  Message: Hardcoded key detected in source code
  Suggestion: Use environment variables or secure key management
  References:
    - https://cwe.mitre.org/data/definitions/798.html

[ALGO001] Weak Cipher Algorithm
  File: src/crypto.ml:45:16
  Severity: ERROR
  Message: DES cipher is cryptographically broken
  Suggestion: Use AES-256-GCM or ChaCha20-Poly1305
  References:
    - CVE-2016-2183 (SWEET32)

[SIDE001] Variable-Time String Comparison
  File: src/auth.ml:67:8
  Severity: ERROR  
  Message: String comparison vulnerable to timing attacks
  Suggestion: Use Eqaf.equal for constant-time comparison

[ALGO002] Weak Hash Algorithm
  File: src/legacy.ml:12:10
  Severity: WARNING
  Message: MD5 is vulnerable to collision attacks
  Context: Used for non-cryptographic checksum (lower severity)
  Suggestion: Use SHA-256 or BLAKE2b for security-critical hashing
```

### Usage

```bash
# Default text output to stdout
ocaml-crypto-linter src/

# Save to file
ocaml-crypto-linter src/ -o report.txt

# With color output (if terminal supports)
ocaml-crypto-linter src/ --color
```

## JSON Format

Machine-readable format for integration with other tools.

### Schema

```json
{
  "version": "1.0",
  "tool": {
    "name": "ocaml-crypto-linter",
    "version": "0.1.0"
  },
  "summary": {
    "files_analyzed": 15,
    "analysis_time": 0.23,
    "total_findings": 4,
    "critical": 1,
    "errors": 2,
    "warnings": 1,
    "info": 0
  },
  "findings": [
    {
      "rule_id": "KEY001",
      "severity": "critical",
      "message": "Hardcoded key detected in source code",
      "vulnerability": {
        "type": "hardcoded_key"
      },
      "location": {
        "file": "src/auth.ml",
        "line": 23,
        "column": 13,
        "end_line": 23,
        "end_column": 45
      },
      "code_snippet": "let secret_key = \"my_super_secret_key_123\"",
      "suggestion": "Use environment variables or secure key management",
      "references": [
        "https://cwe.mitre.org/data/definitions/798.html"
      ],
      "confidence": 0.95,
      "context": {
        "function": "authenticate_user",
        "module": "Auth"
      }
    }
  ],
  "errors": [
    {
      "file": "src/broken.ml",
      "error": "Syntax error at line 42"
    }
  ],
  "metadata": {
    "timestamp": "2024-01-19T10:30:45Z",
    "host": "ci-runner-01",
    "working_directory": "/home/user/project"
  }
}
```

### Usage

```bash
# Generate JSON report
ocaml-crypto-linter src/ -f json -o report.json

# Pretty-printed JSON
ocaml-crypto-linter src/ -f json --pretty

# Parse with jq
ocaml-crypto-linter src/ -f json | jq '.summary'
ocaml-crypto-linter src/ -f json | jq '.findings[] | select(.severity == "critical")'
```

### Processing JSON Output

```python
# Python example
import json
import sys

with open('report.json') as f:
    report = json.load(f)

critical_findings = [f for f in report['findings'] if f['severity'] == 'critical']
if critical_findings:
    print(f"Found {len(critical_findings)} critical issues!")
    sys.exit(1)
```

```javascript
// Node.js example
const report = require('./report.json');

const groupedByFile = report.findings.reduce((acc, finding) => {
  const file = finding.location.file;
  if (!acc[file]) acc[file] = [];
  acc[file].push(finding);
  return acc;
}, {});

console.log('Issues by file:', groupedByFile);
```

## SARIF Format

Static Analysis Results Interchange Format for IDE and CI/CD integration.

### SARIF 2.1.0 Schema

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "ocaml-crypto-linter",
          "version": "0.1.0",
          "informationUri": "https://github.com/ShaiKKO/Vortex",
          "rules": [
            {
              "id": "KEY001",
              "name": "HardcodedCryptographicKey",
              "shortDescription": {
                "text": "Hardcoded cryptographic key"
              },
              "fullDescription": {
                "text": "Cryptographic keys should not be hardcoded in source code"
              },
              "helpUri": "https://cwe.mitre.org/data/definitions/798.html",
              "properties": {
                "tags": ["security", "cryptography"],
                "precision": "high"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "KEY001",
          "level": "error",
          "message": {
            "text": "Hardcoded key detected in source code"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/auth.ml"
                },
                "region": {
                  "startLine": 23,
                  "startColumn": 13,
                  "endLine": 23,
                  "endColumn": 45
                }
              }
            }
          ],
          "fixes": [
            {
              "description": {
                "text": "Use environment variable"
              },
              "artifactChanges": [
                {
                  "artifactLocation": {
                    "uri": "src/auth.ml"
                  },
                  "replacements": [
                    {
                      "deletedRegion": {
                        "startLine": 23,
                        "startColumn": 13,
                        "endLine": 23,
                        "endColumn": 45
                      },
                      "insertedContent": {
                        "text": "Sys.getenv \"SECRET_KEY\""
                      }
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

### Usage

```bash
# Generate SARIF report
ocaml-crypto-linter src/ -f sarif -o results.sarif

# Use with GitHub Actions
ocaml-crypto-linter . -f sarif -o results.sarif
# Then upload with github/codeql-action/upload-sarif
```

### GitHub Integration

SARIF files integrate with GitHub Security tab:

```yaml
- name: Run Crypto Linter
  run: ocaml-crypto-linter . -f sarif -o results.sarif
  
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: crypto-security
```

## Custom Formats

### CSV Export

```bash
# Convert JSON to CSV
ocaml-crypto-linter src/ -f json | jq -r '
  ["file","line","rule","severity","message"] as $headers |
  $headers, (.findings[] | [
    .location.file,
    .location.line,
    .rule_id,
    .severity,
    .message
  ]) | @csv'
```

### HTML Report

```bash
# Generate HTML from JSON
ocaml-crypto-linter src/ -f json | python3 -c "
import json, sys
data = json.load(sys.stdin)
print('<html><body>')
print(f'<h1>Crypto Lint Report</h1>')
print(f'<p>Found {data[\"summary\"][\"total_findings\"]} issues</p>')
for f in data['findings']:
    print(f'<div class=\"{f[\"severity\"]}\">')
    print(f'  <h3>{f[\"rule_id\"]}: {f[\"message\"]}</h3>')
    print(f'  <p>{f[\"location\"][\"file\"]}:{f[\"location\"][\"line\"]}</p>')
    print(f'</div>')
print('</body></html>')
" > report.html
```

### JUnit Format

For test runners:

```bash
# Convert to JUnit XML
ocaml-crypto-linter src/ -f json | python3 -c "
import json, sys
from xml.etree.ElementTree import Element, SubElement, tostring

data = json.load(sys.stdin)
testsuites = Element('testsuites')
testsuite = SubElement(testsuites, 'testsuite', 
    name='OCaml Crypto Linter',
    tests=str(data['summary']['files_analyzed']),
    failures=str(data['summary']['total_findings']))

for f in data['findings']:
    testcase = SubElement(testsuite, 'testcase',
        name=f['rule_id'],
        classname=f['location']['file'])
    failure = SubElement(testcase, 'failure',
        message=f['message'],
        type=f['severity'])
    failure.text = f'{f[\"location\"][\"file\"]}:{f[\"location\"][\"line\"]}'

print(tostring(testsuites, encoding='unicode'))
" > junit.xml
```

## Format Selection Guide

| Format | Use Case | Pros | Cons |
|--------|----------|------|------|
| Text | Human review, CLI | Readable, concise | Not machine-parseable |
| JSON | Automation, scripts | Flexible, complete data | Verbose |
| SARIF | IDE/GitHub integration | Standard format, rich metadata | Complex schema |

## Output Options

### Filtering

```bash
# Only show errors and above
ocaml-crypto-linter src/ --min-severity error

# Specific rules only
ocaml-crypto-linter src/ --rules KEY001,ALGO001

# Exclude files
ocaml-crypto-linter src/ --exclude "*_test.ml"
```

### Sorting

```bash
# Sort by severity (JSON)
ocaml-crypto-linter src/ -f json | jq '.findings | sort_by(.severity)'

# Group by file
ocaml-crypto-linter src/ -f json | jq '.findings | group_by(.location.file)'
```

### Summary Only

```bash
# Just the summary
ocaml-crypto-linter src/ --summary-only

# Exit code based on findings
ocaml-crypto-linter src/ || echo "Found issues: $?"
```

## Integration Examples

### Slack Notification

```bash
REPORT=$(ocaml-crypto-linter src/ -f json)
CRITICAL=$(echo "$REPORT" | jq '.summary.critical')

if [ "$CRITICAL" -gt 0 ]; then
  curl -X POST $SLACK_WEBHOOK -d "{
    \"text\": \"🚨 Critical crypto vulnerabilities found!\",
    \"attachments\": [{
      \"color\": \"danger\",
      \"fields\": [{
        \"title\": \"Critical Issues\",
        \"value\": \"$CRITICAL\",
        \"short\": true
      }]
    }]
  }"
fi
```

### Email Report

```python
#!/usr/bin/env python3
import json
import smtplib
from email.mime.text import MIMEText

with open('report.json') as f:
    report = json.load(f)

if report['summary']['critical'] > 0:
    body = f"""
    Crypto Security Scan Results
    
    Critical: {report['summary']['critical']}
    Errors: {report['summary']['errors']}
    
    Top issues:
    """
    for finding in report['findings'][:5]:
        body += f"\n- {finding['rule_id']}: {finding['message']}"
    
    msg = MIMEText(body)
    msg['Subject'] = 'Critical Crypto Vulnerabilities'
    msg['From'] = 'security@example.com'
    msg['To'] = 'team@example.com'
    
    # Send email...
```

## Best Practices

1. **Use SARIF for CI/CD** - Best integration with security tools
2. **JSON for automation** - Easy to parse and process
3. **Text for development** - Quick feedback during coding
4. **Archive reports** - Keep history of security findings
5. **Set up alerts** - Notify on critical findings immediately