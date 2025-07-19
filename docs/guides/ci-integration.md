# CI/CD Integration Guide

Integrate OCaml Crypto Linter into your continuous integration pipeline to catch vulnerabilities early.

## GitHub Actions

### Basic Setup

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  crypto-lint:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup OCaml
        uses: ocaml/setup-ocaml@v3
        with:
          ocaml-compiler: 5.2.x
      
      - name: Install OCaml Crypto Linter
        run: opam install ocaml-crypto-linter
      
      - name: Run Security Scan
        run: |
          ocaml-crypto-linter . -f sarif -o results.sarif
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Advanced Configuration

```yaml
name: Comprehensive Security Check

on: [push, pull_request]

jobs:
  crypto-security:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup OCaml
        uses: ocaml/setup-ocaml@v3
        with:
          ocaml-compiler: 5.2.x
          cache-prefix: crypto-lint-v1
      
      - name: Cache OPAM
        uses: actions/cache@v4
        with:
          path: ~/.opam
          key: ${{ runner.os }}-opam-${{ hashFiles('*.opam') }}
      
      - name: Install Dependencies
        run: |
          opam install ocaml-crypto-linter semgrep
      
      - name: Run Crypto Linter
        id: crypto-lint
        run: |
          ocaml-crypto-linter src/ lib/ -f json -o report.json --semgrep
          
          # Extract summary for PR comment
          CRITICAL=$(jq '.summary.critical // 0' report.json)
          HIGH=$(jq '.summary.errors // 0' report.json)
          echo "critical=$CRITICAL" >> $GITHUB_OUTPUT
          echo "high=$HIGH" >> $GITHUB_OUTPUT
      
      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const critical = ${{ steps.crypto-lint.outputs.critical }};
            const high = ${{ steps.crypto-lint.outputs.high }};
            
            const comment = `## 🔒 Crypto Security Scan Results
            
            ${critical > 0 ? '❌' : '✅'} Critical: ${critical}
            ${high > 0 ? '⚠️' : '✅'} High: ${high}
            
            <details>
            <summary>View Details</summary>
            
            \`\`\`json
            ${require('fs').readFileSync('report.json', 'utf8')}
            \`\`\`
            </details>`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
      
      - name: Fail on Critical
        if: steps.crypto-lint.outputs.critical > 0
        run: |
          echo "❌ Critical cryptographic vulnerabilities found!"
          exit 1
```

### Docker-based CI

```yaml
name: Docker Security Scan

on: [push, pull_request]

jobs:
  docker-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Crypto Linter in Docker
        run: |
          docker run --rm -v ${{ github.workspace }}:/workspace \
            ghcr.io/shaikko/ocaml-crypto-linter:latest \
            /workspace -f sarif -o /workspace/results.sarif
      
      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## GitLab CI

### Basic `.gitlab-ci.yml`

```yaml
stages:
  - security

crypto-lint:
  stage: security
  image: ocaml/opam:ubuntu-ocaml-5.2
  before_script:
    - opam install ocaml-crypto-linter
  script:
    - ocaml-crypto-linter . -f json -o crypto-report.json
  artifacts:
    reports:
      crypto: crypto-report.json
    paths:
      - crypto-report.json
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

### With Security Dashboard

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml

crypto-security:
  stage: test
  image: ocaml/opam:ubuntu-ocaml-5.2
  script:
    - opam install ocaml-crypto-linter
    - ocaml-crypto-linter . -f sarif -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Jenkins

### Jenkinsfile

```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                sh 'opam install ocaml-crypto-linter'
            }
        }
        
        stage('Crypto Security Scan') {
            steps {
                sh 'ocaml-crypto-linter . -f json -o crypto-report.json'
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'crypto-report.json',
                    reportName: 'Crypto Security Report'
                ])
            }
        }
        
        stage('Check Results') {
            steps {
                script {
                    def report = readJSON file: 'crypto-report.json'
                    if (report.summary.critical > 0) {
                        error("Critical cryptographic vulnerabilities found!")
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'crypto-report.json'
        }
    }
}
```

## CircleCI

### `.circleci/config.yml`

```yaml
version: 2.1

jobs:
  crypto-security:
    docker:
      - image: ocaml/opam:ubuntu-ocaml-5.2
    steps:
      - checkout
      - restore_cache:
          keys:
            - opam-{{ checksum "*.opam" }}
            - opam-
      - run:
          name: Install Crypto Linter
          command: opam install ocaml-crypto-linter
      - save_cache:
          key: opam-{{ checksum "*.opam" }}
          paths:
            - ~/.opam
      - run:
          name: Run Security Scan
          command: |
            ocaml-crypto-linter . -f json -o report.json
            cat report.json | jq '.summary'
      - store_artifacts:
          path: report.json
      - run:
          name: Check for Critical Issues
          command: |
            CRITICAL=$(cat report.json | jq '.summary.critical')
            if [ "$CRITICAL" -gt 0 ]; then
              echo "Critical vulnerabilities found!"
              exit 1
            fi

workflows:
  security:
    jobs:
      - crypto-security
```

## Travis CI

### `.travis.yml`

```yaml
language: minimal
os: linux
dist: focal

before_install:
  - sudo apt-get update
  - sudo apt-get install -y opam
  - opam init --disable-sandboxing -y
  - eval $(opam env)
  - opam switch create 5.2.0
  - eval $(opam env)

install:
  - opam install ocaml-crypto-linter

script:
  - ocaml-crypto-linter . -f json -o report.json
  - |
    CRITICAL=$(jq '.summary.critical' report.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi

after_success:
  - cat report.json | jq '.summary'
```

## Azure DevOps

### `azure-pipelines.yml`

```yaml
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UseOpam@0
  inputs:
    version: '2.x'
    
- script: |
    opam init -y
    eval $(opam env)
    opam install ocaml-crypto-linter
  displayName: 'Install OCaml Crypto Linter'
  
- script: |
    eval $(opam env)
    ocaml-crypto-linter . -f sarif -o $(Build.ArtifactStagingDirectory)/crypto-scan.sarif
  displayName: 'Run Crypto Security Scan'
  
- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)'
    artifactName: 'security-reports'
    
- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '**/crypto-scan.sarif'
```

## Integration Best Practices

### 1. Fail Fast Strategy

```yaml
# Fail immediately on critical issues
- run: |
    ocaml-crypto-linter . -f json | \
    jq -e '.summary.critical == 0' || \
    (echo "Critical crypto vulnerabilities!" && exit 1)
```

### 2. Gradual Enforcement

```yaml
# Warning phase (don't fail build)
- run: |
    ocaml-crypto-linter . -f json -o report.json || true
    
# After fixing issues, enforce
- run: |
    ocaml-crypto-linter . --severity-threshold error
```

### 3. Caching for Speed

```yaml
# Cache OPAM and dependencies
- uses: actions/cache@v4
  with:
    path: |
      ~/.opam
      _opam
    key: ${{ runner.os }}-opam-${{ hashFiles('**/*.opam') }}
```

### 4. Parallel Analysis

```yaml
# Run on different parts in parallel
- run: |
    ocaml-crypto-linter src/ -o src-report.json &
    ocaml-crypto-linter lib/ -o lib-report.json &
    wait
```

### 5. Custom Configuration

```yaml
# Use CI-specific config
- run: |
    OCAML_CRYPTO_LINTER_CONFIG=.crypto-linter.ci.json \
    ocaml-crypto-linter .
```

## Notifications

### Slack Integration

```yaml
- name: Notify Slack
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: custom
    custom_payload: |
      {
        text: "🚨 Crypto vulnerabilities found in ${{ github.ref }}",
        attachments: [{
          color: 'danger',
          text: 'Critical issues detected by OCaml Crypto Linter'
        }]
      }
```

### Email Notifications

```yaml
- name: Send Email Alert
  if: steps.crypto-lint.outputs.critical > 0
  uses: dawidd6/action-send-mail@v3
  with:
    to: security@example.com
    subject: Critical Crypto Vulnerabilities
    body: |
      Critical cryptographic vulnerabilities found in ${{ github.repository }}
      View details: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
```

## Security Gates

### Pull Request Protection

```yaml
# Require approval for crypto changes
- name: Require Security Review
  if: |
    contains(github.event.pull_request.files.*.filename, 'crypto') ||
    contains(github.event.pull_request.files.*.filename, 'auth')
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.pulls.requestReviewers({
        owner: context.repo.owner,
        repo: context.repo.repo,
        pull_number: context.issue.number,
        team_reviewers: ['security-team']
      });
```

## Monitoring

### Track Metrics Over Time

```yaml
- name: Record Metrics
  run: |
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    CRITICAL=$(jq '.summary.critical' report.json)
    HIGH=$(jq '.summary.errors' report.json)
    
    echo "$TIMESTAMP,$CRITICAL,$HIGH" >> metrics.csv
    
    # Store in artifact for trending
```

## Troubleshooting CI Issues

1. **Timeout Issues**
   ```yaml
   timeout-minutes: 30  # Increase for large codebases
   ```

2. **Memory Issues**
   ```yaml
   env:
     OCAML_CRYPTO_LINTER_MAX_MEMORY: 2048  # MB
   ```

3. **Flaky Tests**
   ```yaml
   retry:
     max-attempts: 2
     when: runner-error
   ```