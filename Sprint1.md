# ReleaseShield AI — Sprint 1 Detailed Technical Architecture Specification

**Component:** Sprint 1 End-to-End Orchestration & Ingestion CLI Engine

**Language/Runtime:** Python 3.10+ (Standard Library Focus)

**Primary Focus:** Repository scanning, SARIF v2.1.0 ingestion, deterministic category-aware fingerprinting, 2-level secret hashing, and normalized consolidation.

## 1. High-Level Architecture Diagram

```
                                  [ USER / CI RUNNER INVOCATION ]
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. CLI ENTRY POINT & ARGUMENT PARSER (`releaseshield_cli.py`)                                   │
│    - Validates `--repo <path>` directory existence                                             │
│    - Accepts optional `--output <file>` path (Default: `unified_findings.json`)                 │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. SUBPROCESS ORCHESTRATION ENGINE (`execute_scanners`)                                         │
│                                                                                                 │
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────┐  │
│  │ Semgrep (SAST)              │  │ Trivy (SCA/Dependencies)    │  │ Gitleaks (Secrets)      │  │
│  │ `semgrep scan --sarif ...`  │  │ `trivy fs --format sarif ...│  │ `gitleaks detect ...`   │  │
│  └──────────────┬──────────────┘  └──────────────┬──────────────┘  └────────────┬────────────┘  │
└─────────────────│────────────────────────────────│──────────────────────────────│───────────────┘
                  │ `semgrep_out.json`             │ `trivy_out.json`             │ `gitleaks_out.json`
                  └────────────────────────┬───────┴──────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. SARIF v2.1.0 INGESTION & PARSING ENGINE (`parse_sarif_file`)                                 │
│    - Safe JSON decoding & file presence validation                                              │
│    - Traverses `runs[].results[]`, `tool.driver.name`, and `locations[].physicalLocation`      │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 4. CATEGORY-AWARE DEDUPLICATION & HASHING ENGINE                                                │
│                                                                                                 │
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌─────────────────────────┐  │
│  │ SAST Stream                 │  │ SCA Dependency Stream       │  │ Secret Stream           │  │
│  │ Native `partialFingerprints`│  │ Synthetic Hash:             │  │ 2-Level Hashing:        │  │
│  │ OR Context Fallback Hash    │  │ `SHA256(Manifest||CVE)`     │  │ Global + Local Instance │  │
│  └──────────────┬──────────────┘  └──────────────┬──────────────┘  └────────────┬────────────┘  │
└─────────────────│────────────────────────────────│──────────────────────────────│───────────────┘
                  └────────────────────────┬───────┴──────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 5. UNIFIED CONSOLIDATION & OUTPUT ENGINE                                                        │
│    - Normalizes into unified JSON schema                                                        │
│    - Writes output to `unified_findings.json`                                                   │
│    - Displays real-time terminal execution metrics summary                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

```

## 2. Low-Level Component Specifications & Implementation Details

### Component 1: CLI Entry Point & Arguments Parser

* **Module:** `argparse` (Built-in)

* **Function:** `main()`

* **Input Parameters:**

  * `--repo` (string, required): Absolute or relative filesystem path to the target repository.

  * `--output` (string, optional): Destination path for consolidated output. Defaults to `unified_findings.json`.

* **Validation & Safety Checks:**

  1. Checks if the repository directory exists using `os.path.exists(repo_path)`. If it does not exist, logs an error and terminates execution immediately with exit status `1`.

  2. Ensures output directory path is writable before scanner execution.

### Component 2: Subprocess Scanner Orchestrator Engine

* **Module:** `subprocess` (Built-in)

* **Function:** `execute_scanners(repo_path: str)`

* **Execution Flow & Arguments:**

  1. **Semgrep (SAST Engine):**

     * Command: `semgrep scan --sarif --output semgrep_out.json <repo_path>`

     * Purpose: Scans for static code security patterns and code-level vulnerabilities.

  2. **Trivy (SCA / Dependency Engine):**

     * Command: `trivy fs --format sarif --output trivy_out.json <repo_path>`

     * Purpose: Scans repository manifests (`package.json`, `requirements.txt`, `pom.xml`) for known CVEs.

  3. **Gitleaks (Secrets Detection Engine):**

     * Command: `gitleaks detect --source <repo_path> --report-format sarif --report-path gitleaks_out.json`

     * Purpose: Identifies hardcoded API keys, JWT tokens, private keys, and passwords.

* **Error Handling & Resilience:**

  * Wraps scanner invocations in `subprocess.run(..., capture_output=True, text=True, check=False)`.

  * Accepts non-zero exit codes (since scanners like Gitleaks and Semgrep return non-zero codes when vulnerabilities are discovered).

  * Traps `FileNotFoundError` if a binary (e.g., `semgrep`) is missing from the host environment, logging a warning while allowing remaining scanners to proceed.

### Component 3: SARIF v2.1.0 Ingestion & Parser

* **Module:** `json` (Built-in)

* **Function:** `parse_sarif_file(file_path: str, scanner_type: str)`

* **Schema Navigation Logic:**

  * Opens the designated output JSON file.

  * Parses top-level JSON structure and extracts `runs` array.

  * Iterates over each run object to retrieve driver name from `run.tool.driver.name`.

  * Iterates over `results[]` array, extracting:

    * `ruleId`: Unique vulnerability identification code (e.g., `CVE-2023-1234` or `CWE-89`).

    * `message.text`: Human-readable summary of the issue.

    * `locations[0].physicalLocation.artifactLocation.uri`: Target file path or manifest path where the issue was detected.

### Component 4: Category-Aware Fingerprinting & Two-Level Secret Hashing Engine

* **Module:** `hashlib` (Built-in - `hashlib.sha256`)

* **Functions:** `process_sast_finding()`, `process_dependency_finding()`, `process_secret_finding()`

#### Category 1: SAST Code Fingerprint Logic (Semgrep)

1. **Primary Check:** Inspects `result.partialFingerprints.primaryLocationLineHash`. If present, uses this native hash directly.

2. **Fallback Mechanism (Context-Window Hash):** If native fingerprint is absent, extracts rule ID, file URI, and surrounding context message to generate a synthetic SHA-256 hash:
   

   $$
   \text{SAST Hash} = \text{SHA256}(\text{file\_path} \mathbin{\Vert} \text{rule\_id} \mathbin{\Vert} \text{message\_text})
   $$

#### Category 2: Dependency / SCA Fingerprint Logic (Trivy)

Trivy omits `partialFingerprints` in raw SARIF outputs. To prevent line drift issues across lockfiles:

1. Extracts `artifactLocation.uri` (e.g., `package-lock.json` or `go.sum`).

2. Extracts `ruleId` (e.g., `CVE-2021-44228`).

3. Computes a location-agnostic synthetic fingerprint:
   

   $$
   \text{SCA Hash} = \text{SHA256}(\text{manifest\_path} \mathbin{\Vert} \text{cve\_rule\_id})
   $$

#### Category 3: Two-Level Secret Hashing Logic (Gitleaks)

Protects raw secret exposure while enabling organization-wide tracking and localized cleanup:

1. **Level 1 — Global Secret Hash (Parent Record):**

   * Computes SHA-256 directly on the extracted secret payload string.

   * Purpose: Tracks credential revocation across all company repositories.
     

     $$
     \text{Global Secret Hash} = \text{SHA256}(\text{raw\_secret\_payload})
     $$

2. **Level 2 — Local Instance Hash (Child Record):**

   * Combines repo context, target file path, and global secret hash.

   * Purpose: Uniquely identifies the precise file location for remediation.
     

     $$
     \text{Local Instance Hash} = \text{SHA256}(\text{repo\_name} \mathbin{\Vert} \text{branch} \mathbin{\Vert} \text{file\_path} \mathbin{\Vert} \text{Global Secret Hash})
     $$

### Component 5: Unified Normalization & Output Schema

The CLI transforms diverse scanner schemas into a standardized JSON structure.

#### Normalized Finding Schema Output Example (`unified_findings.json`)

```
[
  {
    "tool": "semgrep",
    "ruleId": "python.lang.security.audit.eval-detected",
    "message": "Detected user input passing into eval(), presenting Remote Code Execution risk.",
    "targetLocation": "src/utils/parser.py",
    "computedFingerprint": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "metadata": {
      "filePath": "src/utils/parser.py"
    }
  },
  {
    "tool": "gitleaks",
    "ruleId": "aws-access-token",
    "message": "AWS Access Key ID detected in source code.",
    "targetLocation": "config/aws_credentials.py",
    "computedFingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "metadata": {
      "globalSecretHash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "localInstanceHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }
]

```

## 3. End-to-End Execution Sequence & How-To Guide

### Step 1: Pre-requisites & Environment Setup

Ensure Python 3.10+ and scanner binaries are available on your system path:

```
# Verify Python version
python3 --version

# Verify Security Scanners Availability (Optional - CLI handles missing binaries gracefully)
semgrep --version
trivy --version
gitleaks version

```

### Step 2: Executing the Orchestration CLI

Run the CLI engine by passing the target project repository path:

```
python3 releaseshield_cli.py --repo ./my-target-app --output unified_findings.json

```

### Step 3: Terminal Metric Output Verification

Upon execution completion, the engine logs execution metrics directly to `stdout`:

```
==================================================
   RELEASESHIELD AI: REPOSITORY ORCHESTRATION     
==================================================

==================================================
 TARGET REPOSITORY: ./my-target-app
==================================================
[⚙️] Running Semgrep SAST Scanner...
    [✓] Semgrep SAST Scanner completed successfully.
[⚙️] Running Trivy Dependency Scanner...
    [✓] Trivy Dependency Scanner completed successfully.
[⚙️] Running Gitleaks Secret Scanner...
    [✓] Gitleaks Secret Scanner completed successfully.

[+] Ingesting semgrep report from: semgrep_out.json
[✓] Successfully processed 4 findings.

[+] Ingesting trivy report from: trivy_out.json
[✓] Successfully processed 12 findings.

[+] Ingesting gitleaks report from: gitleaks_out.json
[✓] Successfully processed 2 findings.

[🚀] Pipeline Complete! Total Unified Findings: 18
[💾] Consolidated control plane data saved to: unified_findings.json

```
