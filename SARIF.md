# Understanding SARIF Output

## 1. What Is SARIF?

**SARIF (Static Analysis Results Interchange Format)** is a standard JSON-based format used to represent results from static analysis and security scanning tools.

In this project, SARIF outputs from **Trivy, Semgrep, and Gitleaks** can be combined into a unified report for parsing and displaying security findings.

## 2. Basic SARIF Structure

A SARIF log has two required top-level properties:

- `version` — specifies the SARIF format version, commonly `"2.1.0"`.
- `runs` — an array containing analysis runs.

The `$schema` property is optional.

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Semgrep"
        }
      },
      "results": []
    }
  ]
}
```

This is a simplified example; actual reports may contain additional properties.

## 3. Runs, Tools, and Rules

### `runs`

Each item in `runs` represents an analysis run. A run requires a `tool` object identifying the scanner.

### `tool`

The `tool` object describes the scanner through its `driver` and, optionally, other tool components.

Important fields include:

- `driver.name` — required tool name.
- `driver.version` — optional scanner version.
- `driver.rules` — optional array of rule definitions.

### `rules`

Rules describe the types of issues a scanner can detect.

**Important:** A rule definition does not prove that an issue was detected. Actual findings are represented by entries in the `results` array.

## 4. Results and Findings

The `results` property is optional and contains reported findings when present. Every result object requires a `message`.

| Property | Purpose |
|---|---|
| `message` | Required description of the finding. |
| `ruleId` | Identifies the rule associated with the finding. |
| `level` | Reporting level, commonly `error`, `warning`, or `note`. |
| `locations` | Identifies where the issue was detected, when available. |
| `fingerprints` | Helps identify and track findings across scans. |
| `partialFingerprints` | Provides partial identifying information for findings. |
| `suppressions` | Describes suppressions applied to a finding. |
| `fixes` | Contains suggested fixes, when provided. |
| `properties` | Holds additional tool-specific information. |

These properties are optional unless otherwise specified by the SARIF schema.

### Reporting level vs. security severity

SARIF `level` and security severity are not necessarily the same.

- `level`: `error`, `warning`, or `note`.
- Security severity: values such as `HIGH`, `MEDIUM`, or `LOW`, often supplied through tool-specific metadata.

Do not assume that a SARIF reporting level directly represents a vulnerability's security severity.

## 5. Locations

A result may contain a `locations` array describing where an issue was found.

Important location fields include:

- `physicalLocation.artifactLocation.uri` — the affected file or artifact.
- `physicalLocation.region.startLine` — starting line.
- `physicalLocation.region.startColumn` — starting column.
- `physicalLocation.region.endLine` — ending line.
- `physicalLocation.region.endColumn` — ending column.
- `physicalLocation.region.snippet` — optional text from the relevant region.

Location details are optional. Some findings, such as certain container-image or configuration findings, may not correspond to a specific source-code line.

## 6. Fingerprints and Partial Fingerprints

Both `fingerprints` and `partialFingerprints` are optional properties of a result.

### `fingerprints`

Fingerprints help identify a finding across repeated scans. They can support tracking recurring findings and identifying potential duplicates.

### `partialFingerprints`

Partial fingerprints provide identifying information that can help correlate findings when a complete fingerprint is unavailable or differs between tools.

Example:

```json
{
  "ruleId": "example-rule",
  "message": {
    "text": "Example security finding"
  },
  "fingerprints": {
    "exampleFingerprint": "abc123"
  },
  "partialFingerprints": {
    "primaryLocationLineHash": "def456"
  }
}
```

The fingerprint names and values above are illustrative only. Actual keys and calculation methods depend on the scanner.

**Important:** Do not assume that all scanners generate the same fingerprints or use identical fingerprinting algorithms.

## 7. Can `results` Be Empty or Missing?

Yes. A scanner that detects no issues may produce an empty array:

```json
{
  "tool": {
    "driver": {
      "name": "Semgrep"
    }
  },
  "results": []
}
```

A SARIF run may also omit the `results` property.

However, a missing `results` property does not prove that the scan succeeded or found zero issues. The output could be incomplete, or the scan might have failed.

## 8. Determining Whether a Scan Is Done

A scanner should not be marked **Done** merely because its executable is installed or an output file exists.

The application should verify that:

1. The scanner was actually executed.
2. Execution completed and the exit status was handled correctly.
3. Output was generated and parsed successfully.
4. The output has the expected SARIF structure.
5. Findings were extracted when present.
6. A valid scan with zero findings is recognized as a successful outcome.

Track **execution status separately from finding count**.

Suggested application statuses:

| Status | Meaning |
|---|---|
| `Done` | Scan completed successfully and its output was validated, including when no findings were detected. |
| `Scanning` | The scan is still running. |
| `Failed` | Scanner execution failed. |
| `Unable to verify results` | Output is missing, invalid, or incomplete, so successful completion cannot be confirmed. |

An empty `results` array can represent a successful scan. However, the application should confirm successful execution and valid output before marking the scanner as Done.

## 9. Key Takeaways

- SARIF is a standard format for exchanging static-analysis results.
- `version` and `runs` are required at the root level.
- A run requires `tool`, and the tool's `driver` requires `name`.
- Every result requires a `message`.
- The `results` property itself is optional.
- Rules describe possible issues; results represent reported findings.
- `fingerprints` and `partialFingerprints` help identify and correlate findings across scans.
- Locations and line information are optional.
- An empty `results` array can be a valid outcome.
- Missing results do not automatically mean a scan succeeded.
- Validate scanner execution and output before displaying `Done`.

## References

- [OASIS SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- [Official SARIF 2.1.0 JSON Schema](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json)
