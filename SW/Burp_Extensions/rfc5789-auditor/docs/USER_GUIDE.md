# User Guide

## Overview

The RFC 5789 Auditor is a Burp Suite extension that detects security vulnerabilities arising from ambiguities in the HTTP PATCH specification ([RFC 5789](https://datatracker.ietf.org/doc/html/rfc5789)). It implements 6 active checks covering Content-Type confusion, unauthorized resource creation, atomicity race conditions, WAF bypass, cache poisoning, and side-effect TOCTOU attacks.

The extension integrates with Burp's scanner (Professional edition) and provides a context menu action (both editions). All checks support two modes: **Safe** (canary payloads, no server-side impact) and **Aggressive** (real attack payloads).

## Extension Tabs

### Dashboard

Displays a summary of scan activity and findings. Shows:

- Total findings count grouped by severity (High, Medium, Low, Information)
- Current scan mode (Safe or Aggressive)
- Quick-action buttons for exporting reports

### Configuration

Controls scan behaviour:

- **Scan Mode toggle**: Switch between Safe and Aggressive mode
- **Enabled checks**: Toggle individual checks on or off (all 6 enabled by default)
- **Concurrent PATCH count**: Number of parallel requests for the atomicity check (AMB-03). Default: 10. Minimum: 2
- **Collaborator domain**: Configure a Burp Collaborator domain for out-of-band detection (Aggressive mode only, used by AMB-06)
- **Collaborator poll interval**: How often to poll for Collaborator interactions (default: 5000 ms)
- **Background Monitoring**: Toggle to auto-run active checks when PATCH traffic is observed. When enabled, each unique PATCH URL is audited once per session in a background thread. Works in both Community and Professional editions.
- **Export**: Buttons to export findings as JSON or Markdown reports.
- **Apply**: Button pinned at the bottom (always visible), applies all configuration changes.

### Side-Effect Monitor

Configuration for the AMB-02 (Side-Effect TOCTOU) check:

- **Target URL Pattern**: The URL that receives the PATCH request
- **Monitor Paths**: One or more URLs to GET before and after the PATCH to detect side effects
- Add multiple target/monitor pairs for complex API relationships

### Payloads

Shows the payload sets used by each check in the current mode:

- Safe mode payloads use `__rfc5789_*` canary prefixes
- Aggressive mode payloads use real attack strings (XSS, SQLi, SSTI, command injection, path traversal)
- WAF bypass payloads show both the full payload and the decomposed fragments

### Results

Detailed results table showing all findings:

- Check ID (AMB-XX)
- Finding title and severity
- Confidence level (Certain, Firm, Tentative)
- Timestamp
- Mode used when the finding was produced
- Expandable detail with full description, remediation, and HTTP evidence

## Mode Selection

### Safe Mode (default)

Use Safe mode when:

- Testing against **production** systems
- Performing **bug bounty** reconnaissance
- Running an **initial assessment** before requesting authorization for deeper testing
- You want **zero server-side impact** -- all payloads are inert canary strings

Safe mode payloads:
- Use the prefix `__rfc5789_` in all fields (e.g., `__rfc5789_ct_probe`, `__rfc5789_creation_probe`)
- Do not inject real attack strings
- Do not use Burp Collaborator
- Still detect differential behaviour, status code differences, and missing security controls

### Aggressive Mode

Use Aggressive mode when:

- Testing against **staging or test environments** with explicit authorization
- You need **confirmed exploitation** evidence (e.g., for a pentest report)
- Testing WAF bypass with real payloads (`<script>alert(document.domain)</script>`, `' OR 1=1--`, etc.)
- You want Collaborator-based out-of-band confirmation for cache poisoning

Aggressive mode will:
- Send real attack payloads that may create, modify, or delete server resources
- Use the original request body (rather than canary replacements) for some checks
- Inject Collaborator URLs for OOB detection
- Attempt to create real resources via PATCH to non-existent URLs

**Warning**: Aggressive mode can cause data modification. Only use against systems you are authorized to test.

## Running a Scan

### Burp Suite Professional -- Active Scan

1. Capture PATCH requests through the Proxy or identify them in the Target site map.
2. Right-click the target or request -> **Scan** -> **Active scan**.
3. The extension's checks run automatically as part of Burp's active scan pipeline.
4. Findings appear in Burp's **Issue activity** panel and in the extension's Results tab.

### Burp Suite Community or Professional -- Context Menu

1. Capture or craft a PATCH request (Proxy History, Repeater, or Target site map).
2. Right-click the PATCH request.
3. Select **Run RFC 5789 Audit**.
4. The extension runs all enabled checks against the selected request.
5. Findings appear in the extension's Results tab. Findings also appear in Burp's Dashboard Issues panel (with correct severity) and Target site map.

### Manual Workflow

For precise control:

1. Open a PATCH request in **Repeater**.
2. Ensure the request is well-formed with a valid `Content-Type` header.
3. Right-click -> **Run RFC 5789 Audit**.
4. Review findings in the Results tab.
5. Use Repeater to manually replay the evidence requests for verification.

## Interpreting Results

### Severity Levels

| Severity | Meaning |
|---|---|
| **High** | Confirmed vulnerability with direct security impact. Exploitation demonstrated or highly likely. |
| **Medium** | Likely vulnerability or compliance violation. May require manual verification or specific conditions. |
| **Low** | Informational finding. Potential side-effect paths discovered but no changes detected. |

### Confidence Levels

| Confidence | Meaning |
|---|---|
| **Certain** | Unambiguous evidence (e.g., 201 Created returned for resource creation on a non-existent URL). |
| **Firm** | Strong evidence from differential analysis or confirmed state changes. |
| **Tentative** | Behavioural anomaly detected but exploitation not confirmed. Manual investigation recommended. |

### Common Finding Patterns

- **"Differential Behaviour"**: The server responded differently to the same body with different Content-Type headers. This is a compliance violation and a potential attack vector.
- **"Confirmed (201 Created)"**: The server created a new resource via PATCH. This is a confirmed vulnerability.
- **"Partial Merge Detected"**: Concurrent PATCH requests resulted in a mixed state. Atomicity is broken.
- **"WAF Bypass - XSS (Confirmed)"**: The full XSS payload was blocked by the WAF, but the same payload split across sequential PATCHes was accepted.

## Configuring Side-Effect Monitoring (AMB-02)

The Side-Effect TOCTOU check works in two phases:

### Phase A: Automatic Heuristic Discovery

The check automatically generates sibling URLs from the PATCH target path. For example, if PATCHing `/api/users/123`, it will also GET:

- `/api/users/124`, `/api/users/122` (adjacent IDs)
- `/api/users/123/profile`, `/api/users/123/permissions`, `/api/users/123/settings`

It GETs these before and after the PATCH to detect changes.

### Phase B: Configured Pairs

For APIs where side effects are not discoverable by heuristic:

1. Open the **Side-Effect Monitor** tab.
2. Add a pair:
   - **Target URL Pattern**: `/api/groups/5` (the URL that receives the PATCH)
   - **Monitor Paths**: `/api/members/5`, `/api/audit-log/latest` (URLs to watch for changes)
3. When AMB-02 runs against a matching PATCH target, it GETs the monitor URLs before and after, comparing bodies and ETags.

Configure pairs for:
- Parent-child relationships (PATCH parent, child changes)
- Audit log entries created by PATCH operations
- Membership or role tables affected by group PATCHes
- Billing or quota records affected by resource PATCHes

## Using Collaborator Integration

Collaborator integration is used by the Cache Poisoning check (AMB-06) in **Aggressive mode only**.

### Setup

1. In Burp Professional, go to **Burp** -> **Collaborator client** to generate a Collaborator domain.
2. In the RFC 5789 Auditor **Configuration** tab, paste the Collaborator domain.
3. Set the poll interval (default: 5000 ms).
4. Switch to **Aggressive** mode.

### How It Works

The AMB-06 check injects a Collaborator URL into a PATCH body. It then GETs the resource and checks whether the Collaborator domain appears in the cached response. If it does, this confirms that:

1. The PATCH modified the resource.
2. The cache served the modified content to a subsequent GET.
3. An attacker-controlled URL is now embedded in the cached response.

## Exporting Reports

From the Dashboard or Results tab:

- **JSON export**: Machine-readable format including all finding metadata, severity, confidence, evidence request/response pairs, and timestamps.
- **Markdown export**: Human-readable report suitable for inclusion in pentest deliverables. Includes finding descriptions, remediation guidance, and evidence summaries.

## Best Practices

### Bug Bounty Programs

1. Always use **Safe mode** for initial reconnaissance.
2. Review the program's scope and rules regarding automated scanning.
3. Safe mode payloads are designed to be inert -- they use `__rfc5789_*` prefixed field names that have no server-side meaning.
4. Export findings in Markdown for clean report submission.
5. If the program allows active testing, switch to Aggressive mode only against explicitly in-scope endpoints.

### Authorized Penetration Tests

1. Start with **Safe mode** to map the attack surface and identify which checks produce findings.
2. Switch to **Aggressive mode** for confirmed exploitation against staging or pre-production environments.
3. Configure side-effect pairs (AMB-02) based on API documentation or prior reconnaissance.
4. Set up Collaborator for cache poisoning confirmation (AMB-06).
5. Use the JSON export for integration with your reporting pipeline.
6. Document the mode used for each finding -- the extension records this in the finding metadata.

### CI/CD Integration

The extension can be driven via Burp's REST API (Professional 2023.1+) or by scripting the context menu action. Pair it with the test harness for regression testing:

```bash
cd test-harness
python integration_test.py
```

This validates that all 6 checks produce the expected findings against the intentionally vulnerable endpoints.
