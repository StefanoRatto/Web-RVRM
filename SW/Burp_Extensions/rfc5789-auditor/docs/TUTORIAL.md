# RFC 5789 Auditor -- Hands-On Tutorial

**A step-by-step walkthrough for first-time users.**

This tutorial walks you through installing the extension, exploring every feature, running your first audit against a local vulnerable test harness, interpreting the results, and enabling always-on background monitoring. By the end, you will have verified every capability of the extension and be ready to use it against real targets.

**Time required**: 30-45 minutes

**Prerequisites**:
- Burp Suite Community or Professional (any recent version)
- Python 3.10+ with Flask (`pip install flask`)
- The built extension JAR (`rfc5789-auditor-1.0.0.jar`)
- A terminal for running curl commands

---

## Table of Contents

1. [Start the Vulnerable Test Harness](#step-1-start-the-vulnerable-test-harness)
2. [Install the Extension in Burp Suite](#step-2-install-the-extension-in-burp-suite)
3. [Explore the Extension UI](#step-3-explore-the-extension-ui)
4. [Send Baseline Traffic Through Burp](#step-4-send-baseline-traffic-through-burp)
5. [Send PATCH Requests Through Burp](#step-5-send-patch-requests-through-burp)
6. [Run Your First Active Audit (Context Menu)](#step-6-run-your-first-active-audit)
7. [Audit Every Vulnerable Endpoint](#step-7-audit-every-vulnerable-endpoint)
8. [Interpret the Results](#step-8-interpret-the-results)
9. [Enable Background Monitoring](#step-9-enable-background-monitoring)
10. [Export a Report](#step-10-export-a-report)
11. [Switch to Aggressive Mode (Authorized Targets Only)](#step-11-switch-to-aggressive-mode)
12. [Clean Up](#step-12-clean-up)
13. [Quick Reference Card](#quick-reference-card)
14. [What To Do Next](#what-to-do-next)

---

## Step 1: Start the Vulnerable Test Harness

The extension ships with a Flask-based test harness that intentionally exhibits all 6 vulnerabilities the extension detects. Start it first so it's ready when Burp needs a target.

Open a terminal and run:

```bash
cd rfc5789-auditor/test-harness
pip install flask
python3 harness.py
```

You should see a startup banner listing all endpoints:

```
============================================================
  RFC 5789 Auditor - Vulnerable Test Harness
  Running on http://localhost:5789
============================================================
  AMB-04  PATCH /api/users/{id}      Content-Type Confusion
  AMB-01  PATCH /api/items/{id}      Resource Creation
  AMB-03  PATCH /api/counters/{id}   Atomicity Race Condition
  AMB-11  PATCH /api/comments/{id}   WAF Bypass
  AMB-06  PATCH /api/cached/{id}     Cache Poisoning
  AMB-02  PATCH /api/groups/{id}     Side-Effect TOCTOU
============================================================
```

Verify it's running:

```bash
curl -s http://localhost:5789/api/health
```

Expected response:

```json
{"status": "ok", "version": "1.0.0"}
```

**Leave this terminal open.** The harness must keep running throughout the tutorial.

---

## Step 2: Install the Extension in Burp Suite

1. Open Burp Suite (Community or Professional)
2. Go to the **Extensions** tab in the top menu bar
3. Click **Installed** in the left panel
4. Click the **Add** button
5. In the dialog:
   - Extension type: **Java**
   - Extension file: Click **Select file...** and navigate to:
     ```
     rfc5789-auditor/build/libs/rfc5789-auditor-1.0.0.jar
     ```
6. Click **Next**

### What You Should See

The **Output** tab at the bottom of the Extensions panel displays:

```
[RFC5789] Passive scan check registered.
[RFC5789] Active scan check registered.
[RFC5789] Context menu provider registered.
[RFC5789] Traffic monitor registered (always-on PATCH detection).
[RFC5789] UI tab group registered.

============================================================
  RFC 5789 Auditor v1.0.0
  by RFC 5789 Auditor Contributors
============================================================
  PATCH Method Security & Compliance Scanner
------------------------------------------------------------
  Passive checks : Enabled (detects missing headers,
                   generic Content-Types, missing Accept-Patch)
  Active checks  : Enabled (Burp Pro) / Context menu (Community)
  Default mode   : SAFE (canary payloads only)
------------------------------------------------------------
  Right-click any PATCH request -> 'Run RFC 5789 Audit'
============================================================
```

A new tab appears in Burp's top tab bar: **RFC 5789 Auditor**.

### Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| "Error loading extension" | Wrong Java version | Burp must run on Java 17+. Check Burp's startup config. |
| Output tab shows stack trace | API incompatibility | Verify you built against Montoya API 2025.4 |
| No new tab appears | Extension loaded but UI failed | Check the Errors tab in Extensions for details |

---

## Step 3: Explore the Extension UI

Click the **RFC 5789 Auditor** tab. You'll see 5 sub-tabs. Take a moment to understand each one before running any scans.

### Tab 1: Dashboard

Your command center. Three sections:

- **Top**: Large mode indicator. Shows **SAFE MODE** (green background). This means the extension uses canary payloads only -- no real exploitation.
- **Middle**: Findings summary table with 9 rows -- 6 active checks (AMB-04, AMB-01, AMB-03, AMB-11, AMB-06, AMB-02) and 3 passive checks (PASSIVE-01, PASSIVE-02, PASSIVE-03). All counts are zero initially.
- **Bottom**: Status log. Timestamped messages appear here as the extension observes traffic and runs checks. Currently shows the initialization message.

### Tab 2: Configuration

Controls for the extension. Do not change anything yet -- just read.

- **Scan Mode**: Dropdown to switch between SAFE and AGGRESSIVE. Currently SAFE.
- **Enabled Checks**: 6 checkboxes, all checked. Each corresponds to one vulnerability check.
- **Background Monitoring**: "Auto-run active checks when PATCH traffic is observed" -- currently OFF. You will enable this in Step 9.
- **Concurrency**: Number of parallel PATCHes for the race condition check. Default 10.
- **Collaborator**: For Burp Pro out-of-band detection. Leave empty for now.
- **Export**: Buttons to export findings as JSON or Markdown.
- **Apply**: Pinned at the bottom. Always visible.

### Tab 3: Side-Effect Monitor

For AMB-02 (Side-Effect TOCTOU detection). Shows an empty table where you define pairs of "target URL" and "monitor paths." When a PATCH hits the target, the extension GETs the monitor paths before and after to detect unauthorized side-effect modifications. You will configure this in Step 7.

### Tab 4: Payloads

A reference view of the WAF bypass payloads used by AMB-11:

- **Left panel**: Click through payload classes (XSS, SQLi, SSTI, CmdInj, PathTraversal)
- **Right panel**: Shows how each payload is split for decomposition attacks, with both the Safe canary version and the Aggressive real version

This tab is view-only. It helps you understand what the WAF bypass check sends.

### Tab 5: Results

Empty initially. Findings appear here as checks run. You can filter by check ID and severity, and click any row to see the full detail including HTTP request/response evidence.

---

## Step 4: Send Baseline Traffic Through Burp

Now you need to route traffic through Burp's proxy so the extension can see it.

### 4.1 Prepare the Proxy

1. Go to Burp's **Proxy** tab
2. Click the **Intercept** sub-tab
3. Make sure the button says **"Intercept is off"**. If it says "Intercept is on", click it to turn it off. (You want traffic to flow through without being held.)
4. Confirm the proxy listener is active on `127.0.0.1:8080` (check Proxy -> Proxy settings -> Proxy listeners)

### 4.2 Send Baseline GETs

Open a **new terminal** (keep the harness terminal running) and send GET requests through the proxy to establish baseline resource states:

```bash
# Baseline GET for each endpoint
curl -s -x http://127.0.0.1:8080 http://localhost:5789/api/users/1
curl -s -x http://127.0.0.1:8080 http://localhost:5789/api/items/1
curl -s -x http://127.0.0.1:8080 http://localhost:5789/api/counters/1
curl -s -x http://127.0.0.1:8080 http://localhost:5789/api/comments/1
curl -s -x http://127.0.0.1:8080 http://localhost:5789/api/cached/1
curl -s -x http://127.0.0.1:8080 http://localhost:5789/api/groups/1
curl -s -x http://127.0.0.1:8080 http://localhost:5789/api/members/10
```

Each command should return JSON data. For example:

```json
{"email":"alice@example.com","id":1,"name":"Alice","role":"user"}
```

### 4.3 Verify in Burp

Go to **Proxy -> HTTP history**. You should see 7 GET requests to `localhost:5789`.

The extension's Dashboard status log should be quiet -- GETs don't trigger PATCH monitoring.

---

## Step 5: Send PATCH Requests Through Burp

Now send PATCH requests. These are the requests the extension will detect and audit.

Run each command in your terminal:

```bash
# AMB-04 target: Content-Type Confusion
curl -s -x http://127.0.0.1:8080 \
  -X PATCH http://localhost:5789/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice Updated"}'

# AMB-01 target: Resource Creation
curl -s -x http://127.0.0.1:8080 \
  -X PATCH http://localhost:5789/api/items/1 \
  -H "Content-Type: application/json" \
  -d '{"name": "Widget Updated"}'

# AMB-03 target: Atomicity Race Condition
curl -s -x http://127.0.0.1:8080 \
  -X PATCH http://localhost:5789/api/counters/1 \
  -H "Content-Type: application/json" \
  -d '{"value": 1, "label": "hits"}'

# AMB-11 target: WAF Bypass
curl -s -x http://127.0.0.1:8080 \
  -X PATCH http://localhost:5789/api/comments/1 \
  -H "Content-Type: application/json" \
  -d '{"text": "Updated comment"}'

# AMB-06 target: Cache Poisoning
curl -s -x http://127.0.0.1:8080 \
  -X PATCH http://localhost:5789/api/cached/1 \
  -H "Content-Type: application/json" \
  -d '{"data": "modified"}'

# AMB-02 target: Side-Effect TOCTOU
curl -s -x http://127.0.0.1:8080 \
  -X PATCH http://localhost:5789/api/groups/1 \
  -H "Content-Type: application/json" \
  -d '{"name": "Security Team"}'

# Trigger PASSIVE-03: OPTIONS without Accept-Patch
curl -s -x http://127.0.0.1:8080 \
  -X OPTIONS http://localhost:5789/api/users/1
```

### What Happens Immediately

Three things fire for each PATCH request:

1. **Passive checks** (Burp Pro): The extension flags each PATCH for:
   - PASSIVE-01: Missing `If-Match` header (all 6 PATCHes)
   - PASSIVE-02: Generic `Content-Type: application/json` instead of patch-specific type (all 6 PATCHes)

2. **Traffic monitor**: The Dashboard status log shows a line for each PATCH:
   ```
   PATCH #1 observed: http://localhost:5789/api/users/1 [200]
   PATCH #2 observed: http://localhost:5789/api/items/1 [200]
   ...
   ```

3. **No active checks yet** -- background monitoring is OFF and you haven't right-clicked anything. Active checks require a manual trigger at this point.

### Verify in Burp

- **Proxy -> HTTP history**: You should now see 14 requests (7 GETs + 6 PATCHes + 1 OPTIONS)
- **Dashboard tab**: Status log shows 6 PATCH observations. Summary table may show PASSIVE findings.
- **Burp Issues panel** (Pro only): Passive findings for missing conditional headers and generic Content-Type

---

## Step 6: Run Your First Active Audit

Now the main event. You'll right-click a PATCH request and run the full 6-check vulnerability audit.

### 6.1 Audit the Users Endpoint (AMB-04)

1. Go to **Proxy -> HTTP history**
2. Find the PATCH request to `/api/users/1`
3. **Right-click** on it
4. Click **"Run RFC 5789 Audit"**

### 6.2 Watch the Dashboard

Switch to the **RFC 5789 Auditor -> Dashboard** tab. The status log shows real-time progress:

```
Running RFC 5789 Audit on http://localhost:5789/api/users/1
[AMB-04] Content-Type Confusion: running...
[AMB-04] Content-Type Confusion: 2 issues found
[AMB-01] Resource Creation via PATCH: running...
[AMB-03] Atomicity Race Condition: running...
...
Audit complete: N total issues
```

The audit takes 10-30 seconds. The race condition check (AMB-03) is the slowest because it sends 10 parallel requests and waits for all responses.

### 6.3 Check Results

Go to the **Results** tab. You should see new findings, including:

| Check | Title | Severity | What It Means |
|---|---|---|---|
| AMB-04 | Content-Type Confusion - Cross-Format Accepted | MEDIUM | Server accepted a JSON Patch array body with merge-patch Content-Type |
| AMB-04 | Content-Type Confusion - Cross-Format Accepted (Reverse) | MEDIUM | Server accepted a merge-patch body with JSON Patch Content-Type |
| AMB-03 | Atomicity Race Condition - Partial Merge Detected | HIGH | Concurrent PATCHes merged data from multiple requests -- atomicity MUST violated |

Click any finding row to see the full detail in the panel below, including the HTTP request/response evidence.

---

## Step 7: Audit Every Vulnerable Endpoint

Repeat the right-click audit for each remaining PATCH request. Before auditing the groups endpoint, configure a side-effect monitoring pair for stronger AMB-02 detection.

### 7.1 Configure Side-Effect Monitoring (Before Auditing Groups)

1. Go to **RFC 5789 Auditor -> Side-Effect Monitor** tab
2. In the "Target URL Pattern" field, enter: `/api/groups/1`
3. In the "Monitor Paths" field, enter: `/api/members/10,/api/members/11`
4. Click **Add**

The table now shows one row. This tells the extension: "When a PATCH hits `/api/groups/1`, also check whether `/api/members/10` and `/api/members/11` changed."

### 7.2 Audit Each Endpoint

Go to **Proxy -> HTTP history** and right-click -> "Run RFC 5789 Audit" on each PATCH:

| PATCH Target | Primary Check | What to Expect |
|---|---|---|
| `/api/items/1` | AMB-01 | HIGH: Extension PATCHes `/api/items/99999999` (non-existent), server returns 201 Created. Confirms unauthorized resource creation. |
| `/api/counters/1` | AMB-03 | HIGH: 10 concurrent PATCHes all succeed without 409 Conflict. Partial merge detected. |
| `/api/comments/1` | AMB-11 | HIGH: Full XSS canary payload blocked by WAF (403), but split fragments accepted (200). Confirmed WAF bypass. |
| `/api/cached/1` | AMB-06 | MEDIUM: ETag unchanged after PATCH -- stale cache confirmed. |
| `/api/groups/1` | AMB-02 | HIGH: Configured monitor paths `/api/members/10` and `/api/members/11` show changed `group_name` field after the PATCH. Confirmed side-effect without authorization check. |

Each audit takes 10-30 seconds. You can audit multiple endpoints in sequence without waiting -- findings accumulate in the Results tab.

---

## Step 8: Interpret the Results

After auditing all 6 endpoints, go to the **Results** tab. You should see 40-60 findings.

### Understanding Severity Levels

| Severity | Meaning | Action |
|---|---|---|
| **HIGH** | Confirmed vulnerability with demonstrated impact | Report immediately. Include the evidence from the finding detail. |
| **MEDIUM** | Confirmed differential behavior or weakness, exploitation plausible | Investigate further. May need manual verification to confirm exploitability. |
| **LOW** | Potential issue or informational indicator | Note for completeness. Low priority unless it chains with another finding. |

### Understanding Finding Types

**Findings you'll see from the test harness:**

| Finding Title | What It Proves |
|---|---|
| Content-Type Confusion - Cross-Format Accepted | The server interprets the same body differently based on Content-Type. An attacker can send a body designed for one format with a different format's Content-Type to trigger unintended behavior. |
| Atomicity Race Condition - Partial Merge Detected | Concurrent PATCHes produced a resource state containing data from multiple requests. The server does not enforce atomic PATCH application, violating RFC 5789's MUST requirement. |
| WAF Bypass via PATCH Decomposition - XSS (Confirmed) | The WAF blocks the full XSS payload in a single request, but accepts the payload split across two sequential PATCHes. The WAF inspects each PATCH independently and does not track accumulated state. |
| WAF Bypass via PATCH Decomposition - XSS (No WAF Detected) | The endpoint accepted both the full payload and the split fragments. No WAF was detected on this endpoint. Not a bypass -- just an observation that the endpoint has no WAF. |
| Cache Poisoning via PATCH - Stale Cache | The cache did not invalidate after a successful PATCH. Subsequent GETs return pre-PATCH data. If the PATCH modified security-relevant fields (roles, permissions), clients receive stale authorization data. |
| Side-Effect TOCTOU - Confirmed Side-Effect (Configured) | PATCHing the target resource silently modified the monitored resources without an authorization check on those resources. |

### Filtering and Exploring

- Use the **Check** dropdown to filter by a specific AMB ID (e.g., "AMB-11" to see only WAF bypass findings)
- Use the **Severity** dropdown to show only HIGH findings
- Click any row to see the **Finding Detail** panel with:
  - Full vulnerability description with RFC section references
  - Remediation recommendation
  - HTTP request/response evidence

---

## Step 9: Enable Background Monitoring

So far, every active check was triggered manually via right-click. Now enable always-on monitoring so the extension audits PATCH requests automatically.

1. Go to **RFC 5789 Auditor -> Configuration** tab
2. Check the box: **"Auto-run active checks when PATCH traffic is observed"**
3. Click **Apply**
4. Confirm the "Configuration applied successfully" dialog

### How It Works

With background monitoring enabled:

- Every PATCH request that flows through Burp's proxy is automatically detected
- Each unique PATCH URL is audited once per session (deduplicated to avoid noise)
- Active checks run in a background thread -- your browsing is not slowed down
- Findings appear in the Dashboard and Results tabs automatically
- The Dashboard status log shows auto-check activity in real time

### Test It

Send a PATCH to a URL the extension has never seen:

```bash
# Create a new resource first
curl -s -X PATCH http://localhost:5789/api/items/50 \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Item", "price": 5.00}'

# Now send through Burp's proxy -- auto-check should trigger
curl -s -x http://127.0.0.1:8080 \
  -X PATCH http://localhost:5789/api/items/50 \
  -H "Content-Type: application/json" \
  -d '{"name": "Auto-Detected Item", "price": 99.99}'
```

Watch the **Dashboard status log**. Within seconds you should see:

```
PATCH #N observed: http://localhost:5789/api/items/50 [200]
Auto-active-check queued for: http://localhost:5789/api/items/50 (mode: SAFE)
[AUTO] Content-Type Confusion found N issue(s) on http://localhost:5789/api/items/50
[AUTO] Resource Creation via PATCH found N issue(s) on http://localhost:5789/api/items/50
...
Auto-check complete for http://localhost:5789/api/items/50: N total issues
```

No right-click needed. The extension found vulnerabilities automatically.

### When to Use Background Monitoring

| Scenario | Background Monitoring | Manual Audit |
|---|---|---|
| Browsing a target to discover PATCH endpoints | ON -- catches everything automatically | -- |
| Focused testing of a specific endpoint | Optional | Right-click for immediate results |
| Bug bounty recon | ON -- zero-effort coverage | Right-click interesting endpoints |
| Authorized pentest | ON with AGGRESSIVE mode | Right-click + configured side-effect pairs |

---

## Step 10: Export a Report

Export your findings for documentation, bug bounty submissions, or pentest deliverables.

### Markdown Report

1. Go to **RFC 5789 Auditor -> Configuration** tab
2. Click **Export Markdown**
3. Choose a save location and filename (e.g., `rfc5789-report.md`)

The Markdown report includes:
- Summary table (findings per check and severity)
- Detailed findings with RFC section references
- Remediation recommendations
- HTTP request/response evidence

### JSON Report

1. Click **Export JSON** instead
2. Save as `rfc5789-report.json`

The JSON report is structured for machine consumption. Use it to:
- Feed findings into other tools or dashboards
- Diff findings between assessment runs
- Automate reporting pipelines

### Export from Results Tab

You can also export a filtered view:

1. Go to the **Results** tab
2. Set filters (e.g., Check: AMB-11, Severity: HIGH)
3. Click the **Export** button at the top
4. Only the filtered findings are exported

---

## Step 11: Switch to Aggressive Mode (Authorized Targets Only)

SAFE mode uses canary payloads that prove the mechanism works without causing real impact. AGGRESSIVE mode uses real exploitation payloads.

**Only use AGGRESSIVE mode when you have explicit written authorization.**

### Switching Modes

1. Go to **Configuration** tab
2. Change Mode dropdown to **AGGRESSIVE**
3. Click **Apply**
4. A warning dialog appears:
   ```
   AGGRESSIVE mode sends real payloads that may create, modify,
   or delete resources.

   Only use this against test/staging environments.

   Switch to AGGRESSIVE mode?
   ```
5. Click **Yes** to confirm

### What Changes in Aggressive Mode

| Check | Safe Mode | Aggressive Mode |
|---|---|---|
| AMB-04 | Canary field: `__rfc5789_ct_probe` | Attempts to set `role: admin` |
| AMB-01 | Creates resource with probe body | Creates resource with original body content |
| AMB-03 | Same (race conditions are observational) | Same |
| AMB-11 | Inert canary: `<rfc5789-xss-canary>` | Real payload: `<script>alert(document.domain)</script>` |
| AMB-06 | Canary cache value | Collaborator URL injection (if configured) |
| AMB-02 | Observes side effects only | Modifies PATCH body to maximize side effects |

The Dashboard mode indicator turns **red: "AGGRESSIVE MODE"** as a constant visual reminder.

### Switch Back

After aggressive testing, always switch back:

1. Configuration tab -> Mode: **SAFE** -> **Apply**
2. Dashboard indicator returns to green: "SAFE MODE"

---

## Step 12: Clean Up

When you're done with the tutorial:

### Stop the Test Harness

Go to the terminal running `harness.py` and press `Ctrl+C`. Or from any terminal:

```bash
pkill -f "python3 harness.py"
```

### Unload the Extension (Optional)

To unload without removing:
1. Go to **Extensions -> Installed**
2. Uncheck the checkbox next to "RFC 5789 Auditor"

To remove completely:
1. Select the extension
2. Click **Remove**

---

## Quick Reference Card

| Action | How |
|---|---|
| **Start test harness** | `cd test-harness && python3 harness.py` (runs on :5789) |
| **Install extension** | Extensions -> Add -> Java -> select `rfc5789-auditor-1.0.0.jar` |
| **Manual audit** | Right-click any PATCH in HTTP history -> "Run RFC 5789 Audit" |
| **Enable auto-monitoring** | Configuration tab -> check "Auto-run active checks" -> Apply |
| **Switch to Aggressive** | Configuration tab -> Mode: AGGRESSIVE -> Apply -> Confirm |
| **Configure side-effects** | Side-Effect Monitor tab -> add Target URL + Monitor Paths -> Add |
| **View findings** | Results tab -> filter by check / severity -> click row for detail |
| **Export report** | Configuration tab -> "Export JSON" or "Export Markdown" |
| **Rebuild JAR** | `cd rfc5789-auditor && ./gradlew fatJar` |
| **Run integration tests** | `cd test-harness && python3 integration_test.py` |

---

## What To Do Next

### Test Against Real Targets

1. Point Burp at your target application (configure browser proxy or use Burp's embedded browser)
2. Enable background monitoring in the Configuration tab
3. Browse the application normally -- use every feature that sends PATCH requests
4. Watch the Dashboard for auto-detected findings
5. Right-click specific PATCH endpoints for deeper manual audits
6. For APIs with known resource relationships, configure side-effect pairs

### Recommended Testing Workflow

```
1. Recon:      Browse the target with background monitoring ON
               Let the extension auto-detect PATCH endpoints
               Review passive findings in the Dashboard

2. Targeted:   Right-click the most interesting PATCH endpoints
               Configure side-effect pairs for known resource relationships
               Review active findings in the Results tab

3. Deep dive:  For confirmed findings, switch to AGGRESSIVE mode
               Re-run the audit on confirmed-vulnerable endpoints
               Capture exploitation evidence for your report

4. Report:     Export findings as Markdown or JSON
               Include the request/response evidence from each finding
               Reference the RFC 5789 section for each vulnerability
```

### Understanding False Positives

| Finding | Common False Positive Cause | How to Verify |
|---|---|---|
| Content-Type Confusion | Dynamic response content (timestamps, CSRF tokens) causes body diff | Check if the actual resource state changed, not just response metadata |
| Resource Creation | Server returns 200 for non-existent resource without actually creating it | Send a GET to the probe URL -- if 404, it wasn't created |
| Atomicity Race | API legitimately accepts concurrent updates to different fields | Check if the same field was corrupted, not just different fields updated |
| WAF Bypass (No WAF) | Endpoint simply has no WAF -- fragments accepted because nothing blocks them | Not a false positive, but not a bypass either. Only "Confirmed" findings indicate actual bypass. |
| Cache Poisoning | CDN returns same ETag for content-addressed resources where the PATCH was a no-op | Verify the PATCH actually changed a field, then check if stale data is served |
| Side-Effect TOCTOU (Heuristic) | Background process or another client modified the sibling resource | Repeat the test multiple times. Consistent changes correlated with PATCH = real side-effect. |

---

*For detailed documentation on each check, see [CHECKS.md](CHECKS.md). For configuration options, see [USER_GUIDE.md](USER_GUIDE.md). For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).*
