# RFC 5789 Auditor

**Burp Suite extension for detecting and exploiting ambiguities in HTTP PATCH ([RFC 5789](https://datatracker.ietf.org/doc/html/rfc5789)) implementations.**

Open source | [Apache 2.0 License](LICENSE)

---

## What This Does

RFC 5789 defines the HTTP PATCH method, but its specification contains deliberate ambiguities -- places where the RFC uses SHOULD instead of MUST, or leaves behaviour entirely to the implementor. These ambiguities produce real, exploitable vulnerabilities when web frameworks make different assumptions about how PATCH should work.

This extension implements the **RFC Vulnerability Research Methodology (RVRM)**: systematically extracting each ambiguity from the RFC text, mapping it to a concrete attack vector, and building automated detection for it. We identified 12 ambiguities in RFC 5789; 6 of them produce exploitable security issues across major web frameworks including Spring Data REST, Django REST Framework, ASP.NET Web API, Express.js, and Laravel.

The RFC 5789 Auditor automates detection of these 6 vulnerability classes. It operates as both a passive observer (flagging compliance issues in existing PATCH traffic) and an active scanner (sending targeted probes to confirm exploitability). Every check has a **Safe mode** that uses canary payloads with no server-side impact, and an **Aggressive mode** that uses real attack payloads for confirmed exploitation.

## Checks

| ID | Check | Severity | Vector |
|---|---|---|---|
| AMB-04 | Content-Type Confusion | High | JSON Patch vs Merge Patch type confusion |
| AMB-01 | Resource Creation via PATCH | High | ACL bypass via auto-create on non-existent resources |
| AMB-03 | Atomicity Race Condition | High | Data corruption via concurrent PATCH without transactions |
| AMB-11 | WAF Bypass via PATCH Decomposition | Medium-High | Split attack payloads across sequential PATCHes |
| AMB-06 | Cache Poisoning via PATCH | Medium-High | CDN/proxy serves stale data after PATCH |
| AMB-02 | Side-Effect TOCTOU | Medium-High | Authorization bypass via unchecked side-effect resources |

See [docs/CHECKS.md](docs/CHECKS.md) for detailed documentation of each check.

## Features

- **Two operational modes**: Safe Scan (canary payloads only) and Aggressive Exploit (real payloads)
- **Works with both Burp editions**: Professional (active scan integration) and Community (context menu)
- **Passive detection**: Flags RFC 5789 compliance issues in existing PATCH traffic without sending additional requests
- **Active probing**: 6 targeted checks that send crafted PATCH requests to confirm vulnerabilities
- **Burp Collaborator integration**: Out-of-band detection for cache poisoning (AMB-06) in Aggressive mode
- **Side-effect monitoring**: Configurable URL pairs for detecting TOCTOU conditions (AMB-02)
- **Concurrent race testing**: Configurable parallelism for atomicity checks (AMB-03, default 10 threads)
- **Background monitoring**: Always-on PATCH traffic detection with optional auto-active-check that audits every observed PATCH endpoint automatically (deduplicated per session)
- **Burp Dashboard integration**: Active findings appear in Burp's native Dashboard Issues panel with correct HIGH/MEDIUM severity via queue-drain bridge
- **JSON and Markdown report export**: Export findings for inclusion in pentest reports
- **Vulnerable test harness**: Flask application with intentional vulnerabilities for validation and development

## Quick Start

```bash
# 1. Build the extension
git clone https://github.com/rfc5789-auditor/rfc5789-auditor.git
cd rfc5789-auditor
./gradlew fatJar

# 2. Load in Burp Suite
#    Burp -> Extensions -> Installed -> Add
#    Extension type: Java
#    Extension file: build/libs/rfc5789-auditor-1.0.0.jar

# 3. Start the test harness (optional, for validation)
cd test-harness
pip install -r requirements.txt
python harness.py
# Harness runs on http://localhost:5789

# 4. Run a scan
#    In Burp, send a PATCH request to http://localhost:5789/api/users/1
#    Right-click the request -> "Run RFC 5789 Audit"
```

## Installation

### Prerequisites

- **Burp Suite** Community or Professional (2023.1+, Montoya API)
- **JDK 17** (build from source only)
- **Gradle 8+** (build from source only; or use the included wrapper)

### Option A: Pre-built JAR

Download `rfc5789-auditor-1.0.0.jar` from the [Releases](https://github.com/rfc5789-auditor/rfc5789-auditor/releases) page.

### Option B: Build from source

```bash
git clone https://github.com/rfc5789-auditor/rfc5789-auditor.git
cd rfc5789-auditor
./gradlew fatJar
```

The JAR is produced at `build/libs/rfc5789-auditor-1.0.0.jar`.

### Loading in Burp Suite

1. Open Burp Suite
2. Go to **Extensions** -> **Installed** -> **Add**
3. Set **Extension type** to **Java**
4. Select the JAR file
5. Click **Next** -- the Output tab should show the startup banner:

```
============================================================
  RFC 5789 Auditor v1.0.0
  by RFC 5789 Auditor Contributors
============================================================
```

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for detailed installation and troubleshooting.

## Usage

### Safe Mode vs Aggressive Mode

| | Safe Mode (default) | Aggressive Mode |
|---|---|---|
| **Payloads** | Canary strings (`__rfc5789_*`) | Real attack payloads |
| **Server impact** | None -- canary fields are inert | May create, modify, or delete resources |
| **Use case** | Production, bug bounty, initial recon | Staging, authorized pentests, CTFs |
| **Collaborator** | Not used | Used for OOB detection (AMB-06) |

Switch modes in the extension's Configuration tab.

### Running Checks

**Burp Suite Professional:**
- Active scan any PATCH request -- the extension's checks run automatically alongside Burp's built-in active scan checks.

**Burp Suite Community (or manual):**
- Right-click any PATCH request in Proxy, Repeater, or Target -> **Run RFC 5789 Audit**

### Test Harness

The included Flask application exposes intentionally vulnerable endpoints for all 6 checks:

```bash
cd test-harness
pip install -r requirements.txt
python harness.py          # Starts on http://localhost:5789
python integration_test.py # Automated validation
```

See [test-harness/README.md](test-harness/README.md) for endpoint details.

## Building from Source

```bash
# Prerequisites: JDK 17, Gradle (or use the wrapper)
git clone https://github.com/rfc5789-auditor/rfc5789-auditor.git
cd rfc5789-auditor
./gradlew fatJar
# Output: build/libs/rfc5789-auditor-1.0.0.jar

# Run tests
./gradlew test
```

## Research Background

This extension is the automated tooling output of a systematic analysis of [RFC 5789 (PATCH Method for HTTP)](https://datatracker.ietf.org/doc/html/rfc5789) using the **RFC Vulnerability Research Methodology (RVRM)**. The methodology works by:

1. **Extracting ambiguities** -- identifying every SHOULD, MAY, undefined, or implementation-dependent clause in the RFC
2. **Mapping to attack vectors** -- determining which ambiguities produce exploitable behaviour when frameworks make different choices
3. **Building automated detection** -- creating two-phase checks (safe fingerprint, then aggressive confirmation) for each vector
4. **Validating across frameworks** -- testing against Spring Data REST, Django REST Framework, ASP.NET Web API, Express.js, Laravel, and others

This process identified 12 ambiguities in RFC 5789. Six produce confirmed security vulnerabilities, which are the 6 checks implemented in this extension.

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)

## License

Apache License 2.0 -- See [LICENSE](LICENSE)
