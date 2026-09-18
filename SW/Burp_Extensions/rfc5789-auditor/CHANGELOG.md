# Changelog

All notable changes to the RFC 5789 Auditor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-01

### Added

- Initial release of the RFC 5789 Auditor Burp Suite extension.
- **AMB-04: Content-Type Confusion** -- Detects differential behaviour when the same PATCH body is sent with different Content-Type headers (`application/json-patch+json`, `application/merge-patch+json`, `application/json`). Detects cross-format confusion where body format does not match the declared Content-Type.
- **AMB-01: Resource Creation via PATCH** -- Tests whether PATCH to non-existent resource URLs results in resource creation (201 Created or 2xx with follow-up GET confirmation).
- **AMB-03: Atomicity Race Condition** -- Fires concurrent PATCH requests to detect partial merge (atomicity violation) and missing conflict detection (no 409 responses).
- **AMB-11: WAF Bypass via PATCH Decomposition** -- Tests whether attack payloads (XSS, SQLi, SSTI, command injection, path traversal) split across sequential PATCHes bypass WAF or input filtering.
- **AMB-06: Cache Poisoning via PATCH** -- Detects stale cache responses after a successful PATCH by comparing ETags, X-Cache headers, response bodies, and Age headers before and after the PATCH. Includes Collaborator-based confirmation in Aggressive mode.
- **AMB-02: Side-Effect TOCTOU** -- Detects side effects on sibling or related resources after a PATCH, using both heuristic sibling discovery and user-configured monitoring pairs.
- **Two scan modes**: Safe (canary payloads, no server impact) and Aggressive (real payloads, Collaborator integration).
- **Passive scan check**: Detects RFC 5789 compliance issues in existing PATCH traffic (missing Accept-Patch header, generic Content-Types).
- **Active scan check**: Integrates with Burp Suite Professional's active scanner.
- **Context menu action**: "Run RFC 5789 Audit" available in both Community and Professional editions.
- **Thread-safe findings store** with PropertyChangeListener support for UI updates.
- **Configurable concurrency** for the atomicity check (default: 10 concurrent PATCHes).
- **Side-effect pair configuration** for targeted TOCTOU detection.
- **Burp Collaborator integration** for out-of-band cache poisoning confirmation.
- **Vulnerable test harness**: Flask application with intentionally vulnerable endpoints for all 6 checks.
- **Integration test suite**: Automated validation of all checks against the test harness.
- **Always-on background traffic monitor** (PatchTrafficMonitor) via HttpHandler for passive PATCH detection.
- **Auto-active-check toggle** for automatic background auditing of observed PATCH endpoints (deduplicated per session).
- **Queue-drain bridge** routing active findings to Burp's Dashboard Issues panel via the passive scan check's `auditResult()` drain.
- **Resource creation check (AMB-01)** attempts DELETE cleanup after confirmed creation.
- **WAF bypass check (AMB-11)** includes same-field reassembly test and follow-up GET verification.
- **Content-Type confusion check (AMB-04)** uses 0.95 Jaccard similarity threshold for body comparison.
- **Atomicity race check (AMB-03)** merges canary fields into original request body.
- **SiteMap integration** pushes findings to Burp's Target site map.
- **Extension unload handler** shuts down background executors.
- **Configuration tab Apply button** pinned outside scroll area for visibility.

### Technical

- Built with Java 17 and the Burp Suite Montoya API (2025.4).
- Zero external runtime dependencies -- single fat JAR deployment.
- All check implementations are stateless and thread-safe via the `PatchCheck` interface.

[1.0.0]: https://github.com/rfc5789-auditor/rfc5789-auditor/releases/tag/v1.0.0
