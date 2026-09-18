# Contributing to RFC 5789 Auditor

Thank you for your interest in contributing. This guide covers the process for reporting bugs, suggesting improvements, and submitting code changes.

## Reporting Bugs

1. Check the [existing issues](https://github.com/rfc5789-auditor/rfc5789-auditor/issues) to avoid duplicates.
2. Open a new issue with:
   - Burp Suite version (Community or Professional, version number)
   - Extension version
   - Steps to reproduce
   - Expected vs actual behaviour
   - Extension Output and Errors tab content (if applicable)
   - Target framework (if relevant to a specific check)

## Suggesting New Checks

We track potential new checks as issues with the `new-check` label. When proposing a new check:

1. Identify the **RFC ambiguity** or specification gap that enables the vulnerability.
2. Provide the **RFC section reference** and quote the relevant text.
3. Describe the **attack vector** -- how does an attacker exploit this ambiguity?
4. List **affected frameworks** (with version numbers if known).
5. Propose both a **Safe mode** approach (canary/fingerprint) and an **Aggressive mode** approach (real payload).
6. If possible, provide a proof-of-concept request sequence.

## Code Style

- **Java 17**: Use Java 17 language features (records, sealed classes, text blocks) where appropriate.
- **Montoya API**: All Burp Suite integration uses the [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/). Do not use the legacy `IBurpExtenderCallbacks` API.
- **No external dependencies**: The extension ships as a single JAR with no runtime dependencies beyond the Montoya API (which is provided by Burp). The `montoya-api` dependency is `compileOnly`. Do not add libraries like Gson, Jackson, OkHttp, or Apache Commons.
- **Thread safety**: Check implementations must be stateless and thread-safe. Use the `PatchCheck` interface contract. Shared mutable state belongs in `AuditorConfig` (synchronized) or `FindingsStore` (CopyOnWriteArrayList). FindingsStore also contains a `ConcurrentLinkedQueue<AuditIssue>` (`pendingBurpIssues`) used to bridge active findings from the context menu and traffic monitor into Burp's Dashboard Issues panel via the passive scan check's `auditResult()` drain.
- **Javadoc**: All public classes, methods, and constants require Javadoc. Include `@param`, `@return`, and `@throws` tags.
- **Naming**: Check classes are named `<Description>Check.java` and placed in `com.rfc5789.auditor.checks`. Use the `AMB-XX` identifier consistently in the class, Javadoc, and findings.
- **SiteMap integration**: `ManualScanAction` and `PatchTrafficMonitor` accept a `SiteMap` parameter. They call `siteMap.add(issue)` to push findings to Burp's Target site map, and `store.queueBurpIssue(issue)` to push findings to Burp's Dashboard Issues panel. Individual `PatchCheck` implementations do not need to handle this -- the check pipeline manages routing.
- **UI wiring**: `ConfigurationTab.setSiblingTabs(DashboardTab, PayloadsTab)` is called by `MainTabGroup` to wire mode indicator refresh when the user clicks Apply.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Write or update tests** for your changes. The project uses JUnit 5 (`org.junit.jupiter`).
3. **Run the full build and tests**:

   ```bash
   ./gradlew clean build test
   ```

4. **Run the test harness** to verify end-to-end behaviour:

   ```bash
   cd test-harness
   pip install -r requirements.txt
   python integration_test.py
   ```

5. **Update documentation** if your change affects:
   - Check behaviour (update `docs/CHECKS.md`)
   - Configuration options (update `docs/USER_GUIDE.md`)
   - Build process (update `docs/INSTALLATION.md`)
   - The check list (update `README.md`)

6. **Submit the PR** against `main` with a description that includes:
   - What the change does
   - Which AMB-XX check(s) it affects (if any)
   - Test results (build output, integration test output)

7. A maintainer will review the PR. Expect feedback on code style, test coverage, and documentation.

## Adding a New Check

1. Create a new class in `src/main/java/com/rfc5789/auditor/checks/` implementing the `PatchCheck` interface.
2. Implement all four methods: `id()`, `name()`, `description()`, and `run()`.
3. Register the check in `RFC5789Auditor.initialize()` by adding it to the `activeChecks` list.
4. Add a constant and name entry in `AuditorConfig` for the new check index.
5. Add a corresponding vulnerable endpoint to the test harness (`test-harness/harness.py`).
6. Add an integration test case to `test-harness/integration_test.py`.
7. Document the check in `docs/CHECKS.md`.
8. Update the checks table in `README.md`.

## Adding New Payload Classes for AMB-11

The WAF Bypass check (AMB-11) supports multiple payload classes. To add a new class:

1. Open `WafBypassCheck.java`.
2. Add the class name to the `PAYLOAD_CLASSES` array.
3. Add the full payload to both `SAFE_FULL` and `AGGRESSIVE_FULL`.
4. Add the split payload fragments to both `SAFE_PARTS` and `AGGRESSIVE_PARTS`. Each split should produce fragments that are individually benign but malicious when reassembled.
5. Ensure array indices are consistent across all four arrays.
6. Add a corresponding test case in the test harness that blocks the full payload (via a simple keyword filter) but accepts the fragments.

Example -- adding an LDAP injection payload class:

```java
// PAYLOAD_CLASSES
"LDAPi"

// SAFE_FULL
"rfc5789-ldapi-canary)(|(cn=*)"

// SAFE_PARTS
{"rfc5789-ldapi-", "canary)(|(cn=*)"}

// AGGRESSIVE_FULL
"*)(|(objectClass=*)"

// AGGRESSIVE_PARTS
{"*)(|", "(objectClass=*)"}
```

## Running the Test Harness

The test harness is a Flask application in `test-harness/` that exposes intentionally vulnerable endpoints for all 6 checks. Always run the integration tests before submitting a PR:

```bash
cd test-harness
pip install -r requirements.txt
python integration_test.py
```

Expected output:

```
[PASS] AMB-04: Content-Type Confusion
[PASS] AMB-01: Resource Creation via PATCH
[PASS] AMB-03: Atomicity Race Condition
[PASS] AMB-11: WAF Bypass via PATCH Decomposition
[PASS] AMB-06: Cache Poisoning via PATCH
[PASS] AMB-02: Side-Effect TOCTOU
```

If any test fails, the exit code will be 1.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](../LICENSE).
