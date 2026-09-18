/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.rfc5789.auditor.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.Finding;
import com.rfc5789.auditor.model.FindingsStore;
import com.rfc5789.auditor.model.ScanMode;
import com.rfc5789.auditor.util.PatchRequestHelper;
import com.rfc5789.auditor.util.ResponseDiff;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * AMB-11: WAF Bypass via PATCH Decomposition check.
 *
 * <p>Tests whether a Web Application Firewall (WAF) or input filter can
 * be bypassed by decomposing an attack payload across multiple sequential
 * PATCH requests. Each individual PATCH carries an innocuous fragment
 * that is only malicious when the fragments are reassembled in the
 * server-side resource state.</p>
 */
public final class WafBypassCheck implements PatchCheck {

    private static final String ID = "AMB-11";
    private static final String NAME = "WAF Bypass via PATCH Decomposition";
    private static final String DESCRIPTION =
            "Tests whether attack payloads split across sequential PATCH "
                    + "requests can bypass WAF or input filtering.";

    private static final String REMEDIATION =
            "WAFs and input filters should inspect the cumulative resource "
                    + "state, not just individual request payloads. Server-side "
                    + "output encoding and context-aware sanitisation should be "
                    + "applied regardless of how data arrives.";

    /** Payload class names for reporting. */
    private static final String[] PAYLOAD_CLASSES = {
            "XSS", "SQLi", "SSTI", "CmdInj", "PathTraversal"
    };

    /** Safe canary payloads (full). */
    private static final String[] SAFE_FULL = {
            "<rfc5789-xss-canary>",
            "rfc5789-sqli-canary' OR",
            "{{rfc5789-ssti-canary}}",
            "; rfc5789-cmdi-canary",
            "../../rfc5789-path-canary"
    };

    /** Safe canary payloads split into parts. */
    private static final String[][] SAFE_PARTS = {
            {"<rfc5789-", "xss-canary>"},
            {"rfc5789-sqli-", "canary' OR"},
            {"{{rfc5789-", "ssti-canary}}"},
            {"; rfc5789-", "cmdi-canary"},
            {"../../", "rfc5789-path-canary"}
    };

    /** Aggressive real payloads (full). */
    private static final String[] AGGRESSIVE_FULL = {
            "<script>alert(document.domain)</script>",
            "' OR 1=1-- ",
            "{{7*7}}",
            "; cat /etc/passwd",
            "../../etc/passwd"
    };

    /** Aggressive real payloads split into parts. */
    private static final String[][] AGGRESSIVE_PARTS = {
            {"<script>alert(", "document.domain)</script>"},
            {"' OR ", "1=1-- "},
            {"{{7", "*7}}"},
            {"; cat ", "/etc/passwd"},
            {"../../", "etc/passwd"}
    };

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String description() {
        return DESCRIPTION;
    }

    @Override
    public List<AuditIssue> run(HttpRequestResponse baseReqResp,
                                Http http,
                                AuditorConfig config,
                                FindingsStore store) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpRequest baseReq = baseReqResp.request();
        String baseUrl = baseReq.url();
        ScanMode mode = config.getCurrentMode();

        // Identify a target text field from the original PATCH body for same-field tests
        String targetField = findStringField(baseReq.bodyToString());

        String[] fullPayloads = mode == ScanMode.SAFE ? SAFE_FULL : AGGRESSIVE_FULL;
        String[][] splitPayloads = mode == ScanMode.SAFE ? SAFE_PARTS : AGGRESSIVE_PARTS;

        HttpRequest getReq = PatchRequestHelper.buildGetRequest(baseReq);

        for (int p = 0; p < PAYLOAD_CLASSES.length; p++) {
            String payloadClass = PAYLOAD_CLASSES[p];
            String fullPayload = fullPayloads[p];
            String[] parts = splitPayloads[p];

            List<HttpRequestResponse> evidence = new ArrayList<>();
            evidence.add(baseReqResp);

            // Send the full (unsplit) payload as a single PATCH
            String fullBody = "{\"waf_test_field\": \"" + escapeJson(fullPayload) + "\"}";
            HttpRequest fullReq = PatchRequestHelper.withBody(baseReq, fullBody);
            HttpRequestResponse fullRR = http.sendRequest(fullReq);
            HttpResponse fullResp = fullRR.response();
            evidence.add(fullRR);

            boolean fullBlocked = isWafBlocked(fullResp);

            // --- Test 1: Send fragments to separate fields (tests per-request WAF inspection) ---
            boolean allPartsSucceeded = true;
            for (int i = 0; i < parts.length; i++) {
                String partBody = "{\"waf_test_part_" + i + "\": \""
                        + escapeJson(parts[i]) + "\"}";
                HttpRequest partReq = PatchRequestHelper.withBody(baseReq, partBody);
                HttpRequestResponse partRR = http.sendRequest(partReq);
                evidence.add(partRR);

                if (!ResponseDiff.isSuccess(partRR.response())) {
                    allPartsSucceeded = false;
                }
            }

            // --- Test 2: Send fragments to the SAME field sequentially ---
            boolean sameFieldPartsSucceeded = true;
            for (int i = 0; i < parts.length; i++) {
                String sameFieldBody = "{\"" + escapeJson(targetField) + "\": \""
                        + escapeJson(parts[i]) + "\"}";
                HttpRequest sameFieldReq = PatchRequestHelper.withBody(baseReq, sameFieldBody);
                HttpRequestResponse sameFieldRR = http.sendRequest(sameFieldReq);
                evidence.add(sameFieldRR);

                if (!ResponseDiff.isSuccess(sameFieldRR.response())) {
                    sameFieldPartsSucceeded = false;
                }
            }

            // --- Test 3: GET the resource and check if the full payload is present ---
            HttpRequestResponse getAfterSplit = http.sendRequest(getReq);
            evidence.add(getAfterSplit);
            HttpResponse getResp = getAfterSplit.response();
            String getBody = getResp != null ? getResp.bodyToString() : "";
            if (getBody == null) {
                getBody = "";
            }

            boolean fullPayloadInResponse = getBody.contains(fullPayload);
            boolean anyPartInResponse = false;
            for (String part : parts) {
                if (getBody.contains(part)) {
                    anyPartInResponse = true;
                    break;
                }
            }

            if (fullBlocked && allPartsSucceeded) {
                if (fullPayloadInResponse) {
                    // CERTAIN: full payload reconstructed in resource state
                    String detail = "WAF bypass confirmed for " + payloadClass + " payload. "
                            + "The full payload was blocked (HTTP " + statusOrUnknown(fullResp)
                            + ") but the same payload split across " + parts.length
                            + " sequential PATCH requests was accepted by the server. "
                            + "A follow-up GET confirmed the full payload is now present "
                            + "in the resource state. An attacker can decompose malicious "
                            + "payloads across multiple PATCH operations to evade WAF detection.";

                    AuditIssue issue = auditIssue(
                            NAME + " - " + payloadClass + " (Confirmed, Payload Persisted)",
                            detail,
                            REMEDIATION,
                            baseUrl,
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.CERTAIN,
                            "PATCH semantics allow partial updates. If a WAF only "
                                    + "inspects individual requests, split payloads will "
                                    + "each appear benign while the assembled state is malicious.",
                            null,
                            AuditIssueSeverity.HIGH,
                            evidence);
                    issues.add(issue);

                    store.addFinding(new Finding(
                            ID, NAME + " - " + payloadClass + " (Confirmed, Payload Persisted)",
                            detail, REMEDIATION, AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.CERTAIN,
                            evidence, System.currentTimeMillis(), mode));

                } else {
                    // FIRM: fragments accepted but full payload not verified in GET
                    String detail = "WAF bypass likely for " + payloadClass + " payload. "
                            + "The full payload was blocked (HTTP " + statusOrUnknown(fullResp)
                            + ") but the same payload split across " + parts.length
                            + " sequential PATCH requests was accepted by the server. "
                            + (anyPartInResponse
                            ? "A follow-up GET found payload fragments in the response body."
                            : "A follow-up GET did not find the full payload in the response, "
                                    + "but the server accepted the split requests without WAF blocking.")
                            + " An attacker may be able to decompose malicious payloads across "
                            + "multiple PATCH operations to evade WAF detection.";

                    AuditIssue issue = auditIssue(
                            NAME + " - " + payloadClass + " (Fragments Accepted)",
                            detail,
                            REMEDIATION,
                            baseUrl,
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.FIRM,
                            "PATCH semantics allow partial updates. If a WAF only "
                                    + "inspects individual requests, split payloads will "
                                    + "each appear benign while the assembled state is malicious.",
                            null,
                            AuditIssueSeverity.HIGH,
                            evidence);
                    issues.add(issue);

                    store.addFinding(new Finding(
                            ID, NAME + " - " + payloadClass + " (Fragments Accepted)",
                            detail, REMEDIATION, AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.FIRM,
                            evidence, System.currentTimeMillis(), mode));
                }

            } else if (allPartsSucceeded && !fullBlocked) {
                String detail = "Split " + payloadClass + " payload accepted. "
                        + "The full payload was also accepted (HTTP "
                        + statusOrUnknown(fullResp) + "), so no WAF block was "
                        + "observed. However, the server accepts payload fragments "
                        + "via sequential PATCH requests, which could bypass "
                        + "future WAF deployments or content filters.";

                AuditIssue issue = auditIssue(
                        NAME + " - " + payloadClass + " (No WAF Detected)",
                        detail,
                        REMEDIATION,
                        baseUrl,
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.TENTATIVE,
                        null, null,
                        AuditIssueSeverity.MEDIUM,
                        evidence);
                issues.add(issue);

                store.addFinding(new Finding(
                        ID, NAME + " - " + payloadClass + " (No WAF Detected)",
                        detail, REMEDIATION,
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.TENTATIVE,
                        evidence, System.currentTimeMillis(), mode));
            }
        }

        return issues;
    }

    /**
     * Finds the first string-valued field name in a JSON object body.
     * Uses simple parsing (no JSON library dependency) -- looks for
     * {@code "key": "value"} patterns. Returns a default if no suitable
     * field is found or the body is not a JSON object.
     */
    private static String findStringField(String body) {
        if (body == null || body.isBlank()) {
            return "text";
        }
        String trimmed = body.trim();
        if (!trimmed.startsWith("{")) {
            return "text";
        }
        // Simple regex to find "key": "value" patterns
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "\"([^\"]+)\"\\s*:\\s*\"[^\"]*\"");
        java.util.regex.Matcher matcher = pattern.matcher(trimmed);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "text";
    }

    /**
     * Determines whether the response indicates a WAF or filter blocked
     * the request. Checks for 403, 406, and common WAF indicators.
     */
    private static boolean isWafBlocked(HttpResponse resp) {
        if (resp == null) {
            return false;
        }
        int status = resp.statusCode();
        if (status == 403 || status == 406 || status == 419 || status == 429) {
            return true;
        }
        if (ResponseDiff.containsPattern(resp, "blocked")
                || ResponseDiff.containsPattern(resp, "waf")
                || ResponseDiff.containsPattern(resp, "firewall")
                || ResponseDiff.containsPattern(resp, "access denied")
                || ResponseDiff.containsPattern(resp, "request rejected")) {
            return true;
        }
        String server = resp.headerValue("Server");
        if (server != null) {
            String lower = server.toLowerCase();
            if (lower.contains("cloudflare") || lower.contains("akamai")
                    || lower.contains("imperva") || lower.contains("barracuda")) {
                return ResponseDiff.isClientError(resp);
            }
        }
        return false;
    }

    /**
     * Minimal JSON string escaping for payload values.
     */
    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Returns the status code as a string, or "N/A" if the response is null.
     */
    private static String statusOrUnknown(HttpResponse resp) {
        return resp != null ? String.valueOf(resp.statusCode()) : "N/A";
    }
}
