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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * AMB-04: Content-Type Confusion check.
 *
 * <p>Replays the observed PATCH request with different PATCH-related
 * Content-Type values and detects differential behaviour that indicates
 * the server fails to strictly validate the Content-Type, allowing
 * cross-format confusion attacks.</p>
 */
public final class ContentTypeConfusionCheck implements PatchCheck {

    private static final String ID = "AMB-04";
    private static final String NAME = "Content-Type Confusion";
    private static final String DESCRIPTION =
            "Tests whether the server differentiates between JSON Patch, "
                    + "Merge Patch, and plain JSON Content-Types, and detects "
                    + "cross-format confusion that could lead to unexpected "
                    + "resource state changes.";

    private static final String REMEDIATION =
            "Servers MUST validate that the Content-Type matches the expected "
                    + "patch format and reject requests with an unsupported "
                    + "Content-Type with 415 Unsupported Media Type. "
                    + "See RFC 5789 Section 2.";

    private static final String CT_JSON_PATCH = "application/json-patch+json";
    private static final String CT_MERGE_PATCH = "application/merge-patch+json";
    private static final String CT_PLAIN_JSON = "application/json";

    private static final String[] CONTENT_TYPES = {
            CT_JSON_PATCH, CT_MERGE_PATCH, CT_PLAIN_JSON
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

        // --- Phase 1: Replay with each Content-Type, same body ---
        Map<String, HttpRequestResponse> ctResponses = new LinkedHashMap<>();
        for (String ct : CONTENT_TYPES) {
            HttpRequest probe = PatchRequestHelper.withContentType(baseReq, ct);
            HttpRequestResponse rr = http.sendRequest(probe);
            ctResponses.put(ct, rr);
        }

        // Detect differential behaviour across Content-Types
        List<HttpRequestResponse> differentialEvidence = new ArrayList<>();
        boolean statusDiff = false;
        boolean bodyDiff = false;

        String[] ctKeys = ctResponses.keySet().toArray(new String[0]);
        for (int i = 0; i < ctKeys.length; i++) {
            for (int j = i + 1; j < ctKeys.length; j++) {
                HttpResponse ri = ctResponses.get(ctKeys[i]).response();
                HttpResponse rj = ctResponses.get(ctKeys[j]).response();
                if (ResponseDiff.statusDiffers(ri, rj)) {
                    statusDiff = true;
                }
                if (ResponseDiff.bodySimilarity(ri, rj) <= 0.95) {
                    bodyDiff = true;
                }
            }
        }

        if (statusDiff || bodyDiff) {
            differentialEvidence.addAll(ctResponses.values());
            differentialEvidence.add(baseReqResp);

            AuditIssueSeverity severity = statusDiff
                    ? AuditIssueSeverity.HIGH
                    : AuditIssueSeverity.MEDIUM;
            AuditIssueConfidence confidence = statusDiff
                    ? AuditIssueConfidence.FIRM
                    : AuditIssueConfidence.TENTATIVE;

            String detail = "The server produced different responses when the same PATCH body "
                    + "was sent with different Content-Type headers. "
                    + (statusDiff ? "Status codes differed across Content-Types. " : "")
                    + (bodyDiff ? "Response bodies differed across Content-Types. " : "")
                    + "This indicates the server interprets the same body differently "
                    + "depending on the Content-Type, which may allow an attacker to "
                    + "trigger unintended state changes via format confusion.";

            AuditIssue issue = auditIssue(
                    NAME + " - Differential Behaviour",
                    detail,
                    REMEDIATION,
                    baseUrl,
                    severity,
                    confidence,
                    "RFC 5789 requires servers to understand the semantics of the "
                            + "patch document media type. Accepting multiple formats for "
                            + "the same endpoint without strict validation violates this.",
                    null,
                    severity,
                    differentialEvidence);
            issues.add(issue);

            store.addFinding(new Finding(
                    ID, NAME + " - Differential Behaviour", detail,
                    REMEDIATION, severity, confidence,
                    differentialEvidence, System.currentTimeMillis(), mode));
        }

        // --- Phase 2: Cross-format confusion ---
        String canaryValue = mode == ScanMode.SAFE
                ? "__rfc5789_ct_probe"
                : "admin";

        String jsonPatchBody = "[{\"op\":\"replace\",\"path\":\"/name\","
                + "\"value\":\"" + canaryValue + "\"}]";
        String mergePatchBody = "{\"name\":\"" + canaryValue + "\"}";

        // JSON Patch body + merge-patch CT
        HttpRequest crossProbe1 = PatchRequestHelper.withContentType(
                PatchRequestHelper.withBody(baseReq, jsonPatchBody),
                CT_MERGE_PATCH);
        HttpRequestResponse cross1 = http.sendRequest(crossProbe1);
        HttpResponse crossResp1 = cross1.response();

        // Merge patch body + JSON Patch CT
        HttpRequest crossProbe2 = PatchRequestHelper.withContentType(
                PatchRequestHelper.withBody(baseReq, mergePatchBody),
                CT_JSON_PATCH);
        HttpRequestResponse cross2 = http.sendRequest(crossProbe2);
        HttpResponse crossResp2 = cross2.response();

        // If server accepts the mismatched format without error, report
        if (ResponseDiff.isSuccess(crossResp1)) {
            List<HttpRequestResponse> evidence = List.of(cross1, baseReqResp);
            String detail = "The server accepted a JSON Patch array body "
                    + "(application/json-patch+json format) sent with the "
                    + "application/merge-patch+json Content-Type. "
                    + "This cross-format confusion may allow attackers to "
                    + "perform unintended operations.";

            AuditIssue issue = auditIssue(
                    NAME + " - Cross-Format Accepted",
                    detail,
                    REMEDIATION,
                    baseUrl,
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.FIRM,
                    null, null,
                    AuditIssueSeverity.MEDIUM,
                    evidence);
            issues.add(issue);

            store.addFinding(new Finding(
                    ID, NAME + " - Cross-Format Accepted", detail,
                    REMEDIATION, AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.FIRM,
                    evidence, System.currentTimeMillis(), mode));
        }

        if (ResponseDiff.isSuccess(crossResp2)) {
            List<HttpRequestResponse> evidence = List.of(cross2, baseReqResp);
            String detail = "The server accepted a merge-patch JSON object "
                    + "body sent with the application/json-patch+json "
                    + "Content-Type. This indicates the server does not "
                    + "validate the Content-Type against the body format.";

            AuditIssue issue = auditIssue(
                    NAME + " - Cross-Format Accepted (Reverse)",
                    detail,
                    REMEDIATION,
                    baseUrl,
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.FIRM,
                    null, null,
                    AuditIssueSeverity.MEDIUM,
                    evidence);
            issues.add(issue);

            store.addFinding(new Finding(
                    ID, NAME + " - Cross-Format Accepted (Reverse)", detail,
                    REMEDIATION, AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.FIRM,
                    evidence, System.currentTimeMillis(), mode));
        }

        return issues;
    }
}
