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
 * AMB-03: Atomicity Race Condition check.
 *
 * <p>Tests whether the server enforces atomic application of PATCH
 * operations by firing multiple concurrent PATCH requests and observing
 * whether partial merges or missing conflict detection occur. RFC 5789
 * Section 2 requires that a PATCH be applied atomically; a partially
 * applied patch MUST NOT be observable by other clients.</p>
 */
public final class AtomicityRaceCheck implements PatchCheck {

    private static final String ID = "AMB-03";
    private static final String NAME = "Atomicity Race Condition";
    private static final String DESCRIPTION =
            "Tests whether concurrent PATCH requests reveal atomicity "
                    + "violations or missing conflict detection.";

    private static final String REMEDIATION =
            "Servers MUST apply PATCH operations atomically: either the "
                    + "entire patch is applied or none of it. Implement optimistic "
                    + "concurrency control (e.g. ETag/If-Match) and return 409 "
                    + "Conflict when concurrent modifications are detected. "
                    + "See RFC 5789 Section 2.";

    private static final String CANARY_PREFIX = "__rfc5789_race_";

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
        int concurrentCount = config.getConcurrentPatchCount();

        // Step 1: GET baseline resource state
        HttpRequest getReq = PatchRequestHelper.buildGetRequest(baseReq);
        HttpRequestResponse baselineRR = http.sendRequest(getReq);

        // Step 2: Build N PATCH requests, merging canary field into original body
        String originalBody = baseReqResp.request().bodyToString();
        boolean isJsonObject = originalBody != null
                && originalBody.trim().startsWith("{");

        List<HttpRequest> patchRequests = new ArrayList<>(concurrentCount);
        for (int i = 0; i < concurrentCount; i++) {
            String body;
            if (isJsonObject) {
                // Inject canary field into the original JSON object
                String trimmed = originalBody.trim();
                if ("{}".equals(trimmed)) {
                    // Empty object -- produce clean JSON without trailing comma
                    body = "{\"" + CANARY_PREFIX + i + "\": \"probe_" + i + "\"}";
                } else {
                    body = "{\"" + CANARY_PREFIX + i + "\": \"probe_" + i + "\","
                            + trimmed.substring(1);
                }
            } else {
                // Not JSON or unparseable -- use original body unchanged
                body = originalBody != null ? originalBody : "";
            }
            HttpRequest patchReq = PatchRequestHelper.withBody(baseReq, body);
            patchRequests.add(patchReq);
        }

        // Step 3: Fire all PATCHes in parallel
        List<HttpRequestResponse> patchResponses = http.sendRequests(patchRequests);

        // Collect evidence
        List<HttpRequestResponse> allEvidence = new ArrayList<>();
        allEvidence.add(baselineRR);
        allEvidence.add(baseReqResp);

        // Step 4: Analyze responses for conflict detection
        int successCount = 0;
        int conflictCount = 0;
        for (HttpRequestResponse rr : patchResponses) {
            allEvidence.add(rr);
            HttpResponse resp = rr.response();
            if (resp != null) {
                if (resp.statusCode() == 409) {
                    conflictCount++;
                } else if (ResponseDiff.isSuccess(resp)) {
                    successCount++;
                }
            }
        }

        // Step 5: GET final state, check for merged canary values
        HttpRequestResponse finalStateRR = http.sendRequest(getReq);
        allEvidence.add(finalStateRR);

        HttpResponse finalStateResp = finalStateRR.response();
        String finalBody = finalStateResp != null ? finalStateResp.bodyToString() : "";
        if (finalBody == null) {
            finalBody = "";
        }

        int canaryMergeCount = 0;
        if (isJsonObject) {
            for (int i = 0; i < concurrentCount; i++) {
                if (finalBody.contains(CANARY_PREFIX + i)) {
                    canaryMergeCount++;
                }
            }
        }

        boolean partialMerge = isJsonObject && canaryMergeCount > 1;
        boolean noConflictDetection = conflictCount == 0 && successCount > 1;

        // Step 6: Interleaved PATCH+GET to detect partial state exposure
        boolean partialExposure = false;
        if (noConflictDetection) {
            // Use original body for the interleaved test
            HttpRequest interleavedPatch = PatchRequestHelper.withBody(baseReq,
                    originalBody != null ? originalBody : "");

            http.sendRequest(interleavedPatch);
            HttpRequestResponse interleaveGetRR = http.sendRequest(getReq);
            allEvidence.add(interleaveGetRR);

            HttpResponse interleaveGetResp = interleaveGetRR.response();
            if (interleaveGetResp != null && finalStateResp != null) {
                if (ResponseDiff.bodyDiffers(interleaveGetResp, finalStateResp)) {
                    partialExposure = true;
                }
            }
        }

        // Report findings
        if (partialMerge) {
            String detail = "Multiple concurrent PATCH requests resulted in a partial "
                    + "merge of " + canaryMergeCount + " out of " + concurrentCount
                    + " canary fields in the final resource state. This is a MUST "
                    + "violation of RFC 5789 atomicity requirements -- a patch "
                    + "MUST be applied in its entirety or not at all. "
                    + (partialExposure ? "Additionally, interleaved GET requests "
                            + "revealed intermediate state." : "");

            AuditIssue issue = auditIssue(
                    NAME + " - Partial Merge Detected",
                    detail,
                    REMEDIATION,
                    baseUrl,
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    "RFC 5789 Section 2 states: 'The server MUST apply the "
                            + "entire set of changes atomically and never provide "
                            + "a partially modified representation.'",
                    null,
                    AuditIssueSeverity.HIGH,
                    allEvidence);
            issues.add(issue);

            store.addFinding(new Finding(
                    ID, NAME + " - Partial Merge Detected", detail,
                    REMEDIATION, AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    allEvidence, System.currentTimeMillis(), mode));

        } else if (noConflictDetection) {
            String detail = "All " + successCount + " concurrent PATCH requests "
                    + "succeeded without any 409 Conflict responses. The server "
                    + "does not appear to implement conflict detection for "
                    + "concurrent PATCH operations. "
                    + "This may lead to lost updates or race conditions.";

            AuditIssue issue = auditIssue(
                    NAME + " - No Conflict Detection",
                    detail,
                    REMEDIATION,
                    baseUrl,
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.TENTATIVE,
                    null, null,
                    AuditIssueSeverity.MEDIUM,
                    allEvidence);
            issues.add(issue);

            store.addFinding(new Finding(
                    ID, NAME + " - No Conflict Detection", detail,
                    REMEDIATION, AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.TENTATIVE,
                    allEvidence, System.currentTimeMillis(), mode));
        }

        return issues;
    }
}
