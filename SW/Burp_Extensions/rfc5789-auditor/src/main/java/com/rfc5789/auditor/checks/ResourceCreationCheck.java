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
import java.util.UUID;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * AMB-01: Resource Creation via PATCH check.
 *
 * <p>Tests whether a server incorrectly allows PATCH requests to create
 * new resources by sending PATCH to non-existent resource URLs. RFC 5789
 * Section 2 states that PATCH should be applied to an existing resource;
 * resource creation via PATCH is an implementation ambiguity that can be
 * exploited for unauthorized object creation.</p>
 */
public final class ResourceCreationCheck implements PatchCheck {

    private static final String ID = "AMB-01";
    private static final String NAME = "Resource Creation via PATCH";
    private static final String DESCRIPTION =
            "Tests whether the server allows PATCH to create new resources "
                    + "by sending PATCH to non-existent resource URLs.";

    private static final String REMEDIATION =
            "Servers SHOULD return 404 Not Found when a PATCH is sent to a "
                    + "non-existent resource, unless the server explicitly supports "
                    + "resource creation via PATCH (which should then require "
                    + "appropriate authorization). See RFC 5789 Section 2.";

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
        String basePath = baseReq.path();
        String baseUrl = baseReq.url();
        ScanMode mode = config.getCurrentMode();

        // Extract and verify resource ID exists in the URL
        String existingId = PatchRequestHelper.extractResourceId(basePath);
        if (existingId == null) {
            return issues;
        }

        // Generate non-existent IDs
        List<String> fakeIds = new ArrayList<>();
        fakeIds.add("99999999");
        fakeIds.add(UUID.randomUUID().toString());
        fakeIds.add("rfc5789-probe-" + System.currentTimeMillis());

        // Determine body
        String body;
        if (mode == ScanMode.SAFE) {
            body = "{\"__rfc5789_creation_probe\": true, \"name\": \"canary\"}";
        } else {
            body = baseReq.bodyToString();
        }

        for (String fakeId : fakeIds) {
            String newPath = PatchRequestHelper.replaceResourceId(basePath, fakeId);
            HttpRequest probe = PatchRequestHelper.withPath(
                    PatchRequestHelper.withBody(baseReq, body), newPath);
            HttpRequestResponse probeRR = http.sendRequest(probe);
            HttpResponse resp = probeRR.response();

            if (resp == null) {
                continue;
            }

            int status = resp.statusCode();

            if (status == 201) {
                // Attempt cleanup of the created resource
                String probeUrl = probe.url();
                HttpRequest deleteReq = PatchRequestHelper.buildGetRequest(probe)
                        .withMethod("DELETE");
                HttpRequestResponse deleteRR = http.sendRequest(deleteReq);
                String cleanupStatus = deleteRR.response() != null
                        ? String.valueOf(deleteRR.response().statusCode())
                        : "no response";

                List<HttpRequestResponse> evidence = List.of(probeRR, deleteRR, baseReqResp);
                String detail = "The server returned 201 Created when a PATCH was sent "
                        + "to a non-existent resource URL (fake ID: " + fakeId + "). "
                        + "This confirms that PATCH can create new resources, which "
                        + "may allow unauthorized object creation. "
                        + "Cleanup DELETE returned HTTP " + cleanupStatus
                        + (isCleanupSuccess(deleteRR.response())
                        ? " (resource cleaned up successfully)."
                        : " (resource may require manual cleanup at: " + probeUrl + ").");

                AuditIssue issue = auditIssue(
                        NAME + " - Confirmed (201 Created)",
                        detail,
                        REMEDIATION,
                        baseUrl,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        "RFC 5789 does not mandate that PATCH create resources, "
                                + "but many implementations allow it. This is a security "
                                + "concern when creation bypasses authorization controls.",
                        null,
                        AuditIssueSeverity.HIGH,
                        evidence);
                issues.add(issue);

                store.addFinding(new Finding(
                        ID, NAME + " - Confirmed (201 Created)", detail,
                        REMEDIATION, AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        evidence, System.currentTimeMillis(), mode));
                break;

            } else if (ResponseDiff.isSuccess(resp)) {
                HttpRequest getReq = PatchRequestHelper.buildGetRequest(probe);
                HttpRequestResponse getRR = http.sendRequest(getReq);
                HttpResponse getResp = getRR.response();

                boolean resourceExists = ResponseDiff.isSuccess(getResp);

                // Attempt cleanup if resource was confirmed created
                String cleanupInfo = "";
                if (resourceExists) {
                    String probeUrl = probe.url();
                    HttpRequest deleteReq = PatchRequestHelper.buildGetRequest(probe)
                            .withMethod("DELETE");
                    HttpRequestResponse deleteRR = http.sendRequest(deleteReq);
                    String cleanupStatus = deleteRR.response() != null
                            ? String.valueOf(deleteRR.response().statusCode())
                            : "no response";
                    cleanupInfo = " Cleanup DELETE returned HTTP " + cleanupStatus
                            + (isCleanupSuccess(deleteRR.response())
                            ? " (resource cleaned up successfully)."
                            : " (resource may require manual cleanup at: " + probeUrl + ").");
                }

                List<HttpRequestResponse> evidence = List.of(probeRR, getRR, baseReqResp);
                AuditIssueSeverity severity = resourceExists
                        ? AuditIssueSeverity.HIGH
                        : AuditIssueSeverity.MEDIUM;
                AuditIssueConfidence confidence = resourceExists
                        ? AuditIssueConfidence.FIRM
                        : AuditIssueConfidence.TENTATIVE;

                String detail = "The server returned " + status + " when a PATCH was "
                        + "sent to a non-existent resource URL (fake ID: " + fakeId + "). "
                        + (resourceExists
                        ? "A follow-up GET confirmed the resource now exists." + cleanupInfo
                        : "A follow-up GET did not confirm creation, but the 2xx "
                                + "response suggests the server may have accepted the request.");

                AuditIssue issue = auditIssue(
                        NAME + " - Suspected (" + status + ")",
                        detail,
                        REMEDIATION,
                        baseUrl,
                        severity,
                        confidence,
                        null, null,
                        severity,
                        evidence);
                issues.add(issue);

                store.addFinding(new Finding(
                        ID, NAME + " - Suspected (" + status + ")", detail,
                        REMEDIATION, severity, confidence,
                        evidence, System.currentTimeMillis(), mode));

                if (resourceExists) {
                    break;
                }
            }
        }

        return issues;
    }

    /**
     * Returns true if the cleanup DELETE response indicates success (2xx or 204).
     */
    private static boolean isCleanupSuccess(HttpResponse resp) {
        if (resp == null) {
            return false;
        }
        int status = resp.statusCode();
        return status >= 200 && status <= 299;
    }
}
