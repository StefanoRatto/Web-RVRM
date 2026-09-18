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
import com.rfc5789.auditor.model.AuditorConfig.SideEffectPair;
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
 * AMB-02: Side-Effect TOCTOU (Time-of-Check to Time-of-Use) check.
 *
 * <p>Tests whether a PATCH request to one resource causes observable side
 * effects on sibling or related resources. Uses a hybrid approach:
 * heuristic discovery of sibling URLs and user-configured monitoring
 * pairs. Detects TOCTOU conditions where a side effect occurs without
 * its own authorization gate.</p>
 */
public final class SideEffectTocTouCheck implements PatchCheck {

    private static final String ID = "AMB-02";
    private static final String NAME = "Side-Effect TOCTOU";
    private static final String DESCRIPTION =
            "Tests whether a PATCH to one resource causes observable side "
                    + "effects on sibling or related resources.";

    private static final String REMEDIATION =
            "Side effects triggered by PATCH should be subject to their own "
                    + "authorization checks. Document all side effects in the API "
                    + "specification. Return 209 Content Returned or include "
                    + "Link headers pointing to affected resources. "
                    + "See RFC 5789 Section 2.";

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
        String basePath = baseReq.path();
        ScanMode mode = config.getCurrentMode();

        // === Phase A: Heuristic sibling discovery ===
        List<String> siblingPaths = generateSiblingPaths(basePath);
        if (!siblingPaths.isEmpty()) {
            issues.addAll(runSiblingCheck(
                    baseReqResp, siblingPaths, http, store, mode, baseUrl));
        }

        // === Phase B: Configured side-effect pairs ===
        String patchBody = baseReq.bodyToString();
        String patchUrl = baseUrl;
        int qIdx = patchUrl.indexOf('?');
        String patchUrlNorm = qIdx >= 0 ? patchUrl.substring(0, qIdx) : patchUrl;

        for (SideEffectPair pair : config.getSideEffectPairs()) {
            if (pair.getTargetUrl() == null || pair.getMonitorUrls().isEmpty()) {
                continue;
            }
            if (!patchUrlNorm.endsWith(pair.getTargetUrl())
                    && !pair.getTargetUrl().equals(patchUrlNorm)
                    && !basePath.equals(pair.getTargetUrl())
                    && !basePath.startsWith(pair.getTargetUrl())) {
                continue;
            }

            issues.addAll(runConfiguredCheck(
                    baseReq, patchBody, pair.getMonitorUrls(),
                    http, store, mode, baseUrl));
        }

        return issues;
    }

    /**
     * Phase A: heuristic sibling check.
     * The PATCH was already sent as the base request -- no need to re-send it.
     */
    private List<AuditIssue> runSiblingCheck(HttpRequestResponse baseReqResp,
                                             List<String> siblingPaths,
                                             Http http,
                                             FindingsStore store,
                                             ScanMode mode,
                                             String baseUrl) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpRequest baseReq = baseReqResp.request();
        HttpRequest getBase = PatchRequestHelper.buildGetRequest(baseReq);

        // GET each sibling before relying on the already-executed PATCH
        Map<String, HttpRequestResponse> beforeStates = new LinkedHashMap<>();
        for (String sibPath : siblingPaths) {
            HttpRequest sibGet = PatchRequestHelper.withPath(getBase, sibPath);
            HttpRequestResponse sibRR = http.sendRequest(sibGet);
            if (ResponseDiff.isSuccess(sibRR.response())) {
                beforeStates.put(sibPath, sibRR);
            }
        }

        if (beforeStates.isEmpty()) {
            return issues;
        }

        // The PATCH was already sent as baseReqResp -- use its response
        if (!ResponseDiff.isSuccess(baseReqResp.response())) {
            return issues;
        }

        // Re-GET each sibling after PATCH
        boolean anyChanged = false;
        for (Map.Entry<String, HttpRequestResponse> entry : beforeStates.entrySet()) {
            String sibPath = entry.getKey();
            HttpResponse beforeResp = entry.getValue().response();

            HttpRequest sibGet = PatchRequestHelper.withPath(getBase, sibPath);
            HttpRequestResponse afterRR = http.sendRequest(sibGet);
            HttpResponse afterResp = afterRR.response();

            boolean changed = ResponseDiff.bodyDiffers(beforeResp, afterResp)
                    || ResponseDiff.headerDiffers(beforeResp, afterResp, "ETag");

            if (changed) {
                anyChanged = true;
                List<HttpRequestResponse> evidence = List.of(
                        baseReqResp, entry.getValue(), afterRR);

                String detail = "Heuristic side-effect detected: after PATCHing "
                        + baseReq.path() + ", the sibling resource at "
                        + sibPath + " changed. "
                        + "The response body or ETag differed between the "
                        + "pre-PATCH and post-PATCH GETs to the sibling URL.";

                AuditIssue issue = auditIssue(
                        NAME + " - Sibling Changed (Heuristic)",
                        detail,
                        REMEDIATION,
                        baseUrl,
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.TENTATIVE,
                        "A PATCH to one resource caused observable changes in "
                                + "a sibling resource. This may indicate a "
                                + "TOCTOU condition if the side effect is not "
                                + "subject to its own authorization check.",
                        null,
                        AuditIssueSeverity.MEDIUM,
                        evidence);
                issues.add(issue);

                store.addFinding(new Finding(
                        ID, NAME + " - Sibling Changed (Heuristic)", detail,
                        REMEDIATION, AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.TENTATIVE,
                        evidence, System.currentTimeMillis(), mode));
            }
        }

        // If no changes detected, report LOW for discovered paths
        if (!anyChanged) {
            List<HttpRequestResponse> evidence = List.of(baseReqResp);
            String paths = String.join(", ", beforeStates.keySet());
            String detail = "Potential side-effect paths discovered but no changes "
                    + "detected after PATCH. Sibling paths checked: " + paths
                    + ". These paths may warrant manual investigation.";

            AuditIssue issue = auditIssue(
                    NAME + " - Potential Side-Effect Paths",
                    detail,
                    REMEDIATION,
                    baseUrl,
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.TENTATIVE,
                    null, null,
                    AuditIssueSeverity.LOW,
                    evidence);
            issues.add(issue);

            store.addFinding(new Finding(
                    ID, NAME + " - Potential Side-Effect Paths", detail,
                    REMEDIATION, AuditIssueSeverity.LOW,
                    AuditIssueConfidence.TENTATIVE,
                    evidence, System.currentTimeMillis(), mode));
        }

        return issues;
    }

    /**
     * Phase B: configured side-effect pair check.
     */
    private List<AuditIssue> runConfiguredCheck(HttpRequest baseReq,
                                                String patchBody,
                                                List<String> monitorUrls,
                                                Http http,
                                                FindingsStore store,
                                                ScanMode mode,
                                                String baseUrl) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpRequest getBase = PatchRequestHelper.buildGetRequest(baseReq);

        // GET each monitor URL before PATCH
        Map<String, HttpRequestResponse> beforeStates = new LinkedHashMap<>();
        for (String monUrl : monitorUrls) {
            HttpRequest monGet = PatchRequestHelper.withPath(getBase, monUrl);
            HttpRequestResponse monRR = http.sendRequest(monGet);
            beforeStates.put(monUrl, monRR);
        }

        // Send PATCH
        HttpRequest patchReq = PatchRequestHelper.withBody(baseReq, patchBody);
        HttpRequestResponse patchRR = http.sendRequest(patchReq);

        if (!ResponseDiff.isSuccess(patchRR.response())) {
            return issues;
        }

        // GET each monitor URL after PATCH
        for (Map.Entry<String, HttpRequestResponse> entry : beforeStates.entrySet()) {
            String monUrl = entry.getKey();
            HttpResponse beforeResp = entry.getValue().response();

            HttpRequest monGet = PatchRequestHelper.withPath(getBase, monUrl);
            HttpRequestResponse afterRR = http.sendRequest(monGet);
            HttpResponse afterResp = afterRR.response();

            boolean changed = ResponseDiff.bodyDiffers(beforeResp, afterResp)
                    || ResponseDiff.headerDiffers(beforeResp, afterResp, "ETag");

            if (changed) {
                List<HttpRequestResponse> evidence = List.of(
                        patchRR, entry.getValue(), afterRR);

                String detail = "Configured side-effect confirmed: after PATCHing "
                        + baseReq.path() + ", the monitored URL " + monUrl
                        + " changed. The response body or ETag differed "
                        + "between the pre-PATCH and post-PATCH GETs. "
                        + "This confirms a side effect that should be subject "
                        + "to its own authorization check.";

                AuditIssue issue = auditIssue(
                        NAME + " - Confirmed Side-Effect (Configured)",
                        detail,
                        REMEDIATION,
                        baseUrl,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "A user-configured monitor URL changed after a PATCH "
                                + "to the target resource, confirming a side "
                                + "effect that may lack its own authorization.",
                        null,
                        AuditIssueSeverity.HIGH,
                        evidence);
                issues.add(issue);

                store.addFinding(new Finding(
                        ID, NAME + " - Confirmed Side-Effect (Configured)", detail,
                        REMEDIATION, AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        evidence, System.currentTimeMillis(), mode));
            }
        }

        return issues;
    }

    /**
     * Generates heuristic sibling paths from the PATCH URL.
     *
     * <p>Given /api/users/123, generates:
     * /api/users/124, /api/users/122,
     * /api/users/123/profile, /api/users/123/permissions</p>
     */
    private static List<String> generateSiblingPaths(String path) {
        List<String> siblings = new ArrayList<>();
        if (path == null || path.isEmpty()) {
            return siblings;
        }

        int qIdx = path.indexOf('?');
        String cleanPath = qIdx >= 0 ? path.substring(0, qIdx) : path;

        String existingId = PatchRequestHelper.extractResourceId(cleanPath);
        if (existingId == null) {
            return siblings;
        }

        // Try sequential IDs (+1, -1) if numeric
        try {
            long numId = Long.parseLong(existingId);
            siblings.add(PatchRequestHelper.replaceResourceId(cleanPath,
                    String.valueOf(numId + 1)));
            if (numId > 1) {
                siblings.add(PatchRequestHelper.replaceResourceId(cleanPath,
                        String.valueOf(numId - 1)));
            }
        } catch (NumberFormatException ignored) {
            // Not numeric; skip sequential generation
        }

        // Add related sub-resource paths
        String base = cleanPath.endsWith("/")
                ? cleanPath.substring(0, cleanPath.length() - 1)
                : cleanPath;
        siblings.add(base + "/profile");
        siblings.add(base + "/permissions");
        siblings.add(base + "/settings");

        return siblings;
    }
}
