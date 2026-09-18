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
import com.rfc5789.auditor.collaborator.CollaboratorManager;
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
 * AMB-06: Cache Poisoning via PATCH check.
 *
 * <p>Tests whether caching infrastructure correctly invalidates cached
 * representations after a PATCH modifies the underlying resource. RFC 7234
 * Section 4.4 requires that a successful unsafe method (including PATCH)
 * invalidate the effective Request-URI in the cache. Failure to do so
 * can result in stale or security-relevant data being served from cache.</p>
 */
public final class CachePoisoningCheck implements PatchCheck {

    private static final String ID = "AMB-06";
    private static final String NAME = "Cache Poisoning via PATCH";
    private static final String DESCRIPTION =
            "Tests whether caches invalidate correctly after a PATCH "
                    + "modifies the underlying resource.";

    private static final String REMEDIATION =
            "Ensure caching proxies and CDNs invalidate cached responses "
                    + "for a resource after a successful PATCH. Configure "
                    + "Cache-Control headers appropriately for mutable resources. "
                    + "See RFC 7234 Section 4.4.";

    /** Cache-related headers to inspect. */
    private static final String[] CACHE_INDICATOR_HEADERS = {
            "ETag", "Age", "X-Cache", "CF-Cache-Status", "X-Varnish",
            "X-Cache-Hits"
    };

    private final CollaboratorManager collaboratorManager;

    /**
     * Creates a CachePoisoningCheck without Collaborator support.
     */
    public CachePoisoningCheck() {
        this(null);
    }

    /**
     * Creates a CachePoisoningCheck with optional Collaborator support.
     *
     * @param collaboratorManager the collaborator manager, or null if unavailable
     */
    public CachePoisoningCheck(CollaboratorManager collaboratorManager) {
        this.collaboratorManager = collaboratorManager;
    }

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

        HttpRequest getReq = PatchRequestHelper.buildGetRequest(baseReq);

        // Step 1: GET to prime cache and capture cache headers
        HttpRequestResponse preCacheRR = http.sendRequest(getReq);
        HttpResponse preCacheResp = preCacheRR.response();

        // Step 2: Detect if a cache is present
        boolean cacheDetected = detectCache(preCacheResp);

        // Step 3: Send PATCH
        String patchBody;
        if (mode == ScanMode.SAFE) {
            patchBody = "{\"__rfc5789_cache_probe\": \"" + System.currentTimeMillis() + "\"}";
        } else {
            patchBody = baseReq.bodyToString();
        }
        HttpRequest patchReq = PatchRequestHelper.withBody(baseReq, patchBody);
        HttpRequestResponse patchRR = http.sendRequest(patchReq);
        HttpResponse patchResp = patchRR.response();

        // Only proceed if PATCH was successful
        if (!ResponseDiff.isSuccess(patchResp)) {
            return issues;
        }

        // Step 4: GET again immediately after PATCH
        HttpRequestResponse postCacheRR = http.sendRequest(getReq);
        HttpResponse postCacheResp = postCacheRR.response();

        // Step 5: Compare pre-PATCH and post-PATCH GET responses
        List<HttpRequestResponse> evidence = new ArrayList<>();
        evidence.add(preCacheRR);
        evidence.add(patchRR);
        evidence.add(postCacheRR);
        evidence.add(baseReqResp);

        boolean staleDetected = false;
        StringBuilder staleDetails = new StringBuilder();

        // Check ETag unchanged
        if (!ResponseDiff.headerDiffers(preCacheResp, postCacheResp, "ETag")
                && preCacheResp != null && preCacheResp.headerValue("ETag") != null) {
            staleDetails.append("ETag unchanged after PATCH. ");
            staleDetected = true;
        }

        // Check X-Cache: HIT after PATCH (should have been invalidated)
        if (postCacheResp != null) {
            String xCache = postCacheResp.headerValue("X-Cache");
            String cfCache = postCacheResp.headerValue("CF-Cache-Status");
            if (xCache != null && xCache.toUpperCase().contains("HIT")) {
                staleDetails.append("X-Cache: HIT after PATCH (stale cache). ");
                staleDetected = true;
            }
            if (cfCache != null && cfCache.equalsIgnoreCase("HIT")) {
                staleDetails.append("CF-Cache-Status: HIT after PATCH. ");
                staleDetected = true;
            }
        }

        // Check identical body (strong indicator of stale cache)
        if (!ResponseDiff.bodyDiffers(preCacheResp, postCacheResp)
                && ResponseDiff.bodyDiffers(preCacheResp, patchResp)) {
            staleDetails.append("Response body identical before and after PATCH. ");
            staleDetected = true;
        }

        // Check Age header not reset
        if (!ResponseDiff.headerDiffers(preCacheResp, postCacheResp, "Age")
                && preCacheResp != null && preCacheResp.headerValue("Age") != null) {
            String ageVal = preCacheResp.headerValue("Age");
            try {
                int age = Integer.parseInt(ageVal.trim());
                if (age > 0) {
                    staleDetails.append("Age header not reset after PATCH (Age: ")
                            .append(age).append("). ");
                    staleDetected = true;
                }
            } catch (NumberFormatException ignored) {
                // non-numeric Age, skip
            }
        }

        if (staleDetected) {
            boolean securityRelevant = isSecurityRelevantEndpoint(baseReq.path());
            AuditIssueSeverity severity = securityRelevant
                    ? AuditIssueSeverity.HIGH
                    : AuditIssueSeverity.MEDIUM;
            AuditIssueConfidence confidence = cacheDetected
                    ? AuditIssueConfidence.FIRM
                    : AuditIssueConfidence.TENTATIVE;

            String detail = "The cache did not properly invalidate after a "
                    + "successful PATCH request. Indicators: "
                    + staleDetails.toString().trim()
                    + (cacheDetected
                    ? " A caching layer was detected from response headers."
                    : " No explicit caching layer was detected, but stale "
                            + "indicators are present.")
                    + (securityRelevant
                    ? " The endpoint appears to handle security-relevant data "
                            + "(permissions, roles, tokens), making stale cache "
                            + "responses a higher risk."
                    : "");

            AuditIssue issue = auditIssue(
                    NAME + (securityRelevant
                            ? " - Stale Security Data" : " - Stale Cache"),
                    detail,
                    REMEDIATION,
                    baseUrl,
                    severity,
                    confidence,
                    "RFC 7234 Section 4.4 requires caches to invalidate the "
                            + "effective Request-URI when a successful unsafe "
                            + "request (like PATCH) is received.",
                    null,
                    severity,
                    evidence);
            issues.add(issue);

            store.addFinding(new Finding(
                    ID,
                    NAME + (securityRelevant
                            ? " - Stale Security Data" : " - Stale Cache"),
                    detail, REMEDIATION, severity, confidence,
                    evidence, System.currentTimeMillis(), mode));
        }

        // Step 6: Collaborator-based cache poisoning (AGGRESSIVE only)
        if (mode == ScanMode.AGGRESSIVE
                && collaboratorManager != null
                && collaboratorManager.isAvailable()) {
            String collabPayload = collaboratorManager.generatePayload();
            if (collabPayload != null) {
                String collabUrl = "https://" + collabPayload + "/rfc5789-cache-probe";
                String collabBody = "{\"callback_url\": \"" + collabUrl + "\"}";
                HttpRequest collabPatch = PatchRequestHelper.withBody(baseReq, collabBody);
                HttpRequestResponse collabPatchRR = http.sendRequest(collabPatch);
                HttpResponse collabPatchResp = collabPatchRR.response();

                if (ResponseDiff.isSuccess(collabPatchResp)) {
                    HttpRequestResponse collabGetRR = http.sendRequest(getReq);
                    HttpResponse collabGetResp = collabGetRR.response();

                    if (ResponseDiff.containsPattern(collabGetResp, collabPayload)) {
                        List<HttpRequestResponse> collabEvidence = List.of(
                                collabPatchRR, collabGetRR, baseReqResp);

                        String detail = "A Collaborator URL injected via PATCH was "
                                + "served back through a subsequent GET request, "
                                + "confirming cache poisoning. The injected payload ("
                                + collabPayload + ") appeared in "
                                + "the cached response.";

                        AuditIssue issue = auditIssue(
                                NAME + " - Collaborator Confirmed",
                                detail,
                                REMEDIATION,
                                baseUrl,
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.CERTAIN,
                                null, null,
                                AuditIssueSeverity.HIGH,
                                collabEvidence);
                        issues.add(issue);

                        store.addFinding(new Finding(
                                ID, NAME + " - Collaborator Confirmed",
                                detail, REMEDIATION,
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.CERTAIN,
                                collabEvidence, System.currentTimeMillis(), mode));
                    }
                }
            }
        }

        return issues;
    }

    /**
     * Detects the presence of a caching layer from response headers.
     */
    private static boolean detectCache(HttpResponse resp) {
        if (resp == null) {
            return false;
        }
        for (String header : CACHE_INDICATOR_HEADERS) {
            String val = resp.headerValue(header);
            if (val != null && !val.isEmpty()) {
                // ETag alone doesn't confirm a cache proxy, but the others do
                if (!"ETag".equals(header)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Heuristic: checks if the URL path suggests security-relevant data.
     */
    private static boolean isSecurityRelevantEndpoint(String path) {
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase();
        return lower.contains("permission") || lower.contains("role")
                || lower.contains("auth") || lower.contains("token")
                || lower.contains("session") || lower.contains("admin")
                || lower.contains("privilege") || lower.contains("access")
                || lower.contains("policy") || lower.contains("security");
    }
}
