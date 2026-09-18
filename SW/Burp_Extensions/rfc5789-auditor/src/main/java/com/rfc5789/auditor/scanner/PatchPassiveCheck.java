/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.Finding;
import com.rfc5789.auditor.model.FindingsStore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * Passive scan check that examines existing PATCH traffic for RFC 5789
 * compliance issues without sending any additional requests.
 *
 * <p>Implements the Montoya {@link ScanCheck} interface. The
 * {@link #passiveAudit(HttpRequestResponse)} method performs the actual
 * analysis; {@link #activeAudit(HttpRequestResponse, AuditInsertionPoint)}
 * returns an empty result because active scanning is handled by
 * {@link PatchActiveCheck}.</p>
 *
 * <p>Detects the following passive indicators:</p>
 * <ol>
 *   <li>PATCH requests missing {@code If-Match} or {@code If-Unmodified-Since} headers
 *       (conditional request headers recommended by RFC 5789 Section 2).</li>
 *   <li>PATCH requests using a generic {@code Content-Type} (e.g. {@code application/json})
 *       instead of a proper patch media type (e.g. {@code application/merge-patch+json}).</li>
 *   <li>OPTIONS responses advertising {@code Allow: PATCH} but missing the
 *       {@code Accept-Patch} header (required by RFC 5789 Section 3.1).</li>
 * </ol>
 */
public final class PatchPassiveCheck implements ScanCheck {

    private final AuditorConfig config;
    private final FindingsStore store;

    /**
     * Creates a new passive check.
     *
     * @param config the shared auditor configuration
     * @param store  the findings store for UI notification
     */
    public PatchPassiveCheck(AuditorConfig config, FindingsStore store) {
        this.config = config;
        this.store = store;
    }

    /**
     * Performs passive analysis on the given request/response pair.
     *
     * <p>No additional HTTP requests are sent. The method inspects existing
     * PATCH requests and OPTIONS responses for RFC 5789 compliance issues.</p>
     *
     * @param baseRequestResponse the HTTP message to audit
     * @return an {@link AuditResult} containing any findings
     */
    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();

        // Drain any pending issues from context menu or traffic monitor checks.
        // These are active findings that need to be routed through the passive
        // audit return path to appear in Burp's Dashboard Issues panel.
        List<AuditIssue> pendingIssues = store.drainPendingBurpIssues();
        issues.addAll(pendingIssues);

        HttpRequest request = baseRequestResponse.request();
        HttpResponse response = baseRequestResponse.response();

        if (request == null) {
            return auditResult(Collections.emptyList());
        }

        String method = request.method();
        String url = request.url();

        // --- Check PATCH requests ---
        if ("PATCH".equalsIgnoreCase(method)) {
            checkMissingConditionalHeaders(baseRequestResponse, request, url, issues);
            checkGenericContentType(baseRequestResponse, request, url, issues);
        }

        // --- Check OPTIONS responses for missing Accept-Patch ---
        if ("OPTIONS".equalsIgnoreCase(method) && response != null) {
            checkMissingAcceptPatch(baseRequestResponse, response, url, issues);
        }

        return auditResult(issues);
    }

    /**
     * Active audit is a no-op for this check; active scanning is handled by
     * {@link PatchActiveCheck}.
     *
     * @param baseRequestResponse the base request/response (unused)
     * @param insertionPoint      the insertion point (unused)
     * @return an empty audit result
     */
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint) {
        return auditResult(Collections.emptyList());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (existingIssue.name().equals(newIssue.name())
                && existingIssue.baseUrl().equals(newIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    /**
     * Detects PATCH requests without If-Match or If-Unmodified-Since headers.
     */
    private void checkMissingConditionalHeaders(HttpRequestResponse reqResp,
                                                 HttpRequest request,
                                                 String url,
                                                 List<AuditIssue> issues) {
        boolean hasIfMatch = request.headerValue("If-Match") != null;
        boolean hasIfUnmodifiedSince = request.headerValue("If-Unmodified-Since") != null;

        if (!hasIfMatch && !hasIfUnmodifiedSince) {
            String title = "RFC 5789: PATCH Missing Conditional Headers";
            String detail = "The PATCH request to <b>" + escapeHtml(url) + "</b> does not include "
                    + "an <code>If-Match</code> or <code>If-Unmodified-Since</code> header. "
                    + "RFC 5789 Section 2 recommends conditional requests to prevent "
                    + "lost-update problems when multiple clients PATCH the same resource.";
            String remediation = "Include an <code>If-Match</code> header with the resource's "
                    + "current ETag, or an <code>If-Unmodified-Since</code> header with the "
                    + "resource's last-modified timestamp. Return <code>412 Precondition Failed</code> "
                    + "when the condition is not met.";

            AuditIssue issue = auditIssue(
                    title,
                    detail,
                    remediation,
                    url,
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.CERTAIN,
                    "RFC 5789 Section 2 states that PATCH requests should be applied "
                            + "conditionally to avoid lost updates.",
                    null,
                    AuditIssueSeverity.LOW,
                    reqResp
            );
            issues.add(issue);

            store.addFinding(new Finding(
                    "PASSIVE-01", title, detail, remediation,
                    AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN,
                    List.of(reqResp), System.currentTimeMillis(), config.getCurrentMode()
            ));
        }
    }

    /**
     * Detects PATCH requests using generic Content-Type instead of a patch media type.
     */
    private void checkGenericContentType(HttpRequestResponse reqResp,
                                          HttpRequest request,
                                          String url,
                                          List<AuditIssue> issues) {
        String contentType = request.headerValue("Content-Type");
        if (contentType == null) {
            return;
        }

        String ctLower = contentType.toLowerCase(Locale.ROOT).trim();

        // If it already uses a patch-specific media type, no issue
        if (ctLower.contains("patch+") || ctLower.contains("patch-")) {
            return;
        }

        // Flag generic JSON/XML content types on PATCH requests
        boolean isGeneric = ctLower.startsWith("application/json")
                || ctLower.startsWith("application/xml")
                || ctLower.startsWith("text/xml")
                || ctLower.startsWith("text/json");

        if (isGeneric) {
            String title = "RFC 5789: PATCH with Generic Content-Type";
            String detail = "The PATCH request to <b>" + escapeHtml(url) + "</b> uses "
                    + "<code>" + escapeHtml(contentType) + "</code> as its Content-Type. "
                    + "RFC 5789 recommends using a patch-specific media type "
                    + "(e.g. <code>application/merge-patch+json</code> per RFC 7396, or "
                    + "<code>application/json-patch+json</code> per RFC 6902) so the server "
                    + "can unambiguously determine patch semantics.";
            String remediation = "Use <code>application/merge-patch+json</code> for JSON Merge Patch "
                    + "(RFC 7396) or <code>application/json-patch+json</code> for JSON Patch "
                    + "(RFC 6902). Reject PATCH requests with unsupported Content-Types with "
                    + "<code>415 Unsupported Media Type</code>.";

            AuditIssue issue = auditIssue(
                    title,
                    detail,
                    remediation,
                    url,
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.FIRM,
                    "RFC 5789 Section 2 defines PATCH semantics as being determined by "
                            + "the Content-Type of the request body.",
                    null,
                    AuditIssueSeverity.LOW,
                    reqResp
            );
            issues.add(issue);

            store.addFinding(new Finding(
                    "PASSIVE-02", title, detail, remediation,
                    AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM,
                    List.of(reqResp), System.currentTimeMillis(), config.getCurrentMode()
            ));
        }
    }

    /**
     * Detects OPTIONS responses that advertise PATCH in Allow but lack Accept-Patch.
     */
    private void checkMissingAcceptPatch(HttpRequestResponse reqResp,
                                          HttpResponse response,
                                          String url,
                                          List<AuditIssue> issues) {
        String allow = response.headerValue("Allow");
        if (allow == null) {
            return;
        }

        boolean patchAllowed = false;
        for (String method : allow.split(",")) {
            if ("PATCH".equalsIgnoreCase(method.trim())) {
                patchAllowed = true;
                break;
            }
        }

        if (!patchAllowed) {
            return;
        }

        String acceptPatch = response.headerValue("Accept-Patch");
        if (acceptPatch != null && !acceptPatch.isBlank()) {
            return;
        }

        String title = "RFC 5789: OPTIONS Advertises PATCH Without Accept-Patch";
        String detail = "The OPTIONS response from <b>" + escapeHtml(url) + "</b> includes "
                + "<code>PATCH</code> in the <code>Allow</code> header but does not include "
                + "an <code>Accept-Patch</code> header. RFC 5789 Section 3.1 states that "
                + "servers advertising PATCH support SHOULD include <code>Accept-Patch</code> "
                + "to indicate which patch document formats are accepted.";
        String remediation = "Include an <code>Accept-Patch</code> header in OPTIONS responses "
                + "listing the supported patch media types, e.g. "
                + "<code>Accept-Patch: application/merge-patch+json</code>.";

        AuditIssue issue = auditIssue(
                title,
                detail,
                remediation,
                url,
                AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.CERTAIN,
                "RFC 5789 Section 3.1 requires servers to advertise accepted "
                        + "patch media types via the Accept-Patch header.",
                null,
                AuditIssueSeverity.LOW,
                reqResp
        );
        issues.add(issue);

        store.addFinding(new Finding(
                "PASSIVE-03", title, detail, remediation,
                AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN,
                List.of(reqResp), System.currentTimeMillis(), config.getCurrentMode()
        ));
    }

    /**
     * Minimal HTML entity escaping for safe embedding in issue detail HTML.
     */
    private static String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
