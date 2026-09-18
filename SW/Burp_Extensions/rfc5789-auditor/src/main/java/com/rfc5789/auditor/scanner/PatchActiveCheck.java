/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.scanner;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.rfc5789.auditor.checks.PatchCheck;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.FindingsStore;
import com.rfc5789.auditor.util.PatchRequestHelper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;

/**
 * Active scan check for Burp Suite Professional.
 *
 * <p>Implements the Montoya {@link ScanCheck} interface. The
 * {@link #activeAudit(HttpRequestResponse, AuditInsertionPoint)} method runs
 * all enabled {@link PatchCheck} implementations against PATCH requests.
 * The {@link #passiveAudit(HttpRequestResponse)} method returns an empty
 * result because passive scanning is handled by {@link PatchPassiveCheck}.</p>
 *
 * <p>Since the Montoya {@code activeAudit} method does not provide an
 * {@link Http} handle, the {@code Http} reference is captured at construction
 * time from the {@link burp.api.montoya.MontoyaApi}.</p>
 *
 * <p>The check respects the {@link AuditorConfig} to determine which
 * individual checks are enabled and which scan mode to use.</p>
 */
public final class PatchActiveCheck implements ScanCheck {

    private final List<PatchCheck> checks;
    private final AuditorConfig config;
    private final FindingsStore store;
    private final Http http;

    /**
     * Creates a new active scan check.
     *
     * @param checks the ordered list of individual PATCH checks to run
     * @param config the shared auditor configuration
     * @param store  the findings store for UI notification
     * @param http   the Montoya HTTP handle for sending probe requests
     */
    public PatchActiveCheck(List<PatchCheck> checks,
                            AuditorConfig config,
                            FindingsStore store,
                            Http http) {
        this.checks = List.copyOf(checks);
        this.config = config;
        this.store = store;
        this.http = http;
    }

    /**
     * Performs active auditing of PATCH requests by running all enabled checks.
     *
     * <p>Non-PATCH requests are ignored with an empty result.</p>
     *
     * @param baseRequestResponse the base request/response to audit
     * @param insertionPoint      the insertion point (not used; checks operate on the full request)
     * @return an {@link AuditResult} containing all findings from enabled checks
     */
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint) {
        // Only audit PATCH requests
        if (baseRequestResponse.request() == null
                || !PatchRequestHelper.isPatchRequest(baseRequestResponse.request())) {
            return auditResult(Collections.emptyList());
        }

        List<AuditIssue> allIssues = new ArrayList<>();

        for (PatchCheck check : checks) {
            if (!config.isCheckEnabledById(check.id())) {
                continue;
            }
            try {
                List<AuditIssue> issues = check.run(baseRequestResponse, http, config, store);
                if (issues != null) {
                    allIssues.addAll(issues);
                }
            } catch (RuntimeException e) {
                // Individual check failure should not abort the entire scan.
                // Burp's extension error log captures stderr output.
                System.err.println("[RFC5789] Check " + check.id() + " (" + check.name()
                        + ") threw an exception: " + e.getMessage());
            }
        }

        return auditResult(allIssues);
    }

    /**
     * Passive audit is a no-op for this check; passive scanning is handled by
     * {@link PatchPassiveCheck}.
     *
     * @param baseRequestResponse the base request/response (unused)
     * @return an empty audit result
     */
    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
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
     * Returns the list of registered checks (for use by {@link ManualScanAction}).
     *
     * @return unmodifiable list of checks
     */
    public List<PatchCheck> getChecks() {
        return checks;
    }

}
