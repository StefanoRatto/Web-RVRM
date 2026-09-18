/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.FindingsStore;

import java.util.List;

/**
 * Contract for a single RFC 5789 PATCH semantic check.
 *
 * <p>Each implementation probes one specific ambiguity or misconfiguration
 * in how a server handles PATCH requests. Implementations must be stateless
 * and thread-safe.</p>
 */
public interface PatchCheck {

    /**
     * Returns the short identifier for this check (e.g. "AMB-04").
     *
     * @return the check id
     */
    String id();

    /**
     * Returns the human-readable name of this check (e.g. "Content-Type Confusion").
     *
     * @return the check name
     */
    String name();

    /**
     * Returns a brief description of what this check tests.
     *
     * @return the description
     */
    String description();

    /**
     * Executes this check against the given base PATCH request/response.
     *
     * <p>Implementations may use the {@code http} handle to send additional
     * requests. Findings should be added to the {@code store} in addition
     * to being returned as {@link AuditIssue} objects so that the UI tab
     * can display them.</p>
     *
     * @param baseReqResp the original PATCH request and its response
     * @param http        the Montoya HTTP handle for sending requests
     * @param config      the current auditor configuration
     * @param store       the findings store for UI notification
     * @return a list of audit issues found (may be empty, never null)
     */
    List<AuditIssue> run(HttpRequestResponse baseReqResp,
                         Http http,
                         AuditorConfig config,
                         FindingsStore store);
}
