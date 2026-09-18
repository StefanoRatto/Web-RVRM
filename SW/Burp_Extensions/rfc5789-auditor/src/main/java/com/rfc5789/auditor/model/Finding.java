/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Immutable data class representing a single finding produced by the auditor.
 *
 * <p>Each finding captures the check that produced it, a human-readable title
 * and detail, remediation guidance, severity/confidence, the HTTP evidence,
 * and metadata about when and how it was discovered.</p>
 */
public final class Finding {

    private final String checkId;
    private final String title;
    private final String detail;
    private final String remediation;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final List<HttpRequestResponse> evidence;
    private final long timestamp;
    private final ScanMode modeUsed;

    /**
     * Creates a new finding.
     *
     * @param checkId     the check identifier, e.g. "AMB-04"
     * @param title       short human-readable title
     * @param detail      detailed description of the finding
     * @param remediation remediation guidance
     * @param severity    issue severity
     * @param confidence  detection confidence
     * @param evidence    HTTP request/response pairs that demonstrate the finding
     * @param timestamp   epoch millis when the finding was created
     * @param modeUsed    the scan mode that was active when the finding was produced
     */
    public Finding(String checkId,
                   String title,
                   String detail,
                   String remediation,
                   AuditIssueSeverity severity,
                   AuditIssueConfidence confidence,
                   List<HttpRequestResponse> evidence,
                   long timestamp,
                   ScanMode modeUsed) {
        this.checkId = checkId;
        this.title = title;
        this.detail = detail;
        this.remediation = remediation;
        this.severity = severity;
        this.confidence = confidence;
        this.evidence = evidence == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(evidence));
        this.timestamp = timestamp;
        this.modeUsed = modeUsed;
    }

    /**
     * Returns the check identifier (e.g. "AMB-04").
     *
     * @return the check id
     */
    public String getCheckId() {
        return checkId;
    }

    /**
     * Returns the short human-readable title.
     *
     * @return the title
     */
    public String getTitle() {
        return title;
    }

    /**
     * Returns the detailed description of the finding.
     *
     * @return the detail string
     */
    public String getDetail() {
        return detail;
    }

    /**
     * Returns remediation guidance.
     *
     * @return the remediation text
     */
    public String getRemediation() {
        return remediation;
    }

    /**
     * Returns the severity of the finding.
     *
     * @return the severity
     */
    public AuditIssueSeverity getSeverity() {
        return severity;
    }

    /**
     * Returns the confidence level of the detection.
     *
     * @return the confidence
     */
    public AuditIssueConfidence getConfidence() {
        return confidence;
    }

    /**
     * Returns the HTTP evidence for this finding.
     *
     * @return unmodifiable list of request/response pairs
     */
    public List<HttpRequestResponse> getEvidence() {
        return evidence;
    }

    /**
     * Returns the epoch timestamp (milliseconds) when this finding was created.
     *
     * @return the timestamp
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Returns the scan mode that was active when this finding was produced.
     *
     * @return the scan mode
     */
    public ScanMode getModeUsed() {
        return modeUsed;
    }

    @Override
    public String toString() {
        return "Finding{checkId='" + checkId + "', title='" + title
                + "', severity=" + severity + ", confidence=" + confidence
                + ", mode=" + modeUsed + "}";
    }
}
