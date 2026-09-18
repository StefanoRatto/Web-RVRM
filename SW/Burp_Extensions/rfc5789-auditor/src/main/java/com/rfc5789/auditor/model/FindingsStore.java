/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.model;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Thread-safe store for all findings produced by the RFC 5789 auditor.
 *
 * <p>Backed by a {@link CopyOnWriteArrayList} so readers never need to synchronize.
 * Fires {@link java.beans.PropertyChangeEvent}s on the property name
 * {@value #PROPERTY_FINDINGS} whenever a finding is added or the store is cleared,
 * allowing the UI to refresh.</p>
 */
public final class FindingsStore {

    /** Property name used for {@link PropertyChangeListener} events. */
    public static final String PROPERTY_FINDINGS = "findings";

    private final CopyOnWriteArrayList<Finding> findings;
    private final PropertyChangeSupport changeSupport;

    /**
     * Queue of AuditIssue objects from context menu and traffic monitor checks
     * that need to be pushed into Burp's Dashboard via the passive scan check's
     * auditResult return. This is the bridge between programmatic checks and
     * Burp's scanner-based issue reporting.
     */
    private final ConcurrentLinkedQueue<AuditIssue> pendingBurpIssues;

    /**
     * Creates an empty findings store.
     */
    public FindingsStore() {
        this.findings = new CopyOnWriteArrayList<>();
        this.changeSupport = new PropertyChangeSupport(this);
        this.pendingBurpIssues = new ConcurrentLinkedQueue<>();
    }

    /**
     * Adds a finding to the store and fires a property-change event.
     *
     * @param finding the finding to add; must not be null
     */
    public void addFinding(Finding finding) {
        if (finding != null) {
            findings.add(finding);
            changeSupport.firePropertyChange(PROPERTY_FINDINGS, null, null);
        }
    }

    /**
     * Returns an unmodifiable snapshot of all findings.
     *
     * @return unmodifiable list of findings
     */
    public List<Finding> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    /**
     * Returns all findings that match the given check ID.
     *
     * @param checkId the check identifier, e.g. "AMB-04"
     * @return list of matching findings (never null, may be empty)
     */
    public List<Finding> getFindingsByCheck(String checkId) {
        if (checkId == null) {
            return Collections.emptyList();
        }
        return findings.stream()
                .filter(f -> checkId.equals(f.getCheckId()))
                .collect(Collectors.toUnmodifiableList());
    }

    /**
     * Removes all findings from the store and fires a property-change event.
     */
    public void clear() {
        findings.clear();
        changeSupport.firePropertyChange(PROPERTY_FINDINGS, null, null);
    }

    /**
     * Returns a count of findings grouped by severity.
     *
     * @return an unmodifiable map from severity to count
     */
    public Map<AuditIssueSeverity, Integer> getCountBySeverity() {
        EnumMap<AuditIssueSeverity, Integer> counts = new EnumMap<>(AuditIssueSeverity.class);
        for (Finding f : findings) {
            counts.merge(f.getSeverity(), 1, Integer::sum);
        }
        return Collections.unmodifiableMap(counts);
    }

    /**
     * Returns the total number of findings.
     *
     * @return the count
     */
    public int size() {
        return findings.size();
    }

    /**
     * Registers a listener that is notified whenever findings are added or cleared.
     *
     * @param listener the listener to add
     */
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        changeSupport.addPropertyChangeListener(listener);
    }

    /**
     * Removes a previously registered listener.
     *
     * @param listener the listener to remove
     */
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        changeSupport.removePropertyChangeListener(listener);
    }

    /**
     * Queues an AuditIssue for inclusion in the next passive scan check return.
     * This bridges findings from the context menu and traffic monitor into
     * Burp's Dashboard Issues panel, which only shows findings returned by
     * registered ScanCheck implementations.
     *
     * @param issue the AuditIssue to queue for Dashboard reporting
     */
    public void queueBurpIssue(AuditIssue issue) {
        if (issue != null) {
            pendingBurpIssues.add(issue);
        }
    }

    /**
     * Drains all pending AuditIssue objects from the queue.
     * Called by the passive scan check to include these issues in its
     * auditResult return, which Burp processes and displays in the Dashboard.
     *
     * @return list of pending issues (may be empty, never null)
     */
    public List<AuditIssue> drainPendingBurpIssues() {
        List<AuditIssue> drained = new ArrayList<>();
        AuditIssue issue;
        while ((issue = pendingBurpIssues.poll()) != null) {
            drained.add(issue);
        }
        return drained;
    }
}
