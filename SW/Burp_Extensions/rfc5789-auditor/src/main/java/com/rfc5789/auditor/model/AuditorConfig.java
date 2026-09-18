/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared mutable configuration for the RFC 5789 auditor extension.
 *
 * <p>Holds the current scan mode, enabled checks, concurrency settings,
 * collaborator configuration, and side-effect monitoring pairs.
 * All public mutators are synchronized for thread safety.</p>
 */
public final class AuditorConfig {

    /** Index constant for the Content-Type Confusion check (AMB-04). */
    public static final int CHECK_CONTENT_TYPE_CONFUSION = 0;

    /** Index constant for the Resource Creation check (AMB-01). */
    public static final int CHECK_RESOURCE_CREATION = 1;

    /** Index constant for the Atomicity / Race Condition check (AMB-03). */
    public static final int CHECK_ATOMICITY_RACE = 2;

    /** Index constant for the WAF Bypass check (AMB-11). */
    public static final int CHECK_WAF_BYPASS = 3;

    /** Index constant for the Cache Poisoning check (AMB-06). */
    public static final int CHECK_CACHE_POISONING = 4;

    /** Index constant for the Side-Effect / TOCTOU check (AMB-02). */
    public static final int CHECK_SIDE_EFFECT_TOCTOU = 5;

    /** Total number of checks available. */
    public static final int CHECK_COUNT = 6;

    /** Human-readable names for each check, indexed by the CHECK_* constants. */
    public static final String[] CHECK_NAMES = {
        "Content-Type Confusion",
        "Resource Creation via PATCH",
        "Atomicity / Race Condition",
        "WAF / Filter Bypass",
        "Cache Poisoning",
        "Side-Effect / TOCTOU"
    };

    private volatile ScanMode currentMode;
    private final boolean[] enabledChecks;
    private volatile int concurrentPatchCount;
    private final List<SideEffectPair> sideEffectPairs;
    private volatile boolean autoActiveCheck;
    private volatile String collaboratorDomain;
    private volatile int collaboratorPollIntervalMs;

    /**
     * Creates a new configuration with default values:
     * <ul>
     *   <li>Mode: {@link ScanMode#SAFE}</li>
     *   <li>All 6 checks enabled</li>
     *   <li>Concurrent PATCH count: 10</li>
     *   <li>Collaborator poll interval: 5000 ms</li>
     * </ul>
     */
    public AuditorConfig() {
        this.currentMode = ScanMode.SAFE;
        this.enabledChecks = new boolean[CHECK_COUNT];
        for (int i = 0; i < CHECK_COUNT; i++) {
            this.enabledChecks[i] = true;
        }
        this.concurrentPatchCount = 10;
        this.autoActiveCheck = false;
        this.sideEffectPairs = new ArrayList<>();
        this.collaboratorDomain = null;
        this.collaboratorPollIntervalMs = 5000;
    }

    /**
     * Returns the current scan mode.
     *
     * @return the current {@link ScanMode}
     */
    public ScanMode getCurrentMode() {
        return currentMode;
    }

    /**
     * Sets the scan mode.
     *
     * @param mode the new {@link ScanMode}; must not be null
     */
    public synchronized void setCurrentMode(ScanMode mode) {
        if (mode == null) {
            throw new IllegalArgumentException("ScanMode must not be null");
        }
        this.currentMode = mode;
    }

    /**
     * Returns whether the check at the given index is enabled.
     *
     * @param index check index (use the CHECK_* constants)
     * @return true if the check is enabled
     */
    public synchronized boolean isCheckEnabled(int index) {
        if (index < 0 || index >= CHECK_COUNT) {
            return false;
        }
        return enabledChecks[index];
    }

    /**
     * Resolves a check ID string to the corresponding CHECK_* index,
     * or returns -1 if unknown.
     */
    public static int checkIndexForId(String checkId) {
        if (checkId == null) return -1;
        switch (checkId) {
            case "AMB-04": return CHECK_CONTENT_TYPE_CONFUSION;
            case "AMB-01": return CHECK_RESOURCE_CREATION;
            case "AMB-03": return CHECK_ATOMICITY_RACE;
            case "AMB-11": return CHECK_WAF_BYPASS;
            case "AMB-06": return CHECK_CACHE_POISONING;
            case "AMB-02": return CHECK_SIDE_EFFECT_TOCTOU;
            default: return -1;
        }
    }

    /**
     * Returns whether the check with the given ID is enabled.
     * Unknown check IDs are treated as enabled.
     */
    public boolean isCheckEnabledById(String checkId) {
        int index = checkIndexForId(checkId);
        return index < 0 || isCheckEnabled(index);
    }

    /**
     * Enables or disables a specific check.
     *
     * @param index   check index (use the CHECK_* constants)
     * @param enabled true to enable, false to disable
     */
    public synchronized void setCheckEnabled(int index, boolean enabled) {
        if (index >= 0 && index < CHECK_COUNT) {
            enabledChecks[index] = enabled;
        }
    }

    /**
     * Returns a defensive copy of the enabled-checks array.
     *
     * @return a boolean array of length {@value #CHECK_COUNT}
     */
    public synchronized boolean[] getEnabledChecks() {
        boolean[] copy = new boolean[CHECK_COUNT];
        System.arraycopy(enabledChecks, 0, copy, 0, CHECK_COUNT);
        return copy;
    }

    /**
     * Returns the number of concurrent PATCH requests to send for the
     * atomicity/race-condition check (AMB-03).
     *
     * @return the concurrent PATCH count
     */
    public int getConcurrentPatchCount() {
        return concurrentPatchCount;
    }

    /**
     * Sets the number of concurrent PATCH requests for the atomicity check.
     *
     * @param count must be at least 2
     */
    public synchronized void setConcurrentPatchCount(int count) {
        if (count < 2) {
            throw new IllegalArgumentException("concurrentPatchCount must be >= 2, was: " + count);
        }
        this.concurrentPatchCount = count;
    }

    /**
     * Returns whether the extension should automatically run active checks
     * when a PATCH request is observed in proxy traffic.
     *
     * @return true if auto-active-check is enabled
     */
    public boolean isAutoActiveCheck() {
        return autoActiveCheck;
    }

    /**
     * Enables or disables automatic active checking on observed PATCH traffic.
     * When enabled, the extension runs the full active check pipeline in a
     * background thread whenever a PATCH request flows through the proxy.
     *
     * @param enabled true to enable, false to disable
     */
    public synchronized void setAutoActiveCheck(boolean enabled) {
        this.autoActiveCheck = enabled;
    }

    /**
     * Returns a defensive copy of the side-effect monitoring pairs.
     *
     * @return list of {@link SideEffectPair}
     */
    public synchronized List<SideEffectPair> getSideEffectPairs() {
        return new ArrayList<>(sideEffectPairs);
    }

    /**
     * Replaces all side-effect pairs with the given list.
     *
     * @param pairs the new list of side-effect pairs
     */
    public synchronized void setSideEffectPairs(List<SideEffectPair> pairs) {
        this.sideEffectPairs.clear();
        if (pairs != null) {
            this.sideEffectPairs.addAll(pairs);
        }
    }

    /**
     * Adds a single side-effect pair.
     *
     * @param pair the pair to add
     */
    public synchronized void addSideEffectPair(SideEffectPair pair) {
        if (pair != null) {
            this.sideEffectPairs.add(pair);
        }
    }

    /**
     * Returns the Burp Collaborator domain, or null if not configured.
     *
     * @return the collaborator domain, or null
     */
    public String getCollaboratorDomain() {
        return collaboratorDomain;
    }

    /**
     * Sets the Burp Collaborator domain.
     *
     * @param domain the domain, or null to clear
     */
    public synchronized void setCollaboratorDomain(String domain) {
        this.collaboratorDomain = domain;
    }

    /**
     * Returns the collaborator polling interval in milliseconds.
     *
     * @return the poll interval in ms
     */
    public int getCollaboratorPollIntervalMs() {
        return collaboratorPollIntervalMs;
    }

    /**
     * Sets the collaborator polling interval.
     *
     * @param ms interval in milliseconds; must be positive
     */
    public synchronized void setCollaboratorPollIntervalMs(int ms) {
        if (ms <= 0) {
            throw new IllegalArgumentException("Poll interval must be positive, was: " + ms);
        }
        this.collaboratorPollIntervalMs = ms;
    }

    /**
     * Represents a pair of a target URL and a list of URLs to monitor for
     * side effects after a PATCH is sent to the target.
     */
    public static final class SideEffectPair {

        private final String targetUrl;
        private final List<String> monitorUrls;

        /**
         * Creates a new side-effect pair.
         *
         * @param targetUrl   the URL that receives the PATCH request
         * @param monitorUrls URLs to GET before and after to detect side effects
         */
        public SideEffectPair(String targetUrl, List<String> monitorUrls) {
            this.targetUrl = targetUrl;
            this.monitorUrls = monitorUrls == null ? List.of() : List.copyOf(monitorUrls);
        }

        /**
         * Returns the target URL that receives the PATCH request.
         *
         * @return the target URL
         */
        public String getTargetUrl() {
            return targetUrl;
        }

        /**
         * Returns the URLs to monitor for side effects.
         *
         * @return unmodifiable list of monitor URLs
         */
        public List<String> getMonitorUrls() {
            return monitorUrls;
        }

        @Override
        public String toString() {
            return "SideEffectPair{target='" + targetUrl + "', monitors=" + monitorUrls + "}";
        }
    }
}
