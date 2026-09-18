/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.scanner;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import com.rfc5789.auditor.checks.PatchCheck;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.FindingsStore;
import com.rfc5789.auditor.ui.DashboardTab;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Always-on HTTP traffic monitor that watches all proxy traffic for PATCH
 * requests and optionally triggers active checks automatically.
 *
 * <p>This handler is registered via {@code api.http().registerHttpHandler()}
 * and works in BOTH Burp Community and Professional editions.</p>
 *
 * <p>Behaviour:</p>
 * <ul>
 *   <li><b>Always</b>: Logs every PATCH request to the Dashboard status log,
 *       increments the observed PATCH counter, and records the URL for
 *       deduplication.</li>
 *   <li><b>When auto-active-check is ON</b>: Queues the PATCH request for
 *       background active checking using the same check pipeline as the
 *       active scan / context menu. Each unique PATCH URL is checked only
 *       once per session to avoid noise.</li>
 *   <li><b>When auto-active-check is OFF</b>: Only passive observation.
 *       No additional requests are sent.</li>
 * </ul>
 *
 * <p>The auto-active-check setting is toggled from the Configuration tab.</p>
 */
public final class PatchTrafficMonitor implements HttpHandler {

    private final AuditorConfig config;
    private final FindingsStore store;
    private final List<PatchCheck> checks;
    private final Http http;
    private final Logging logging;
    private final SiteMap siteMap;
    private volatile DashboardTab dashboard;

    /** URLs already checked in this session to avoid re-scanning the same endpoint. */
    private final Set<String> checkedUrls = ConcurrentHashMap.newKeySet();

    /** Background thread pool for running active checks without blocking proxy traffic. */
    private final ExecutorService executor = Executors.newFixedThreadPool(2,
            r -> {
                Thread t = new Thread(r, "RFC5789-AutoCheck");
                t.setDaemon(true);
                return t;
            });

    /** Counter of PATCH requests observed this session. */
    private final AtomicInteger patchCount = new AtomicInteger(0);

    /**
     * Creates the traffic monitor.
     *
     * @param checks  the active check implementations
     * @param config  shared auditor configuration
     * @param store   findings store for UI notification
     * @param http    Montoya HTTP service for sending probe requests
     * @param logging Montoya logging service
     * @param siteMap Montoya site map for registering issues in Burp's Dashboard
     */
    public PatchTrafficMonitor(List<PatchCheck> checks,
                                AuditorConfig config,
                                FindingsStore store,
                                Http http,
                                Logging logging,
                                SiteMap siteMap) {
        this.checks = List.copyOf(checks);
        this.config = config;
        this.store = store;
        this.http = http;
        this.logging = logging;
        this.siteMap = siteMap;
    }

    /**
     * Sets the dashboard reference for logging messages to the UI.
     * Called after the UI is created in the extension entry point.
     *
     * @param dashboard the dashboard tab instance
     */
    public void setDashboard(DashboardTab dashboard) {
        this.dashboard = dashboard;
    }

    /**
     * Returns the total number of PATCH requests observed this session.
     *
     * @return the PATCH request count
     */
    public int getPatchCount() {
        return patchCount.get();
    }

    /**
     * Handles outbound requests. Detects PATCH method and logs/queues.
     * Does NOT modify the request -- purely observational on the request side.
     */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // No modification, just observe
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    /**
     * Handles inbound responses. When a PATCH request's response arrives,
     * logs the observation and optionally queues active checks.
     */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        HttpRequest request = responseReceived.initiatingRequest();

        if (request != null && "PATCH".equalsIgnoreCase(request.method())) {
            int count = patchCount.incrementAndGet();
            String url = request.url();

            // Build a normalized key for deduplication (method + URL path without query)
            String urlPath = url;
            int queryIdx = urlPath.indexOf('?');
            if (queryIdx > 0) {
                urlPath = urlPath.substring(0, queryIdx);
            }

            // Log to dashboard
            String msg = String.format("PATCH #%d observed: %s [%d]",
                    count, url, responseReceived.statusCode());

            if (dashboard != null) {
                dashboard.logMessage(msg);
            }
            logging.logToOutput("[RFC5789-Monitor] " + msg);

            // If auto-active-check is enabled and we haven't checked this URL yet
            if (config.isAutoActiveCheck() && checkedUrls.add(urlPath)) {
                // Build an HttpRequestResponse from the observed traffic
                HttpRequestResponse observed = HttpRequestResponse.httpRequestResponse(
                        request, responseReceived);

                String autoMsg = String.format(
                        "Auto-active-check queued for: %s (mode: %s)",
                        url, config.getCurrentMode().name());
                if (dashboard != null) {
                    dashboard.logMessage(autoMsg);
                }
                logging.logToOutput("[RFC5789-Monitor] " + autoMsg);

                // Run active checks in background thread
                executor.submit(() -> runActiveChecks(observed, url));
            }
        }

        // Never modify the response
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /**
     * Runs all enabled active checks against the observed PATCH request.
     * Executes in a background thread to avoid blocking proxy traffic.
     */
    private void runActiveChecks(HttpRequestResponse observed, String url) {
        try {
            int totalIssues = 0;

            for (int i = 0; i < checks.size(); i++) {
                PatchCheck check = checks.get(i);

                if (!config.isCheckEnabledById(check.id())) {
                    continue;
                }

                try {
                    List<AuditIssue> issues = check.run(observed, http, config, store);
                    if (issues == null) issues = Collections.emptyList();
                    totalIssues += issues.size();

                    if (!issues.isEmpty()) {
                        String findingMsg = String.format(
                                "[AUTO] %s found %d issue(s) on %s",
                                check.name(), issues.size(), url);
                        if (dashboard != null) {
                            dashboard.logMessage(findingMsg);
                        }
                        logging.logToOutput("[RFC5789-Monitor] " + findingMsg);

                        // Queue findings for Burp's Dashboard via passive check drain
                        for (AuditIssue issue : issues) {
                            store.queueBurpIssue(issue);
                            try {
                                siteMap.add(issue);
                            } catch (Exception ex) {
                                // siteMap.add goes to Target, not Dashboard -- queue handles Dashboard
                            }
                        }
                    }
                } catch (Exception e) {
                    logging.logToError("[RFC5789-Monitor] Check " + check.name()
                            + " failed on " + url + ": " + e.getMessage());
                }
            }

            String summary = String.format(
                    "Auto-check complete for %s: %d total issues", url, totalIssues);
            if (dashboard != null) {
                dashboard.logMessage(summary);
            }
            logging.logToOutput("[RFC5789-Monitor] " + summary);

        } catch (Exception e) {
            logging.logToError("[RFC5789-Monitor] Auto-check failed for "
                    + url + ": " + e.getMessage());
        }
    }

    /**
     * Shuts down the background executor.
     */
    public void shutdown() {
        executor.shutdownNow();
    }

    /**
     * Clears the checked-URLs deduplication set.
     * Call this when starting a new engagement.
     */
    public void resetCheckedUrls() {
        checkedUrls.clear();
        patchCount.set(0);
    }
}
