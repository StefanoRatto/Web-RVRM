/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.rfc5789.auditor.checks.AtomicityRaceCheck;
import com.rfc5789.auditor.checks.CachePoisoningCheck;
import com.rfc5789.auditor.checks.ContentTypeConfusionCheck;
import com.rfc5789.auditor.checks.PatchCheck;
import com.rfc5789.auditor.checks.ResourceCreationCheck;
import com.rfc5789.auditor.checks.SideEffectTocTouCheck;
import com.rfc5789.auditor.checks.WafBypassCheck;
import com.rfc5789.auditor.collaborator.CollaboratorManager;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.FindingsStore;
import com.rfc5789.auditor.scanner.ManualScanAction;
import com.rfc5789.auditor.scanner.PatchActiveCheck;
import com.rfc5789.auditor.scanner.PatchPassiveCheck;
import com.rfc5789.auditor.scanner.PatchTrafficMonitor;
import com.rfc5789.auditor.ui.DashboardTab;
import com.rfc5789.auditor.ui.MainTabGroup;

import java.util.List;

/**
 * Main entry point for the RFC 5789 Auditor Burp Suite extension.
 *
 * <p>This extension audits HTTP PATCH request handling for RFC 5789
 * compliance issues and common security misconfigurations. It supports
 * both Burp Suite Community Edition (via context menu) and Professional
 * Edition (via active/passive scan checks).</p>
 *
 * <p>The extension registers:</p>
 * <ul>
 *   <li>A passive scan check that detects RFC 5789 compliance issues in
 *       existing PATCH traffic.</li>
 *   <li>An active scan check (Professional only) that probes PATCH
 *       endpoints with targeted payloads.</li>
 *   <li>A context menu item "Run RFC 5789 Audit" that works in both
 *       Community and Professional editions.</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5789">RFC 5789 - PATCH Method for HTTP</a>
 */
public class RFC5789Auditor implements BurpExtension {

    /** Extension display name shown in Burp's Extensions tab. */
    private static final String EXTENSION_NAME = "RFC 5789 Auditor";

    /** Version string for logging. */
    private static final String VERSION = "1.0.0";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        Logging logging = api.logging();

        // Initialize shared configuration and findings store
        AuditorConfig config = new AuditorConfig();
        FindingsStore store = new FindingsStore();

        // Initialize Collaborator manager (degrades gracefully in Community Edition)
        CollaboratorManager collaboratorManager = new CollaboratorManager(api, config);

        // Build the list of active PatchCheck implementations.
        List<PatchCheck> activeChecks = List.of(
                new ContentTypeConfusionCheck(),
                new ResourceCreationCheck(),
                new AtomicityRaceCheck(),
                new WafBypassCheck(),
                new CachePoisoningCheck(collaboratorManager),
                new SideEffectTocTouCheck()
        );

        // Register passive scan check (detects issues in existing traffic)
        PatchPassiveCheck passiveCheck = new PatchPassiveCheck(config, store);
        api.scanner().registerScanCheck(passiveCheck);
        logging.logToOutput("[RFC5789] Passive scan check registered.");

        // Register active scan check (sends probe requests; works in Professional edition)
        PatchActiveCheck activeCheck = new PatchActiveCheck(
                activeChecks, config, store, api.http());
        api.scanner().registerScanCheck(activeCheck);
        logging.logToOutput("[RFC5789] Active scan check registered.");

        // Register context menu item (works in both Community and Professional)
        ManualScanAction menuAction = new ManualScanAction(
                activeChecks, config, store, api.http(), logging, api.siteMap());
        api.userInterface().registerContextMenuItemsProvider(menuAction);
        logging.logToOutput("[RFC5789] Context menu provider registered.");

        // Register always-on traffic monitor (works in BOTH Community and Professional)
        PatchTrafficMonitor trafficMonitor = new PatchTrafficMonitor(
                activeChecks, config, store, api.http(), logging, api.siteMap());
        api.http().registerHttpHandler(trafficMonitor);
        logging.logToOutput("[RFC5789] Traffic monitor registered (always-on PATCH detection).");

        // Register the UI tab group and wire the dashboard to the traffic monitor
        MainTabGroup mainTab = new MainTabGroup(api, config, store);
        api.userInterface().registerSuiteTab("RFC 5789 Auditor", mainTab);
        DashboardTab dashboard = mainTab.getDashboardTab();
        if (dashboard != null) {
            trafficMonitor.setDashboard(dashboard);
        }
        logging.logToOutput("[RFC5789] UI tab group registered.");

        // Register unload handler
        api.extension().registerUnloadingHandler(() -> {
            trafficMonitor.shutdown();
            menuAction.shutdown();
            logging.logToOutput("[RFC5789] Extension unloaded.");
        });

        // Log startup banner
        logBanner(logging);
    }

    /**
     * Logs the startup banner with extension name, version, and capabilities.
     */
    private void logBanner(Logging logging) {
        String banner = "\n"
                + "============================================================\n"
                + "  RFC 5789 Auditor v" + VERSION + "\n"
                + "  Open Source\n"
                + "============================================================\n"
                + "  PATCH Method Security & Compliance Scanner\n"
                + "------------------------------------------------------------\n"
                + "  Passive checks : Enabled (detects missing headers,\n"
                + "                   generic Content-Types, missing Accept-Patch)\n"
                + "  Active checks  : Enabled (Burp Pro) / Context menu (Community)\n"
                + "  Default mode   : SAFE (canary payloads only)\n"
                + "------------------------------------------------------------\n"
                + "  Right-click any PATCH request -> 'Run RFC 5789 Audit'\n"
                + "============================================================\n";
        logging.logToOutput(banner);
    }
}
