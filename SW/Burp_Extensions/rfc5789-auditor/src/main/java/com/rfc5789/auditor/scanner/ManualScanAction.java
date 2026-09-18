/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.scanner;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.rfc5789.auditor.checks.PatchCheck;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.FindingsStore;
import com.rfc5789.auditor.util.PatchRequestHelper;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.JMenuItem;

/**
 * Context menu provider that adds a "Run RFC 5789 Audit" item to Burp's
 * right-click context menu.
 *
 * <p>This enables the extension to work in Burp Community Edition (which
 * does not support active scanning) as well as in Professional Edition.
 * When the user right-clicks on a PATCH request in the Proxy history,
 * Repeater, or any other tool, this menu item appears and triggers the
 * same check pipeline used by the active scan check.</p>
 *
 * <p>Checks run in a background thread to keep the UI responsive.</p>
 */
public final class ManualScanAction implements ContextMenuItemsProvider {

    private static final String MENU_ITEM_LABEL = "Run RFC 5789 Audit";

    private final List<PatchCheck> checks;
    private final AuditorConfig config;
    private final FindingsStore store;
    private final Http http;
    private final Logging logging;
    private final SiteMap siteMap;
    private final ExecutorService executor;

    /**
     * Creates a new manual scan action provider.
     *
     * @param checks  the ordered list of individual PATCH checks to run
     * @param config  the shared auditor configuration
     * @param store   the findings store for UI notification
     * @param http    the Montoya HTTP handle for sending requests
     * @param logging the Montoya logging handle for output
     * @param siteMap the Montoya site map for registering issues in Burp's Dashboard
     */
    public ManualScanAction(List<PatchCheck> checks,
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
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "RFC5789-ManualScan");
            t.setDaemon(true);
            return t;
        });
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // Collect all selected request/response items that are PATCH requests
        List<HttpRequestResponse> patchItems = new ArrayList<>();

        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
        if (selectedItems != null) {
            for (HttpRequestResponse item : selectedItems) {
                if (item.request() != null && PatchRequestHelper.isPatchRequest(item.request())) {
                    patchItems.add(item);
                }
            }
        }

        // Also check the message editor request if nothing selected
        if (patchItems.isEmpty()) {
            HttpRequestResponse messageEditorItem = event.messageEditorRequestResponse()
                    .isPresent()
                    ? event.messageEditorRequestResponse().get().requestResponse()
                    : null;
            if (messageEditorItem != null
                    && messageEditorItem.request() != null
                    && PatchRequestHelper.isPatchRequest(messageEditorItem.request())) {
                patchItems.add(messageEditorItem);
            }
        }

        if (patchItems.isEmpty()) {
            return Collections.emptyList();
        }

        // Create the menu item
        JMenuItem menuItem = new JMenuItem(MENU_ITEM_LABEL);
        List<HttpRequestResponse> itemsToScan = List.copyOf(patchItems);

        menuItem.addActionListener(e -> executor.submit(() -> runAudit(itemsToScan)));

        return List.of(menuItem);
    }

    /**
     * Runs all enabled checks against each PATCH request in the background.
     */
    private void runAudit(List<HttpRequestResponse> items) {
        logging.logToOutput("[RFC5789] Manual audit started for " + items.size()
                + " PATCH request(s) in " + config.getCurrentMode() + " mode.");

        int totalIssues = 0;

        for (HttpRequestResponse item : items) {
            String url = item.request().url();
            logging.logToOutput("[RFC5789] Auditing: " + url);

            for (PatchCheck check : checks) {
                if (!config.isCheckEnabledById(check.id())) {
                    continue;
                }
                try {
                    List<AuditIssue> issues = check.run(item, http, config, store);
                    int count = issues != null ? issues.size() : 0;
                    totalIssues += count;
                    if (count > 0) {
                        logging.logToOutput("[RFC5789]   " + check.id() + " ("
                                + check.name() + "): " + count + " issue(s)");
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
                } catch (RuntimeException ex) {
                    logging.logToError("[RFC5789] Check " + check.id() + " failed: "
                            + ex.getMessage());
                }
            }
        }

        logging.logToOutput("[RFC5789] Manual audit complete. Total issues: " + totalIssues);
    }

    /**
     * Shuts down the background executor.
     */
    public void shutdown() {
        executor.shutdownNow();
    }
}
