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
package com.rfc5789.auditor.ui;

import burp.api.montoya.MontoyaApi;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.FindingsStore;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;

/**
 * Main tab group for the RFC 5789 Auditor extension.
 *
 * <p>Contains a {@link JTabbedPane} with five sub-tabs: Dashboard,
 * Configuration, Side-Effect Monitor, Payloads, and Results. This panel
 * is registered as a suite tab in Burp's user interface.</p>
 */
public final class MainTabGroup extends JPanel {

    private final DashboardTab dashboardTab;
    private final ConfigurationTab configurationTab;
    private final SideEffectMonitorTab sideEffectMonitorTab;
    private final PayloadsTab payloadsTab;
    private final ResultsTab resultsTab;

    /**
     * Creates the main tab group with all five sub-tabs.
     *
     * @param api    the Montoya API handle
     * @param config the shared auditor configuration
     * @param store  the findings store
     */
    public MainTabGroup(MontoyaApi api, AuditorConfig config, FindingsStore store) {
        super(new BorderLayout());

        this.dashboardTab = new DashboardTab(config, store);
        this.configurationTab = new ConfigurationTab(config, store);
        this.sideEffectMonitorTab = new SideEffectMonitorTab(config);
        this.payloadsTab = new PayloadsTab(config);
        this.resultsTab = new ResultsTab(store, config);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Dashboard", dashboardTab);
        tabbedPane.addTab("Configuration", configurationTab);
        tabbedPane.addTab("Side-Effect Monitor", sideEffectMonitorTab);
        tabbedPane.addTab("Payloads", payloadsTab);
        tabbedPane.addTab("Results", resultsTab);

        add(tabbedPane, BorderLayout.CENTER);

        // Wire cross-tab references for mode indicator refresh
        configurationTab.setSiblingTabs(dashboardTab, payloadsTab);
    }

    /**
     * Returns the dashboard tab, allowing other components to log status
     * messages.
     *
     * @return the dashboard tab
     */
    public DashboardTab getDashboardTab() {
        return dashboardTab;
    }

    /**
     * Returns the configuration tab.
     *
     * @return the configuration tab
     */
    public ConfigurationTab getConfigurationTab() {
        return configurationTab;
    }

    /**
     * Returns the side-effect monitor tab.
     *
     * @return the side-effect monitor tab
     */
    public SideEffectMonitorTab getSideEffectMonitorTab() {
        return sideEffectMonitorTab;
    }

    /**
     * Returns the payloads tab.
     *
     * @return the payloads tab
     */
    public PayloadsTab getPayloadsTab() {
        return payloadsTab;
    }

    /**
     * Returns the results tab.
     *
     * @return the results tab
     */
    public ResultsTab getResultsTab() {
        return resultsTab;
    }
}
