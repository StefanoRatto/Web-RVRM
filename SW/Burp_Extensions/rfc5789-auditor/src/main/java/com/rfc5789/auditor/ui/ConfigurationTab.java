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

import com.rfc5789.auditor.export.JsonExporter;
import com.rfc5789.auditor.export.MarkdownExporter;
import com.rfc5789.auditor.export.ReportExporter;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.FindingsStore;
import com.rfc5789.auditor.model.ScanMode;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;

/**
 * Configuration tab for the RFC 5789 Auditor.
 *
 * <p>Provides controls for scan mode selection, individual check toggles,
 * concurrency settings, Collaborator configuration, and report export.</p>
 */
public final class ConfigurationTab extends JPanel {

    private static final String[] AMB_IDS = {
            "AMB-04", "AMB-01", "AMB-03", "AMB-11", "AMB-06", "AMB-02"
    };

    private final AuditorConfig config;
    private final FindingsStore store;
    private DashboardTab dashboardTab;
    private PayloadsTab payloadsTab;

    private final JComboBox<ScanMode> modeCombo;
    private final JCheckBox[] checkBoxes;
    private final JCheckBox autoActiveCheckBox;
    private final JSpinner concurrencySpinner;
    private final JTextField collaboratorDomainField;
    private final JSpinner pollIntervalSpinner;

    /**
     * Creates the configuration tab.
     *
     * @param config the auditor configuration
     * @param store  the findings store (needed for export)
     */
    public ConfigurationTab(AuditorConfig config, FindingsStore store) {
        super(new BorderLayout(10, 10));
        this.config = config;
        this.store = store;

        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));
        formPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- Mode section ---
        JPanel modePanel = createTitledPanel("Scan Mode");
        modePanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        modeCombo = new JComboBox<>(ScanMode.values());
        modeCombo.setSelectedItem(config.getCurrentMode());
        modePanel.add(new JLabel("Mode: "));
        modePanel.add(modeCombo);
        formPanel.add(modePanel);
        formPanel.add(Box.createVerticalStrut(8));

        // --- Checks section ---
        JPanel checksPanel = createTitledPanel("Enabled Checks");
        checksPanel.setLayout(new BoxLayout(checksPanel, BoxLayout.Y_AXIS));
        checkBoxes = new JCheckBox[AuditorConfig.CHECK_COUNT];
        boolean[] enabled = config.getEnabledChecks();
        for (int i = 0; i < AuditorConfig.CHECK_COUNT; i++) {
            String label = "[" + AMB_IDS[i] + "] " + AuditorConfig.CHECK_NAMES[i];
            checkBoxes[i] = new JCheckBox(label, enabled[i]);
            checkBoxes[i].setAlignmentX(Component.LEFT_ALIGNMENT);
            checksPanel.add(checkBoxes[i]);
        }
        formPanel.add(checksPanel);
        formPanel.add(Box.createVerticalStrut(8));

        // --- Auto-Active-Check section ---
        JPanel autoPanel = createTitledPanel("Background Monitoring");
        autoPanel.setLayout(new BoxLayout(autoPanel, BoxLayout.Y_AXIS));
        autoActiveCheckBox = new JCheckBox(
                "Auto-run active checks when PATCH traffic is observed",
                config.isAutoActiveCheck());
        autoActiveCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        autoPanel.add(autoActiveCheckBox);
        JLabel autoNote = new JLabel(
                "When enabled, active checks run automatically on observed PATCH traffic. "
                + "Each unique URL is checked once per session.");
        autoNote.setFont(autoNote.getFont().deriveFont(11.0f));
        autoNote.setAlignmentX(Component.LEFT_ALIGNMENT);
        autoPanel.add(Box.createVerticalStrut(4));
        autoPanel.add(autoNote);
        formPanel.add(autoPanel);
        formPanel.add(Box.createVerticalStrut(8));

        // --- Concurrency section ---
        JPanel concurrencyPanel = createTitledPanel("Concurrency");
        concurrencyPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        concurrencySpinner = new JSpinner(new SpinnerNumberModel(
                config.getConcurrentPatchCount(), 2, 50, 1));
        concurrencyPanel.add(new JLabel("Concurrent PATCH requests: "));
        concurrencyPanel.add(concurrencySpinner);
        formPanel.add(concurrencyPanel);
        formPanel.add(Box.createVerticalStrut(8));

        // --- Collaborator section ---
        JPanel collabPanel = createTitledPanel("Collaborator (Burp Professional)");
        collabPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 4, 2, 4);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0;
        gbc.gridy = 0;
        collabPanel.add(new JLabel("Collaborator Domain: "), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        collaboratorDomainField = new JTextField(
                config.getCollaboratorDomain() != null ? config.getCollaboratorDomain() : "", 30);
        collabPanel.add(collaboratorDomainField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        collabPanel.add(new JLabel("Poll Interval (ms): "), gbc);
        gbc.gridx = 1;
        pollIntervalSpinner = new JSpinner(new SpinnerNumberModel(
                config.getCollaboratorPollIntervalMs(), 1000, 30000, 500));
        collabPanel.add(pollIntervalSpinner, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        JLabel noteLabel = new JLabel("Note: Collaborator features require Burp Suite Professional.");
        noteLabel.setFont(noteLabel.getFont().deriveFont(11.0f));
        collabPanel.add(noteLabel, gbc);

        formPanel.add(collabPanel);
        formPanel.add(Box.createVerticalStrut(8));

        // --- Export section ---
        JPanel exportPanel = createTitledPanel("Export");
        exportPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        JButton exportJsonBtn = new JButton("Export JSON");
        JButton exportMdBtn = new JButton("Export Markdown");
        exportJsonBtn.addActionListener(e -> exportReport(true));
        exportMdBtn.addActionListener(e -> exportReport(false));
        exportPanel.add(exportJsonBtn);
        exportPanel.add(exportMdBtn);
        formPanel.add(exportPanel);
        formPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(formPanel);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);

        // --- Apply button pinned to bottom (always visible) ---
        JPanel applyPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton applyBtn = new JButton("Apply");
        applyBtn.addActionListener(e -> applyConfiguration());
        applyPanel.add(applyBtn);
        add(applyPanel, BorderLayout.SOUTH);
    }

    /**
     * Reads all UI controls and pushes values into the AuditorConfig.
     */
    private void applyConfiguration() {
        ScanMode selectedMode = (ScanMode) modeCombo.getSelectedItem();

        if (selectedMode == ScanMode.AGGRESSIVE
                && config.getCurrentMode() != ScanMode.AGGRESSIVE) {
            int choice = JOptionPane.showConfirmDialog(
                    this,
                    "AGGRESSIVE mode sends real payloads that may create, modify, "
                            + "or delete resources.\n\n"
                            + "Only use this against test/staging environments.\n\n"
                            + "Switch to AGGRESSIVE mode?",
                    "Warning: Aggressive Mode",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) {
                modeCombo.setSelectedItem(config.getCurrentMode());
                return;
            }
        }

        config.setCurrentMode(selectedMode);

        config.setAutoActiveCheck(autoActiveCheckBox.isSelected());

        for (int i = 0; i < checkBoxes.length; i++) {
            config.setCheckEnabled(i, checkBoxes[i].isSelected());
        }

        int concurrency = (Integer) concurrencySpinner.getValue();
        config.setConcurrentPatchCount(concurrency);

        String domain = collaboratorDomainField.getText().trim();
        if (!domain.isEmpty()) {
            // Basic domain validation: must contain at least one dot and no spaces/slashes
            if (!domain.contains(".") || domain.contains(" ") || domain.contains("/")) {
                JOptionPane.showMessageDialog(this,
                        "Invalid Collaborator domain: must be a valid domain name (e.g., xyz.burpcollaborator.net)",
                        "Validation Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        config.setCollaboratorDomain(domain.isEmpty() ? null : domain);

        int pollInterval = (Integer) pollIntervalSpinner.getValue();
        config.setCollaboratorPollIntervalMs(pollInterval);

        // Refresh UI components that reflect the current mode
        if (dashboardTab != null) {
            dashboardTab.updateModeLabel();
        }
        if (payloadsTab != null) {
            payloadsTab.updateModeIndicator();
        }

        JOptionPane.showMessageDialog(
                this,
                "Configuration applied successfully.",
                "Configuration",
                JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Opens a file chooser and exports findings.
     *
     * @param asJson true for JSON export, false for Markdown
     */
    private void exportReport(boolean asJson) {
        JFileChooser chooser = new JFileChooser();
        if (asJson) {
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Files (*.json)", "json"));
            chooser.setSelectedFile(new File("rfc5789-report.json"));
        } else {
            chooser.setFileFilter(new FileNameExtensionFilter("Markdown Files (*.md)", "md"));
            chooser.setSelectedFile(new File("rfc5789-report.md"));
        }

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = chooser.getSelectedFile();
        try {
            ReportExporter exporter = asJson
                    ? new JsonExporter(config.getCurrentMode())
                    : new MarkdownExporter();
            exporter.export(store.getFindings(), file);
            JOptionPane.showMessageDialog(
                    this,
                    "Report exported to:\n" + file.getAbsolutePath(),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "Export failed: " + ex.getMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Creates a JPanel with a titled border.
     */
    private static JPanel createTitledPanel(String title) {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Let the panel size to its content, not a fixed max
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, Short.MAX_VALUE));
        return panel;
    }

    /**
     * Sets references to sibling tabs so that mode changes can refresh their indicators.
     *
     * @param dashboard the dashboard tab
     * @param payloads  the payloads tab
     */
    public void setSiblingTabs(DashboardTab dashboard, PayloadsTab payloads) {
        this.dashboardTab = dashboard;
        this.payloadsTab = payloads;
    }
}
