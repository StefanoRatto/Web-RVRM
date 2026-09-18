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

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.Finding;
import com.rfc5789.auditor.model.FindingsStore;
import com.rfc5789.auditor.model.ScanMode;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Dashboard tab showing the current mode, findings summary, and status log.
 *
 * <p>The mode indicator displays "SAFE MODE" (green) or "AGGRESSIVE MODE"
 * (red). The summary table breaks down findings by check and severity.
 * The status log appends timestamped messages as operations proceed.</p>
 */
public final class DashboardTab extends JPanel implements PropertyChangeListener {

    private static final DateTimeFormatter LOG_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String[] CHECK_IDS = {
            "AMB-04", "AMB-01", "AMB-03", "AMB-11", "AMB-06", "AMB-02",
            "PASSIVE-01", "PASSIVE-02", "PASSIVE-03"
    };

    private static final String[] CHECK_LABELS = {
            "Content-Type Confusion",
            "Resource Creation via PATCH",
            "Atomicity / Race Condition",
            "WAF Bypass via PATCH Decomposition",
            "Cache Poisoning",
            "Side-Effect / TOCTOU",
            "Missing Conditional Headers",
            "Generic Content-Type on PATCH",
            "Missing Accept-Patch Header"
    };

    private static final String[] SUMMARY_COLUMNS = {
            "Check", "Total", "Critical", "High", "Medium", "Low", "Info"
    };

    private final AuditorConfig config;
    private final FindingsStore store;
    private final JLabel modeLabel;
    private final DefaultTableModel summaryModel;
    private final JTextArea statusLog;

    /**
     * Creates the dashboard tab.
     *
     * @param config the auditor configuration
     * @param store  the findings store
     */
    public DashboardTab(AuditorConfig config, FindingsStore store) {
        super(new BorderLayout(10, 10));
        this.config = config;
        this.store = store;

        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- Top: Mode indicator ---
        modeLabel = new JLabel("", SwingConstants.CENTER);
        modeLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 24));
        modeLabel.setOpaque(true);
        modeLabel.setPreferredSize(new Dimension(0, 60));
        updateModeLabel();
        add(modeLabel, BorderLayout.NORTH);

        // --- Middle: Summary table ---
        summaryModel = new DefaultTableModel(SUMMARY_COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        for (int i = 0; i < CHECK_IDS.length; i++) {
            summaryModel.addRow(new Object[]{
                    "[" + CHECK_IDS[i] + "] " + CHECK_LABELS[i],
                    0, 0, 0, 0, 0, 0
            });
        }
        JTable summaryTable = new JTable(summaryModel);
        summaryTable.setFillsViewportHeight(true);
        JScrollPane tableScroll = new JScrollPane(summaryTable);
        tableScroll.setPreferredSize(new Dimension(0, 200));
        add(tableScroll, BorderLayout.CENTER);

        // --- Bottom: Status log ---
        statusLog = new JTextArea();
        statusLog.setEditable(false);
        statusLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        statusLog.setLineWrap(true);
        statusLog.setWrapStyleWord(true);
        JScrollPane logScroll = new JScrollPane(statusLog);
        logScroll.setPreferredSize(new Dimension(0, 180));
        logScroll.setBorder(BorderFactory.createTitledBorder("Status Log"));
        add(logScroll, BorderLayout.SOUTH);

        // Listen for findings changes
        store.addPropertyChangeListener(this);

        logMessage("RFC 5789 Auditor initialised. Mode: " + config.getCurrentMode().name());
    }

    /**
     * Appends a timestamped message to the status log.
     *
     * @param msg the message to log
     */
    public void logMessage(String msg) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = LocalDateTime.now().format(LOG_FMT);
            statusLog.append("[" + timestamp + "] " + msg + "\n");
            statusLog.setCaretPosition(statusLog.getDocument().getLength());
        });
    }

    /**
     * Refreshes the mode indicator label based on current configuration.
     */
    public void updateModeLabel() {
        SwingUtilities.invokeLater(() -> {
            ScanMode mode = config.getCurrentMode();
            if (mode == ScanMode.AGGRESSIVE) {
                modeLabel.setText("AGGRESSIVE MODE");
                modeLabel.setForeground(Color.WHITE);
                modeLabel.setBackground(new Color(180, 30, 30));
            } else {
                modeLabel.setText("SAFE MODE");
                modeLabel.setForeground(Color.WHITE);
                modeLabel.setBackground(new Color(30, 130, 50));
            }
        });
    }

    @Override
    public void propertyChange(PropertyChangeEvent evt) {
        if (FindingsStore.PROPERTY_FINDINGS.equals(evt.getPropertyName())) {
            SwingUtilities.invokeLater(this::refreshSummaryTable);
        }
    }

    /**
     * Recalculates and updates the summary table from the findings store.
     */
    private void refreshSummaryTable() {
        List<Finding> allFindings = store.getFindings();

        for (int row = 0; row < CHECK_IDS.length; row++) {
            String checkId = CHECK_IDS[row];
            int total = 0;
            int critical = 0;
            int high = 0;
            int medium = 0;
            int low = 0;
            int info = 0;

            for (Finding f : allFindings) {
                if (checkId.equals(f.getCheckId())) {
                    total++;
                    AuditIssueSeverity sev = f.getSeverity();
                    if (sev == AuditIssueSeverity.HIGH) {
                        high++;
                    } else if (sev == AuditIssueSeverity.MEDIUM) {
                        medium++;
                    } else if (sev == AuditIssueSeverity.LOW) {
                        low++;
                    } else if (sev == AuditIssueSeverity.INFORMATION) {
                        info++;
                    }
                }
            }

            summaryModel.setValueAt(total, row, 1);
            summaryModel.setValueAt(critical, row, 2);
            summaryModel.setValueAt(high, row, 3);
            summaryModel.setValueAt(medium, row, 4);
            summaryModel.setValueAt(low, row, 5);
            summaryModel.setValueAt(info, row, 6);
        }
    }
}
