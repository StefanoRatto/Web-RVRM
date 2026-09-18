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

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.rfc5789.auditor.export.JsonExporter;
import com.rfc5789.auditor.export.MarkdownExporter;
import com.rfc5789.auditor.export.ReportExporter;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.Finding;
import com.rfc5789.auditor.model.FindingsStore;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Results tab showing all findings with filtering and detail view.
 *
 * <p>Displays a filterable table of findings that auto-updates as new
 * findings are added to the store. Selecting a row shows the full finding
 * detail including remediation and evidence snippets in the bottom panel.</p>
 */
public final class ResultsTab extends JPanel implements PropertyChangeListener {

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    .withZone(ZoneOffset.UTC);

    private static final String[] CHECK_FILTER_OPTIONS = {
            "All", "AMB-04", "AMB-01", "AMB-03", "AMB-11", "AMB-06", "AMB-02"
    };

    private static final String[] SEVERITY_FILTER_OPTIONS = {
            "All", "High", "Medium", "Low", "Information"
    };

    private static final String[] TABLE_COLUMNS = {
            "Timestamp", "Check", "Severity", "Title", "Mode"
    };

    private final FindingsStore store;
    private final AuditorConfig config;
    private final JComboBox<String> checkFilter;
    private final JComboBox<String> severityFilter;
    private final DefaultTableModel tableModel;
    private final JTable findingsTable;
    private final JTextArea detailArea;

    /** Filtered view of findings currently displayed in the table. */
    private final List<Finding> displayedFindings;

    /**
     * Creates the results tab.
     *
     * @param store  the findings store
     * @param config the auditor configuration (for export mode)
     */
    public ResultsTab(FindingsStore store, AuditorConfig config) {
        super(new BorderLayout(10, 10));
        this.store = store;
        this.config = config;
        this.displayedFindings = new ArrayList<>();
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- Top: Filter controls ---
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        filterPanel.add(new JLabel("Check:"));
        checkFilter = new JComboBox<>(CHECK_FILTER_OPTIONS);
        checkFilter.addActionListener(e -> refreshTable());
        filterPanel.add(checkFilter);

        filterPanel.add(new JLabel("Severity:"));
        severityFilter = new JComboBox<>(SEVERITY_FILTER_OPTIONS);
        severityFilter.addActionListener(e -> refreshTable());
        filterPanel.add(severityFilter);

        JButton clearBtn = new JButton("Clear All");
        clearBtn.addActionListener(e -> {
            store.clear();
            refreshTable();
        });
        filterPanel.add(clearBtn);

        JButton exportBtn = new JButton("Export");
        exportBtn.addActionListener(e -> exportFindings());
        filterPanel.add(exportBtn);

        add(filterPanel, BorderLayout.NORTH);

        // --- Middle/Bottom: Split pane with table and detail ---
        tableModel = new DefaultTableModel(TABLE_COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        findingsTable = new JTable(tableModel);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.setFillsViewportHeight(true);
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedDetail();
            }
        });

        JScrollPane tableScroll = new JScrollPane(findingsTable);

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Finding Detail"));
        detailScroll.setPreferredSize(new Dimension(0, 250));

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        splitPane.setDividerLocation(250);
        splitPane.setResizeWeight(0.5);
        add(splitPane, BorderLayout.CENTER);

        // Listen for findings changes
        store.addPropertyChangeListener(this);
    }

    @Override
    public void propertyChange(PropertyChangeEvent evt) {
        if (FindingsStore.PROPERTY_FINDINGS.equals(evt.getPropertyName())) {
            SwingUtilities.invokeLater(this::refreshTable);
        }
    }

    /**
     * Rebuilds the table rows based on the current filter selections.
     */
    private void refreshTable() {
        String selectedCheck = (String) checkFilter.getSelectedItem();
        String selectedSeverity = (String) severityFilter.getSelectedItem();

        List<Finding> all = store.getFindings();
        displayedFindings.clear();
        tableModel.setRowCount(0);

        for (Finding f : all) {
            if (!"All".equals(selectedCheck) && !selectedCheck.equals(f.getCheckId())) {
                continue;
            }
            if (!"All".equals(selectedSeverity)
                    && !matchesSeverityFilter(f.getSeverity(), selectedSeverity)) {
                continue;
            }

            displayedFindings.add(f);
            String ts = TIMESTAMP_FMT.format(Instant.ofEpochMilli(f.getTimestamp()));
            tableModel.addRow(new Object[]{
                    ts,
                    f.getCheckId(),
                    f.getSeverity().name(),
                    f.getTitle(),
                    f.getModeUsed().name()
            });
        }

        detailArea.setText("");
    }

    /**
     * Checks whether a finding severity matches the selected filter string.
     */
    private static boolean matchesSeverityFilter(AuditIssueSeverity severity, String filter) {
        switch (filter) {
            case "High":
                return severity == AuditIssueSeverity.HIGH;
            case "Medium":
                return severity == AuditIssueSeverity.MEDIUM;
            case "Low":
                return severity == AuditIssueSeverity.LOW;
            case "Information":
                return severity == AuditIssueSeverity.INFORMATION;
            default:
                return true;
        }
    }

    /**
     * Shows the full detail for the currently selected table row.
     */
    private void showSelectedDetail() {
        int row = findingsTable.getSelectedRow();
        if (row < 0 || row >= displayedFindings.size()) {
            detailArea.setText("");
            return;
        }

        Finding f = displayedFindings.get(row);
        StringBuilder sb = new StringBuilder(1024);
        sb.append("Check: [").append(f.getCheckId()).append("] ").append(f.getTitle()).append("\n");
        sb.append("Severity: ").append(f.getSeverity().name()).append("\n");
        sb.append("Confidence: ").append(f.getConfidence().name()).append("\n");
        sb.append("Mode: ").append(f.getModeUsed().name()).append("\n");
        sb.append("Timestamp: ")
                .append(TIMESTAMP_FMT.format(Instant.ofEpochMilli(f.getTimestamp())))
                .append(" UTC\n");
        sb.append("\n--- Detail ---\n");
        sb.append(f.getDetail()).append("\n");
        sb.append("\n--- Remediation ---\n");
        sb.append(f.getRemediation()).append("\n");

        List<HttpRequestResponse> evidence = f.getEvidence();
        if (!evidence.isEmpty()) {
            sb.append("\n--- Evidence (").append(evidence.size()).append(" exchange(s)) ---\n");
            for (int i = 0; i < evidence.size(); i++) {
                HttpRequestResponse rr = evidence.get(i);
                sb.append("\n[Exchange ").append(i + 1).append("]\n");
                try {
                    if (rr.request() != null) {
                        sb.append("Request:\n").append(rr.request().toString()).append("\n");
                    }
                } catch (Exception ex) {
                    sb.append("Request: (error extracting)\n");
                }
                try {
                    if (rr.response() != null) {
                        sb.append("Response:\n").append(rr.response().toString()).append("\n");
                    }
                } catch (Exception ex) {
                    sb.append("Response: (error extracting)\n");
                }
            }
        }

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    /**
     * Opens a file chooser and exports the currently displayed (filtered) findings.
     */
    private void exportFindings() {
        if (displayedFindings.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "No findings to export.",
                    "Export",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] options = {"JSON", "Markdown", "Cancel"};
        int choice = JOptionPane.showOptionDialog(
                this,
                "Select export format:",
                "Export Findings",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);

        if (choice < 0 || choice == 2) {
            return;
        }

        boolean asJson = (choice == 0);
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
            exporter.export(new ArrayList<>(displayedFindings), file);
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
}
