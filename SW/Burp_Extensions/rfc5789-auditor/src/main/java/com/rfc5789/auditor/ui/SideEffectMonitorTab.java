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

import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.AuditorConfig.SideEffectPair;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Side-Effect Monitor tab for configuring AMB-02 TOCTOU monitoring pairs.
 *
 * <p>Allows users to define target URL patterns and associated monitor URLs.
 * When a PATCH is sent to a target URL, the monitor URLs are fetched before
 * and after to detect unintended side effects.</p>
 */
public final class SideEffectMonitorTab extends JPanel {

    private final AuditorConfig config;
    private final DefaultTableModel tableModel;
    private final JTextField targetField;
    private final JTextField monitorField;

    /**
     * Creates the side-effect monitor tab.
     *
     * @param config the auditor configuration
     */
    public SideEffectMonitorTab(AuditorConfig config) {
        super(new BorderLayout(10, 10));
        this.config = config;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- Top: Description ---
        JTextArea description = new JTextArea(
                "AMB-02: Side-Effect / TOCTOU Monitoring\n\n"
                + "Define pairs of target URL patterns and monitor URLs. When the auditor "
                + "sends a PATCH request matching a target URL pattern, the monitor URLs "
                + "are fetched before and after the PATCH to detect unintended side effects "
                + "(time-of-check to time-of-use vulnerabilities).\n\n"
                + "For example, if PATCH /api/users/1 should only update user 1's name, "
                + "monitoring GET /api/users/2 can reveal whether the update leaks into "
                + "other users' data.");
        description.setEditable(false);
        description.setLineWrap(true);
        description.setWrapStyleWord(true);
        description.setOpaque(false);
        description.setRows(5);
        add(description, BorderLayout.NORTH);

        // --- Middle: Table ---
        String[] columns = {"Target URL Pattern", "Monitor Paths (comma-separated, e.g. /api/users/1)", "Actions"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 2;
            }
        };

        // Load existing pairs from config
        for (SideEffectPair pair : config.getSideEffectPairs()) {
            tableModel.addRow(new Object[]{
                    pair.getTargetUrl(),
                    String.join(", ", pair.getMonitorUrls()),
                    "Remove"
            });
        }

        JTable table = new JTable(tableModel);
        table.getColumn("Actions").setCellRenderer(new ButtonRenderer());
        table.getColumn("Actions").setCellEditor(new ButtonEditor(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                tableModel.removeRow(row);
                syncToConfig();
            }
        }));
        table.getColumn("Actions").setPreferredWidth(80);
        table.getColumn("Actions").setMaxWidth(100);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(0, 250));
        add(tableScroll, BorderLayout.CENTER);

        // --- Bottom: Add pair panel ---
        JPanel addPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addPanel.setBorder(BorderFactory.createTitledBorder("Add Pair"));

        addPanel.add(new JLabel("Target URL Pattern:"));
        targetField = new JTextField(25);
        addPanel.add(targetField);

        addPanel.add(new JLabel("Monitor Paths (comma-separated, must start with /):")); 
        monitorField = new JTextField(30);
        addPanel.add(monitorField);

        JButton addBtn = new JButton("Add");
        addBtn.addActionListener(e -> addPair());
        addPanel.add(addBtn);

        add(addPanel, BorderLayout.SOUTH);
    }

    /**
     * Adds a new side-effect pair from the input fields.
     */
    private void addPair() {
        String target = targetField.getText().trim();
        String monitors = monitorField.getText().trim();

        if (target.isEmpty() || monitors.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Both Target URL Pattern and Monitor URLs are required.",
                    "Validation Error",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        tableModel.addRow(new Object[]{target, monitors, "Remove"});
        syncToConfig();

        targetField.setText("");
        monitorField.setText("");
    }

    /**
     * Synchronises the table contents back into the AuditorConfig.
     */
    private void syncToConfig() {
        List<SideEffectPair> pairs = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String target = (String) tableModel.getValueAt(i, 0);
            String monitorsStr = (String) tableModel.getValueAt(i, 1);
            List<String> monitorUrls = Arrays.asList(monitorsStr.split("\\s*,\\s*"));
            pairs.add(new SideEffectPair(target, monitorUrls));
        }
        config.setSideEffectPairs(pairs);
    }

    /**
     * Simple button renderer for the "Remove" column.
     */
    private static final class ButtonRenderer extends JButton
            implements javax.swing.table.TableCellRenderer {

        ButtonRenderer() {
            setOpaque(true);
        }

        @Override
        public java.awt.Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            setText(value != null ? value.toString() : "Remove");
            return this;
        }
    }

    /**
     * Simple button editor for the "Remove" column.
     */
    private static final class ButtonEditor extends javax.swing.DefaultCellEditor {

        private final JButton button;
        private final java.awt.event.ActionListener listener;
        private boolean clicked;

        ButtonEditor(java.awt.event.ActionListener listener) {
            // JTextField is required by DefaultCellEditor's constructor but is not used;
            // the actual editing component is a JButton configured below.
            super(new JTextField());
            this.listener = listener;
            this.button = new JButton("Remove");
            this.button.setOpaque(true);
            this.button.addActionListener(e -> fireEditingStopped());
        }

        @Override
        public java.awt.Component getTableCellEditorComponent(
                JTable table, Object value, boolean isSelected, int row, int column) {
            clicked = true;
            return button;
        }

        @Override
        public Object getCellEditorValue() {
            if (clicked) {
                listener.actionPerformed(null);
            }
            clicked = false;
            return "Remove";
        }

        @Override
        public boolean stopCellEditing() {
            clicked = false;
            return super.stopCellEditing();
        }
    }
}
