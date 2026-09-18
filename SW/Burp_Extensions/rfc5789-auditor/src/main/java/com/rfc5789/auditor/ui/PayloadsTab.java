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
import com.rfc5789.auditor.model.ScanMode;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/**
 * Payloads tab showing AMB-11 WAF bypass payload decomposition details.
 *
 * <p>This tab is view-only. It displays the payload classes (XSS, SQLi,
 * SSTI, CmdInj, PathTraversal) and their safe/aggressive variants with
 * the split decomposition used for sequential PATCH bypass testing.</p>
 */
public final class PayloadsTab extends JPanel {

    private static final String[] PAYLOAD_CLASSES = {
            "XSS", "SQLi", "SSTI", "CmdInj", "PathTraversal"
    };

    private static final String[] SAFE_FULL = {
            "<rfc5789-xss-canary>",
            "rfc5789-sqli-canary' OR",
            "{{rfc5789-ssti-canary}}",
            "; rfc5789-cmdi-canary",
            "../../rfc5789-path-canary"
    };

    private static final String[][] SAFE_PARTS = {
            {"<rfc5789-", "xss-canary>"},
            {"rfc5789-sqli-", "canary' OR"},
            {"{{rfc5789-", "ssti-canary}}"},
            {"; rfc5789-", "cmdi-canary"},
            {"../../", "rfc5789-path-canary"}
    };

    private static final String[] AGGRESSIVE_FULL = {
            "<script>alert(document.domain)</script>",
            "' OR 1=1-- ",
            "{{7*7}}",
            "; cat /etc/passwd",
            "../../etc/passwd"
    };

    private static final String[][] AGGRESSIVE_PARTS = {
            {"<script>alert(", "document.domain)</script>"},
            {"' OR ", "1=1-- "},
            {"{{7", "*7}}"},
            {"; cat ", "/etc/passwd"},
            {"../../", "etc/passwd"}
    };

    private final AuditorConfig config;
    private final JLabel modeIndicator;
    private final JTextField fullPayloadField;
    private final JTextField part1Field;
    private final JTextField part2Field;
    private final JTextField safeVariantField;
    private final JTextField aggressiveVariantField;

    /**
     * Creates the payloads tab.
     *
     * @param config the auditor configuration
     */
    public PayloadsTab(AuditorConfig config) {
        super(new BorderLayout(10, 10));
        this.config = config;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- Top: Description + mode indicator ---
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));

        JTextArea description = new JTextArea(
                "AMB-11: WAF Bypass Payload Decomposition\n\n"
                + "This tab shows the payload classes used for WAF bypass testing via "
                + "PATCH decomposition. Each attack payload is split into two parts that "
                + "are individually innocuous but malicious when reassembled in the "
                + "server-side resource state.\n\n"
                + "Select a payload class on the left to see its full and split variants.");
        description.setEditable(false);
        description.setLineWrap(true);
        description.setWrapStyleWord(true);
        description.setOpaque(false);
        description.setRows(4);
        topPanel.add(description, BorderLayout.CENTER);

        modeIndicator = new JLabel("", SwingConstants.CENTER);
        modeIndicator.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        modeIndicator.setOpaque(true);
        modeIndicator.setPreferredSize(new Dimension(0, 30));
        updateModeIndicator();
        topPanel.add(modeIndicator, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);

        // --- Left: Payload class list ---
        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (String cls : PAYLOAD_CLASSES) {
            listModel.addElement(cls);
        }
        JList<String> classList = new JList<>(listModel);
        classList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        classList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        JScrollPane listScroll = new JScrollPane(classList);
        listScroll.setPreferredSize(new Dimension(180, 0));
        listScroll.setBorder(BorderFactory.createTitledBorder("Payload Classes"));

        // --- Right: Detail panel ---
        JPanel detailPanel = new JPanel(new GridBagLayout());
        detailPanel.setBorder(BorderFactory.createTitledBorder("Payload Details"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;

        fullPayloadField = createReadOnlyField();
        part1Field = createReadOnlyField();
        part2Field = createReadOnlyField();
        safeVariantField = createReadOnlyField();
        aggressiveVariantField = createReadOnlyField();

        int row = 0;
        addLabeledField(detailPanel, gbc, row++, "Full Payload:", fullPayloadField);
        addLabeledField(detailPanel, gbc, row++, "Part 1:", part1Field);
        addLabeledField(detailPanel, gbc, row++, "Part 2:", part2Field);
        addLabeledField(detailPanel, gbc, row++, "Safe Canary:", safeVariantField);
        addLabeledField(detailPanel, gbc, row, "Aggressive Real:", aggressiveVariantField);

        // Fill remaining space
        gbc.gridx = 0;
        gbc.gridy = row + 1;
        gbc.weighty = 1.0;
        gbc.gridwidth = 2;
        detailPanel.add(new JPanel(), gbc);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listScroll, detailPanel);
        splitPane.setDividerLocation(180);
        add(splitPane, BorderLayout.CENTER);

        // --- Bottom: Reset button ---
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.addActionListener(e -> {
            classList.clearSelection();
            clearDetailFields();
        });
        bottomPanel.add(resetBtn);
        add(bottomPanel, BorderLayout.SOUTH);

        // Selection listener
        classList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) {
                    return;
                }
                int idx = classList.getSelectedIndex();
                if (idx < 0 || idx >= PAYLOAD_CLASSES.length) {
                    clearDetailFields();
                    return;
                }
                showPayload(idx);
            }
        });
    }

    /**
     * Updates the mode indicator label.
     */
    public void updateModeIndicator() {
        ScanMode mode = config.getCurrentMode();
        if (mode == ScanMode.AGGRESSIVE) {
            modeIndicator.setText("Active Payload Set: AGGRESSIVE (Real Payloads)");
            modeIndicator.setForeground(Color.WHITE);
            modeIndicator.setBackground(new Color(180, 30, 30));
        } else {
            modeIndicator.setText("Active Payload Set: SAFE (Canary Payloads)");
            modeIndicator.setForeground(Color.WHITE);
            modeIndicator.setBackground(new Color(30, 130, 50));
        }
    }

    /**
     * Shows the payload details for the given index.
     */
    private void showPayload(int idx) {
        ScanMode mode = config.getCurrentMode();
        String[] full = (mode == ScanMode.SAFE) ? SAFE_FULL : AGGRESSIVE_FULL;
        String[][] parts = (mode == ScanMode.SAFE) ? SAFE_PARTS : AGGRESSIVE_PARTS;

        fullPayloadField.setText(full[idx]);
        part1Field.setText(parts[idx][0]);
        part2Field.setText(parts[idx][1]);
        safeVariantField.setText(SAFE_FULL[idx]);
        aggressiveVariantField.setText(AGGRESSIVE_FULL[idx]);
    }

    /**
     * Clears all detail fields.
     */
    private void clearDetailFields() {
        fullPayloadField.setText("");
        part1Field.setText("");
        part2Field.setText("");
        safeVariantField.setText("");
        aggressiveVariantField.setText("");
    }

    /**
     * Creates a read-only JTextField.
     */
    private static JTextField createReadOnlyField() {
        JTextField field = new JTextField(40);
        field.setEditable(false);
        field.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return field;
    }

    /**
     * Adds a label and field at the given row in a GridBagLayout.
     */
    private static void addLabeledField(JPanel panel, GridBagConstraints gbc,
                                        int row, String label, JTextField field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(field, gbc);
    }
}
