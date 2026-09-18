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
package com.rfc5789.auditor.export;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.rfc5789.auditor.model.AuditorConfig;
import com.rfc5789.auditor.model.Finding;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Exports findings as a Markdown report.
 *
 * <p>Produces a human-readable report with a summary table followed by
 * detailed sections for each finding, including evidence snippets.</p>
 */
public final class MarkdownExporter implements ReportExporter {

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")
                    .withZone(ZoneOffset.UTC);

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

    @Override
    public void export(List<Finding> findings, File outputFile) throws IOException {
        StringBuilder sb = new StringBuilder(8192);

        sb.append("# RFC 5789 Auditor Report\n\n");
        sb.append("Generated: ").append(TIMESTAMP_FMT.format(Instant.now())).append("\n\n");

        // --- Summary table ---
        sb.append("## Summary\n\n");
        sb.append("| Check | Findings | Critical | High | Medium | Low |\n");
        sb.append("|-------|----------|----------|------|--------|-----|\n");

        Map<String, List<Finding>> byCheck = groupByCheck(findings);

        for (int i = 0; i < CHECK_IDS.length; i++) {
            String cid = CHECK_IDS[i];
            String label = CHECK_LABELS[i];
            List<Finding> checkFindings = byCheck.getOrDefault(cid, List.of());
            int total = checkFindings.size();
            int critical = 0; // Montoya API has no CRITICAL severity
            int high = countBySeverity(checkFindings, AuditIssueSeverity.HIGH);
            int medium = countBySeverity(checkFindings, AuditIssueSeverity.MEDIUM);
            int low = countBySeverity(checkFindings, AuditIssueSeverity.LOW);

            sb.append("| [").append(cid).append("] ").append(label)
                    .append(" | ").append(total)
                    .append(" | ").append(critical)
                    .append(" | ").append(high)
                    .append(" | ").append(medium)
                    .append(" | ").append(low)
                    .append(" |\n");
        }

        sb.append("\n**Total findings:** ").append(findings.size()).append("\n\n");

        // --- Detailed findings ---
        sb.append("## Findings\n\n");

        for (Finding f : findings) {
            sb.append("### [").append(f.getCheckId()).append("] ")
                    .append(f.getTitle()).append("\n\n");
            sb.append("**Severity**: ").append(f.getSeverity().name()).append("\n\n");
            sb.append("**Confidence**: ").append(f.getConfidence().name()).append("\n\n");
            sb.append("**Mode**: ").append(f.getModeUsed().name()).append("\n\n");
            sb.append("**Timestamp**: ")
                    .append(TIMESTAMP_FMT.format(
                            Instant.ofEpochMilli(f.getTimestamp())))
                    .append("\n\n");
            sb.append("**Detail**: ").append(f.getDetail()).append("\n\n");
            sb.append("**Remediation**: ").append(f.getRemediation()).append("\n\n");

            List<HttpRequestResponse> evidence = f.getEvidence();
            if (!evidence.isEmpty()) {
                sb.append("**Evidence**:\n\n");
                for (int e = 0; e < evidence.size(); e++) {
                    HttpRequestResponse rr = evidence.get(e);
                    sb.append("*Exchange ").append(e + 1).append("*\n\n");
                    sb.append("Request:\n```http\n");
                    sb.append(safeToString(rr, true));
                    sb.append("\n```\n\n");
                    sb.append("Response:\n```http\n");
                    sb.append(safeToString(rr, false));
                    sb.append("\n```\n\n");
                }
            }

            sb.append("---\n\n");
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile, StandardCharsets.UTF_8))) {
            writer.write(sb.toString());
        }
    }

    /**
     * Groups findings by their check ID, preserving insertion order.
     */
    private static Map<String, List<Finding>> groupByCheck(List<Finding> findings) {
        Map<String, List<Finding>> map = new LinkedHashMap<>();
        for (Finding f : findings) {
            map.computeIfAbsent(f.getCheckId(), k -> new ArrayList<>()).add(f);
        }
        return map;
    }

    /**
     * Counts findings with the given severity.
     */
    private static int countBySeverity(List<Finding> findings, AuditIssueSeverity severity) {
        int count = 0;
        for (Finding f : findings) {
            if (f.getSeverity() == severity) {
                count++;
            }
        }
        return count;
    }

    /**
     * Safely converts request or response to a string, handling nulls gracefully.
     */
    private static String safeToString(HttpRequestResponse rr, boolean isRequest) {
        try {
            if (rr == null) {
                return "(no data)";
            }
            if (isRequest) {
                return rr.request() != null ? rr.request().toString() : "(no request)";
            } else {
                return rr.response() != null ? rr.response().toString() : "(no response)";
            }
        } catch (Exception e) {
            return "(error extracting " + (isRequest ? "request" : "response") + ")";
        }
    }
}
