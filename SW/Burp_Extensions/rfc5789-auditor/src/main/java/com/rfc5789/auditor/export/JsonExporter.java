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
import com.rfc5789.auditor.model.Finding;
import com.rfc5789.auditor.model.ScanMode;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Exports findings as a self-contained JSON report.
 *
 * <p>Uses plain string building to avoid any external JSON library dependency,
 * keeping the extension fully self-contained for Burp Suite deployment.</p>
 */
public final class JsonExporter implements ReportExporter {

    private static final String VERSION = "1.0.0";
    private static final DateTimeFormatter ISO_FORMATTER =
            DateTimeFormatter.ISO_INSTANT;

    private final ScanMode currentMode;

    /**
     * Creates a new JSON exporter.
     *
     * @param currentMode the scan mode to record in the report metadata
     */
    public JsonExporter(ScanMode currentMode) {
        this.currentMode = currentMode;
    }

    @Override
    public void export(List<Finding> findings, File outputFile) throws IOException {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("{\n");
        sb.append("  \"tool\": \"RFC 5789 Auditor\",\n");
        sb.append("  \"version\": \"").append(VERSION).append("\",\n");
        sb.append("  \"timestamp\": \"")
                .append(ISO_FORMATTER.format(Instant.now().atOffset(ZoneOffset.UTC)))
                .append("\",\n");
        sb.append("  \"mode\": \"").append(currentMode.name()).append("\",\n");
        sb.append("  \"findings\": [\n");

        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append("    {\n");
            sb.append("      \"checkId\": ").append(jsonString(f.getCheckId())).append(",\n");
            sb.append("      \"title\": ").append(jsonString(f.getTitle())).append(",\n");
            sb.append("      \"severity\": ").append(jsonString(f.getSeverity().name())).append(",\n");
            sb.append("      \"confidence\": ").append(jsonString(f.getConfidence().name())).append(",\n");
            sb.append("      \"detail\": ").append(jsonString(f.getDetail())).append(",\n");
            sb.append("      \"remediation\": ").append(jsonString(f.getRemediation())).append(",\n");
            sb.append("      \"modeUsed\": ").append(jsonString(f.getModeUsed().name())).append(",\n");
            sb.append("      \"timestamp\": \"")
                    .append(ISO_FORMATTER.format(
                            Instant.ofEpochMilli(f.getTimestamp()).atOffset(ZoneOffset.UTC)))
                    .append("\",\n");

            sb.append("      \"evidence\": [\n");
            List<HttpRequestResponse> evidence = f.getEvidence();
            for (int e = 0; e < evidence.size(); e++) {
                HttpRequestResponse rr = evidence.get(e);
                sb.append("        {\n");
                sb.append("          \"request\": ")
                        .append(jsonString(safeToString(rr, true)))
                        .append(",\n");
                sb.append("          \"response\": ")
                        .append(jsonString(safeToString(rr, false)))
                        .append("\n");
                sb.append("        }");
                if (e < evidence.size() - 1) {
                    sb.append(',');
                }
                sb.append('\n');
            }
            sb.append("      ]\n");

            sb.append("    }");
            if (i < findings.size() - 1) {
                sb.append(',');
            }
            sb.append('\n');
        }

        sb.append("  ]\n");
        sb.append("}\n");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile, StandardCharsets.UTF_8))) {
            writer.write(sb.toString());
        }
    }

    /**
     * Wraps a value in JSON double-quotes, escaping special characters.
     */
    private static String jsonString(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length() + 16);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * Safely converts request or response to a string, handling nulls gracefully.
     *
     * @param rr        the HTTP request/response pair
     * @param isRequest true to extract the request, false for the response
     * @return the string representation, or an empty string on failure
     */
    private static String safeToString(HttpRequestResponse rr, boolean isRequest) {
        try {
            if (rr == null) {
                return "";
            }
            if (isRequest) {
                return rr.request() != null ? rr.request().toString() : "";
            } else {
                return rr.response() != null ? rr.response().toString() : "";
            }
        } catch (Exception e) {
            return "(error extracting " + (isRequest ? "request" : "response") + ")";
        }
    }
}
