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
package com.rfc5789.auditor.collaborator;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import com.rfc5789.auditor.model.AuditorConfig;

import java.net.InetAddress;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Manages Burp Collaborator integration for out-of-band detection.
 *
 * <p>Wraps the Montoya Collaborator API to provide payload generation and
 * interaction polling. Collaborator is only available in Burp Suite
 * Professional; this manager degrades gracefully in Community Edition
 * by reporting itself as unavailable.</p>
 */
public final class CollaboratorManager {

    private final MontoyaApi api;
    private final AuditorConfig config;
    private volatile CollaboratorClient client;
    private volatile boolean available;

    /**
     * Creates a new CollaboratorManager.
     *
     * @param api    the Montoya API handle
     * @param config the auditor configuration (for poll interval, etc.)
     */
    public CollaboratorManager(MontoyaApi api, AuditorConfig config) {
        this.api = api;
        this.config = config;
        this.client = null;
        this.available = false;
        initClient();
    }

    /**
     * Attempts to initialise the Collaborator client. If Collaborator is
     * not available (Community Edition or disabled), marks this manager
     * as unavailable without throwing.
     */
    private void initClient() {
        try {
            this.client = api.collaborator().createClient();
            this.available = true;
        } catch (Exception e) {
            this.client = null;
            this.available = false;
        }
    }

    /**
     * Returns {@code true} if the Collaborator API is accessible.
     *
     * @return true if Collaborator is available (Burp Professional with
     *         Collaborator enabled), false otherwise
     */
    public boolean isAvailable() {
        return available;
    }

    /**
     * Generates a Collaborator payload URL.
     *
     * <p>Returns the full Collaborator interaction URL that can be embedded
     * in PATCH payloads. Returns {@code null} if Collaborator is not
     * available.</p>
     *
     * @return the Collaborator payload string, or null if unavailable
     */
    public String generatePayload() {
        if (!available || client == null) {
            return null;
        }
        try {
            CollaboratorPayload payload = client.generatePayload();
            return payload.toString();
        } catch (Exception e) {
            available = false;
            return null;
        }
    }

    /**
     * Polls the Collaborator server for all interactions recorded since the
     * last poll.
     *
     * <p>Returns an empty list if Collaborator is not available or if no
     * interactions have been recorded.</p>
     *
     * @return list of {@link CollaboratorFinding} objects, never null
     */
    public List<CollaboratorFinding> pollInteractions() {
        if (!available || client == null) {
            return Collections.emptyList();
        }
        try {
            List<Interaction> interactions = client.getAllInteractions();
            if (interactions == null || interactions.isEmpty()) {
                return Collections.emptyList();
            }
            List<CollaboratorFinding> results = new ArrayList<>(interactions.size());
            for (Interaction interaction : interactions) {
                InteractionType type = interaction.type();
                InetAddress clientIp = interaction.clientIp();
                ZonedDateTime timestamp = interaction.timeStamp();
                results.add(new CollaboratorFinding(
                        type != null ? type.name() : "UNKNOWN",
                        clientIp != null ? clientIp.getHostAddress() : "unknown",
                        timestamp != null ? timestamp.toString() : "unknown"
                ));
            }
            return results;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    /**
     * Returns the configured poll interval in milliseconds.
     *
     * @return the poll interval from the auditor configuration
     */
    public int getPollIntervalMs() {
        return config.getCollaboratorPollIntervalMs();
    }

    /**
     * Represents a single Collaborator interaction finding.
     *
     * <p>Captures the interaction type (DNS, HTTP, SMTP), the IP address
     * of the client that triggered the interaction, and the timestamp.</p>
     */
    public static final class CollaboratorFinding {

        private final String interactionType;
        private final String clientIp;
        private final String timestamp;

        /**
         * Creates a new CollaboratorFinding.
         *
         * @param interactionType the type of interaction (e.g. "DNS", "HTTP")
         * @param clientIp        the IP address of the interacting client
         * @param timestamp       the timestamp of the interaction
         */
        public CollaboratorFinding(String interactionType,
                                   String clientIp,
                                   String timestamp) {
            this.interactionType = interactionType;
            this.clientIp = clientIp;
            this.timestamp = timestamp;
        }

        /**
         * Returns the interaction type.
         *
         * @return the interaction type string
         */
        public String getInteractionType() {
            return interactionType;
        }

        /**
         * Returns the client IP address.
         *
         * @return the client IP
         */
        public String getClientIp() {
            return clientIp;
        }

        /**
         * Returns the interaction timestamp.
         *
         * @return the timestamp string
         */
        public String getTimestamp() {
            return timestamp;
        }

        @Override
        public String toString() {
            return "CollaboratorFinding{type='" + interactionType
                    + "', clientIp='" + clientIp
                    + "', timestamp='" + timestamp + "'}";
        }
    }
}
