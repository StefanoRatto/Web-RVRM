/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.model;

/**
 * Defines the scan intensity mode for the RFC 5789 auditor.
 *
 * <p>{@link #SAFE} uses canary payloads that do not modify server state.
 * {@link #AGGRESSIVE} uses real payloads that may create, modify, or delete resources.</p>
 */
public enum ScanMode {

    /**
     * Safe mode: only sends canary/fingerprint payloads that should not
     * cause any server-side state changes. Suitable for production environments.
     */
    SAFE,

    /**
     * Aggressive mode: sends real payloads that may create, modify, or delete
     * resources. Should only be used against test/staging environments.
     */
    AGGRESSIVE
}
