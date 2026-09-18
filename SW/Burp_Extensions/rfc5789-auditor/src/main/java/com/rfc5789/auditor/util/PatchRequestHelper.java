/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.util;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static utility methods for constructing and manipulating PATCH HTTP requests.
 *
 * <p>All methods return new {@link HttpRequest} instances; the originals are
 * never mutated (the Montoya API is immutable by design).</p>
 */
public final class PatchRequestHelper {

    /**
     * Pattern matching a resource identifier in a URL path segment.
     * Matches UUIDs, purely numeric IDs, and alphanumeric slugs that look like
     * identifiers (at least 2 digits, or at least 8 characters total).
     * This avoids false positives on version prefixes like {@code v1}, {@code api2}.
     */
    private static final Pattern RESOURCE_ID_PATTERN = Pattern.compile(
            "(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
                    + "|(?:\\d+)"
                    + "|(?:[a-zA-Z0-9_-]{8,})"
    );

    private PatchRequestHelper() {
        // utility class
    }

    /**
     * Checks whether the given request uses the PATCH HTTP method.
     *
     * @param req the request to inspect
     * @return true if the method is PATCH (case-insensitive)
     */
    public static boolean isPatchRequest(HttpRequest req) {
        if (req == null) {
            return false;
        }
        return "PATCH".equalsIgnoreCase(req.method());
    }

    /**
     * Returns a copy of the request with the Content-Type header replaced.
     *
     * @param req         the original request
     * @param contentType the new Content-Type value
     * @return a new request with the updated header
     */
    public static HttpRequest withContentType(HttpRequest req, String contentType) {
        return req.withUpdatedHeader("Content-Type", contentType);
    }

    /**
     * Returns a copy of the request with the body replaced.
     *
     * @param req  the original request
     * @param body the new body content
     * @return a new request with the replaced body
     */
    public static HttpRequest withBody(HttpRequest req, String body) {
        return req.withBody(body);
    }

    /**
     * Returns a copy of the request with the path replaced.
     *
     * @param req     the original request
     * @param newPath the new path (should start with '/')
     * @return a new request with the replaced path
     */
    public static HttpRequest withPath(HttpRequest req, String newPath) {
        return req.withPath(newPath);
    }

    /**
     * Returns a copy of the request with additional headers added or updated.
     *
     * @param req     the original request
     * @param headers a map of header name to header value
     * @return a new request with the additional headers
     */
    public static HttpRequest withAddedHeaders(HttpRequest req, Map<String, String> headers) {
        HttpRequest result = req;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            result = result.withUpdatedHeader(entry.getKey(), entry.getValue());
        }
        return result;
    }

    /**
     * Extracts a resource identifier from the given URL path.
     *
     * <p>Scans path segments from right to left and returns the first segment
     * that looks like a resource ID (UUID, numeric, or alphanumeric with digits).</p>
     *
     * @param path the URL path, e.g. "/api/users/123" or "/items/abc-42/details"
     * @return the extracted ID, or null if none found
     */
    public static String extractResourceId(String path) {
        if (path == null || path.isEmpty()) {
            return null;
        }
        // Strip query string
        int queryIdx = path.indexOf('?');
        String cleanPath = queryIdx >= 0 ? path.substring(0, queryIdx) : path;

        String[] segments = cleanPath.split("/");
        // Iterate from right to left
        for (int i = segments.length - 1; i >= 0; i--) {
            String segment = segments[i];
            if (segment.isEmpty()) {
                continue;
            }
            Matcher m = RESOURCE_ID_PATTERN.matcher(segment);
            if (m.matches()) {
                return segment;
            }
        }
        return null;
    }

    /**
     * Replaces the resource identifier in the path with a new value.
     *
     * <p>Finds the rightmost path segment matching the resource ID pattern
     * and substitutes it.</p>
     *
     * @param path  the original URL path
     * @param newId the replacement ID
     * @return the path with the ID replaced, or the original path if no ID found
     */
    public static String replaceResourceId(String path, String newId) {
        if (path == null || newId == null) {
            return path;
        }
        String existingId = extractResourceId(path);
        if (existingId == null) {
            return path;
        }
        // Replace the last occurrence to be safe
        int lastIdx = path.lastIndexOf(existingId);
        if (lastIdx < 0) {
            return path;
        }
        return path.substring(0, lastIdx) + newId + path.substring(lastIdx + existingId.length());
    }

    /**
     * Builds a GET request targeting the same URL and service as the given PATCH request.
     *
     * @param patchReq the original PATCH request
     * @return a GET request for the same URL
     */
    public static HttpRequest buildGetRequest(HttpRequest patchReq) {
        return patchReq
                .withMethod("GET")
                .withRemovedHeader("Content-Type")
                .withRemovedHeader("Content-Length")
                .withBody("");
    }
}
