/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */
package com.rfc5789.auditor.util;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Static utility methods for comparing and inspecting HTTP responses.
 *
 * <p>Used by the various {@link com.rfc5789.auditor.checks.PatchCheck}
 * implementations to detect behavioural differences that indicate
 * RFC 5789 semantic issues.</p>
 */
public final class ResponseDiff {

    private ResponseDiff() {
        // utility class
    }

    /**
     * Returns true if the two responses have different HTTP status codes.
     *
     * @param a first response (may be null)
     * @param b second response (may be null)
     * @return true if statuses differ or exactly one response is null
     */
    public static boolean statusDiffers(HttpResponse a, HttpResponse b) {
        if (a == null || b == null) {
            return a != b;
        }
        return a.statusCode() != b.statusCode();
    }

    /**
     * Returns true if the two responses have different body content.
     *
     * @param a first response (may be null)
     * @param b second response (may be null)
     * @return true if bodies differ or exactly one response is null
     */
    public static boolean bodyDiffers(HttpResponse a, HttpResponse b) {
        if (a == null || b == null) {
            return a != b;
        }
        String bodyA = a.bodyToString();
        String bodyB = b.bodyToString();
        if (bodyA == null && bodyB == null) {
            return false;
        }
        if (bodyA == null || bodyB == null) {
            return true;
        }
        return !bodyA.equals(bodyB);
    }

    /**
     * Returns true if the named header has different values in the two responses.
     *
     * @param a          first response (may be null)
     * @param b          second response (may be null)
     * @param headerName the header to compare (case-insensitive in practice)
     * @return true if the header values differ
     */
    public static boolean headerDiffers(HttpResponse a, HttpResponse b, String headerName) {
        if (a == null || b == null) {
            return a != b;
        }
        String valA = a.headerValue(headerName);
        String valB = b.headerValue(headerName);
        if (valA == null && valB == null) {
            return false;
        }
        if (valA == null || valB == null) {
            return true;
        }
        return !valA.equals(valB);
    }

    /**
     * Returns true if the response has a 2xx status code.
     *
     * @param r the response to check (may be null)
     * @return true if status is in the range [200, 299]
     */
    public static boolean isSuccess(HttpResponse r) {
        if (r == null) {
            return false;
        }
        int status = r.statusCode();
        return status >= 200 && status <= 299;
    }

    /**
     * Returns true if the response has a 4xx status code.
     *
     * @param r the response to check (may be null)
     * @return true if status is in the range [400, 499]
     */
    public static boolean isClientError(HttpResponse r) {
        if (r == null) {
            return false;
        }
        int status = r.statusCode();
        return status >= 400 && status <= 499;
    }

    /**
     * Returns true if the response body contains the given pattern (case-insensitive).
     *
     * @param r       the response to search (may be null)
     * @param pattern the substring to search for
     * @return true if the pattern is found in the body
     */
    public static boolean containsPattern(HttpResponse r, String pattern) {
        if (r == null || pattern == null) {
            return false;
        }
        String body = r.bodyToString();
        if (body == null) {
            return false;
        }
        return body.toLowerCase(Locale.ROOT).contains(pattern.toLowerCase(Locale.ROOT));
    }

    /**
     * Computes a simple Jaccard similarity coefficient between the word sets
     * of two response bodies.
     *
     * <p>Returns 1.0 for identical word sets, 0.0 for completely disjoint
     * word sets, and a value in between for partial overlap. If either body
     * is null or empty, returns 0.0.</p>
     *
     * @param a first response (may be null)
     * @param b second response (may be null)
     * @return Jaccard similarity in [0.0, 1.0]
     */
    public static double bodySimilarity(HttpResponse a, HttpResponse b) {
        if (a == null || b == null) {
            return 0.0;
        }
        String bodyA = a.bodyToString();
        String bodyB = b.bodyToString();
        if (bodyA == null || bodyB == null || bodyA.isEmpty() || bodyB.isEmpty()) {
            return 0.0;
        }

        Set<String> wordsA = tokenize(bodyA);
        Set<String> wordsB = tokenize(bodyB);

        if (wordsA.isEmpty() && wordsB.isEmpty()) {
            return 1.0;
        }

        Set<String> intersection = new HashSet<>(wordsA);
        intersection.retainAll(wordsB);

        Set<String> union = new HashSet<>(wordsA);
        union.addAll(wordsB);

        if (union.isEmpty()) {
            return 1.0;
        }

        return (double) intersection.size() / (double) union.size();
    }

    /**
     * Tokenizes a string into a set of lowercase words.
     */
    private static Set<String> tokenize(String text) {
        String[] tokens = text.toLowerCase(Locale.ROOT).split("\\W+");
        Set<String> result = new HashSet<>();
        for (String token : tokens) {
            if (!token.isEmpty()) {
                result.add(token);
            }
        }
        return result;
    }
}
