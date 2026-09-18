# Checks Reference

Detailed documentation for each of the 6 security checks implemented by the RFC 5789 Auditor.

---

## AMB-04: Content-Type Confusion

**Severity**: High | **Confidence**: Firm (status diff) / Tentative (body diff only)
**RFC Section**: Section 2 ("the server MUST understand and apply the patch document media type")

### The Ambiguity

RFC 5789 Section 2 states:

> "The PATCH method requests that a set of changes described in the request entity be applied to the resource identified by the Request-URI. The set of changes is represented in a format called a 'patch document' identified by a media type."

The RFC requires the server to understand the media type of the patch document, but does not mandate that the server reject requests where the Content-Type does not match the body format. This creates ambiguity: if a server accepts `application/json-patch+json` and `application/merge-patch+json` on the same endpoint, and does not strictly validate that the body matches the declared Content-Type, an attacker can send a JSON Patch array with a Merge Patch Content-Type (or vice versa) to trigger unintended state changes.

### What the Check Does

**Phase 1 -- Differential Behaviour Detection:**

1. Replays the original PATCH request three times, each with a different Content-Type: `application/json-patch+json`, `application/merge-patch+json`, `application/json`.
2. Compares response status codes and body similarity (using a 0.95 word-level Jaccard threshold to filter dynamic noise like timestamps and CSRF tokens).
3. If status codes or bodies differ beyond the similarity threshold, reports a differential behaviour finding.

**Phase 2 -- Cross-Format Confusion:**

1. Constructs a JSON Patch array body (`[{"op":"replace","path":"/name","value":"..."}]`) and sends it with the `application/merge-patch+json` Content-Type.
2. Constructs a Merge Patch object body (`{"name":"..."}`) and sends it with the `application/json-patch+json` Content-Type.
3. If the server returns a 2xx response to either mismatched request, reports a cross-format confusion finding.

### Safe vs Aggressive

| Aspect | Safe | Aggressive |
|---|---|---|
| Canary value in Phase 2 | `__rfc5789_ct_probe` | `admin` |
| Server impact | None (canary field is inert) | May change the resource's `name` field to `admin` |

### Example Finding Output

```
Title: Content-Type Confusion - Differential Behaviour
Severity: HIGH
Confidence: FIRM
Detail: The server produced different responses when the same PATCH body was sent
with different Content-Type headers. Status codes differed across Content-Types.
This indicates the server interprets the same body differently depending on the
Content-Type, which may allow an attacker to trigger unintended state changes via
format confusion.
```

### Known Affected Frameworks

- **Spring Data REST**: Accepts both JSON Patch and Merge Patch on the same endpoint. Does not validate body-to-Content-Type consistency by default.
- **Django REST Framework**: With `django-rest-framework-json-api`, accepts `application/vnd.api+json` alongside standard types without strict validation.
- **Express.js** (with `fast-json-patch`): Parses the body based on structure, ignoring the Content-Type header entirely.

### Remediation

- Validate that the `Content-Type` header matches the expected patch format.
- Reject requests with an unsupported or mismatched `Content-Type` with `415 Unsupported Media Type`.
- If the endpoint supports multiple patch formats, strictly parse the body according to the declared Content-Type and reject malformed documents.

### False Positive Guidance

A differential response may occur for legitimate reasons (e.g., the server returns a descriptive error for one Content-Type and a different error for another). Verify that the differential behaviour leads to different resource state, not just different error messages. Check whether the 2xx response actually modified the resource by sending a follow-up GET.

---

## AMB-01: Resource Creation via PATCH

**Severity**: High | **Confidence**: Certain (201 Created) / Firm (2xx + GET confirms) / Tentative (2xx only)
**RFC Section**: Section 2 ("applied to the resource identified by the Request-URI")

### The Ambiguity

RFC 5789 Section 2 states:

> "The PATCH method requests that a set of changes described in the request entity be applied to the resource identified by the Request-URI."

The word "applied" implies the resource already exists, but the RFC does not explicitly prohibit resource creation via PATCH. This contrasts with PUT, which has a well-defined create-or-replace semantic. Some frameworks interpret PATCH as "upsert" -- update if exists, create if not -- which allows unauthorized object creation when the PATCH endpoint has weaker authorization than the POST/PUT creation endpoint.

### What the Check Does

1. Extracts the resource ID from the PATCH URL (e.g., `123` from `/api/users/123`).
2. Generates non-existent resource IDs: a large numeric ID (`99999999`), a random UUID, and a timestamped probe ID.
3. Sends PATCH requests to the URL with each non-existent ID.
4. If the server returns `201 Created`, reports a confirmed finding.
5. If the server returns any other 2xx status, sends a follow-up GET to check whether the resource was actually created.
6. After confirming resource creation (201 or 2xx + GET verification), the check sends a DELETE request to the probe URL and reports the cleanup result (success or failure) in the finding detail.
7. Reports severity based on confirmation level.

### Safe vs Aggressive

| Aspect | Safe | Aggressive |
|---|---|---|
| PATCH body | `{"__rfc5789_creation_probe": true, "name": "canary"}` | Original request body (from the observed PATCH) |
| Server impact | May create a resource with a canary field | Creates a resource with real data |

### Example Finding Output

```
Title: Resource Creation via PATCH - Confirmed (201 Created)
Severity: HIGH
Confidence: CERTAIN
Detail: The server returned 201 Created when a PATCH was sent to a non-existent
resource URL (fake ID: 99999999). This confirms that PATCH can create new resources,
which may allow unauthorized object creation.
```

### Known Affected Frameworks

- **Spring Data REST**: Default `RepositoryRestController` allows PATCH to create resources if the repository's `save()` method performs upsert.
- **Django REST Framework**: `partial_update` with `ModelSerializer` can trigger `create()` if `perform_update` calls `serializer.save()` on a new instance.
- **ASP.NET Web API**: `JsonPatchDocument.ApplyTo()` does not distinguish between update and creation contexts.
- **Laravel**: `updateOrCreate` pattern is commonly used in PATCH handlers.

### Remediation

- Return `404 Not Found` when a PATCH targets a non-existent resource.
- If resource creation via PATCH is an intentional feature, enforce the same authorization checks as the POST creation endpoint.
- Use separate controller methods for creation (POST) and update (PATCH).

### False Positive Guidance

Some APIs legitimately support PATCH-based upsert. This is a finding only if the creation path has weaker authorization than the dedicated creation endpoint (POST). Verify by comparing the authentication and authorization requirements of `PATCH /resource/{id}` vs `POST /resource`.

---

## AMB-03: Atomicity Race Condition

**Severity**: High (partial merge) / Medium (no conflict detection) | **Confidence**: Firm / Tentative
**RFC Section**: Section 2 ("the server MUST apply the entire set of changes atomically")

### The Ambiguity

RFC 5789 Section 2 states:

> "The server MUST apply the entire set of changes atomically and never provide a partially modified representation to a GET request."

This is a MUST requirement, but the RFC does not specify how atomicity should be implemented. It does not mandate optimistic concurrency (ETags), pessimistic locking, or any particular mechanism. Many frameworks apply patches without any concurrency control, leading to race conditions where concurrent PATCHes produce a merged state that no single client intended.

### What the Check Does

1. GETs the baseline resource state.
2. Builds N concurrent PATCH requests (N = configurable, default 10). Each PATCH merges a unique canary field (e.g., `__rfc5789_race_0`) into the original request body, preserving the original fields so the server accepts the request even with schema validation.
3. Fires all N PATCHes in parallel using `Http.sendRequests()`.
4. Counts how many returned 2xx (success) vs 409 (conflict).
5. GETs the final resource state and counts how many canary fields appear.
6. If multiple canary fields merged into the final state, reports a **Partial Merge** (atomicity violation, High severity).
7. If all PATCHes succeeded with no 409 responses, reports **No Conflict Detection** (Medium severity).
8. Sends an additional interleaved PATCH+GET to check for intermediate state exposure.

### Safe vs Aggressive

Both modes behave identically for this check -- canary field names are always used. Both modes merge canary fields into the original request body. The original body content is preserved alongside the injected canary. The only configurable parameter is the concurrent PATCH count (default: 10, minimum: 2).

### Example Finding Output

```
Title: Atomicity Race Condition - Partial Merge Detected
Severity: HIGH
Confidence: FIRM
Detail: Multiple concurrent PATCH requests resulted in a partial merge of 4 out
of 10 canary fields in the final resource state. This is a MUST violation of RFC
5789 atomicity requirements -- a patch MUST be applied in its entirety or not at all.
```

### Known Affected Frameworks

- **Django REST Framework**: Default `partial_update` uses no locking. `Model.save(update_fields=...)` is not wrapped in a transaction by default.
- **Express.js** (Mongoose): `findByIdAndUpdate` without `{new: true}` and without version keys (`__v`) has no conflict detection.
- **Spring Data REST**: `@PatchMapping` with `@Transactional` uses read-committed isolation by default, which does not prevent lost updates from concurrent PATCHes.
- **Laravel** (Eloquent): `update()` does not check for concurrent modifications unless explicit optimistic locking (`lockForUpdate`) is used.

### Remediation

- Implement optimistic concurrency control using `ETag` and `If-Match` headers. Return `412 Precondition Failed` on mismatch.
- Alternatively, return `409 Conflict` when concurrent modifications are detected.
- Wrap PATCH application in a database transaction with serializable isolation.
- Use version columns or row-level locks for critical resources.

### False Positive Guidance

If the application uses append-only or additive merge semantics (e.g., adding tags to a set), multiple canary fields appearing in the final state may be intended behaviour rather than a race condition. Verify whether the application's PATCH semantic is "last-writer-wins" or "merge-all-fields". The finding is valid if the merged state was not intended by any single client.

---

## AMB-11: WAF Bypass via PATCH Decomposition

**Severity**: High (confirmed bypass) / Medium (no WAF detected) | **Confidence**: Firm / Tentative
**RFC Section**: Section 2 (partial update semantic)

### The Ambiguity

RFC 5789 defines PATCH as a partial update method. The specification does not address how Web Application Firewalls or input filters should handle partial updates. Because each individual PATCH request carries only a fragment of the final resource state, a WAF that inspects individual request payloads cannot detect attack strings that are split across multiple PATCHes. The assembled resource state is malicious, but no single request contains a complete attack payload.

### What the Check Does

1. For each of 5 payload classes (XSS, SQLi, SSTI, Command Injection, Path Traversal):
   a. Sends the **full** attack payload in a single PATCH request.
   b. Sends the **same payload decomposed** across 2 sequential PATCH requests, each containing one fragment.
   c. If the full payload was blocked (403, 406, WAF indicators) but the split payloads were all accepted (2xx), reports a **Confirmed WAF Bypass**.
   d. If both full and split payloads were accepted, reports **No WAF Detected** (the endpoint lacks filtering entirely).
2. **Test 2: Same-field reassembly** -- sends payload fragments sequentially to a single field (identified from the original request body via `findStringField()`), testing whether the WAF detects within-field payload accumulation.
3. **Test 3: Persistence verification** -- sends a follow-up GET to the resource and checks if the full payload appears in the response body. If found, elevates confidence to CERTAIN.

WAF detection heuristics check for HTTP 403/406/419/429 status codes and response body patterns: "blocked", "waf", "firewall", "access denied", "request rejected". Also checks `Server` headers for known WAF vendors (Cloudflare, Akamai, Imperva, Barracuda).

### Safe vs Aggressive

| Aspect | Safe | Aggressive |
|---|---|---|
| XSS payload | `<rfc5789-xss-canary>` | `<script>alert(document.domain)</script>` |
| SQLi payload | `rfc5789-sqli-canary' OR` | `' OR 1=1-- ` |
| SSTI payload | `{{rfc5789-ssti-canary}}` | `{{7*7}}` |
| CmdInj payload | `; rfc5789-cmdi-canary` | `; cat /etc/passwd` |
| PathTraversal payload | `../../rfc5789-path-canary` | `../../etc/passwd` |
| Server impact | Canary strings stored in resource fields | Real attack strings stored in resource fields |

### Example Finding Output

```
Title: WAF Bypass via PATCH Decomposition - XSS (Confirmed)
Severity: HIGH
Confidence: FIRM
Detail: WAF bypass confirmed for XSS payload. The full payload was blocked (HTTP
403) but the same payload split across 2 sequential PATCH requests was accepted
by the server. An attacker can decompose malicious payloads across multiple PATCH
operations to evade WAF detection.
```

### Known Affected Frameworks

This check is framework-independent -- it targets the WAF/CDN layer. Known vulnerable configurations:

- **Cloudflare** (managed rules): Inspects individual request bodies but not cumulative resource state.
- **AWS WAF**: SQL injection and XSS rules apply per-request.
- **ModSecurity** (CRS): Default rules match patterns within a single request body.
- **Imperva**: Request-level inspection does not account for multi-request state assembly.

The vulnerability requires the backend framework to support merge-based PATCH (most REST frameworks do).

### Remediation

- WAFs should inspect the cumulative resource state, not just individual request payloads.
- Apply server-side output encoding regardless of how data was ingested (per-field, not per-request).
- Use context-aware sanitization on output (HTML encoding, SQL parameterization) rather than relying solely on input filtering.
- Consider rate-limiting sequential PATCHes to the same resource.

### False Positive Guidance

A "No WAF Detected" finding does not necessarily mean the endpoint is vulnerable to XSS/SQLi -- it means there is no request-level filtering. The application may have proper output encoding or parameterized queries. A "Confirmed WAF Bypass" finding means the WAF can be evaded, but exploitation depends on whether the stored payload is rendered or executed in a dangerous context.

---

## AMB-06: Cache Poisoning via PATCH

**Severity**: High (security-relevant endpoint or Collaborator confirmed) / Medium (generic stale cache) | **Confidence**: Firm (cache detected) / Tentative (no cache detected) / Certain (Collaborator confirmed)
**RFC Section**: Section 2 + RFC 7234 Section 4.4

### The Ambiguity

RFC 5789 Section 2 does not address caching behaviour for PATCH responses. RFC 7234 Section 4.4 states:

> "A cache MUST invalidate the effective Request-URI [...] when a non-error status code is received in response to an unsafe request method."

PATCH is an unsafe method, so caches must invalidate after a successful PATCH. However, many CDNs and reverse proxies do not recognize PATCH as an unsafe method (they handle GET, POST, PUT, DELETE but treat PATCH as unknown) and therefore fail to invalidate. This causes stale, pre-PATCH data to be served from cache after the resource has been modified.

### What the Check Does

1. Sends a GET to prime the cache and capture cache indicator headers (ETag, Age, X-Cache, CF-Cache-Status, X-Varnish, X-Cache-Hits).
2. Detects whether a caching layer is present from response headers.
3. Sends a PATCH to modify the resource.
4. Sends another GET immediately after the PATCH.
5. Compares the pre-PATCH and post-PATCH GET responses for staleness indicators:
   - ETag unchanged after PATCH
   - `X-Cache: HIT` or `CF-Cache-Status: HIT` after PATCH (should have been invalidated)
   - Response body identical before and after PATCH
   - `Age` header not reset after PATCH
6. If the endpoint path contains security-relevant keywords (permission, role, auth, token, session, admin, privilege, access, policy, security), elevates severity to High.
7. **Aggressive mode only**: Injects a Collaborator URL via PATCH, then GETs the resource to check if the Collaborator domain appears in the cached response.

### Safe vs Aggressive

| Aspect | Safe | Aggressive |
|---|---|---|
| PATCH body | `{"__rfc5789_cache_probe": "<timestamp>"}` | Original request body |
| Collaborator injection | Not used | Injects Collaborator URL; reports Certain confidence if it appears in cached GET |
| Server impact | Adds a canary field | Uses original data; may inject external URL |

### Example Finding Output

```
Title: Cache Poisoning via PATCH - Stale Security Data
Severity: HIGH
Confidence: FIRM
Detail: The cache did not properly invalidate after a successful PATCH request.
Indicators: ETag unchanged after PATCH. X-Cache: HIT after PATCH (stale cache).
A caching layer was detected from response headers. The endpoint appears to handle
security-relevant data (permissions, roles, tokens), making stale cache responses
a higher risk.
```

### Known Affected Frameworks

This check targets the caching layer, not the application framework:

- **Varnish**: Default VCL does not include PATCH in `req.method` cache invalidation rules.
- **Nginx** (proxy_cache): `proxy_cache_methods` defaults to GET HEAD; PATCH is not in the invalidation list.
- **Cloudflare**: Purge-on-update requires explicit API calls or Cache-Tag configuration; PATCH alone does not trigger purge.
- **AWS CloudFront**: Does not invalidate on PATCH without explicit invalidation API calls.
- **Fastly**: Requires Surrogate-Key or explicit purge logic for PATCH-triggered invalidation.

### Remediation

- Configure caching proxies to invalidate on PATCH (add PATCH to the list of unsafe methods that trigger cache purge).
- Set `Cache-Control: no-store` or `Cache-Control: private, no-cache` on mutable resource responses.
- Use `Surrogate-Key` or `Cache-Tag` headers and trigger purges from the application after successful PATCHes.
- Ensure ETags are updated after every PATCH.

### False Positive Guidance

Identical response bodies before and after PATCH may occur if the PATCH payload did not actually change the resource (e.g., setting a field to its current value). Verify by using a PATCH that changes a visible field. If the ETag is server-generated and deterministic (content-based), an unchanged ETag after a no-op PATCH is expected and not a false positive for the ETag indicator specifically -- but is still suspicious in combination with other indicators.

---

## AMB-02: Side-Effect TOCTOU

**Severity**: High (configured pair confirmed) / Medium (heuristic sibling changed) / Low (potential paths discovered, no changes) | **Confidence**: Firm (configured) / Tentative (heuristic)
**RFC Section**: Section 2 ("a set of changes [...] be applied to the resource identified by the Request-URI")

### The Ambiguity

RFC 5789 Section 2 scopes the PATCH operation to "the resource identified by the Request-URI". However, it does not address whether a PATCH may cause side effects on other resources. In practice, many APIs trigger cascading changes: PATCHing a group modifies its member list, PATCHing a user's role updates permission records, PATCHing a parent resource updates child resources.

If the PATCH endpoint checks authorization for the target resource but the side-effect resources have their own authorization requirements that are not re-checked, a Time-of-Check to Time-of-Use (TOCTOU) condition exists: the caller was authorized to PATCH the target but not authorized to modify the side-effect resource.

### What the Check Does

**Phase A -- Heuristic Sibling Discovery:**

1. Generates sibling URLs from the PATCH target path:
   - Adjacent numeric IDs (e.g., `/api/users/124`, `/api/users/122` from `/api/users/123`)
   - Sub-resources (e.g., `/api/users/123/profile`, `/api/users/123/permissions`, `/api/users/123/settings`)
2. GETs each discovered sibling URL (capturing current state).
3. Note: the PATCH has already been sent by the scan framework (Phase A runs after the base request completes). Phase A does NOT re-send the PATCH.
4. Re-GETs each sibling URL and compares bodies and ETags against the step 2 snapshot.
5. If any sibling changed, reports a **Sibling Changed (Heuristic)** finding. Because the "before" GETs occur shortly after the PATCH, this detects side effects that take time to propagate (e.g., async cascading updates). However, changes that completed instantaneously before step 2 will not be detected by Phase A alone.
6. If no siblings changed but valid sibling paths were discovered, reports **Potential Side-Effect Paths** for manual investigation.

**Phase B -- Configured Pair Check:**

1. Reads side-effect pairs from the extension configuration.
2. For each pair where the target URL matches the current PATCH URL:
   a. GETs all monitor URLs.
   b. Sends the PATCH.
   c. Re-GETs all monitor URLs.
   d. If any monitor URL changed (body or ETag), reports a **Confirmed Side-Effect (Configured)** finding.

### Safe vs Aggressive

Both modes use the original request body for the PATCH. The difference is in the canary values used by other checks that may precede AMB-02 in the scan pipeline. AMB-02 itself does not modify the PATCH body.

### Example Finding Output

```
Title: Side-Effect TOCTOU - Confirmed Side-Effect (Configured)
Severity: HIGH
Confidence: FIRM
Detail: Configured side-effect confirmed: after PATCHing /api/groups/5, the
monitored URL /api/members/5 changed. The response body or ETag differed between
the pre-PATCH and post-PATCH GETs. This confirms a side effect that should be
subject to its own authorization check.
```

### Known Affected Frameworks

- **Spring Data REST**: `@HandleAfterSave` and `@HandleAfterLinkSave` event handlers can modify related entities without re-checking authorization.
- **Django REST Framework**: `perform_update` with `post_save` signals can cascade to related models.
- **Rails** (Active Record): `after_update` callbacks on associations modify related records outside the controller's authorization context.
- **ASP.NET Web API**: Entity Framework `SaveChanges()` cascades to navigation properties.

### Remediation

- Enforce authorization checks on side-effect resources independently of the PATCH target.
- Document all side effects in the API specification.
- Return `Link` headers pointing to affected resources so clients are aware of cascading changes.
- Consider returning `209 Content Returned` or a multi-status response when side effects occur.
- Use event-driven authorization that re-validates permissions for each affected entity.

### False Positive Guidance

Sibling URL changes detected by heuristic discovery (Phase A) may be coincidental -- another client or a background process may have modified the sibling resource between the two GETs. Configured pair checks (Phase B) are higher confidence because the monitor URLs are chosen based on known API relationships. For heuristic findings, verify by repeating the test multiple times and checking whether the sibling consistently changes only when the PATCH is sent.
