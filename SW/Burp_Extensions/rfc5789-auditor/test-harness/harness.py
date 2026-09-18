#!/usr/bin/env python3
"""
RFC 5789 Auditor - Vulnerable Test Harness

A Flask application that intentionally exhibits ALL 6 vulnerabilities
detected by the RFC 5789 Auditor Burp Suite extension. This harness is
used for integration testing and development.

Runs on localhost:5789.
"""

import json
import re
import time
import hashlib
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory data stores (seeded with test data)
# ---------------------------------------------------------------------------

# AMB-04: Content-Type Confusion
users = {
    1: {"id": 1, "name": "Alice", "role": "user", "email": "alice@example.com"}
}

# AMB-01: Resource Creation
items = {
    1: {"id": 1, "name": "Widget", "price": 9.99}
}

# AMB-03: Atomicity Race Condition
counters = {
    1: {"id": 1, "value": 0, "label": "hits"}
}

# AMB-11: WAF Bypass
comments = {
    1: {"id": 1, "text": "Hello", "author": "Bob"}
}

# AMB-06: Cache Poisoning
cached = {
    1: {"id": 1, "status": "active", "data": "original"}
}
# Simulated ETag that does NOT get updated on PATCH
cached_etags = {
    1: "etag-v1-" + hashlib.md5(b"original").hexdigest()[:8]
}
# Request counter for simulating cache hit/miss
cached_request_counts = {}

# AMB-02: Side-Effect TOCTOU
groups = {
    1: {"id": 1, "name": "Engineering", "member_ids": [10, 11]}
}
members = {
    10: {"id": 10, "name": "Carol", "group_id": 1, "group_name": "Engineering"},
    11: {"id": 11, "name": "Dave", "group_id": 1, "group_name": "Engineering"},
}

# ---------------------------------------------------------------------------
# WAF regex patterns (AMB-11)
# ---------------------------------------------------------------------------

WAF_PATTERNS = [
    re.compile(r"<script>", re.IGNORECASE),
    re.compile(r"'\s*OR", re.IGNORECASE),
    re.compile(r"\{\{"),
    re.compile(r";\s*cat\b", re.IGNORECASE),
    re.compile(r"\.\./"),
]


def waf_check(body_str):
    """Returns True if the body triggers the WAF (should be blocked)."""
    for pattern in WAF_PATTERNS:
        if pattern.search(body_str):
            return True
    return False


# ---------------------------------------------------------------------------
# Request logging
# ---------------------------------------------------------------------------

@app.after_request
def log_request(response):
    print(f"[{request.method}] {request.path} -> {response.status_code}")
    return response


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


# ---------------------------------------------------------------------------
# AMB-04: Content-Type Confusion - PATCH /api/users/<id>
# ---------------------------------------------------------------------------

@app.route("/api/users/<int:user_id>", methods=["PATCH", "GET", "OPTIONS"])
def user_endpoint(user_id):
    if request.method == "OPTIONS":
        resp = Response("", status=204)
        resp.headers["Allow"] = "GET, PATCH, OPTIONS"
        # Intentionally NO Accept-Patch header (discovery issue)
        return resp

    if request.method == "GET":
        user = users.get(user_id)
        if user is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(user)

    # PATCH
    ct = request.content_type or ""
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    if body is None:
        return jsonify({"error": "invalid JSON"}), 400

    user = users.get(user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404

    if "json-patch" in ct:
        # RFC 6902: expect array of operations
        if not isinstance(body, list):
            return jsonify({"error": "json-patch requires array"}), 400
        for op in body:
            if op.get("op") == "replace":
                field = op.get("path", "").lstrip("/")
                if field in user:
                    user[field] = op.get("value")
            elif op.get("op") == "add":
                field = op.get("path", "").lstrip("/")
                user[field] = op.get("value")
            elif op.get("op") == "remove":
                field = op.get("path", "").lstrip("/")
                user.pop(field, None)
    else:
        # merge-patch or plain JSON: shallow merge
        if isinstance(body, dict):
            for key, value in body.items():
                if value is None:
                    user.pop(key, None)
                else:
                    user[key] = value

    return jsonify(user)


# ---------------------------------------------------------------------------
# AMB-01: Resource Creation - PATCH /api/items/<id>
# ---------------------------------------------------------------------------

@app.route("/api/items/<int:item_id>", methods=["PATCH", "GET"])
def item_endpoint(item_id):
    if request.method == "GET":
        item = items.get(item_id)
        if item is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(item)

    # PATCH - creates resource if it doesn't exist (vulnerability!)
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    if body is None:
        return jsonify({"error": "invalid JSON"}), 400

    if item_id not in items:
        # Resource creation via PATCH (AMB-01 violation)
        new_item = {"id": item_id}
        if isinstance(body, dict):
            new_item.update(body)
        new_item["id"] = item_id  # enforce ID
        items[item_id] = new_item
        return jsonify(new_item), 201
    else:
        item = items[item_id]
        if isinstance(body, dict):
            for key, value in body.items():
                item[key] = value
        return jsonify(item)


# ---------------------------------------------------------------------------
# AMB-03: Atomicity Race Condition - PATCH /api/counters/<id>
# ---------------------------------------------------------------------------

@app.route("/api/counters/<int:counter_id>", methods=["PATCH", "GET"])
def counter_endpoint(counter_id):
    if request.method == "GET":
        counter = counters.get(counter_id)
        if counter is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(counter)

    # PATCH - read-modify-write WITHOUT locking (race condition!)
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    if body is None:
        return jsonify({"error": "invalid JSON"}), 400

    counter = counters.get(counter_id)
    if counter is None:
        return jsonify({"error": "not found"}), 404

    # Read current value
    current_value = counter["value"]

    # Artificial 100ms delay to widen the race window for testing purposes.
    # Real-world race conditions have microsecond windows and may require
    # hundreds of concurrent requests to trigger reliably.
    time.sleep(0.1)

    # Write new value (using the stale read)
    if "value" in body:
        counter["value"] = body["value"]
    if "label" in body:
        counter["label"] = body["label"]

    return jsonify(counter)


# ---------------------------------------------------------------------------
# AMB-11: WAF Bypass - POST/PATCH /api/comments
# ---------------------------------------------------------------------------

@app.route("/api/comments", methods=["POST"])
def create_comment():
    raw_body = request.get_data(as_text=True)

    # WAF check on full body
    if waf_check(raw_body):
        return jsonify({"error": "blocked by WAF"}), 403

    try:
        body = json.loads(raw_body)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    new_id = max(comments.keys(), default=0) + 1
    comment = {"id": new_id}
    if isinstance(body, dict):
        comment.update(body)
    comment["id"] = new_id
    comments[new_id] = comment
    return jsonify(comment), 201


@app.route("/api/comments/<int:comment_id>", methods=["PATCH", "GET"])
def comment_endpoint(comment_id):
    if request.method == "GET":
        comment = comments.get(comment_id)
        if comment is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(comment)

    # PATCH - WAF checks EACH patch independently (split payloads pass!)
    raw_body = request.get_data(as_text=True)

    if waf_check(raw_body):
        return jsonify({"error": "blocked by WAF"}), 403

    try:
        body = json.loads(raw_body)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    comment = comments.get(comment_id)
    if comment is None:
        return jsonify({"error": "not found"}), 404

    if isinstance(body, dict):
        for key, value in body.items():
            comment[key] = value

    return jsonify(comment)


# ---------------------------------------------------------------------------
# AMB-06: Cache Poisoning - GET/PATCH /api/cached/<id>
# ---------------------------------------------------------------------------

@app.route("/api/cached/<int:cached_id>", methods=["GET"])
def cached_get(cached_id):
    resource = cached.get(cached_id)
    if resource is None:
        return jsonify({"error": "not found"}), 404

    # Track request count for cache simulation
    key = f"cached-{cached_id}"
    cached_request_counts[key] = cached_request_counts.get(key, 0) + 1
    count = cached_request_counts[key]

    etag = cached_etags.get(cached_id, "etag-unknown")

    resp = jsonify(resource)
    resp.headers["Cache-Control"] = "public, max-age=60"
    resp.headers["ETag"] = f'"{etag}"'
    # Simulate cache: first request is MISS, subsequent are HIT
    resp.headers["X-Cache"] = "HIT" if count > 1 else "MISS"
    return resp


@app.route("/api/cached/<int:cached_id>", methods=["PATCH"])
def cached_patch(cached_id):
    resource = cached.get(cached_id)
    if resource is None:
        return jsonify({"error": "not found"}), 404

    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    if body is None:
        return jsonify({"error": "invalid JSON"}), 400

    if isinstance(body, dict):
        for key, value in body.items():
            resource[key] = value

    # BUG: Does NOT update the ETag (cache poisoning vulnerability!)
    # cached_etags[cached_id] = "etag-v2-..."  # intentionally omitted

    return jsonify(resource)


# ---------------------------------------------------------------------------
# AMB-02: Side-Effect TOCTOU - PATCH /api/groups/<id>, GET /api/members/<id>
# ---------------------------------------------------------------------------

@app.route("/api/groups/<int:group_id>", methods=["PATCH", "GET"])
def group_endpoint(group_id):
    if request.method == "GET":
        group = groups.get(group_id)
        if group is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(group)

    # PATCH
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    if body is None:
        return jsonify({"error": "invalid JSON"}), 400

    group = groups.get(group_id)
    if group is None:
        return jsonify({"error": "not found"}), 404

    old_name = group.get("name")

    if isinstance(body, dict):
        for key, value in body.items():
            group[key] = value

    # Side effect: if name changed, update ALL members' group_name (no auth check!)
    new_name = group.get("name")
    if new_name != old_name:
        for member_id in group.get("member_ids", []):
            member = members.get(member_id)
            if member and member.get("group_id") == group_id:
                member["group_name"] = new_name

    return jsonify(group)


@app.route("/api/members/<int:member_id>", methods=["GET"])
def member_endpoint(member_id):
    member = members.get(member_id)
    if member is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(member)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def print_banner():
    banner = """
============================================================
  RFC 5789 Auditor - Vulnerable Test Harness
  Running on http://localhost:5789
============================================================

  Endpoints:
  ----------
  [AMB-04] PATCH /api/users/<id>      Content-Type Confusion
  [AMB-04] OPTIONS /api/users/<id>    Missing Accept-Patch header
  [AMB-01] PATCH /api/items/<id>      Resource Creation via PATCH
  [AMB-03] PATCH /api/counters/<id>   Atomicity Race Condition
  [AMB-11] POST  /api/comments        WAF-protected comment creation
  [AMB-11] PATCH /api/comments/<id>   WAF Bypass via split PATCHes
  [AMB-06] GET   /api/cached/<id>     Cache Poisoning (stale ETag)
  [AMB-06] PATCH /api/cached/<id>     Cache Poisoning (no invalidation)
  [AMB-02] PATCH /api/groups/<id>     Side-Effect TOCTOU
  [AMB-02] GET   /api/members/<id>    Side-effect target (read-only)

  Utility:
  --------
  GET /api/health                     Health check

============================================================
"""
    print(banner)


if __name__ == "__main__":
    print_banner()
    app.run(host="127.0.0.1", port=5789, debug=False, threaded=True)
