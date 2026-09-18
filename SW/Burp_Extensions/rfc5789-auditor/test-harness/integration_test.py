#!/usr/bin/env python3
"""
RFC 5789 Auditor - Integration Tests

Starts the vulnerable test harness in a background subprocess, runs
validation tests for each vulnerability (AMB-01 through AMB-11), and
reports PASS/FAIL results.

Uses only stdlib: urllib.request, subprocess, json, time, concurrent.futures.
"""

import atexit
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://127.0.0.1:5789"
HARNESS_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harness.py")
TIMEOUT_PER_TEST = 30
harness_process = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def cleanup():
    """Kill the harness subprocess on exit."""
    global harness_process
    if harness_process and harness_process.poll() is None:
        try:
            if hasattr(os, 'killpg'):
                os.killpg(os.getpgid(harness_process.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            harness_process.terminate()
            harness_process.wait(timeout=5)
        except Exception:
            harness_process.kill()


atexit.register(cleanup)


def start_harness():
    """Start the harness as a background subprocess."""
    global harness_process
    harness_process = subprocess.Popen(
        [sys.executable, HARNESS_SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid if hasattr(os, 'setsid') else None,
    )
    return harness_process


def wait_for_health(max_wait=15):
    """Wait until the harness health endpoint responds."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            resp = http_get("/api/health")
            if resp.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def http_get(path):
    """Send a GET request and return parsed JSON."""
    url = BASE_URL + path
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=TIMEOUT_PER_TEST) as resp:
        return json.loads(resp.read().decode())


def http_get_full(path):
    """Send a GET request and return (status_code, headers, body_dict)."""
    url = BASE_URL + path
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_PER_TEST) as resp:
            body = json.loads(resp.read().decode())
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode()) if e.fp else {}
        return e.code, dict(e.headers), body


def http_patch(path, body, content_type="application/json"):
    """Send a PATCH request and return (status_code, body_dict)."""
    url = BASE_URL + path
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="PATCH")
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_PER_TEST) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_resp = json.loads(e.read().decode()) if e.fp else {}
        return e.code, body_resp


def http_post(path, body, content_type="application/json"):
    """Send a POST request and return (status_code, body_dict)."""
    url = BASE_URL + path
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_PER_TEST) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_resp = json.loads(e.read().decode()) if e.fp else {}
        return e.code, body_resp


def http_options(path):
    """Send an OPTIONS request and return (status_code, headers)."""
    url = BASE_URL + path
    req = urllib.request.Request(url, method="OPTIONS")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_PER_TEST) as resp:
            return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


# ---------------------------------------------------------------------------
# Test implementations
# ---------------------------------------------------------------------------

def test_amb04_content_type_confusion():
    """AMB-04: Same body, different Content-Type -> different resource state."""
    # Reset user to known state
    http_patch("/api/users/1", {"name": "Alice", "role": "user", "email": "alice@example.com"})

    body = [{"op": "replace", "path": "/role", "value": "admin"}]

    # Send as json-patch+json (RFC 6902 - parsed as operations array)
    status1, resp1 = http_patch("/api/users/1", body, "application/json-patch+json")

    # Reset user
    http_patch("/api/users/1", {"name": "Alice", "role": "user", "email": "alice@example.com"})

    # Send same body as merge-patch (parsed as shallow merge - array overwrites the whole thing)
    status2, resp2 = http_patch("/api/users/1", body, "application/merge-patch+json")

    # With json-patch, role should be "admin"
    # With merge-patch, the body is an array which gets merged differently
    # The responses should differ because parsing semantics differ
    if resp1 != resp2:
        return True, f"Responses differ as expected: json-patch role={resp1.get('role')}, merge-patch has different structure"
    else:
        return False, f"Responses should differ but were identical: {resp1}"


def test_amb01_resource_creation():
    """AMB-01: PATCH creates a resource that didn't exist."""
    # PATCH a non-existent item
    status, resp = http_patch("/api/items/99999", {"name": "ghost"})
    if status != 201:
        return False, f"Expected 201 Created, got {status}"

    # Verify it exists via GET
    item = http_get("/api/items/99999")
    if item.get("name") != "ghost":
        return False, f"Created item doesn't have expected name: {item}"

    return True, f"PATCH created resource with 201: {item}"


def test_amb03_atomicity_race():
    """AMB-03: Concurrent PATCHes lose updates due to race condition."""
    # Reset counter
    http_patch("/api/counters/1", {"value": 0})

    num_threads = 20

    def increment(_i):
        """Read current value, then write value+1 (with race window)."""
        counter = http_get("/api/counters/1")
        current = counter["value"]
        new_val = current + 1
        status, resp = http_patch("/api/counters/1", {"value": new_val})
        return status, resp

    with ThreadPoolExecutor(max_workers=num_threads) as pool:
        futures = [pool.submit(increment, i) for i in range(num_threads)]
        for f in as_completed(futures):
            f.result()  # wait for all

    # Read final value
    counter = http_get("/api/counters/1")
    final_value = counter["value"]

    if final_value < num_threads:
        return True, f"Race condition confirmed: final value={final_value}, expected={num_threads} (lost {num_threads - final_value} updates)"
    else:
        return False, f"No race detected: final value={final_value}, expected less than {num_threads}"


def test_amb11_waf_bypass():
    """AMB-11: WAF blocks full payload in POST but split PATCHes bypass it."""
    # Step 1: Verify WAF blocks the full payload via POST
    status_post, _ = http_post("/api/comments", {"text": "<script>alert(1)</script>", "author": "Mallory"})
    if status_post != 403:
        return False, f"WAF should block POST with <script>, got status {status_post}"

    # Step 2: Send first fragment via PATCH - "<scr" does NOT match /<script>/
    status_p1, resp_p1 = http_patch("/api/comments/1", {"text": "<scr"})
    if status_p1 != 200:
        return False, f"First split PATCH should pass WAF, got status {status_p1}"

    # Step 3: Send second fragment via PATCH - "ipt>alert(1)</scr" does NOT match /<script>/
    status_p2, resp_p2 = http_patch("/api/comments/1", {"text_suffix": "ipt>alert(1)</scr"})
    if status_p2 != 200:
        return False, f"Second split PATCH should pass WAF, got status {status_p2}"

    # Combined, the resource now has text="<scr" + text_suffix="ipt>alert(1)</scr"
    # which together form the XSS payload, but each PATCH passed the WAF independently
    return True, "WAF blocked full payload (403) but both split PATCHes passed (200)"


def test_amb06_cache_poisoning():
    """AMB-06: PATCH updates resource but ETag stays stale."""
    # GET to capture initial ETag
    status1, headers1, body1 = http_get_full("/api/cached/1")
    etag_before = headers1.get("ETag") or headers1.get("etag")

    if not etag_before:
        return False, "No ETag in initial GET response"

    # PATCH to change the resource
    status_patch, _ = http_patch("/api/cached/1", {"data": "poisoned"})
    if status_patch != 200:
        return False, f"PATCH failed with status {status_patch}"

    # GET again - ETag should be the same (stale!)
    status2, headers2, body2 = http_get_full("/api/cached/1")
    etag_after = headers2.get("ETag") or headers2.get("etag")

    if etag_before == etag_after:
        return True, f"Stale ETag confirmed: before={etag_before}, after={etag_after}, data changed to '{body2.get('data')}'"
    else:
        return False, f"ETag changed (no vulnerability): before={etag_before}, after={etag_after}"


def test_amb02_side_effect_toctou():
    """AMB-02: PATCH on group silently modifies members' group_name."""
    # Reset group and members
    http_patch("/api/groups/1", {"name": "Engineering"})

    # GET member before
    member_before = http_get("/api/members/10")
    group_name_before = member_before.get("group_name")

    # PATCH the group name
    status, resp = http_patch("/api/groups/1", {"name": "Security"})
    if status != 200:
        return False, f"Group PATCH failed with status {status}"

    # GET member after - group_name should have changed (side effect!)
    member_after = http_get("/api/members/10")
    group_name_after = member_after.get("group_name")

    if group_name_after == "Security" and group_name_before != group_name_after:
        return True, f"Side effect confirmed: member group_name changed from '{group_name_before}' to '{group_name_after}'"
    else:
        return False, f"No side effect: before='{group_name_before}', after='{group_name_after}'"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TESTS = [
    ("AMB-04 Content-Type Confusion", test_amb04_content_type_confusion),
    ("AMB-01 Resource Creation", test_amb01_resource_creation),
    ("AMB-03 Atomicity Race Condition", test_amb03_atomicity_race),
    ("AMB-11 WAF Bypass", test_amb11_waf_bypass),
    ("AMB-06 Cache Poisoning", test_amb06_cache_poisoning),
    ("AMB-02 Side-Effect TOCTOU", test_amb02_side_effect_toctou),
]


def main():
    print("=" * 60)
    print("  RFC 5789 Auditor - Integration Tests")
    print("=" * 60)
    print()

    # Start harness
    print("[*] Starting test harness...")
    start_harness()

    print("[*] Waiting for harness to be ready...")
    if not wait_for_health():
        print("[!] FATAL: Harness did not start within timeout.")
        # Print any stderr from the harness
        if harness_process and harness_process.poll() is not None:
            stderr = harness_process.stderr.read().decode() if harness_process.stderr else ""
            if stderr:
                print(f"[!] Harness stderr:\n{stderr}")
        sys.exit(1)

    print("[*] Harness is ready. Running tests...")
    print()

    results = []
    pass_count = 0
    fail_count = 0

    for test_name, test_fn in TESTS:
        print(f"  [{test_name}]")
        try:
            passed, detail = test_fn()
            if passed:
                print(f"    PASS: {detail}")
                results.append(("PASS", test_name))
                pass_count += 1
            else:
                print(f"    FAIL: {detail}")
                results.append(("FAIL", test_name))
                fail_count += 1
        except Exception as e:
            print(f"    FAIL: Exception - {e}")
            results.append(("FAIL", test_name))
            fail_count += 1
        print()

    # Summary
    print("=" * 60)
    print("  SUMMARY")
    print("-" * 60)
    for status, name in results:
        marker = "PASS" if status == "PASS" else "FAIL"
        print(f"  [{marker}] {name}")
    print("-" * 60)
    print(f"  Total: {pass_count + fail_count}  |  Passed: {pass_count}  |  Failed: {fail_count}")
    print("=" * 60)

    # Exit code
    sys.exit(0 if fail_count == 0 else 1)


if __name__ == "__main__":
    main()
