# RFC 5789 Auditor - Vulnerable Test Harness

A Flask application that **intentionally exhibits all 6 vulnerabilities** detected by the RFC 5789 Auditor Burp Suite extension. Used for integration testing and development.

## Install

```bash
pip install -r requirements.txt
```

## Run the harness

```bash
python harness.py
```

Starts on `http://localhost:5789`.

## Run integration tests

```bash
python integration_test.py
```

Starts the harness automatically, runs all tests, prints PASS/FAIL per test, and exits with code 0 (all pass) or 1 (any fail).

## Endpoints and AMB IDs

| AMB ID | Method | Endpoint | Vulnerability |
|--------|--------|----------|---------------|
| AMB-04 | PATCH | `/api/users/<id>` | Content-Type Confusion |
| AMB-04 | OPTIONS | `/api/users/<id>` | Missing Accept-Patch header |
| AMB-01 | PATCH | `/api/items/<id>` | Resource Creation via PATCH |
| AMB-03 | PATCH | `/api/counters/<id>` | Atomicity Race Condition |
| AMB-11 | POST | `/api/comments` | WAF-protected comment creation |
| AMB-11 | PATCH | `/api/comments/<id>` | WAF Bypass via split PATCHes |
| AMB-06 | GET | `/api/cached/<id>` | Cache Poisoning (stale ETag) |
| AMB-06 | PATCH | `/api/cached/<id>` | Cache Poisoning (no invalidation) |
| AMB-02 | PATCH | `/api/groups/<id>` | Side-Effect TOCTOU |
| AMB-02 | GET | `/api/members/<id>` | Side-effect target |
| - | GET | `/api/health` | Health check |

### Note on AMB-03 (Atomicity Race Condition)

The test harness injects an artificial 100ms `time.sleep()` delay in the counters endpoint to widen the race window for testing purposes. Real-world race conditions typically have microsecond-scale windows and may require hundreds of concurrent requests to trigger reliably. The harness delay makes the vulnerability trivially reproducible in integration tests, but should not be taken as representative of production timing.
