# Remediation Plan

This document records what was fixed in code and, for findings that were not fully
remediated, the residual risk, the effort required, and any compensating controls.
Finding IDs refer to `docs/findings.md`. Before/after scan evidence is in `reports/`
and `reports/after/`.

## Fixed in this submission

| ID | Finding | Fix | Verified by |
|----|---------|-----|-------------|
| F1 | SQL injection in scan search | Parameterised query, escaped LIKE wildcards, scoped to `owner_id` | Regression tests; SAST 0 findings |
| F2 | Hardcoded JWT key / secrets | `SECRET_KEY` from env or mounted file, app refuses to start without it; unused DB/admin secrets deleted | Startup test; SAST secret rule clear |
| F3 | IDOR on `GET /scans/{id}` | Query scoped to `owner_id` | Regression test |
| F4 | Passwords written to logs | Log username only | Regression test asserting no password in logs |
| F8 | `alg=none` accepted | Removed `"none"` from accepted algorithms | Regression test (forged token rejected) |
| F10 | No brute-force limit on share password | Lockout after 5 failed attempts (HTTP 429) | Regression test |
| F11 | Share password in query string | Accept `X-Share-Password` header; query param kept as documented fallback | Regression test |
| F13 | Helm hardening gaps | Configurable namespace (default `vulntracker`), deploy by digest, pull policy | Checkov 96 pass / 0 fail |
| F6 (partial) | Vulnerable dependencies | Upgraded the security-critical libraries to their latest fixed versions | Python + Node 20 test suites pass |

Scan deltas after remediation: SAST 4 → 0 findings; IaC 6 → 0 failures; SCA
critical/high 3/25 → 2/10; container image critical/high 5/71 → 3/68.

---

## Deferred findings

### F5 — Notification service has no authentication (SSRF) · High
**Why not fixed in code:** The brief scopes code changes to the Python API ("no changes
required" to `notify/`), and a correct fix is a non-trivial design change (shared-secret or
mTLS auth on `/notify`, plus an allowlist for webhook destination URLs).

**Residual risk:** An attacker able to reach the service can still register webhooks pointing
at internal or cloud-metadata endpoints and harvest the dispatch key. In a compromised-pod
scenario this is a path to cloud credentials.

**Effort:** ~0.5–1 day — add authentication middleware to `/webhooks` and `/notify`, validate
and allowlist outbound URLs, and move the dispatch key to a secret.

**Compensating controls (in place):** The Helm NetworkPolicy already restricts egress from the
API to DNS and the notify service only, and restricts ingress to the ingress controller, so
the SSRF cannot reach the metadata endpoint or arbitrary internal hosts from the API pod. The
service is `ClusterIP` with no ingress route, so it is not publicly reachable.

### F7 — Verbose error responses leak stack traces · Medium
**Why not fixed:** Lower priority than the access-control and secret findings within the time
budget; the fix is small but touches both services' error handlers.

**Residual risk:** Internal paths, library versions and code structure are disclosed on errors,
which aids an attacker mapping the system. No direct data loss.

**Effort:** ~1–2 hours — return a generic 500 body with a correlation id and log details
server-side; remove `stack`/`traceback` from responses in both services.

**Compensating controls:** None in code yet. In production an API gateway or ingress can be
configured to strip/replace error bodies, but this should be fixed in the application.

### F9 — Permissive CORS (reflect-any-origin with credentials) · Medium
**Why not fixed:** The API authenticates with bearer tokens, not cookies, so a malicious site
cannot ride a victim's session; the real-world impact is low today.

**Residual risk:** Becomes serious if cookie-based auth is ever introduced, at which point this
would allow cross-site credentialed requests from any origin.

**Effort:** ~1 hour — replace the reflecting middleware with an explicit allowlist of trusted
origins and drop `Allow-Credentials` unless required.

**Compensating controls:** Bearer-token auth (not ambient cookies) is the de facto control.

### F12 — OS-package CVEs in the container base image · Medium
**Why not fixed:** Most have no fixed version available in Debian 12 yet, and none are reachable
through the application's code path; fixing the aggregate means changing base image.

**Residual risk:** Known CVEs remain present in the image. Exploitation would require an attacker
to already have code execution in the container to reach the vulnerable OS libraries.

**Effort:** ~0.5 day — move to a distroless or Chainguard/Wolfi base, re-test the app, and adjust
the Dockerfile (no shell for the healthcheck/debug).

**Compensating controls:** Read-only root filesystem, non-root user, dropped capabilities and
seccomp (all in place) sharply limit what a compromised process could do with those libraries.

### F6 (remaining) — Residual dependency CVEs · Mixed
**Why not fully fixed:** The security-critical libraries were upgraded to their latest fixed
versions, but the vulnerability database advances continuously — newer advisories already name
fix versions beyond those (e.g. axios > 1.16, cryptography > 46), and some transitive packages
(`proxy-addr`, `path-to-regexp`) lag their fix. One finding, **`python-jose` CVE-2026-85394, has
no fixed version at all.**

**Residual risk:** Mostly denial-of-service and information-disclosure CVEs in request-handling
and HTTP-client libraries. The unfixable python-jose algorithm issue affects token verification;
it is partly mitigated because the app now pins a single algorithm (F8) rather than accepting a
list.

**Effort:** Ongoing, not one-time. Each individual bump is minutes; keeping current is the real
work. Migrating off `python-jose` (e.g. to `pyjwt`) to escape CVE-2026-85394 is ~0.5 day.

**Compensating controls / recommendation:** Treat dependency patching as a continuous process:
add Dependabot or Renovate to raise upgrade PRs automatically, and gate CI on *new* critical/high
CVEs (the SCA job in CI). This is more effective than a one-off manual sweep.

---

## Cross-cutting: secret rotation (relates to F2)

Removing the hardcoded `SECRET_KEY`, DB password and admin key from the code does **not** remove
them from git history, where they are already public. These values must be treated as compromised
and **rotated**, not merely deleted. Recommended: rotate the signing key and any real credentials,
and add a secret scanner (gitleaks/trufflehog) to CI and pre-commit to prevent recurrence.

## Not remediated by design

- **SQLite / single replica:** acceptable for a prototype; production needs a managed database
  (e.g. PostgreSQL) to allow horizontal scaling and durable storage. Tracked as an architectural
  item, not a vulnerability.
- **Open self-service registration (F14):** acceptable for an internal tool; if the service is
  exposed more broadly, registration should be invite- or SSO-gated.
