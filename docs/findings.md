# Security Findings

Prioritised security findings for VulnTracker, drawn from automated scans and manual
review. Severity is my own assessment in the context of this application, not the raw
tool rating; where the two differ, the difference is explained.

## Scan coverage

| Scan type | Tool | Report |
|---|---|---|
| SAST | Semgrep (p/python, p/javascript, p/secrets, p/jwt, p/owasp-top-ten) | `reports/sast.semgrep.json` |
| SCA (dependencies) | Trivy filesystem | `reports/sca.trivy.json` |
| Container image | Trivy image | `reports/container.trivy.json` |
| IaC (Helm) | Checkov | `reports/iac.checkov.json` |

Manual review covered authorization logic, the notification service, and the new
share-link feature — areas where scanners are weak because the flaw is in intent, not syntax.

## What the tools missed

The highest-impact findings (F2 auth bypass, F3 IDOR, F7 notify SSRF) came from **manual
review**, not the scanners. SAST flagged the SQL injection and password logging but not the
broken access control; SCA found CVEs in dependencies but not the hardcoded secret that
makes those CVEs secondary. This is the argument for layering manual review on top of tools.

## Summary (most to least severe)

| ID | Finding | Source | Severity | Location |
|----|---------|--------|----------|----------|
| F1 | SQL injection in scan search | Semgrep SAST + manual | Critical | Starter |
| F2 | Authentication bypass via hardcoded JWT key | Manual + Semgrep (secrets) | Critical | Starter |
| F3 | Broken access control (IDOR) on `GET /scans/{id}` | Manual | High | Starter |
| F4 | Plaintext passwords written to logs | Semgrep SAST + manual | High | Starter |
| F5 | Notification service: no auth + SSRF via webhook URL | Manual | High | Starter |
| F6 | Known-vulnerable dependencies (jose, cryptography, multipart, axios, starlette) | Trivy SCA | High | Starter |
| F7 | Verbose error responses leak stack traces | Manual + Semgrep | Medium | Starter |
| F8 | `alg=none` accepted in token decode | Semgrep SAST + manual | Medium | Starter |
| F9 | CORS reflects any origin with credentials | Manual | Medium | Starter |
| F10 | No rate limiting on login or share-link password | Manual | Medium | Starter + Feature |
| F11 | Share-link password passed as query parameter | Manual | Medium | Feature |
| F12 | Outdated OS packages in container base image | Trivy image | Medium | Starter (deploy) |
| F13 | Helm: image not pinned by digest, default namespace | Checkov IaC | Low | Feature (deploy) |
| F14 | Open self-service registration | Manual | Low | Starter |

---

## Detailed findings

### F1 — SQL injection in scan search · Critical · Starter
**Source:** Semgrep (`avoid-sqlalchemy-text`, `database.py:28`), confirmed by manual exploitation.

`search_scans_by_query` builds a SQL string with f-string interpolation of the user's query,
so the `q` parameter is executed as SQL. A logged-in user can read every other tenant's scans
and, via a UNION, dump the `users` table including bcrypt password hashes. The query is also
not scoped to the caller's `owner_id`, so even without injection it returns other users' data.

**Business impact:** VulnTracker stores customers' unremediated vulnerabilities — effectively a
map of where each customer is exploitable. One authenticated account (or one stolen token)
turns into disclosure of every customer's security posture plus offline password cracking.
This is the worst outcome the product can produce, hence Critical.

### F2 — Authentication bypass via hardcoded JWT key · Critical · Starter
**Source:** Manual; the secret is also flagged by Semgrep's secrets ruleset in `config.py`.

`SECRET_KEY` is hardcoded in `config.py` and committed to git (public history). Anyone with
repo access can mint a valid token for any username and call the API as that user, with no
password. I confirmed a self-signed token is accepted. Rated Critical because it is a complete
authentication bypass requiring only public information.

*Rating note:* Trivy/Semgrep also surface the hardcoded `DB_PASSWORD` and `ADMIN_API_KEY`. I
rate those lower (Medium) because the application never uses them — SQLite needs no credentials
and no code reads the admin key. They must still be rotated because they are in public history.

### F3 — Broken access control (IDOR) on GET /scans/{id} · High · Starter
**Source:** Manual.

`GET /scans/{scan_id}` looks up the scan by id only, with no owner check, so any authenticated
user can read any scan by guessing sequential integer ids. Notably `PATCH` and `DELETE` on the
same resource *do* check ownership, which shows the control was simply missed on the read path.

**Business impact:** Same data exposure as F1 (cross-tenant disclosure of findings) but simpler
to exploit — no injection, just incrementing an id. High rather than Critical only because it
exposes scans one at a time and not the password hashes.

### F4 — Plaintext passwords written to logs · High · Starter
**Source:** Semgrep (`python-logger-credential-disclosure`, `main.py`), confirmed in container logs.

The login handler logs the username and password on every attempt, success or failure. I
observed cleartext credentials in the running container's stdout. Logs are routinely shipped
to aggregation systems with broad read access, so this spreads credentials far beyond the app.

**Business impact:** Security staff and customers reuse passwords; harvesting them from logs
enables account takeover here and elsewhere. High because exploitation needs only log access,
which is far broader than database access.

### F5 — Notification service: no auth + SSRF · High · Starter
**Source:** Manual review of `notify/src/index.js` and `dispatcher.js`.

`/webhooks` and `/notify` have no authentication (the code comments assume "internal network
only"). Anyone who can reach the service can register an arbitrary webhook URL; the dispatcher
then makes server-side POSTs to that URL and attaches the shared `X-Service-Key` header. This
is a server-side request forgery primitive: an attacker can point webhooks at cloud metadata
endpoints or internal services and simultaneously harvest the service key. `GET /webhooks`
also lists every registered endpoint.

**Business impact:** In a cloud deployment, SSRF to the metadata endpoint can yield cloud
credentials and lead to full environment compromise. High. The Helm NetworkPolicy (Task 4)
is a compensating control, but the service should not rely solely on network position.

### F6 — Known-vulnerable dependencies · High · Starter
**Source:** Trivy SCA (`requirements.txt`, `notify/package-lock.json`).

Pinned dependencies carry known CVEs, several of them directly relevant:
- **python-jose 3.3.0** — algorithm-confusion CVEs in the exact library used for auth tokens.
- **python-multipart 0.0.6**, **starlette 0.27.0** (via FastAPI) — DoS and SSRF/credential CVEs
  in the request-handling path.
- **cryptography 38.0.1** — multiple CVEs including a bundled-OpenSSL issue.
- **axios 0.21.1** — SSRF and credential-leak CVEs; this is the HTTP client the notify service
  uses to call attacker-supplied webhook URLs, so it compounds F5.

**Business impact:** Overall High. I prioritise the auth and request-path libraries (jose,
starlette, multipart) over the larger count of transitive Node CVEs, because those sit on the
authentication and public-request paths of a security product.

### F7 — Verbose error responses leak internals · Medium · Starter
**Source:** Manual; related Semgrep rule on broad exception handling.

The FastAPI global handler returns the exception message, type, full traceback and request URL
in the HTTP 500 body; the Express error handler returns `err.stack`. This hands attackers file
paths, library versions and code structure. Medium: it accelerates other attacks rather than
being direct compromise.

### F8 — `alg=none` accepted in token decode · Medium · Starter
**Source:** Semgrep (`jwt-python-none-alg`, `auth.py:38`), manual verification.

`decode_token` passes `algorithms=[ALGORITHM, "none"]`. On this version of python-jose an
unsigned token did not bypass auth (it raised and surfaced via F7 as a 500) rather than being
accepted, so I rate it Medium, not Critical. It is still an unsafe configuration that must be
removed — a library upgrade could turn it into a true bypass.

*Rating note:* a scanner typically rates `none` acceptance as High/Critical by pattern. I
lowered it after verifying the runtime behaviour on the pinned version — an example of
interpreting, not just reporting.

### F9 — CORS reflects any origin with credentials · Medium · Starter
**Source:** Manual.

The CORS middleware echoes the request `Origin` back as `Access-Control-Allow-Origin` and sets
`Allow-Credentials: true`, which trusts every website. This looks Critical by pattern, but the
API authenticates with `Authorization: Bearer` tokens, not cookies, and browsers do not attach
bearer tokens automatically — so a malicious site cannot ride a victim's ambient session. I
rate it Medium: it becomes serious only if cookie auth is ever introduced.

### F10 — No rate limiting on login or share-link password · Medium · Starter + Feature
**Source:** Manual.

Neither `POST /auth/login` nor `GET /share/{token}` limits attempts, so passwords can be
brute-forced online. For the share link this is the main residual weakness of the new feature:
once a link is known, its password can be guessed indefinitely. Medium; the ingress rate limit
in the Helm chart is a partial, infrastructure-level mitigation.

### F11 — Share-link password passed as query parameter · Medium · Feature
**Source:** Manual review of the Task 1 feature.

Per the brief, `GET /share/{token}?password=...` takes the password in the query string, which
is recorded in access logs, proxy logs and browser history. I kept the brief's interface but
flag this as a design weakness; a header or POST body would avoid the exposure.

### F12 — Outdated OS packages in container image · Medium · Starter (deployment)
**Source:** Trivy image scan of `vulntracker-api:local`.

The `python:3.11-slim` (Debian 12) base contributes OS-level CVEs, including critical ratings
in `zlib` and `libsqlite3`. Most have no fixed version available yet and are not reachable
through the application's code path, so I rate the aggregate Medium rather than Critical.
Reducing the base image (distroless/Chainguard) is the structural fix.

### F13 — Helm hardening gaps · Low · Feature (deployment)
**Source:** Checkov IaC scan (90 checks passed, 6 failed).

Remaining failures: image deployed by tag rather than digest by default (CKV_K8S_43), and
resources render into the default namespace when no namespace is supplied (CKV_K8S_21). The
`imagePullPolicy` finding (CKV_K8S_15) is moot once a digest is pinned. Low, and partly a
scanning artifact of rendering without `--namespace`; the chart already passes the
high-value checks (non-root, read-only FS, dropped capabilities, seccomp, resource limits).

### F14 — Open self-service registration · Low · Starter
**Source:** Manual.

`POST /auth/register` is unauthenticated, so anyone can create an account and then reach the
authenticated endpoints — which amplifies F1 and F3. Low on its own for an internal tool, but
it removes the "needs a valid account" barrier from the Critical/High findings above.

---

## Prioritisation rationale

The ranking follows blast radius against *this* product's core asset — the catalogue of
customers' unremediated vulnerabilities and the credentials guarding it:

1. **F1, F2** expose that catalogue (and password hashes) wholesale to any account or anyone
   with the public repo. They are fixed first.
2. **F3, F4, F5** each give a realistic path to the same data or to credentials with a single
   additional condition (a guessed id, log access, or network reach).
3. **F6** is weighted by *which* libraries are vulnerable, not the CVE count.
4. Medium/Low items either need another weakness to chain, or are mitigated by controls added
   in the deployment layer.
