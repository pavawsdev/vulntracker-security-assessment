# Security Automation Engineer — Take-Home Assignment

Welcome. This assignment is designed to reflect the real work of a Lead Security Automation Engineer: extending an existing service, identifying and assessing security risks, remediating them with code, and deploying it securely. There are no trick questions — we are evaluating your depth of knowledge, your judgment under constraints, and your ability to communicate risk.

**Estimated time: 4–6 hours.** We respect your time. If you find yourself going significantly over, scope down rather than rushing.

---

## Background

**VulnTracker** is a two-service system for managing vulnerability scan results:

- **`app/`** — Python/FastAPI REST API. Security teams use it to log findings, track remediation, and share reports with stakeholders.
- **`notify/`** — Node.js/Express notification service. Intended to dispatch webhook events to registered endpoints when scan records are created or updated.

Both services are working but imperfect internal prototypes. Neither has gone through a formal security review. The Python API calls the notification service in the background whenever a scan is created or updated — start both services to see the full flow.

---

## Getting Started

**Create your own repository for this assignment.** Do not fork — your solution must be in a fresh repo. You may use the starter code as a base, but your work must be in your own repo.

```bash
# 1. Clone the assignment repo locally
git clone https://github.com/cloudtriquetra/asa-assignment.git
cd asa-assignment

# 2. Point it at your own new GitHub repo (create one first at github.com)
git remote set-url origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

From here, work on your own repo and share its URL when you submit.

**Requirements:** Python 3.11 (exactly — see CI), Node.js 20+, Docker

**Python API (`app/`)**

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt   # runtime deps + pytest; the container uses requirements.txt only
```

The API reads its JWT signing key from the environment and refuses to start without one. Copy `.env.example` to `.env` and set `JWT_SECRET_KEY` (generate one with `python -c "import secrets; print(secrets.token_urlsafe(32))"`), or export it in your shell.

The API must be started from inside the `app/` directory — the modules use bare imports and won't resolve from the repo root:

```bash
cd app
JWT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" uvicorn main:app --reload
```

Available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

Run the Python test suite from the **repo root**:

```bash
pytest tests/ -v
```

**Notification Service (`notify/`)**

```bash
cd notify
npm install
npm start
```

Available at `http://localhost:3001`.

Run the Node.js test suite (stop the notify service first if it is running — the test suite starts its own server on the same port):

```bash
cd notify
npm test
```

**Running the API in Docker**

Build from the repo root:

```bash
docker build -t vulntracker-api:local .
```

Run it. The root filesystem is read-only; the SQLite database lives on a named volume mounted at `/data`. The port is bound to localhost only, so other machines on the network can't reach it:

```bash
docker run --rm -p 127.0.0.1:8000:8000 \
  --read-only --tmpfs /tmp \
  -v vulntracker-data:/data \
  -e PUBLIC_BASE_URL=http://localhost:8000 \
  vulntracker-api:local
```

On Windows Git Bash, prefix with `MSYS_NO_PATHCONV=1` so `/tmp` and `/data` aren't rewritten to Windows paths.

Check it is up (the container also reports health via its `HEALTHCHECK`):

```bash
curl http://localhost:8000/health
docker ps --format '{{.Names}}: {{.Status}}'   # shows (healthy) after ~10s
```

The image runs as non-root UID 10001, contains no test tooling, and has no secrets baked in.

**Share link URLs**: `share_url` is built from the `PUBLIC_BASE_URL` environment variable (default `http://localhost:8000`), not from the request's `Host` header, which is client-controlled and unreliable behind a proxy.

**Share link password**: for a password-protected link, supply the password in the `X-Share-Password` header, which keeps it out of server logs and browser history. A `?password=` query parameter is also accepted as a fallback but is discouraged for that reason. A link locks after 5 wrong attempts.

**Deploying to Kubernetes (Helm)**

The chart in `helm/vulntracker` expects [External Secrets Operator](https://external-secrets.io) and a `ClusterSecretStore` backed by your secrets manager. Secrets are mounted into the pod as read-only files, never passed as environment variables.

```bash
helm lint helm/vulntracker --set publicBaseUrl=https://vulntracker.example.com
helm install vulntracker helm/vulntracker \
  --namespace vulntracker --create-namespace \
  --set publicBaseUrl=https://vulntracker.example.com \
  --set image.digest=sha256:<image-digest>
```

---

## Your Tasks

### Task 1 — Extend the App _(~1–1.5 hrs)_

Implement the **"Shared Report Link"** feature:

> As a VulnTracker user, I want to share a specific scan result with an external stakeholder (e.g. a customer or auditor) via a unique link. The link must expire after **24 hours** and must support **optional password protection**.

Add the following endpoints to the app:

| Method | Path                     | Auth          | Description                                                                                                              |
| ------ | ------------------------ | ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `POST` | `/scans/{scan_id}/share` | Bearer token  | Generate a share token for a scan. Accepts optional `password` in the request body. Returns `{ "share_url": "..." }`     |
| `GET`  | `/share/{token}`         | None (public) | Return the scan data if the token is valid and not expired. If password-protected, require a `password` query parameter. |

Implementation choices are yours. We will read and evaluate the code you write here — including the security properties of your implementation. For the `share_url` value, use the incoming request's host, or hard-code `http://localhost:8000` for the prototype — document whichever you choose.

---

### Task 2 — Security Analysis _(~1.5 hrs)_

#### 2a. Run the required scans

You must run **all four** of the following scan categories. Select an appropriate open-source or free-tier tool for each — your tool choices are part of the evaluation.

| Scan type                                      | What it covers                                                                         |
| ---------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Static Application Security Testing (SAST)** | Source code — identify insecure coding patterns, injection risks, hardcoded secrets    |
| **Dependency / SCA vulnerability scan**        | Third-party packages — known CVEs in pinned dependencies                               |
| **Container image scan**                       | The Docker image you build — OS packages, installed libraries, misconfigurations       |
| **Infrastructure-as-Code (IaC) security scan** | Your Helm chart or Terraform — misconfigurations, insecure defaults, policy violations. Complete Task 4 first, then run this scan. |

Save the raw JSON output of each tool to the `reports/` directory, named clearly by scan type:

```
reports/
├── sast.<tool>.json
├── sca.<tool>.json
├── container.<tool>.json
└── iac.<tool>.json
```

#### 2b. Prioritised findings

Write a `docs/findings.md` with a table of security findings, sourced from your scans and your own manual review. For each finding:

- Tool and scan type that detected it (or "manual")
- Severity (your assessment — justify it)
- Business impact in the context of _this specific application_
- Whether it is in the starter code or in your new feature

**Do not copy-paste tool output.** We are evaluating your ability to interpret findings and apply business context to prioritisation — not your ability to run a command.

---

### Task 3 — Remediate _(~1 hr)_

- Fix **at least 3 critical or high severity findings** in code. Show the changes clearly (they will be visible in your git diff / PR).
- At least one fix must be in the code you wrote in Task 1.
- For findings you do not fix, document why in `docs/remediation-plan.md`: what is the residual risk, what effort would remediation require, and what compensating controls (if any) exist?

---

### Task 4 — Containerisation and Deployment Artifacts _(~30–45 min)_

#### Dockerfile (mandatory)

Write a production-grade `Dockerfile` for the **Python FastAPI service** (`app/`). It must:

- Use a minimal, pinned base image
- Run as a non-root user
- Include a `HEALTHCHECK`
- Not embed secrets or credentials

The container image must build successfully and the app must be reachable via `docker run`. Include build and run instructions in your README.

#### Infrastructure

Add either a `terraform/` or `helm/` directory (your choice) that could deploy this service to a Kubernetes cluster or cloud environment. Your deployment must:

- Source secrets from a secrets manager (not hardcoded in manifests or env vars)
- Restrict network ingress to only what is required
- Define resource limits and security contexts

---

### Task 5 — Executive Summary _(~30 min)_

Write `docs/executive-summary.md` as if you are presenting to a CISO who has 5 minutes.

Cover:

1. The overall security posture of the application before and after your work
2. The top 3 residual risks and the reason they were not fully remediated
3. Your recommended next steps if this were a real production service

No jargon. No tool names in the first paragraph. Your audience cares about business risk, not CVE numbers.

---

## Submission

Push your completed solution to your own GitHub repository and share the URL with us. Your repository must contain:

```
/
├── app/                        # extended Python API code
├── notify/                     # Node.js notification service (no changes required)
├── Dockerfile                  # mandatory (may cover one or both services)
├── reports/
│   ├── sast.<tool>.json
│   ├── sca.<tool>.json
│   ├── container.<tool>.json
│   └── iac.<tool>.json
├── terraform/  OR  helm/
├── docs/
│   ├── findings.md
│   ├── remediation-plan.md
│   └── executive-summary.md
├── tests/                      # updated if you added Python tests
└── README.md                   # update with Docker build/run instructions
```

CI must pass (green) on your repo before submission.

---

## What We Are Looking For

We are not grading on volume. We are grading on judgment.

- **Security depth**: Did you find the real issues? Did you prioritise them correctly for this application?
- **Implementation security**: Does your new feature introduce, or avoid, new vulnerabilities?
- **Remediation quality**: Are your fixes correct and complete? Are your deferral reasons honest?
- **Deployment security**: Does your container and infrastructure configuration reflect real-world security practices?
- **Communication**: Would a non-technical executive understand your summary?

Good luck. If anything in the brief is ambiguous, document your assumption and proceed.
