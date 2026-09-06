# AI AppSec Platform

AI AppSec Platform is an application-security workspace that combines static analysis, contextual AI reasoning, attack-surface discovery, runtime evidence, and developer remediation workflows.

The platform is designed to help security and engineering teams move from **finding** to **evidence**, **prioritization**, and **verified remediation**.

## Contents

- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API surface](#api-surface)
- [Frontend](#frontend)
- [Project structure](#project-structure)
- [Security boundaries](#security-boundaries)
- [Testing](#testing)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Troubleshooting](#troubleshooting)

## Capabilities

### Repository security

- GitHub repository scanning with branch selection
- ZIP upload scanning with file-count, archive-size, and extracted-size limits
- Semgrep static analysis
- Framework, endpoint, snippet, and source-context enrichment
- Incremental and diff-only GitHub scans
- Risk scoring, AI analysis, deduplication, and finding triage
- Scan progress, logs, timelines, and persisted scan state

### Website security

- Public website URL scanning
- Bounded breadth-first crawling
- Security-header analysis for CSP, HSTS, clickjacking, MIME sniffing, and related controls
- Client-side checks for dangerous JavaScript sinks, mixed content, open redirects, exposed secrets, and unsafe `postMessage` usage
- Persistent website scan history and live progress polling

### API security

- Static endpoint discovery for Spring Boot, Express.js, and FastAPI projects
- OWASP API Top 10 review mapping
- Non-destructive authentication and authorization probes
- OpenAPI and Swagger contract analysis
- Route-level contract drift detection
- Review signals for missing authentication declarations, path parameters, operation IDs, request schemas, and deprecated operations

### AI and ML security

- Prompt-injection probes
- Jailbreak probes
- Model behavior evaluation
- Safety and refusal assessment
- Canary-leak detection
- Caller-supplied golden-set evaluation
- Accuracy and latency reporting

### Security operations and developer workflows

- Unified security graph connecting scans, findings, endpoints, repositories, and security references
- Candidate attack-path generation
- Automated GitHub security-fix pull requests
- Security regression-test generation and evaluation
- CycloneDX-compatible dependency inventory
- Dependency posture checks and secret detection
- Docker, Terraform, Kubernetes, and CI workflow checks
- Docker-isolated exploit-validation sandbox
- SARIF 2.1.0 export for GitHub Code Scanning
- Configurable CI severity gates
- Runtime/cloud posture correlation from supplied asset evidence
- JSON, HTML, and Markdown reporting

## Architecture

```text
Repository URL or ZIP
        |
        v
Clone or extract with safety limits
        |
        v
Semgrep static analysis --------------------+
        |                                    |
        v                                    |
Normalize findings                          |
        |                                    |
        +--> Framework, endpoint, snippet, and context enrichment
        |                                    |
        +--> Risk scoring -------------------+
        |                                    |
        +--> Model routing and AI/RAG analysis
        |                                    |
        +--> Deduplication
        |                                    |
        v                                    v
Findings repository                    Security graph
(JSON compatibility + SQLAlchemy)      and attack-path candidates
        |
        +--> Findings, reports, SARIF, CI gates, regression tests
        |
        v
Next.js security workspace
```

The platform also exposes independent security-analysis services for websites, APIs, AI/ML targets, supply chain, infrastructure, runtime evidence, and exploit validation.

## Technology stack

### Backend

- Python 3.11+ recommended
- FastAPI and Uvicorn
- SQLAlchemy and Alembic
- SQLite for local development
- PostgreSQL through `DATABASE_URL`
- Semgrep 1.38.0 or newer
- GitPython
- HTTPX
- Groq API with LLaMA models
- LangChain, ChromaDB, and local Hugging Face embeddings for RAG analysis

### Frontend

- Next.js 16
- React 19
- TypeScript
- Tailwind CSS 4
- TanStack React Query
- Recharts
- Lucide icons

## Quick start

### Prerequisites

| Tool | Version | Notes |
|---|---:|---|
| Python | 3.11-3.13 | 3.11 or 3.12 is recommended for dependency compatibility |
| Node.js | 18+ | Required for the frontend |
| Git | Recent | Required for GitHub repository scans |
| Semgrep | 1.38.0+ | Must be available as `semgrep` on `PATH` |
| Docker | Optional | Required for exploit-validation sandbox and Compose deployment |
| PostgreSQL | Optional | Required only when using a PostgreSQL `DATABASE_URL` |

Install Semgrep separately and verify it:

```bash
pip install semgrep
semgrep --version
```

### Clone and install

```bash
git clone https://github.com/Suresh-Nagvanshi/ai-appsec-platform.git
cd ai-appsec-platform

python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Windows cmd
.venv\Scripts\activate.bat

pip install -r backend/requirements.txt
```

### Configure the backend

Create a root `.env` file:

```env
# AI analysis. Optional; local fallback analysis works without it.
GROQ_API_KEY=your_groq_api_key

# Protect application routes. Leave blank only for local development.
API_KEY=replace_with_a_long_random_value
API_KEY_DISABLED=false

# Frontend origins.
CORS_ORIGINS=http://localhost:3000

# Optional database override. SQLite is the default.
# DATABASE_URL=postgresql+psycopg2://appsec:appsec@localhost:5432/appsec

# Optional GitHub token for automated security-fix pull requests.
# GITHUB_TOKEN=github_token_with_required_repository_permissions
```

Start the backend with the project launcher:

```bash
python -m backend.run
```

Use the launcher instead of calling Uvicorn directly. It excludes cloned repositories, extracted archives, uploads, results, and generated JSON from reload watching.

Backend URLs:

- API: `http://127.0.0.1:8000`
- Health: `http://127.0.0.1:8000/health`
- OpenAPI docs: `http://127.0.0.1:8000/docs`

### Configure and start the frontend

From the repository root:

```bash
copy frontend\.env.local.example frontend\.env.local
cd frontend
npm install
npm run dev
```

Recommended `frontend/.env.local`:

```env
# Used by the Next.js backend proxy.
BACKEND_API_URL=http://localhost:8000
BACKEND_API_KEY=replace_with_the_same_value_as_API_KEY

# Compatibility fallback supported by the proxy.
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_API_KEY=replace_with_the_same_value_as_API_KEY
```

Frontend URL: `http://localhost:3000`

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `GROQ_API_KEY` | No | Enables Groq-backed vulnerability analysis and fix generation |
| `API_KEY` | Recommended | Protects all application routers |
| `API_KEY_DISABLED` | No | Explicit local/test bypass; do not enable in deployments |
| `CORS_ORIGINS` | No | Comma-separated allowed frontend origins |
| `DATABASE_URL` | No | SQLAlchemy connection string; SQLite is the default |
| `GITHUB_TOKEN` | For PRs | Allows automated branch, commit, and pull-request creation |
| `BACKEND_API_URL` | Frontend | Server-side URL used by the Next.js proxy |
| `BACKEND_API_KEY` | Frontend | Server-side API key forwarded by the proxy |

## API surface

All routes below are protected by `X-API-Key` when `API_KEY` is configured. `/health` is public.

### Core scanning

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/scans/github` | Start a GitHub scan |
| `POST` | `/api/scans/zip` | Start a ZIP scan |
| `GET` | `/api/scans` | List scans |
| `GET` | `/api/scans/{scan_id}` | Poll scan progress |
| `GET` | `/api/scans/{scan_id}/diff` | Read incremental diff metadata |
| `GET` | `/findings` | List findings with filters and pagination |
| `GET` | `/findings/{finding_id}` | Read a finding |
| `PATCH` | `/findings/{finding_id}/status` | Update triage status |
| `POST` | `/report/generate` | Generate a structured report |
| `GET` | `/report/download/{scan_id}` | Download JSON, HTML, or Markdown |

### API security

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/api-security/endpoints` | Discover source-defined endpoints |
| `POST` | `/api/api-security/mapping` | Map endpoints to OWASP API Top 10 review areas |
| `POST` | `/api/api-security/authz-test` | Run bounded, non-destructive GET probes |
| `POST` | `/api/api-security/contract` | Analyze OpenAPI/Swagger and compare route drift |

### AI/ML security

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/ai-security/test` | Run prompt-injection, jailbreak, behavior, and safety probes |
| `POST` | `/api/ai-security/evaluate` | Run a caller-supplied model golden set |

### Operations and developer workflow

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/security-graph` | Build the unified security graph |
| `POST` | `/api/fix/pull-request` | Create a GitHub security-fix pull request |
| `POST` | `/api/regression-tests/generate` | Convert findings into regression specifications |
| `POST` | `/api/regression-tests/evaluate` | Check whether findings reappeared |
| `POST` | `/api/supply-chain/analyze` | Generate dependency inventory and detect secrets |
| `POST` | `/api/infrastructure/analyze` | Analyze Docker, Terraform, Kubernetes, and CI files |
| `POST` | `/api/validation-sandbox/run` | Run an allowlisted command in a Docker sandbox |
| `GET` | `/api/ci/sarif/{scan_id}` | Export SARIF 2.1.0 |
| `POST` | `/api/ci/gate` | Evaluate a severity-based CI gate |
| `POST` | `/api/runtime-security/posture` | Correlate supplied runtime asset evidence |

## Frontend

The Next.js workspace provides:

- Overview dashboard with posture metrics and recent activity
- Scan creation, history, progress, logs, and pipeline timelines
- Repository registration, branch selection, and scan actions
- Findings list, filters, detail views, AI analysis, code context, and remediation
- Website security scanning and finding inspection
- Report generation and export
- Workspace settings and connection status
- Responsive desktop sidebar and mobile navigation

The frontend calls the same-origin route `/api/backend/*`. The Next.js proxy forwards requests to FastAPI and injects the configured backend API key.

## Project structure

```text
.
├── backend/
│   ├── main.py                         FastAPI application and protected routers
│   ├── run.py                          Uvicorn launcher with reload exclusions
│   ├── api/                            Feature APIs
│   │   ├── scans.py                    GitHub and ZIP scans
│   │   ├── website_scans.py            Website scanning
│   │   ├── api_security.py             API discovery, mapping, probes, contracts
│   │   ├── ai_security.py              AI/ML testing and evaluation
│   │   ├── security_graph.py            Unified graph
│   │   ├── regression_tests.py          Regression registry
│   │   ├── supply_chain.py              SBOM inventory and secrets
│   │   ├── infrastructure_security.py   IaC and container checks
│   │   ├── validation_sandbox.py        Docker exploit validation
│   │   ├── ci_security.py               SARIF and CI gates
│   │   └── runtime_security.py          Runtime posture correlation
│   ├── ai/                             AI, model routing, prompts, and RAG
│   ├── enrichment/                     Framework, endpoint, and context enrichment
│   ├── services/                       Scan and website orchestration
│   ├── storage/                        Findings and diff persistence
│   ├── db/                             SQLAlchemy models, sessions, migrations
│   └── test_*.py                       Backend test suite
├── frontend/
│   └── src/
│       ├── app/                        Next.js App Router pages and proxy
│       ├── components/                 Shared UI and feature components
│       ├── hooks/                      React Query hooks
│       ├── services/                   Typed API clients
│       └── providers/                  Application providers
├── data/                               Knowledge bases and scan artifacts
├── database/                           Local database and compatibility state
├── extracted/                          Temporary extracted archives
├── repos/                              Temporary cloned repositories
├── results/                            Semgrep results
├── uploads/                            Temporary ZIP uploads
├── reports/                            Generated report artifacts
├── docker-compose.yml                  PostgreSQL, backend, and frontend services
└── README.md
```

Generated runtime files and credentials should not be committed.

## Security boundaries

- API routes require `X-API-Key` when `API_KEY` is configured.
- GitHub URLs require HTTPS and the exact `github.com` host.
- Branch names are validated before Git operations.
- ZIP uploads enforce compressed size, member-count, and extracted-size limits.
- Website and API probes reject local/private targets and credential-bearing URLs.
- AI/ML testing uses bounded probes and does not claim that a PASS proves safety.
- Exploit validation uses Docker with no network, a read-only project mount, dropped capabilities, no-new-privileges, memory/CPU/PID limits, and an image allowlist.
- Automated PR generation requires explicit `GITHUB_TOKEN` configuration and exact single-occurrence source replacement.
- Runtime/cloud posture analysis consumes supplied evidence; it does not silently connect to cloud accounts.

Do not expose the backend publicly without configuring API keys, CORS, deployment isolation, rate limits, and tenant authorization.

## Testing

Run the complete backend suite from the repository root:

```bash
python -m pytest -q
```

Run focused backend tests:

```bash
python -m pytest -q backend/test_api_security.py
python -m pytest -q backend/test_api_security.py
python -m pytest -q backend/test_supply_chain.py
```

Run frontend lint and build:

```bash
npm --prefix frontend run lint
npm --prefix frontend run build
```

The suite currently covers scanning, persistence, enrichment, AI analysis, API security, AI/ML evaluation, supply chain, infrastructure, regression tests, CI output, runtime posture, and sandbox controls.

## Known limitations

- RBAC and multi-tenant isolation are not implemented.
- PostgreSQL support exists through SQLAlchemy, but JSON compatibility paths remain during migration.
- The runtime/cloud endpoint correlates supplied asset evidence; provider-native integrations are not yet included.
- CVE matching requires an authoritative vulnerability feed or scanner; local inventory does not claim CVE coverage.
- AI analysis can be slow for large finding sets and may be affected by provider rate limits.
- Website and API probing are bounded passive/low-impact checks, not a full authenticated penetration test.
- Production Dockerfiles and deployment hardening still require verification in the target environment.

## Roadmap

Prioritized next steps:

1. Production Dockerfiles and deployment smoke tests
2. RBAC, organizations, and tenant-isolated data access
3. GitHub App integration and pull-request workflow automation
4. Provider-native cloud posture integrations
5. Dependency reachability and authoritative CVE matching
6. GraphQL and Postman contract imports
7. VS Code extension and richer CI annotations
8. Audit logs, webhooks, and organization policy controls

## Troubleshooting

### Frontend shows backend errors

Confirm the backend is running on port 8000 and that `frontend/.env.local` contains:

```env
BACKEND_API_URL=http://localhost:8000
BACKEND_API_KEY=your_backend_api_key
```

The proxy also accepts `NEXT_PUBLIC_API_URL` and `NEXT_PUBLIC_API_KEY` as compatibility fallbacks. Restart the Next.js dev server after changing environment variables.

### Scans restart or disappear during development

Start the backend with:

```bash
python -m backend.run
```

Do not run `uvicorn backend.main:app --reload` directly because cloned and extracted files can trigger unwanted reloads.

### Semgrep cannot be found

Verify that the binary is installed and available on `PATH`:

```bash
semgrep --version
```

### Exploit validation is unavailable

Install Docker and confirm the daemon is running. The sandbox intentionally returns an error when Docker is unavailable.

## Contributing

1. Create a focused branch.
2. Add or update tests for behavior changes.
3. Run backend tests and frontend lint/build.
4. Keep generated artifacts, credentials, cloned repositories, and uploads out of commits.
5. Use focused commit messages that describe the feature or fix.

Maintained by **Suresh Nagvanshi**.
