# SentinelAI — Application Security Intelligence Platform

<p align="center">
  <img src="frontend/public/hero-shield-art.png" alt="SentinelAI 3D Shield Security Pedestal" width="480" style="border-radius: 16px; box-shadow: 0 12px 32px rgba(0,0,0,0.12);" />
</p>

<p align="center">
  <strong>Evidence-Driven Multi-Agent Application Security Intelligence Platform</strong><br>
  <em>Find Vulnerabilities Before Attackers Do.</em>
</p>

<p align="center">
  <a href="https://github.com/Mahesh-011-vk/SENTINAL-AI/actions/workflows/ci.yml"><img src="https://github.com/Mahesh-011-vk/SENTINAL-AI/actions/workflows/ci.yml/badge.svg" alt="CI Pipeline Status" /></a>
  <img src="https://img.shields.io/badge/Tests-41%2F41%20Passed-10B981?style=flat&logo=pytest" alt="Pytest Status" />
  <img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-3776AB?style=flat&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/Next.js-16.4-000000?style=flat&logo=next.js&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/License-MIT-D4AF37?style=flat" alt="MIT License" />
</p>

---

## 1. Executive Overview

**SentinelAI** is a production-grade, evidence-driven application security intelligence platform that combines conventional security scanners, deterministic policy-as-code engines, cryptographic asset authorization boundaries, bounded AI remediation assistance, and automated fix verification.

> ### 🛡️ Core Architectural Principle
> **AI may interpret evidence, but it must never manufacture evidence.**  
> Deterministic scanners, policy gates, and sandbox verification procedures are the authoritative sources of truth. All AI-generated explanations and patches are strictly isolated as unverified advisory proposals requiring human review.

---

## 2. Key Capabilities & Engine Breakdown

### 🔍 Multi-Engine Deterministic Scanners
- **Semgrep SAST:** Static code analysis parsing ASTs to detect code injection (SQLi, command injection, path traversal) and insecure deserialization.
- **Gitleaks Secret Scanner:** High-entropy regex engine detecting hardcoded API keys, private certificates, AWS/GCP/Slack credentials, and JWTs.
- **OSV-Scanner / pip-audit:** Software composition analysis checking package manifests against Google OSV and GitHub Security Advisories for known CVEs.
- **OWASP ZAP Dynamic (DAST):** Active web vulnerability assessment enforcing mandatory target authorization records and strict SSRF defenses.
- **Security Config & TLS Inspector:** Audits HTTP security response headers (`HSTS`, `CSP`, `X-Content-Type-Options`) and SSL/TLS cipher suites.
- **OpenAPI Spec Security Auditor:** Validates OpenAPI/Swagger schemas for broken object-level authorization (BOLA), unauthenticated admin endpoints, and permissive CORS.

### 📐 Deterministic Risk Engine (v1.0.0)
Replaces arbitrary AI hallucinations with a versioned, explainable mathematical scoring formula ($0.0 \to 100.0$):
$$\text{Risk Score} = \min\left(100.0, \, \left(\text{CVSS} \times 10 \times W_{\text{crit}} \times W_{\text{exp}} \times W_{\text{exploit}}\right) + \text{Penalty}_{\text{secret}}\right)$$
- **Asset Criticality Weight ($W_{\text{crit}}$):** `CRITICAL` (1.4), `HIGH` (1.2), `MEDIUM` (1.0), `LOW` (0.8).
- **Network Exposure Weight ($W_{\text{exp}}$):** `INTERNET_FACING` (1.3), `INTERNAL` (1.0), `RESTRICTED` (0.7).
- **Exploit Availability ($W_{\text{exploit}}$):** Active in-the-wild exploit (1.25), PoC available (1.10), Theoretical (1.0).

### 🔒 Enterprise Target Security & SSRF Defense
- **Strict SSRF Filter:** Resolves hostnames at socket connection time and blocks IPv4 loopback (`127.0.0.1`), RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and AWS/GCP cloud metadata (`169.254.169.254`).
- **Cryptographic Scope Records:** Web/DAST assessments are blocked with `HTTP 403 Forbidden` unless a valid, unexpired `AssetAuthorizationRecord` exists.
- **Archive Security:** Zip Slip path traversal (`../`) and Zip Bomb decompression limits (<5,000 files, <100MB uncompressed).
- **Secret Redactor:** Replaces sensitive credentials with masked placeholders before database write.

### 🤖 Bounded Multi-Agent Remediation & Sandbox Fix Verification
- **Context Sanitization:** Scans code snippets to scrub sensitive secrets before invoking language models.
- **Actionable Patches:** Generates unified diffs and regression unit tests.
- **Automated Fix Verification:** Re-executes the targeted scanner in an isolated sandbox. Only when the scanner deterministically confirms the finding is gone does the state advance to `VERIFIED_RESOLVED`.

### 📋 Policy-as-Code Build Gates & CycloneDX 1.5 SBOM
- **Automated CI/CD Gates:** Evaluates strict criteria (Max Critical findings, Max High findings, Unresolved Secrets, Max CVSS).
- **Software Bill of Materials:** Exports compliant CycloneDX 1.5 JSON mapping all components, dependency versions, and linked CVEs.

---

## 3. System Architecture & Trust Boundaries

```
[Web Client / CLI] ──(TLS / JWT Auth)──> [FastAPI Gateway & RBAC]
                                                  │
                               ┌──────────────────┴──────────────────┐
                               ▼                                     ▼
                    [Application Services]               [Isolated Worker Sandbox]
                    - Project & Asset Scope              - Semgrep (SAST)
                    - Target Authorization Record        - Gitleaks (Secrets)
                    - Deterministic Risk Engine (v1.0.0) - OSV-Scanner (SCA)
                    - Evidence Normalizer                - OWASP ZAP (DAST / Scope Enforced)
                    - Audit Logger                       - Config / TLS Inspector
                               │                                     │
                               ▼                                     ▼
                    [PostgreSQL / SQLite]                [Secret Redaction Engine]
                    - Multi-tenant Isolation            - Shannon Entropy & Regex Masking
                    - Immutable Audit Trail                          │
                               │                                     │
                               └─────────────────┬───────────────────┘
                                                 ▼
                                    [Bounded Multi-Agent AI]
                                    - Context Sanitizer (Zero Secret Leak)
                                    - Pydantic Schema Output Validation
                                    - Untrusted Advisory Proposals
```

---

## 4. Quick Start & Local Execution

### Prerequisites
- **Python:** 3.11, 3.12, or 3.13
- **Node.js:** 18+ (tested on Node 20 & 22)
- **Git**

### Method A: Native Local Development

```bash
# 1. Clone repository
git clone https://github.com/Mahesh-011-vk/SENTINAL-AI.git
cd SENTINAL-AI

# 2. Setup Python Virtual Environment & Install Dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# 3. Run Database Migrations & Seed Security Data
cd backend
alembic upgrade head
cd ..
PYTHONPATH=backend python3 backend/app/seed.py

# 4. Start FastAPI Backend Gateway (Port 8000)
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

In a separate terminal:

```bash
# 5. Start Next.js Security Console (Port 3000)
cd frontend
npm install
npm run dev
```

- **Web Console UI:** [http://localhost:3000](http://localhost:3000)
- **Interactive Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Method B: Docker Compose Deployment

```bash
docker-compose up -d
```

This starts:
- `backend` on `http://localhost:8000`
- `frontend` on `http://localhost:3000`
- `postgres` on port `5432`
- `redis` on port `6379`

---

## 5. DevSecOps CLI Commands

SentinelAI includes a CLI in `backend/app/cli.py` for CI/CD scripting:

```bash
# Activate virtual environment
source .venv/bin/activate
cd backend

# 1. Register a new target asset
python -m app.cli add-asset \
  --project "Nexus Enterprise Services" \
  --name "Customer Portal Web App" \
  --type WEB_APPLICATION \
  --locator "https://portal.internal.company.com" \
  --env STAGING \
  --criticality HIGH \
  --owner "DevSecOps Core"

# 2. List all registered scoped assets
python -m app.cli list-assets --project "Nexus Enterprise Services"

# 3. List active vulnerability catalog
python -m app.cli list-findings --project "Nexus Enterprise Services"

# 4. Evaluate CI/CD Build Gate Policy (Exits 0 on pass, 1 on fail)
python -m app.cli policy-check \
  --project "Nexus Enterprise Services" \
  --max-critical 0 \
  --max-high 2 \
  --mode strict

# 5. Export CycloneDX 1.5 JSON SBOM
python -m app.cli export-sbom \
  --project "Nexus Enterprise Services" \
  --output cyclonedx.json
```

---

## 6. Pre-Configured Demo Credentials

The seeded database contains three distinct personas for testing role-based access control (RBAC):

| Role | Email | Password | Allowed Capabilities |
| :--- | :--- | :--- | :--- |
| **Security Admin** | `admin@sentinelai.io` | `AdminPass123!` | Asset scope authorization, scan scheduling, user management, policy updates, audit inspection. |
| **Lead Engineer** | `engineer@sentinelai.io` | `DevPass123!` | Trigger authorized scans, review finding details, execute fix verifications. |
| **Compliance Auditor** | `auditor@sentinelai.io` | `AuditPass123!` | Read-only access to findings, policy reports, and immutable audit logs. |

---

## 7. Automated Test Suite & CI

The platform includes 41 automated unit, integration, and security test cases:

```bash
# Run full automated test suite
source .venv/bin/activate
pytest -v

# Run code formatting & linter
ruff check backend/

# Run End-to-End Verification Flow
PYTHONPATH=backend python backend/tests/verify_e2e.py
```

### Test Coverage Breakdown
- `test_auth.py`: JWT generation, password hashing, token expiration, invalid credentials.
- `test_rbac_multitenancy.py`: Tenant isolation, unauthorized tenant access prevention, role hierarchies.
- `test_ssrf_and_archives.py`: DNS re-resolution, loopback/private/metadata blocking, Zip Slip directory traversal rejection.
- `test_secret_redactor.py`: Masking AWS, GitHub, private keys, database connection strings, high-entropy tokens.
- `test_risk_engine.py`: Provenance, weight calculations, severity thresholds.
- `test_scanner_adapters.py`: Deduplication, scanner argument arrays, failure handling.
- `test_policy_and_api_spec.py`: Policy evaluation logic, CycloneDX 1.5 SBOM schema, OpenAPI auditor.
- `test_agents_and_lifecycle.py`: State transitions, finding triage rationale recording.

---

## 8. Repository Layout

```
SENTINELAI/
├── .github/workflows/ci.yml       # GitHub Actions CI workflow
├── backend/
│   ├── alembic/                  # Database migration scripts
│   ├── app/
│   │   ├── agents/               # Bounded AI & Fix Verification agents
│   │   ├── api/v1/               # FastAPI REST endpoints
│   │   ├── core/                 # SSRF, Secret Redactor, Archive Validator, Security
│   │   ├── models/               # SQLAlchemy multi-tenant ORM models
│   │   ├── scanners/             # Semgrep, Gitleaks, OSV, ZAP, OpenAPI, TLS adapters
│   │   ├── schemas/              # Pydantic v2 validation schemas
│   │   ├── services/             # Risk engine, SBOM generator, Policy engine
│   │   ├── cli.py                # Native DevSecOps CLI tool
│   │   ├── main.py               # Application entrypoint & middleware
│   │   └── seed.py               # Deterministic demo database seeder
│   ├── tests/                    # 41 Pytest unit & integration tests
│   └── requirements.txt          # Python backend dependencies
├── frontend/
│   ├── public/                   # 3D Shield artwork & design assets
│   ├── src/
│   │   ├── app/                  # Next.js App Router (Layout & Pages)
│   │   └── lib/api.ts            # Type-safe API client & interfaces
│   └── package.json              # Node.js dependencies (Next.js 16, Lucide)
├── docs/                         # Hardening & architectural documentation
├── docker-compose.yml            # Multi-container orchestration
├── CONTRIBUTING.md               # Contribution guidelines
├── LICENSE                       # MIT License
├── README.md                     # Project documentation
└── SECURITY.md                   # Security vulnerability disclosure policy
```

---

## 9. Security & Responsible Disclosure

Please review [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines. To report security vulnerabilities, contact **security@sentinelai.io**.

---

## 10. License

This project is licensed under the [MIT License](LICENSE).
