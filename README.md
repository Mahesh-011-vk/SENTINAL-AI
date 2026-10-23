# SentinelAI — Application Security Intelligence Platform

**SentinelAI** is a production-oriented, evidence-driven, multi-agent application security intelligence platform that unifies static analysis, secret scanning, dependency auditing, dynamic assessment, deterministic risk scoring, bounded AI remediation assistance, and fix verification.

> **Core Architectural Principle:**  
> *AI may interpret evidence, but it must never manufacture evidence.*  
> Deterministic scanners, policy engines, and verification procedures are the authoritative sources of truth. All AI-generated explanations and patches are strictly labeled as unverified advisory proposals.

---

## 1. System Architecture & Trust Boundaries

```
[Web Client] ──(TLS / JWT Auth)──> [FastAPI Gateway & RBAC]
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

### Trust Boundaries
1. **TB1 (Client ↔ API Gateway):** Public/corporate network. Enforces TLS, CORS, HTTP security headers, and short-lived JWT tokens.
2. **TB2 (API Gateway ↔ Domain Services):** Authenticated boundary enforcing multi-tenant isolation and role-based permissions (`SUPERADMIN`, `SECURITY_ADMIN`, `ENGINEER`, `AUDITOR`).
3. **TB3 (Domain Services ↔ Worker Sandbox):** Untrusted code execution boundary. Scanners execute with read-only mounts, timeouts, memory/CPU limits, and strict network egress controls.
4. **TB4 (Scanner Sandbox ↔ Evidence Store):** Untrusted data ingestion. Scanner outputs pass through the `SecretRedactor` (masking 15+ credential formats) before database persistence.
5. **TB5 (Application Service ↔ AI Provider):** Context sanitization, prompt-injection defense, and strict Pydantic output validation.

---

## 2. 12 Specialized Agent Architecture

| # | Agent Name | Boundary & Responsibility |
|---|---|---|
| **1** | **Assessment Planner** | Converts assessment requests into constrained plans; validates asset scopes and tenant policies. |
| **2** | **Asset Intelligence** | Normalizes inventory (repos, web URLs, APIs, containers); tracks authorization expiry. |
| **3** | **Source Code Security (SAST)** | Interprets Semgrep AST evidence; maps rule IDs, file lines, sanitized code snippets. |
| **4** | **Dependency & Supply Chain** | Normalizes OSV/pip-audit records; maps authoritative CVEs and fixed versions. |
| **5** | **Secret Exposure** | Redacts discovered credentials before persistence; records rule and sanitized evidence. |
| **6** | **Web Application (DAST)** | Coordinates OWASP ZAP; enforces mandatory `AssetAuthorizationRecord` and SSRF filters. |
| **7** | **Security Configuration** | Evaluates HTTP headers, TLS settings, and deployment configuration. |
| **8** | **Finding Correlation** | Deduplicates findings via composite fingerprints across tools; tracks recurrence. |
| **9** | **Risk Intelligence** | Explains official risk prioritization calculated by the deterministic risk engine. |
| **10** | **Remediation Assistant** | Explains root causes; suggests minimal, secure patches and regression unit tests. |
| **11** | **Verification Agent** | Reassesses fixed findings; flags `VERIFIED_RESOLVED`, `STILL_DETECTED`, or `INCONCLUSIVE`. |
| **12** | **Reporting & Compliance** | Prepares evidence-backed summaries; exports audit-ready PDF and JSON reports. |

---

## 3. Quick Start & Local Execution

### Prerequisites
- Python 3.11+ (Tested on Python 3.13)
- Node.js 18+ (for frontend)
- Git

### 1. Setup Python Virtual Environment & Install Dependencies
```bash
# Clone and enter workspace
cd /Users/maheshs/Desktop/SENTINELAI

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt
```

### 2. Run Database Migrations
```bash
cd backend
alembic upgrade head
cd ..
```

### 3. Seed Demo Security Data
```bash
PYTHONPATH=backend python3 backend/app/seed.py
```

### 4. Run Automated Pytest Suite
```bash
# Runs 41 unit and integration tests (auth, RBAC, SSRF, secret redaction, risk engine, policy gates, SBOM, OpenAPI)
PYTHONPATH=backend pytest -v
```

### 5. Run End-to-End Verification Pipeline
```bash
PYTHONPATH=backend python3 backend/tests/verify_e2e.py
```

### 6. DevSecOps CLI Automation
SentinelAI includes a native CLI for CI/CD pipelines:
```bash
# 1. Evaluate CI/CD Build Gate Policy (exit 0 on pass, exit 1 on fail)
python -m app.cli policy-check --project "Nexus" --max-critical 0 --max-high 2

# 2. Export CycloneDX 1.5 JSON SBOM
python -m app.cli export-sbom --project "Nexus" --output cyclonedx.json

# 3. List active vulnerabilities in tabular format
python -m app.cli list-findings --project "Nexus"
```

### 7. Start the Backend API Gateway
```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive OpenAPI documentation will be available at:  
👉 **http://localhost:8000/docs**

### 8. Start the Next.js Security Console
```bash
cd frontend
npm install
npm run dev
```
Interactive Security Console will be available at:  
👉 **http://localhost:3000**

---

## 4. Default Seeded Demo Credentials

| Role | Email | Password | Permissions |
|---|---|---|---|
| **Security Admin** | `admin@sentinelai.io` | `AdminPass123!` | Full scan scheduling, asset scope authorization, audit logs, user management |
| **Lead Engineer** | `engineer@sentinelai.io` | `DevPass123!` | Trigger authorized scans, review findings, submit remediation proposals |
| **Compliance Auditor** | `auditor@sentinelai.io` | `AuditPass123!` | Read-only inspection of findings, reports, and security audit trail |

---

## 5. Security Controls & Defenses

- **Strict SSRF Prevention:** Blocks loopback (`127.0.0.1`), RFC1918 private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata (`169.254.169.254`), and non-whitelisted ports. Re-resolves DNS at socket connection time.
- **Zip Slip & Zip Bomb Defense:** Source code archive extractor rejects directory traversal paths (`..`, `/`), symlinks, and enforces strict file count (<5,000) and uncompressed byte (<100MB) limits.
- **High-Entropy Secret Redaction:** Regex and Shannon-entropy detection masks AWS access keys, GitHub PATs, private keys, database credentials, Slack tokens, and JWTs before database write.
- **Mandatory Asset Authorization:** Web and DAST scans are strictly blocked with HTTP 403 Forbidden unless a cryptographically signed, unexpired `AssetAuthorizationRecord` exists.
- **Deterministic Risk Engine v1.0.0:** Transparent, versioned formula scoring findings from 0.0 to 100.0 with full factor provenance.
- **Software Bill of Materials (SBOM):** Standard CycloneDX 1.5 JSON export mapping all software components and vulnerabilities.
- **Deterministic Policy-as-Code:** 6 customizable security build gate rules for CI/CD enforcement.

---

## 6. Implementation Progress & Acceptance Status

- [x] **Phase 1: Architecture, Trust Boundaries & Threat Model** (Complete & Documented)
- [x] **Phase 2: Backend Foundation, Auth, RBAC & Multi-Tenant Isolation** (Complete & Tested)
- [x] **Phase 3: Database Models, Alembic Migrations & Audit Trail** (Complete & Migrated)
- [x] **Phase 4: Target Security, SSRF & Archive Validation** (Complete & Hardened)
- [x] **Phase 5: Secret Redaction & Deterministic Risk Engine v1.0.0** (Complete & Scored)
- [x] **Phase 6: Dedicated Scanner Adapters (Semgrep, Gitleaks, OSV, ZAP, Config, OpenAPI)** (Complete & Tested)
- [x] **Phase 7: Next.js Presentation Dashboard & Console** (Complete & Verified in Browser)
- [x] **Phase 8: Multi-Agent AI Remediation & Fix Verification Pipeline** (Complete & Verified)
- [x] **Phase 9: Compliance & Executive Reporting Engine (PDF/JSON)** (Complete & Generated)
- [x] **Phase 10: Policy-as-Code Build Gates, CycloneDX SBOM & DevSecOps CLI** (Complete & Operational)
