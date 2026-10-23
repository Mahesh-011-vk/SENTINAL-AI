# SentinelAI Production Hardening and Operational Guide

## 1. System Architecture Overview

SentinelAI is designed as an evidence-driven, multi-tenant application security intelligence platform. Unlike wrapper tools or purely heuristic scanners, SentinelAI couples deterministic analysis engines (Semgrep, Gitleaks, OSV-Scanner, OWASP ZAP, native TLS/HTTP and OpenAPI auditors) with a deterministic Risk Scoring Engine, structured CycloneDX 1.5 SBOM generators, and audited AI remediation assistants.

```
                      +-----------------------------+
                      |   Reverse Proxy / Ingress   |
                      |  (TLS 1.3 Termination, WAF) |
                      +--------------+--------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
      +-----------------+                         +-----------------+
      | Next.js Console |                         | FastAPI Backend |
      |   (Port 3000)   |                         |   (Port 8000)   |
      +-----------------+                         +--------+--------+
                                                           |
                      +-------------------+----------------+
                      |                   |                |
                      v                   v                v
             +-----------------+  +---------------+  +------------+
             |  PostgreSQL 16+ |  |  Redis 7+     |  | Celery App |
             |   (RLS & ACID)  |  | (Queue/Locks) |  |  (Workers) |
             +-----------------+  +---------------+  +------------+
```

---

## 2. Multi-Tenant Isolation & Database Hardening

### 2.1 Logical Isolation & Row-Level Security (RLS)
Every security entity in SentinelAI (`projects`, `assets`, `scan_jobs`, `findings`, `remediation_records`, `audit_logs`) includes a mandatory foreign key `tenant_id`.

In PostgreSQL production environments, activate Row-Level Security:
```sql
-- Enable RLS on core tables
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Create tenant isolation policy
CREATE POLICY tenant_isolation_policy ON projects
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_findings_isolation_policy ON findings
    FOR ALL
    USING (project_id IN (
        SELECT id FROM projects WHERE tenant_id = current_setting('app.current_tenant_id', true)
    ));
```

### 2.2 Connection Pooling & Resource Quotas
- Use **PgBouncer** or **SQLAlchemy `QueuePool`**:
  - `pool_size`: 20 connections per worker node.
  - `max_overflow`: 10 connections.
  - `pool_timeout`: 30 seconds.
  - `pool_recycle`: 1800 seconds (prevent stale TCP sockets).
- Enforce statement timeouts: `SET statement_timeout = '15s';` on web request sessions to prevent denial-of-service from runaway queries.

---

## 3. Secret Management & Cryptographic Key Rotation

### 3.1 Key Lifecycle & Environmental Secrets
SentinelAI requires two cryptographic secret keys:
1. `SECRET_KEY`: Used for HS256 JWT access and refresh token signing.
2. `DB_ENCRYPTION_KEY`: Used for AES-256-GCM encryption of sensitive database fields.

### 3.2 Key Rotation Procedure (Zero-Downtime)
1. **Generate New Key Pair**:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(64))"
   ```
2. **Dual-Key Verification Window**:
   - Update backend configuration with `JWT_PRIMARY_KEY` (new) and `JWT_FALLBACK_KEY` (previous).
   - Sign all newly issued tokens with the primary key; accept and verify existing sessions using the fallback key.
   - After token expiration window (e.g., 24 hours), decommission the fallback key.
3. **Database Column Re-encryption**:
   - Run the migration worker:
   ```bash
   python -m app.cli.rotate_keys --old-key "$PREVIOUS_KEY" --new-key "$NEW_KEY"
   ```

---

## 4. Celery Worker Scaling & Scanner Orchestration

### 4.1 Worker Queue Separation
Separate CPU-intensive SAST/SCA scanner workloads from I/O-bound DAST and AI generation tasks:

```bash
# High-priority interactive scans (Queue: scans)
celery -A app.worker.celery_app worker -Q scans -c 4 --loglevel=INFO

# AI patch generation & verification (Queue: ai_remediation)
celery -A app.worker.celery_app worker -Q ai_remediation -c 2 --loglevel=INFO

# Scheduled policy & cron audits (Queue: scheduled)
celery -A app.worker.celery_app worker -Q scheduled -c 2 --loglevel=INFO
```

### 4.2 Scanner Sandboxing & Resource Limits
- Execute scanner binaries (Semgrep, OSV, ZAP) inside unprivileged Docker containers or Linux cgroups.
- Enforce hard execution boundaries:
  - Max runtime: 300 seconds (`timeout_seconds=300`).
  - Max memory: 2GB per scanner process.
  - Read-only filesystem mount on repository target directories.
  - SSRF blocklist enforced on any external outbound calls.

---

## 5. CI/CD Security Gate Enforcement (Policy-as-Code)

Integrate SentinelAI build gates directly into GitLab CI, GitHub Actions, or Jenkins pipelines:

### GitHub Actions Workflow Example
```yaml
name: SentinelAI Security Build Gate

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run SentinelAI Policy-as-Code Evaluation
        env:
          SENTINEL_API_URL: ${{ secrets.SENTINEL_API_URL }}
          SENTINEL_API_TOKEN: ${{ secrets.SENTINEL_API_TOKEN }}
          PROJECT_ID: ${{ secrets.SENTINEL_PROJECT_ID }}
        run: |
          RESPONSE=$(curl -s -X POST "$SENTINEL_API_URL/api/v1/projects/$PROJECT_ID/policy/evaluate" \
            -H "Authorization: Bearer $SENTINEL_API_TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"max_critical_findings": 0, "max_high_findings": 2, "max_risk_score": 60.0}')
          
          STATUS=$(echo "$RESPONSE" | jq -r '.overall_status')
          echo "SentinelAI Build Gate Status: $STATUS"
          
          if [ "$STATUS" = "FAILED" ]; then
            echo "Security Policy Violated! Build Gate Blocked."
            echo "$RESPONSE" | jq '.rule_results[] | select(.status=="FAIL")'
            exit 1
          fi
```

---

## 6. Backup, Disaster Recovery & High Availability

### 6.1 Database Backup Strategy
- **Continuous Archiving**: WAL (Write-Ahead Logging) shipping to AWS S3 / Cloud Storage bucket with object lock (WORM).
- **Daily Physical Snapshot**: Nightly snapshot retained for 90 days.
- **RPO (Recovery Point Objective)**: <= 5 minutes.
- **RTO (Recovery Time Objective)**: <= 30 minutes.

### 6.2 Backup Restoration Test
Validate backup integrity monthly:
```bash
# Restore snapshot into isolated verification cluster
pg_restore -d sentinelai_dr_test /var/backups/sentinelai_latest.dump
# Verify schema and finding counts
psql -d sentinelai_dr_test -c "SELECT count(*) FROM findings;"
```

---

## 7. Audit Logging & Regulatory Compliance

SentinelAI maintains an immutable audit trail (`audit_logs`) satisfying:
- **SOC 2 Type II (Common Criteria CC6.1 - CC6.8)**: Full traceability of user authentication, RBAC authorization, scanner executions, and risk recalculations.
- **ISO/IEC 27001:2022 (Control A.8.15 - Logging)**: Logs contain actor UUID, tenant ID, action code, resource ID, client IP, user agent, and timestamp.
- **PCI-DSS v4.0 (Requirement 6.3 - 6.5 & 10.2)**: Automated vulnerability identification, CVSS-based severity scoring, and verifiable patch remediation records.
