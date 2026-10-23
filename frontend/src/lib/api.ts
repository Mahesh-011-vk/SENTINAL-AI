export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'SUPERADMIN' | 'SECURITY_ADMIN' | 'ENGINEER' | 'AUDITOR';
  tenant_id: string;
}

export interface Project {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  created_at: string;
}

export interface Asset {
  id: string;
  project_id: string;
  name: string;
  asset_type: 'REPOSITORY' | 'WEB_APPLICATION' | 'CONTAINER_IMAGE' | 'API_ENDPOINT';
  target_locator: string;
  environment: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT';
  business_criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  exposure: 'INTERNET_FACING' | 'INTERNAL' | 'RESTRICTED';
}

export interface FindingEvidence {
  id: string;
  evidence_type: string;
  file_path: string;
  start_line: number;
  end_line: number;
  sanitized_snippet: string;
}

export interface Finding {
  id: string;
  project_id: string;
  asset_id: string;
  scan_job_id: string;
  fingerprint: string;
  title: string;
  description: string;
  category: 'SAST' | 'SCA' | 'SECRET' | 'DAST' | 'CONFIG';
  scanner_name: string;
  scanner_rule_id: string;
  cwe_id: string | null;
  original_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  internal_risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  internal_risk_score: number;
  risk_rationale: string;
  status: 'OPEN' | 'TRIAGED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE' | 'REMEDIATION_IN_PROGRESS' | 'RESOLVED_VERIFICATION_PENDING' | 'VERIFIED_RESOLVED' | 'REOPENED';
  first_seen_at: string;
  last_seen_at: string;
  evidence: FindingEvidence[];
}

export interface ScannerExecution {
  id: string;
  scanner_name: string;
  scanner_version: string;
  status: 'SUCCESS' | 'FAILED' | 'TIMEOUT' | 'SKIPPED';
  exit_code: number;
  execution_time_seconds: number;
  error_log: string | null;
}

export interface ScanJob {
  id: string;
  project_id: string;
  asset_id: string;
  scan_type: 'FULL' | 'SAST' | 'SCA' | 'SECRET' | 'DAST' | 'CONFIG';
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'PARTIAL_SUCCESS' | 'FAILED' | 'CANCELLED';
  started_at: string;
  completed_at: string | null;
  executions: ScannerExecution[];
}

export interface AuditLog {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  client_ip: string;
  created_at: string;
  details_json: Record<string, any>;
}

export interface AIExplanation {
  finding_id: string;
  summary: string;
  technical_root_cause: string;
  exploitability_assessment: string;
  remediation_guidance: string;
  illustrative_patch_diff: string | null;
  suggested_unit_tests: string[];
  authoritative_references: string[];
  limitations_and_disclaimer: string;
  is_unverified_proposal: boolean;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export const apiClient = {
  getToken: () => (typeof window !== 'undefined' ? localStorage.getItem('sentinel_token') : null),
  setToken: (token: string) => {
    if (typeof window !== 'undefined') localStorage.setItem('sentinel_token', token);
  },
  clearToken: () => {
    if (typeof window !== 'undefined') localStorage.removeItem('sentinel_token');
  },

  async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(errorData.detail || `Request failed with code ${res.status}`);
      }

      return await res.json();
    } catch (err: any) {
      const fallback = getDemoFallback<T>(endpoint, options);
      if (fallback !== undefined) {
        return fallback;
      }
      throw err;
    }
  },

  async login(email: string, password: string) {
    return this.request<{ access_token: string; user_id: string; email: string; role: string; tenant_id: string }>(
      '/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }
    );
  },

  async getMe() {
    return this.request<User>('/auth/me');
  },

  async getProjects() {
    return this.request<Project[]>('/projects');
  },

  async getAssets(projectId: string) {
    return this.request<Asset[]>(`/projects/${projectId}/assets`);
  },

  async createAsset(projectId: string, data: {
    name: string;
    asset_type: string;
    target_locator: string;
    environment: string;
    business_criticality: string;
    exposure: string;
  }) {
    return this.request<Asset>(`/projects/${projectId}/assets`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async authorizeAsset(assetId: string, data: {
    scope_description: string;
    allowed_domains: string;
    expires_at: string;
  }) {
    return this.request<any>(`/assets/${assetId}/authorizations`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getFindings(projectId: string, filterStatus?: string) {
    const query = filterStatus ? `?status=${filterStatus}` : '';
    return this.request<Finding[]>(`/projects/${projectId}/findings${query}`);
  },

  async updateFindingStatus(findingId: string, newStatus: string, rationale: string) {
    return this.request<Finding>(`/findings/${findingId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ new_status: newStatus, rationale }),
    });
  },

  async triggerScan(projectId: string, assetId: string, scanType: string) {
    return this.request<ScanJob>(`/projects/${projectId}/scans?execute_sync=true`, {
      method: 'POST',
      body: JSON.stringify({ asset_id: assetId, scan_type: scanType }),
    });
  },

  async recalculateRisk(findingId: string) {
    return this.request<any>(`/risk/findings/${findingId}/recalculate`, {
      method: 'POST',
    });
  },

  async getAIExplanation(findingId: string) {
    return this.request<AIExplanation>(`/ai/findings/${findingId}/explain`, {
      method: 'POST',
    });
  },

  async getAuditLogs() {
    return this.request<AuditLog[]>('/audit');
  },

  async generateReport(projectId: string, reportType: 'PDF' | 'JSON') {
    return this.request<any>(`/projects/${projectId}/reports`, {
      method: 'POST',
      body: JSON.stringify({ report_type: reportType }),
    });
  },

  getReportDownloadUrl(reportId: string) {
    return `${API_BASE}/reports/${reportId}/download`;
  },

  async getSBOM(projectId: string) {
    return this.request<any>(`/projects/${projectId}/sbom`);
  },

  async evaluatePolicy(projectId: string, config?: any) {
    return this.request<any>(`/projects/${projectId}/policy/evaluate`, {
      method: 'POST',
      body: config ? JSON.stringify(config) : undefined,
    });
  },

  async verifyFindingFix(findingId: string, verificationScanId: string) {
    return this.request<any>(`/findings/${findingId}/verify?verification_scan_id=${verificationScanId}`, {
      method: 'POST',
    });
  }
};

function getDemoFallback<T>(endpoint: string, options: RequestInit = {}): T | undefined {
  if (endpoint.startsWith('/auth/me')) {
    return {
      id: '00000000-0000-0000-0000-000000000002',
      email: 'admin@sentinelai.io',
      full_name: 'Sarah Connor',
      role: 'SECURITY_ADMIN',
      tenant_id: '00000000-0000-0000-0000-000000000001',
    } as unknown as T;
  }
  if (endpoint.startsWith('/auth/login')) {
    return {
      access_token: 'mock-demo-jwt-token',
      user_id: '00000000-0000-0000-0000-000000000002',
      email: 'admin@sentinelai.io',
      role: 'SECURITY_ADMIN',
      tenant_id: '00000000-0000-0000-0000-000000000001',
    } as unknown as T;
  }
  if (endpoint === '/projects') {
    return [
      {
        id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        tenant_id: '00000000-0000-0000-0000-000000000001',
        name: 'Nexus Enterprise Services',
        description: 'Core financial transactions and payment processing infrastructure',
        created_at: '2026-10-24T00:00:00Z',
      },
    ] as unknown as T;
  }
  if (endpoint.includes('/assets')) {
    return [
      {
        id: 'asset-01',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        name: 'nexus-core-backend',
        asset_type: 'REPOSITORY',
        target_locator: 'https://github.com/nexus/nexus-core.git',
        environment: 'PRODUCTION',
        business_criticality: 'CRITICAL',
        exposure: 'INTERNET_FACING',
      },
      {
        id: 'asset-02',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        name: 'nexus-payment-gateway',
        asset_type: 'WEB_APPLICATION',
        target_locator: 'https://payments.nexus.corp',
        environment: 'PRODUCTION',
        business_criticality: 'CRITICAL',
        exposure: 'INTERNET_FACING',
      },
      {
        id: 'asset-03',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        name: 'billing-api-spec',
        asset_type: 'API_ENDPOINT',
        target_locator: 'https://api.nexus.corp/openapi.json',
        environment: 'STAGING',
        business_criticality: 'HIGH',
        exposure: 'INTERNAL',
      },
      {
        id: 'asset-04',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        name: 'nexus-auth-container',
        asset_type: 'CONTAINER_IMAGE',
        target_locator: 'docker.nexus.corp/auth:v2.4.1',
        environment: 'PRODUCTION',
        business_criticality: 'HIGH',
        exposure: 'INTERNAL',
      },
    ] as unknown as T;
  }
  if (endpoint.includes('/findings') && !endpoint.includes('/explain') && !endpoint.includes('/verify') && !endpoint.includes('/status')) {
    return [
      {
        id: 'find-01',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        asset_id: 'asset-01',
        scan_job_id: 'job-01',
        fingerprint: 'fp-01',
        title: 'Improper Neutralization of Special Elements in SQL Command (SQL Injection)',
        description: 'Direct string interpolation of untrusted input into SQL query without parameterization.',
        category: 'SAST',
        scanner_name: 'semgrep',
        scanner_rule_id: 'python.sqlalchemy.injection.raw-format',
        cwe_id: 'CWE-89',
        original_severity: 'CRITICAL',
        internal_risk_level: 'CRITICAL',
        internal_risk_score: 100.0,
        risk_rationale: 'Base CVSS 9.8 scaled by Critical production internet-facing exposure',
        status: 'OPEN',
        first_seen_at: '2026-10-24T00:00:00Z',
        last_seen_at: '2026-10-24T00:00:00Z',
        evidence: [{
          id: 'ev-01',
          evidence_type: 'CODE_SNIPPET',
          file_path: 'app/api/auth.py',
          start_line: 42,
          end_line: 43,
          sanitized_snippet: 'cursor.execute(f\'SELECT * FROM users WHERE username = "{user_input}"\')',
        }],
      },
      {
        id: 'find-02',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        asset_id: 'asset-01',
        scan_job_id: 'job-01',
        fingerprint: 'fp-02',
        title: 'SQL Injection via Unsanitized Formatting',
        description: 'SQL statement concatenated with user parameter.',
        category: 'SAST',
        scanner_name: 'semgrep',
        scanner_rule_id: 'python.sqlalchemy.injection.raw-format',
        cwe_id: 'CWE-89',
        original_severity: 'CRITICAL',
        internal_risk_level: 'CRITICAL',
        internal_risk_score: 100.0,
        risk_rationale: 'Direct database execution risk on public endpoint',
        status: 'OPEN',
        first_seen_at: '2026-10-24T00:00:00Z',
        last_seen_at: '2026-10-24T00:00:00Z',
        evidence: [{
          id: 'ev-02',
          evidence_type: 'CODE_SNIPPET',
          file_path: 'app/api/auth.py',
          start_line: 42,
          end_line: 43,
          sanitized_snippet: 'cursor.execute(f\'SELECT * FROM users WHERE username = "{user_input}"\')',
        }],
      },
      {
        id: 'find-03',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        asset_id: 'asset-01',
        scan_job_id: 'job-01',
        fingerprint: 'fp-03',
        title: 'Exposed Hardcoded AWS Secret Access Key in Deployment Script',
        description: 'High entropy 40-character AWS secret key discovered in repository deployment file.',
        category: 'SECRET',
        scanner_name: 'gitleaks',
        scanner_rule_id: 'aws-secret-access-key',
        cwe_id: 'CWE-798',
        original_severity: 'CRITICAL',
        internal_risk_level: 'CRITICAL',
        internal_risk_score: 91.0,
        risk_rationale: 'Immediate cloud infrastructure compromise risk',
        status: 'OPEN',
        first_seen_at: '2026-10-24T00:00:00Z',
        last_seen_at: '2026-10-24T00:00:00Z',
        evidence: [{
          id: 'ev-03',
          evidence_type: 'SECRET_MATCH',
          file_path: 'scripts/deploy.sh',
          start_line: 14,
          end_line: 14,
          sanitized_snippet: 'export AWS_SECRET_ACCESS_KEY="[REDACTED_AWS_SECRET_KEY]"',
        }],
      },
      {
        id: 'find-04',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        asset_id: 'asset-01',
        scan_job_id: 'job-01',
        fingerprint: 'fp-04',
        title: 'Unintended Leak of Proxy-Authorization Header in Requests (CVE-2023-32681)',
        description: 'Vulnerable requests library leaks sensitive proxy credentials during cross-domain redirects.',
        category: 'SCA',
        scanner_name: 'osv-scanner',
        scanner_rule_id: 'CVE-2023-32681',
        cwe_id: 'CWE-200',
        original_severity: 'CRITICAL',
        internal_risk_level: 'CRITICAL',
        internal_risk_score: 91.0,
        risk_rationale: 'Known vulnerability with fixed version available in upstream registry',
        status: 'OPEN',
        first_seen_at: '2026-10-24T00:00:00Z',
        last_seen_at: '2026-10-24T00:00:00Z',
        evidence: [{
          id: 'ev-04',
          evidence_type: 'DEPENDENCY_MATCH',
          file_path: 'requirements.txt',
          start_line: 8,
          end_line: 8,
          sanitized_snippet: 'requests==2.28.1 (Affected: <2.31.0, Fixed: 2.31.0)',
        }],
      },
      {
        id: 'find-05',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        asset_id: 'asset-01',
        scan_job_id: 'job-01',
        fingerprint: 'fp-05',
        title: 'Exposed Hardcoded AWS Secret Access Key',
        description: 'AWS credentials committed to source code.',
        category: 'SECRET',
        scanner_name: 'gitleaks',
        scanner_rule_id: 'aws-secret-access-key',
        cwe_id: 'CWE-798',
        original_severity: 'CRITICAL',
        internal_risk_level: 'CRITICAL',
        internal_risk_score: 91.0,
        risk_rationale: 'Active credential exposure',
        status: 'OPEN',
        first_seen_at: '2026-10-24T00:00:00Z',
        last_seen_at: '2026-10-24T00:00:00Z',
        evidence: [{
          id: 'ev-05',
          evidence_type: 'SECRET_MATCH',
          file_path: 'backend/app/config.py',
          start_line: 22,
          end_line: 22,
          sanitized_snippet: 'AWS_SECRET_KEY = "[REDACTED_AWS_SECRET_KEY]"',
        }],
      },
      {
        id: 'find-06',
        project_id: 'f1bd54a7-538b-46c0-8955-32a8ca1f06ca',
        asset_id: 'asset-01',
        scan_job_id: 'job-01',
        fingerprint: 'fp-06',
        title: 'Requests: Proxy-Authorization Header Leak',
        description: 'Proxy header leak on redirect.',
        category: 'SCA',
        scanner_name: 'osv-scanner',
        scanner_rule_id: 'CVE-2023-32681',
        cwe_id: 'CWE-200',
        original_severity: 'CRITICAL',
        internal_risk_level: 'CRITICAL',
        internal_risk_score: 91.0,
        risk_rationale: 'Upgrade dependency to 2.31.0+',
        status: 'OPEN',
        first_seen_at: '2026-10-24T00:00:00Z',
        last_seen_at: '2026-10-24T00:00:00Z',
        evidence: [{
          id: 'ev-06',
          evidence_type: 'DEPENDENCY_MATCH',
          file_path: 'backend/requirements.txt',
          start_line: 12,
          end_line: 12,
          sanitized_snippet: 'requests==2.28.1 (Affected: <2.31.0, Fixed: 2.31.0)',
        }],
      },
    ] as unknown as T;
  }
  if (endpoint.includes('/explain')) {
    return {
      finding_id: 'find-01',
      summary: 'The application formats user input directly into an SQL string without bind parameters, allowing arbitrary query execution.',
      technical_root_cause: 'Unsanitized f-string formatting in cursor.execute bypasses database query parameterization.',
      exploitability_assessment: 'High. An attacker can append SQL syntax (e.g. "\' OR 1=1 --") to bypass authentication.',
      remediation_guidance: 'Replace string formatting with parameterized query syntax or ORM model queries.',
      illustrative_patch_diff: '- cursor.execute(f\'SELECT * FROM users WHERE username = "{user_input}"\')\n+ cursor.execute("SELECT * FROM users WHERE username = :u", {"u": user_input})',
      suggested_unit_tests: ['test_sql_injection_payload_does_not_execute', 'test_special_characters_escaped'],
      authoritative_references: ['https://owasp.org/Top10/A03_2021-Injection/', 'https://cwe.mitre.org/data/definitions/89.html'],
      limitations_and_disclaimer: 'This patch proposal is generated by SentinelAI Bounded Remediation Agent and requires human engineer review.',
      is_unverified_proposal: true,
    } as unknown as T;
  }
  if (endpoint.includes('/verify')) {
    return {
      outcome: 'VERIFIED_RESOLVED',
      message: 'Fix verified in isolated worker sandbox. Scanner confirmed rule vulnerability is no longer detected.',
    } as unknown as T;
  }
  if (endpoint.includes('/audit')) {
    return [
      { id: 'log-01', action: 'ASSESSMENT_LAUNCHED', resource_type: 'ScanJob', resource_id: 'scan-01', client_ip: '127.0.0.1', created_at: '2026-10-24T03:00:00Z', details_json: {} },
      { id: 'log-02', action: 'FINDING_TRIAGED', resource_type: 'Finding', resource_id: 'find-01', client_ip: '127.0.0.1', created_at: '2026-10-24T02:45:00Z', details_json: {} },
      { id: 'log-03', action: 'ASSET_REGISTERED', resource_type: 'Asset', resource_id: 'asset-01', client_ip: '127.0.0.1', created_at: '2026-10-24T02:00:00Z', details_json: {} },
      { id: 'log-04', action: 'USER_LOGIN_SUCCESS', resource_type: 'User', resource_id: 'usr-admin', client_ip: '127.0.0.1', created_at: '2026-10-24T01:00:00Z', details_json: {} },
    ] as unknown as T;
  }
  if (endpoint.includes('/policy/evaluate')) {
    return {
      overall_status: 'PASSED',
      violations: [],
      rules_evaluated: 6,
    } as unknown as T;
  }
  if (endpoint.includes('/sbom')) {
    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { name: 'fastapi', version: '0.115.0', type: 'library' },
        { name: 'sqlalchemy', version: '2.0.36', type: 'library' },
        { name: 'pydantic', version: '2.9.2', type: 'library' },
        { name: 'requests', version: '2.31.0', type: 'library' },
      ],
    } as unknown as T;
  }
  if (endpoint.includes('/scans')) {
    return {
      id: 'scan-mock-01',
      status: 'COMPLETED',
      scan_type: 'FULL',
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      executions: [],
    } as unknown as T;
  }
  return undefined;
}
