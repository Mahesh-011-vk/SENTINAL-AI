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
  }
};
