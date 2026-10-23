'use client';

import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  Bug,
  Terminal,
  Cpu,
  FileText,
  CheckCircle,
  RefreshCw,
  Key,
  Globe,
  Layers,
  Eye,
  Download,
  LogOut,
  ArrowRight,
  Activity,
  Lock,
  Play,
  Sparkles,
  ChevronRight,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  Server
} from 'lucide-react';
import { apiClient, User, Project, Asset, Finding, ScanJob, AuditLog, AIExplanation } from '@/lib/api';

export default function SentinelConsole() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'assets' | 'scans' | 'reports' | 'audit' | 'policy'>('overview');
  
  // Data State
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  
  // Modals & Selections
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [aiExplanation, setAiExplanation] = useState<AIExplanation | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [statusRationale, setStatusRationale] = useState('');
  const [scanType, setScanType] = useState('FULL');
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Policy & SBOM State
  const [policyResult, setPolicyResult] = useState<any>(null);
  const [isEvaluatingPolicy, setIsEvaluatingPolicy] = useState(false);
  const [maxCritical, setMaxCritical] = useState<number>(0);
  const [maxHigh, setMaxHigh] = useState<number>(2);
  const [maxRiskScore, setMaxRiskScore] = useState<number>(60);
  const [allowSecrets, setAllowSecrets] = useState<boolean>(false);
  const [maxCvss, setMaxCvss] = useState<number>(8.5);
  const [enforceTls, setEnforceTls] = useState<boolean>(true);
  const [sbomData, setSbomData] = useState<any>(null);
  const [isGeneratingSbom, setIsGeneratingSbom] = useState(false);

  // Fix verification state
  const [isVerifyingFix, setIsVerifyingFix] = useState(false);
  const [verificationOutcome, setVerificationOutcome] = useState<any>(null);

  // Filter state
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  // Load session or initialize demo credentials
  useEffect(() => {
    initAuth();
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const initAuth = async () => {
    try {
      const user = await apiClient.getMe();
      setCurrentUser(user);
      loadProjectData();
    } catch {
      // Auto login as demo Security Admin
      quickLogin('admin@sentinelai.io', 'AdminPass123!');
    }
  };

  const quickLogin = async (email: string, pass: string) => {
    try {
      const res = await apiClient.login(email, pass);
      apiClient.setToken(res.access_token);
      const user = await apiClient.getMe();
      setCurrentUser(user);
      showToast(`Authenticated as ${user.full_name} (${user.role})`);
      loadProjectData();
    } catch (e: any) {
      showToast(`Authentication failed: ${e.message}`);
    }
  };

  const loadProjectData = async () => {
    try {
      const projs = await apiClient.getProjects();
      setProjects(projs);
      if (projs.length > 0) {
        const p = projs[0];
        setSelectedProject(p);
        refreshProjectDetails(p.id);
      }
    } catch (e: any) {
      console.error(e);
    }
  };

  const refreshProjectDetails = async (projectId: string) => {
    try {
      const [ass, fnd] = await Promise.all([
        apiClient.getAssets(projectId),
        apiClient.getFindings(projectId),
      ]);
      setAssets(ass);
      setFindings(fnd);
      if (ass.length > 0 && !selectedAssetId) {
        setSelectedAssetId(ass[0].id);
      }
      loadAudit();
    } catch (e: any) {
      console.error(e);
    }
  };

  const loadAudit = async () => {
    try {
      const logs = await apiClient.getAuditLogs();
      setAuditLogs(logs);
    } catch {
      // Non-admin may be denied audit access
    }
  };

  const handleTriggerScan = async () => {
    if (!selectedProject || !selectedAssetId) return;
    setIsScanning(true);
    try {
      await apiClient.triggerScan(selectedProject.id, selectedAssetId, scanType);
      showToast(`Scan job dispatched successfully (${scanType}). Findings updated.`);
      await refreshProjectDetails(selectedProject.id);
    } catch (e: any) {
      showToast(`Scan execution failed: ${e.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleUpdateStatus = async (findingId: string, newStatus: string) => {
    try {
      const updated = await apiClient.updateFindingStatus(
        findingId,
        newStatus,
        statusRationale || 'Updated by security analyst from dashboard'
      );
      setFindings((prev) => prev.map((f) => (f.id === findingId ? updated : f)));
      if (selectedFinding?.id === findingId) setSelectedFinding(updated);
      showToast(`Status updated to ${newStatus}`);
      setStatusRationale('');
    } catch (e: any) {
      showToast(`Failed updating status: ${e.message}`);
    }
  };

  const handleRecalculateRisk = async (findingId: string) => {
    try {
      await apiClient.recalculateRisk(findingId);
      if (selectedProject) await refreshProjectDetails(selectedProject.id);
      showToast('Risk score recalculated via Deterministic Engine v1.0.0');
    } catch (e: any) {
      showToast(`Risk recalculation failed: ${e.message}`);
    }
  };

  const handleRequestAIExplanation = async (finding: Finding) => {
    setIsAiLoading(true);
    setAiExplanation(null);
    try {
      const exp = await apiClient.getAIExplanation(finding.id);
      setAiExplanation(exp);
    } catch (e: any) {
      showToast(`AI Assistant unavailable: ${e.message}`);
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleDownloadReport = async (type: 'PDF' | 'JSON') => {
    if (!selectedProject) return;
    try {
      const res = await apiClient.generateReport(selectedProject.id, type);
      if (type === 'PDF') {
        window.open(apiClient.getReportDownloadUrl(res.id), '_blank');
      } else {
        const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sentinelai-report-${selectedProject.name.toLowerCase().replace(/\s+/g, '-')}.json`;
        a.click();
      }
      showToast(`${type} Compliance Report generated.`);
    } catch (e: any) {
      showToast(`Report generation failed: ${e.message}`);
    }
  };

  const handleEvaluatePolicy = async () => {
    if (!selectedProject) return;
    setIsEvaluatingPolicy(true);
    try {
      const payload = {
        max_critical_findings: maxCritical,
        max_high_findings: maxHigh,
        max_risk_score: maxRiskScore,
        allow_unresolved_secrets: allowSecrets,
        max_cvss_threshold: maxCvss,
        enforce_production_tls: enforceTls,
      };
      const res = await apiClient.evaluatePolicy(selectedProject.id, payload);
      setPolicyResult(res);
      showToast(`Build Gate Policy Evaluated: ${res.overall_status}`);
    } catch (e: any) {
      showToast(`Policy evaluation failed: ${e.message}`);
    } finally {
      setIsEvaluatingPolicy(false);
    }
  };

  const handleGenerateSBOM = async () => {
    if (!selectedProject) return;
    setIsGeneratingSbom(true);
    try {
      const res = await apiClient.getSBOM(selectedProject.id);
      setSbomData(res);
      showToast('CycloneDX 1.5 JSON SBOM Generated');
    } catch (e: any) {
      showToast(`SBOM generation failed: ${e.message}`);
    } finally {
      setIsGeneratingSbom(false);
    }
  };

  const handleDownloadSBOM = () => {
    if (!sbomData || !selectedProject) return;
    const blob = new Blob([JSON.stringify(sbomData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyclonedx-sbom-${selectedProject.name.toLowerCase().replace(/\s+/g, '-')}.json`;
    a.click();
    showToast('CycloneDX SBOM JSON downloaded');
  };

  const handleVerifyFix = async (finding: Finding) => {
    if (!selectedProject) return;
    setIsVerifyingFix(true);
    setVerificationOutcome(null);
    try {
      // 1. Run a fresh verification scan on the asset
      const scanRes = await apiClient.triggerScan(selectedProject.id, finding.asset_id, finding.category === 'SAST' ? 'SAST' : 'FULL');
      // 2. Call verifyFindingFix with the new scan ID
      const verRes = await apiClient.verifyFindingFix(finding.id, scanRes.id);
      setVerificationOutcome(verRes);
      // 3. Refresh project details
      await refreshProjectDetails(selectedProject.id);
      showToast(`Fix Verification Complete: ${verRes.outcome}`);
    } catch (e: any) {
      showToast(`Fix verification failed: ${e.message}`);
    } finally {
      setIsVerifyingFix(false);
    }
  };

  // Metrics computation
  const criticalCount = findings.filter((f) => f.internal_risk_level === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.internal_risk_level === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.internal_risk_level === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.internal_risk_level === 'LOW').length;

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.internal_risk_level !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
    return true;
  });

  return (
    <div className="min-h-screen bg-[#070A12] text-slate-100 flex flex-col">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1E293B] border border-amber-500/40 text-amber-200 px-4 py-3 rounded-lg shadow-xl flex items-center space-x-3 text-sm animate-fade-in">
          <Sparkles className="w-4 h-4 text-amber-400" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-[#0A0D18]/90 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-amber-500 to-amber-700 flex items-center justify-center shadow-lg shadow-amber-500/20">
              <Shield className="w-5 h-5 text-slate-950 stroke-[2.5]" />
            </div>
            <div>
              <span className="font-extrabold tracking-wider text-lg text-white">SENTINEL<span className="text-amber-400">AI</span></span>
              <span className="text-[10px] ml-2 px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono">v1.0.0</span>
            </div>
          </div>

          {/* Quick Demo Role Switcher */}
          <div className="hidden md:flex items-center space-x-2 text-xs bg-slate-900/90 border border-slate-800 rounded-lg p-1">
            <span className="text-slate-400 px-2 font-medium">Quick Role:</span>
            <button
              onClick={() => quickLogin('admin@sentinelai.io', 'AdminPass123!')}
              className={`px-2.5 py-1 rounded transition ${currentUser?.role === 'SECURITY_ADMIN' ? 'bg-amber-500 text-slate-950 font-semibold' : 'text-slate-300 hover:bg-slate-800'}`}
            >
              SecAdmin
            </button>
            <button
              onClick={() => quickLogin('engineer@sentinelai.io', 'DevPass123!')}
              className={`px-2.5 py-1 rounded transition ${currentUser?.role === 'ENGINEER' ? 'bg-amber-500 text-slate-950 font-semibold' : 'text-slate-300 hover:bg-slate-800'}`}
            >
              Engineer
            </button>
            <button
              onClick={() => quickLogin('auditor@sentinelai.io', 'AuditPass123!')}
              className={`px-2.5 py-1 rounded transition ${currentUser?.role === 'AUDITOR' ? 'bg-amber-500 text-slate-950 font-semibold' : 'text-slate-300 hover:bg-slate-800'}`}
            >
              Auditor
            </button>
          </div>

          <div className="flex items-center space-x-4 text-xs">
            {currentUser && (
              <div className="text-right">
                <div className="font-medium text-slate-200">{currentUser.full_name}</div>
                <div className="text-slate-400 text-[11px] font-mono">{currentUser.role}</div>
              </div>
            )}
            <button
              onClick={() => {
                apiClient.clearToken();
                setCurrentUser(null);
                showToast('Signed out');
              }}
              className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Mode & Trust Boundary Banner */}
      <div className="bg-amber-950/20 border-b border-amber-500/20 px-4 py-2 text-xs text-amber-300/90 flex items-center justify-between">
        <div className="max-w-7xl mx-auto w-full flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="font-semibold tracking-wide">EVIDENCE-DRIVEN SECURITY WORKSPACE:</span>
            <span>Deterministic Scanners (Semgrep, Gitleaks, OSV, ZAP) &middot; Zero Manufactured Evidence &middot; Multi-Tenant Isolated</span>
          </div>
          <div className="hidden sm:block font-mono text-[11px] text-amber-400/80">
            Tenant: {selectedProject?.name || 'Loading'}
          </div>
        </div>
      </div>

      {/* Main Workspace Layout */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full space-y-6">
        {/* Navigation Tabs */}
        <div className="flex items-center space-x-1 border-b border-slate-800 pb-1 text-sm overflow-x-auto">
          {[
            { id: 'overview', label: 'Security Dashboard', icon: Activity },
            { id: 'findings', label: `Vulnerabilities (${findings.length})`, icon: Bug },
            { id: 'assets', label: `Assets & Scope (${assets.length})`, icon: Layers },
            { id: 'scans', label: 'Scan Orchestrator', icon: Terminal },
            { id: 'policy', label: 'Policy Gates & SBOM', icon: ShieldCheck },
            { id: 'reports', label: 'Reports & Exports', icon: FileText },
            { id: 'audit', label: 'Audit Trail', icon: Key },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 px-4 py-2.5 rounded-t-lg font-medium transition whitespace-nowrap ${
                  isActive
                    ? 'bg-[#0F172A] text-amber-400 border-t-2 border-amber-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-amber-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* TAB 1: OVERVIEW DASHBOARD */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="glass-panel p-4 rounded-xl border border-red-500/20 ruby-glow">
                <div className="text-xs text-red-400 font-semibold uppercase tracking-wider">Critical Risk</div>
                <div className="text-3xl font-extrabold text-white mt-1">{criticalCount}</div>
                <div className="text-[11px] text-slate-400 mt-1">Requires immediate triage</div>
              </div>
              <div className="glass-panel p-4 rounded-xl border border-orange-500/20">
                <div className="text-xs text-orange-400 font-semibold uppercase tracking-wider">High Risk</div>
                <div className="text-3xl font-extrabold text-white mt-1">{highCount}</div>
                <div className="text-[11px] text-slate-400 mt-1">Priority remediation</div>
              </div>
              <div className="glass-panel p-4 rounded-xl border border-yellow-500/20">
                <div className="text-xs text-yellow-400 font-semibold uppercase tracking-wider">Medium Risk</div>
                <div className="text-3xl font-extrabold text-white mt-1">{mediumCount}</div>
                <div className="text-[11px] text-slate-400 mt-1">Scheduled sprint work</div>
              </div>
              <div className="glass-panel p-4 rounded-xl border border-blue-500/20">
                <div className="text-xs text-blue-400 font-semibold uppercase tracking-wider">Low / Info</div>
                <div className="text-3xl font-extrabold text-white mt-1">{lowCount}</div>
                <div className="text-[11px] text-slate-400 mt-1">Hardening observations</div>
              </div>
              <div className="glass-panel p-4 rounded-xl border border-emerald-500/20 emerald-glow">
                <div className="text-xs text-emerald-400 font-semibold uppercase tracking-wider">Scanned Assets</div>
                <div className="text-3xl font-extrabold text-white mt-1">{assets.length}</div>
                <div className="text-[11px] text-slate-400 mt-1">100% tenant coverage</div>
              </div>
            </div>

            {/* Platform Status & Quick Action */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 cols: Recent Findings */}
              <div className="lg:col-span-2 glass-panel p-5 rounded-xl space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <h3 className="font-semibold text-white flex items-center space-x-2">
                    <ShieldAlert className="w-5 h-5 text-amber-400" />
                    <span>Prioritized Findings (Deterministic Risk Score)</span>
                  </h3>
                  <button
                    onClick={() => setActiveTab('findings')}
                    className="text-xs text-amber-400 hover:underline flex items-center space-x-1"
                  >
                    <span>View all</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-3">
                  {findings.slice(0, 4).map((f) => (
                    <div
                      key={f.id}
                      onClick={() => {
                        setSelectedFinding(f);
                        setActiveTab('findings');
                      }}
                      className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:border-amber-500/40 cursor-pointer transition flex items-center justify-between"
                    >
                      <div className="space-y-1 pr-4">
                        <div className="flex items-center space-x-2">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                            f.internal_risk_level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                            f.internal_risk_level === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                            'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                          }`}>
                            {f.internal_risk_level} &middot; Score {f.internal_risk_score}
                          </span>
                          <span className="text-[11px] text-slate-400 font-mono">{f.scanner_name}</span>
                          <span className="text-[11px] text-slate-500 font-mono">{f.cwe_id || f.scanner_rule_id}</span>
                        </div>
                        <div className="text-sm font-medium text-slate-100 line-clamp-1">{f.title}</div>
                      </div>
                      <button className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded transition whitespace-nowrap">
                        Inspect
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right Col: Quick Assessment Dispatch */}
              <div className="glass-panel p-5 rounded-xl space-y-4">
                <h3 className="font-semibold text-white flex items-center space-x-2 border-b border-slate-800 pb-3">
                  <Play className="w-5 h-5 text-emerald-400" />
                  <span>Launch Security Assessment</span>
                </h3>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1 font-medium">Target Asset</label>
                    <select
                      value={selectedAssetId}
                      onChange={(e) => setSelectedAssetId(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-slate-200"
                    >
                      {assets.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name} ({a.asset_type})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1 font-medium">Scanner Profile</label>
                    <select
                      value={scanType}
                      onChange={(e) => setScanType(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-slate-200"
                    >
                      <option value="FULL">Full Assessment (SAST, SCA, Secret, Config)</option>
                      <option value="SAST">Static Application Security (Semgrep)</option>
                      <option value="SECRET">Secret Exposure (Gitleaks)</option>
                      <option value="SCA">Software Composition (OSV-Scanner)</option>
                      <option value="DAST">Dynamic Web Assessment (OWASP ZAP)</option>
                      <option value="CONFIG">HTTP Headers & TLS Hardening</option>
                    </select>
                  </div>

                  <div className="pt-2">
                    <button
                      onClick={handleTriggerScan}
                      disabled={isScanning}
                      className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold transition flex items-center justify-center space-x-2 disabled:opacity-50"
                    >
                      {isScanning ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Executing Scanners...</span>
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="w-4 h-4" />
                          <span>Run Assessment</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400 bg-slate-900/60 p-3 rounded-lg border border-slate-800 leading-relaxed">
                  🛡️ <b>Strict Scope Enforcement:</b> Web/DAST assessment requires an active AssetAuthorizationRecord and enforces socket-level SSRF defense.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: VULNERABILITY FINDINGS LIST & DETAIL */}
        {activeTab === 'findings' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Findings List (7 cols) */}
            <div className="lg:col-span-7 space-y-4">
              {/* Filter controls */}
              <div className="glass-panel p-3 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center space-x-2">
                  <span className="text-slate-400 font-medium">Risk:</span>
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
                    <button
                      key={lvl}
                      onClick={() => setSeverityFilter(lvl)}
                      className={`px-2.5 py-1 rounded font-medium transition ${
                        severityFilter === lvl ? 'bg-amber-500 text-slate-950 font-bold' : 'text-slate-400 hover:bg-slate-800'
                      }`}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>

                <div className="flex items-center space-x-2">
                  <span className="text-slate-400 font-medium">Type:</span>
                  <select
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                    className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-300"
                  >
                    <option value="ALL">All Categories</option>
                    <option value="SAST">SAST</option>
                    <option value="SECRET">Secret</option>
                    <option value="SCA">SCA</option>
                    <option value="DAST">DAST</option>
                    <option value="CONFIG">Config</option>
                  </select>
                </div>
              </div>

              {/* Findings Cards */}
              <div className="space-y-3">
                {filteredFindings.map((f) => {
                  const isSelected = selectedFinding?.id === f.id;
                  return (
                    <div
                      key={f.id}
                      onClick={() => {
                        setSelectedFinding(f);
                        setAiExplanation(null);
                      }}
                      className={`glass-panel p-4 rounded-xl cursor-pointer transition space-y-2 border ${
                        isSelected ? 'border-amber-400 bg-slate-900/90' : 'border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          f.internal_risk_level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                          f.internal_risk_level === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                          'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        }`}>
                          {f.internal_risk_level} &middot; Score {f.internal_risk_score}
                        </span>

                        <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                          {f.status}
                        </span>
                      </div>

                      <div className="font-semibold text-slate-100 text-sm">{f.title}</div>
                      <div className="text-xs text-slate-400 line-clamp-2">{f.description}</div>

                      <div className="flex items-center space-x-3 text-[11px] text-slate-500 pt-1 font-mono">
                        <span>Scanner: {f.scanner_name}</span>
                        <span>Rule: {f.scanner_rule_id}</span>
                        {f.cwe_id && <span>CWE: {f.cwe_id}</span>}
                      </div>
                    </div>
                  );
                })}

                {filteredFindings.length === 0 && (
                  <div className="glass-panel p-8 rounded-xl text-center text-slate-400 text-sm">
                    No findings match the selected filter criteria.
                  </div>
                )}
              </div>
            </div>

            {/* Finding Detail & Evidence Drawer (5 cols) */}
            <div className="lg:col-span-5">
              {selectedFinding ? (
                <div className="glass-panel p-5 rounded-xl space-y-5 sticky top-24">
                  <div className="border-b border-slate-800 pb-3 flex items-start justify-between">
                    <div>
                      <div className="text-xs text-amber-400 font-mono font-medium">Finding Inspector</div>
                      <h3 className="font-bold text-white text-base mt-1">{selectedFinding.title}</h3>
                    </div>
                    <span className="text-xs font-mono px-2 py-1 rounded bg-slate-800 text-slate-300">
                      {selectedFinding.category}
                    </span>
                  </div>

                  {/* Evidence Viewer */}
                  <div className="space-y-2">
                    <div className="text-xs text-slate-300 font-semibold flex items-center justify-between">
                      <span>Sanitized Evidence Provenance</span>
                      {selectedFinding.evidence[0]?.file_path && (
                        <span className="font-mono text-[11px] text-slate-400">
                          {selectedFinding.evidence[0].file_path}
                        </span>
                      )}
                    </div>
                    {selectedFinding.evidence.length > 0 ? (
                      <div className="bg-[#050811] p-3 rounded-lg border border-slate-800 font-mono text-xs text-emerald-300/90 overflow-x-auto whitespace-pre">
                        {selectedFinding.evidence[0].sanitized_snippet}
                      </div>
                    ) : (
                      <div className="text-xs text-slate-500 italic">No code snippet attached.</div>
                    )}
                  </div>

                  {/* Deterministic Risk Breakdown */}
                  <div className="space-y-1.5 bg-slate-900/60 p-3 rounded-lg border border-slate-800/80 text-xs">
                    <div className="font-semibold text-slate-200 flex items-center justify-between">
                      <span>Deterministic Risk Formula</span>
                      <button
                        onClick={() => handleRecalculateRisk(selectedFinding.id)}
                        className="text-amber-400 hover:underline text-[11px] flex items-center space-x-1"
                      >
                        <RefreshCw className="w-3 h-3" />
                        <span>Recalculate</span>
                      </button>
                    </div>
                    <div className="text-slate-400 text-[11px] leading-relaxed">
                      {selectedFinding.risk_rationale}
                    </div>
                  </div>

                  {/* Status Triage Controls */}
                  <div className="space-y-2 pt-2 border-t border-slate-800">
                    <div className="text-xs text-slate-300 font-semibold">Triage & Workflow Transition</div>
                    <div className="flex flex-wrap gap-2 text-xs">
                      {['TRIAGED', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'REMEDIATION_IN_PROGRESS', 'VERIFIED_RESOLVED'].map((st) => (
                        <button
                          key={st}
                          onClick={() => handleUpdateStatus(selectedFinding.id, st)}
                          className={`px-2.5 py-1 rounded transition border ${
                            selectedFinding.status === st
                              ? 'bg-amber-500/20 border-amber-400 text-amber-300 font-semibold'
                              : 'bg-slate-800/80 border-slate-700 text-slate-300 hover:bg-slate-700'
                          }`}
                        >
                          {st.replace(/_/g, ' ')}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* AI Remediation Assistant Action */}
                  <div className="pt-2 border-t border-slate-800">
                    <button
                      onClick={() => handleRequestAIExplanation(selectedFinding)}
                      disabled={isAiLoading}
                      className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-semibold text-xs transition flex items-center justify-center space-x-2 shadow-lg shadow-purple-500/20 disabled:opacity-50"
                    >
                      <Sparkles className="w-4 h-4 text-purple-200" />
                      <span>{isAiLoading ? 'Analyzing Evidence...' : 'Generate AI Remediation Patch'}</span>
                    </button>
                  </div>

                  {/* AI Output Card */}
                  {aiExplanation && (
                    <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 text-xs space-y-3 animate-fade-in">
                      <div className="flex items-center space-x-2 text-purple-300 font-semibold">
                        <Sparkles className="w-4 h-4" />
                        <span>AI Remediation Assistant (Grounded Proposal)</span>
                      </div>
                      <div className="text-slate-300 leading-relaxed">{aiExplanation.summary}</div>
                      
                      {aiExplanation.illustrative_patch_diff && (
                        <div>
                          <div className="text-slate-400 font-medium mb-1">Illustrative Patch Diff (Untrusted Proposal):</div>
                          <pre className="bg-[#050811] p-2.5 rounded border border-purple-500/20 text-emerald-400 overflow-x-auto text-[11px]">
                            {aiExplanation.illustrative_patch_diff}
                          </pre>
                        </div>
                      )}

                      <div className="text-[10px] text-purple-300/70 italic border-t border-purple-500/20 pt-2">
                        {aiExplanation.limitations_and_disclaimer}
                      </div>
                    </div>
                  )}

                  {/* Automated Fix Verification Agent Action */}
                  <div className="pt-2 border-t border-slate-800 space-y-2">
                    <button
                      onClick={() => handleVerifyFix(selectedFinding)}
                      disabled={isVerifyingFix}
                      className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-xs transition flex items-center justify-center space-x-2 shadow-lg shadow-emerald-500/20 disabled:opacity-50"
                    >
                      <CheckCircle className="w-4 h-4 text-emerald-200" />
                      <span>{isVerifyingFix ? 'Re-scanning & Verifying Fix...' : 'Verify Fix via Automated Re-Scan'}</span>
                    </button>

                    {verificationOutcome && (
                      <div className={`p-3 rounded-lg border text-xs space-y-1.5 animate-fade-in ${
                        verificationOutcome.outcome === 'VERIFIED_RESOLVED'
                          ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                          : 'bg-red-950/30 border-red-500/40 text-red-300'
                      }`}>
                        <div className="font-bold flex items-center justify-between">
                          <span>Verification Outcome: {verificationOutcome.outcome}</span>
                          <span className="text-[10px] font-mono text-slate-400">{verificationOutcome.verified_at?.slice(0, 19).replace('T', ' ')}</span>
                        </div>
                        <p className="text-[11px] text-slate-300">{verificationOutcome.comparison_notes}</p>
                        <div className="text-[10px] text-slate-400 font-mono">
                          Status Transition: &rarr; <b>{verificationOutcome.new_finding_status}</b>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="glass-panel p-8 rounded-xl text-center text-slate-400 text-sm">
                  Select a vulnerability from the list to view evidence, inspect risk calculation, or request AI remediation guidance.
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: ASSETS & SCOPE AUTHORIZATION */}
        {activeTab === 'assets' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold text-white">Registered Application Assets</h3>
                <p className="text-xs text-slate-400">Inventory of repositories, web applications, containers, and APIs under security scope.</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {assets.map((a) => (
                <div key={a.id} className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="text-xs text-amber-400 font-mono">{a.asset_type}</div>
                      <h4 className="font-bold text-white text-base mt-0.5">{a.name}</h4>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      {a.environment}
                    </span>
                  </div>

                  <div className="text-xs text-slate-300 font-mono bg-slate-900/80 p-2 rounded border border-slate-800 truncate">
                    {a.target_locator}
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/80">
                    <span>Criticality: <b className="text-slate-200">{a.business_criticality}</b></span>
                    <span>Exposure: <b className="text-slate-200">{a.exposure}</b></span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 4: SCAN ORCHESTRATOR */}
        {activeTab === 'scans' && (
          <div className="glass-panel p-6 rounded-xl space-y-6">
            <div>
              <h3 className="text-lg font-bold text-white">Assessment Execution Pipeline</h3>
              <p className="text-xs text-slate-400">Orchestrate isolated scanner workers and review execution metadata.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {['Semgrep SAST', 'Gitleaks Secret Scanner', 'OSV-Scanner / pip-audit', 'OWASP ZAP Dynamic', 'Security Config & TLS'].map((scanner) => (
                <div key={scanner} className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-emerald-400 text-xs font-semibold">
                    <CheckCircle className="w-4 h-4" />
                    <span>Adapter Ready</span>
                  </div>
                  <div className="font-bold text-white text-sm">{scanner}</div>
                  <div className="text-[11px] text-slate-400">Argument array execution &middot; Zero shell injection &middot; Timeout bounded</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB: POLICY-AS-CODE BUILD GATES & CYCLONEDX SBOM */}
        {activeTab === 'policy' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold text-white">Policy-as-Code Build Gates & CycloneDX SBOM</h3>
                <p className="text-xs text-slate-400">Evaluate deterministic CI/CD release policies and generate standard CycloneDX 1.5 Software Bill of Materials.</p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Build Gate Policy Config & Evaluator (7 cols) */}
              <div className="lg:col-span-7 glass-panel p-6 rounded-xl space-y-5 border border-slate-800">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <ShieldCheck className="w-5 h-5 text-amber-400" />
                    <span className="font-bold text-white text-base">CI/CD Build Gate Policy Engine</span>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    Engine v1.0.0
                  </span>
                </div>

                {/* Form Controls */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div className="space-y-1">
                    <label className="text-slate-300 font-medium">Max Critical Findings Permitted</label>
                    <input
                      type="number"
                      min={0}
                      value={maxCritical}
                      onChange={(e) => setMaxCritical(parseInt(e.target.value) || 0)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-amber-400 outline-none"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-slate-300 font-medium">Max High Findings Permitted</label>
                    <input
                      type="number"
                      min={0}
                      value={maxHigh}
                      onChange={(e) => setMaxHigh(parseInt(e.target.value) || 0)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-amber-400 outline-none"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-slate-300 font-medium">Max Overall Risk Score Ceiling (0-100)</label>
                    <input
                      type="number"
                      min={0}
                      max={100}
                      value={maxRiskScore}
                      onChange={(e) => setMaxRiskScore(parseFloat(e.target.value) || 0)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-amber-400 outline-none"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-slate-300 font-medium">Maximum Single CVSS Threshold</label>
                    <input
                      type="number"
                      step={0.1}
                      min={0}
                      max={10}
                      value={maxCvss}
                      onChange={(e) => setMaxCvss(parseFloat(e.target.value) || 0)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-amber-400 outline-none"
                    />
                  </div>

                  <div className="flex items-center space-x-3 pt-2">
                    <input
                      type="checkbox"
                      id="allowSec"
                      checked={allowSecrets}
                      onChange={(e) => setAllowSecrets(e.target.checked)}
                      className="rounded border-slate-800 text-amber-500 focus:ring-0"
                    />
                    <label htmlFor="allowSec" className="text-slate-300 cursor-pointer">
                      Permit unresolved secrets (Default: False)
                    </label>
                  </div>

                  <div className="flex items-center space-x-3 pt-2">
                    <input
                      type="checkbox"
                      id="enforceTls"
                      checked={enforceTls}
                      onChange={(e) => setEnforceTls(e.target.checked)}
                      className="rounded border-slate-800 text-amber-500 focus:ring-0"
                    />
                    <label htmlFor="enforceTls" className="text-slate-300 cursor-pointer">
                      Enforce TLS on Public Assets
                    </label>
                  </div>
                </div>

                <button
                  onClick={handleEvaluatePolicy}
                  disabled={isEvaluatingPolicy}
                  className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold text-xs transition flex items-center justify-center space-x-2 shadow-lg shadow-amber-500/20 disabled:opacity-50"
                >
                  {isEvaluatingPolicy ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Evaluating Security Gate Rules...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      <span>Evaluate Build Gate Policy</span>
                    </>
                  )}
                </button>

                {/* Evaluation Results */}
                {policyResult && (
                  <div className="space-y-4 pt-3 border-t border-slate-800 animate-fade-in">
                    <div className={`p-4 rounded-xl border flex items-center justify-between ${
                      policyResult.overall_status === 'PASSED'
                        ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                        : policyResult.overall_status === 'WARNING'
                        ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                        : 'bg-red-950/20 border-red-500/40 text-red-300'
                    }`}>
                      <div className="flex items-center space-x-3">
                        {policyResult.overall_status === 'PASSED' ? (
                          <ShieldCheck className="w-7 h-7 text-emerald-400" />
                        ) : (
                          <ShieldAlert className="w-7 h-7 text-red-400" />
                        )}
                        <div>
                          <div className="font-extrabold text-base tracking-wide">
                            POLICY GATE: {policyResult.overall_status}
                          </div>
                          <div className="text-xs text-slate-300">{policyResult.summary}</div>
                        </div>
                      </div>
                      <div className="text-right text-xs font-mono">
                        <div>Blocking: <b className="text-white">{policyResult.blocking_findings_count}</b></div>
                        <div className="text-slate-400 text-[10px]">Evaluated: {policyResult.total_active_findings} findings</div>
                      </div>
                    </div>

                    {/* Rules list */}
                    <div className="space-y-2">
                      <div className="text-xs font-bold text-slate-300 uppercase tracking-wider">Policy Rules Evaluation</div>
                      <div className="space-y-1.5">
                        {policyResult.rule_results?.map((r: any) => (
                          <div key={r.rule_id} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between text-xs">
                            <div className="space-y-0.5">
                              <div className="font-semibold text-slate-200">{r.title}</div>
                              <div className="text-[11px] text-slate-400">{r.message}</div>
                            </div>
                            <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                              r.status === 'PASS'
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                : r.status === 'WARN'
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                : 'bg-red-500/10 text-red-400 border border-red-500/20'
                            }`}>
                              {r.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* CycloneDX SBOM Generator & Preview (5 cols) */}
              <div className="lg:col-span-5 glass-panel p-6 rounded-xl space-y-5 border border-slate-800">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <Layers className="w-5 h-5 text-emerald-400" />
                    <span className="font-bold text-white text-base">CycloneDX 1.5 SBOM</span>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Standard Spec
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  Generate industry-standard Software Bill of Materials (SBOM) cataloging software components, container dependencies, licenses, and mapped vulnerability advisories.
                </p>

                <div className="flex space-x-3">
                  <button
                    onClick={handleGenerateSBOM}
                    disabled={isGeneratingSbom}
                    className="flex-1 py-2 px-3 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded-lg transition flex items-center justify-center space-x-2 shadow-lg shadow-emerald-600/20 disabled:opacity-50"
                  >
                    {isGeneratingSbom ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Generating SBOM...</span>
                      </>
                    ) : (
                      <>
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Generate SBOM</span>
                      </>
                    )}
                  </button>

                  {sbomData && (
                    <button
                      onClick={handleDownloadSBOM}
                      className="py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs rounded-lg transition flex items-center space-x-2 border border-slate-700"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download JSON</span>
                    </button>
                  )}
                </div>

                {sbomData ? (
                  <div className="space-y-3 pt-2">
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                        <div className="text-slate-400 text-[11px]">Components</div>
                        <div className="text-xl font-bold text-white mt-0.5">{sbomData.components?.length || 0}</div>
                      </div>
                      <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                        <div className="text-slate-400 text-[11px]">Vulnerabilities</div>
                        <div className="text-xl font-bold text-amber-400 mt-0.5">{sbomData.vulnerabilities?.length || 0}</div>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="text-[11px] text-slate-400 font-mono">CycloneDX Schema Preview:</div>
                      <pre className="bg-[#050811] p-3 rounded-lg border border-slate-800 text-[10px] text-slate-300 font-mono max-h-64 overflow-y-auto">
                        {JSON.stringify(sbomData, null, 2)}
                      </pre>
                    </div>
                  </div>
                ) : (
                  <div className="p-8 rounded-xl bg-slate-900/40 border border-slate-800/80 text-center text-slate-500 text-xs">
                    Click 'Generate SBOM' to produce the CycloneDX 1.5 bill of materials for {selectedProject?.name || 'this project'}.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: REPORTS & COMPLIANCE */}
        {activeTab === 'reports' && (
          <div className="glass-panel p-6 rounded-xl space-y-6">
            <div>
              <h3 className="text-lg font-bold text-white">Compliance & Executive Reporting</h3>
              <p className="text-xs text-slate-400">Generate reproducible, evidence-grounded PDF and JSON reports for engineering reviews and auditors.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
                <FileText className="w-8 h-8 text-amber-400" />
                <h4 className="font-bold text-white text-base">Executive PDF Report</h4>
                <p className="text-xs text-slate-400">Complete formal audit report including methodology, scanner versions, risk breakdown, and sanitized evidence.</p>
                <button
                  onClick={() => handleDownloadReport('PDF')}
                  className="px-4 py-2 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs rounded-lg transition flex items-center space-x-2"
                >
                  <Download className="w-4 h-4" />
                  <span>Download PDF Report</span>
                </button>
              </div>

              <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
                <Terminal className="w-8 h-8 text-emerald-400" />
                <h4 className="font-bold text-white text-base">Machine-Readable JSON</h4>
                <p className="text-xs text-slate-400">Structured JSON export containing canonical findings, CWE mappings, CVSS scores, and evidence provenance.</p>
                <button
                  onClick={() => handleDownloadReport('JSON')}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs rounded-lg transition flex items-center space-x-2 border border-slate-700"
                >
                  <Download className="w-4 h-4" />
                  <span>Download JSON Export</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 6: AUDIT TRAIL */}
        {activeTab === 'audit' && (
          <div className="glass-panel p-6 rounded-xl space-y-4">
            <div>
              <h3 className="text-lg font-bold text-white">Immutable Platform Audit Trail</h3>
              <p className="text-xs text-slate-400">Chronological security-sensitive event log tracking logins, scan launches, risk updates, and triage decisions.</p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3">Action</th>
                    <th className="py-2.5 px-3">Resource</th>
                    <th className="py-2.5 px-3">Client IP</th>
                    <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 text-amber-400 font-semibold">{log.action}</td>
                      <td className="py-2.5 px-3 text-slate-300">{log.resource_type} ({log.resource_id ? log.resource_id.slice(0, 8) : 'N/A'})</td>
                      <td className="py-2.5 px-3 text-slate-400">{log.client_ip || '127.0.0.1'}</td>
                      <td className="py-2.5 px-3 text-slate-500">{log.created_at.slice(0, 19).replace('T', ' ')}</td>
                    </tr>
                  ))}
                  {auditLogs.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-6 text-center text-slate-500 italic">
                        No audit logs available for current session or role.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-[#06080F] py-4 text-center text-xs text-slate-500">
        SentinelAI &middot; Evidence-Driven Multi-Agent Application Security Intelligence Platform &middot; Confidential
      </footer>
    </div>
  );
}
