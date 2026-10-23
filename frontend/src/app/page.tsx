'use client';

import React, { useState, useEffect, useRef } from 'react';
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
  Server,
  Plus,
  X,
  FolderPlus,
  Home as HomeIcon,
  Search,
  Bell,
  ChevronDown,
  Headphones,
  Target,
  Zap,
  BarChart3,
  Sliders,
  Check,
  Copy,
  Info,
  GitBranch,
  Radio,
  FileCode,
  CheckSquare
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
  
  // Search & Global filter
  const [searchQuery, setSearchQuery] = useState('');
  const searchInputRef = useRef<HTMLInputElement>(null);

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

  // Asset Registration State
  const [showAddAssetModal, setShowAddAssetModal] = useState(false);
  const [newAssetName, setNewAssetName] = useState('');
  const [newAssetType, setNewAssetType] = useState<'REPOSITORY' | 'WEB_APPLICATION' | 'API_ENDPOINT' | 'CONTAINER_IMAGE'>('REPOSITORY');
  const [newAssetLocator, setNewAssetLocator] = useState('');
  const [newAssetEnvironment, setNewAssetEnvironment] = useState<'PRODUCTION' | 'STAGING' | 'DEVELOPMENT'>('PRODUCTION');
  const [newAssetCriticality, setNewAssetCriticality] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('HIGH');
  const [newAssetExposure, setNewAssetExposure] = useState<'INTERNET_FACING' | 'INTERNAL' | 'RESTRICTED'>('INTERNET_FACING');
  const [isSubmittingAsset, setIsSubmittingAsset] = useState(false);

  // Filter state
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  // Keyboard shortcut for Cmd/Ctrl+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

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
      quickLogin('admin@sentinelai.io', 'AdminPass123!');
    }
  };

  const quickLogin = async (email: string, pass: string) => {
    try {
      await apiClient.login(email, pass);
      const user = await apiClient.getMe();
      setCurrentUser(user);
      showToast(`Signed in as ${user.full_name} (${user.role})`);
      loadProjectData();
    } catch (e: any) {
      showToast(`Login failed: ${e.message}`);
    }
  };

  const loadProjectData = async () => {
    try {
      const projs = await apiClient.getProjects();
      setProjects(projs);
      if (projs.length > 0) {
        setSelectedProject(projs[0]);
        await refreshProjectDetails(projs[0].id);
      }
    } catch (e: any) {
      showToast(`Failed loading projects: ${e.message}`);
    }
  };

  const refreshProjectDetails = async (projectId: string) => {
    try {
      const [ass, fnd, logs] = await Promise.all([
        apiClient.getAssets(projectId),
        apiClient.getFindings(projectId),
        apiClient.getAuditLogs(),
      ]);
      setAssets(ass);
      setFindings(fnd);
      setAuditLogs(logs);
      if (ass.length > 0 && !selectedAssetId) {
        setSelectedAssetId(ass[0].id);
      }
    } catch (e: any) {
      console.error(e);
    }
  };

  const triggerScan = async (assetIdOverride?: string, scanTypeOverride?: string) => {
    const targetAssetId = assetIdOverride || selectedAssetId;
    const targetScanType = scanTypeOverride || scanType;
    if (!selectedProject || !targetAssetId) {
      showToast('Please select a target asset first');
      return;
    }
    setIsScanning(true);
    showToast(`Launching ${targetScanType} Security Assessment...`);
    try {
      const job = await apiClient.triggerScan(selectedProject.id, targetAssetId, targetScanType);
      await refreshProjectDetails(selectedProject.id);
      showToast(`Assessment finished with status: ${job.status}`);
    } catch (e: any) {
      showToast(`Scan failed: ${e.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectFinding = async (finding: Finding) => {
    setSelectedFinding(finding);
    setAiExplanation(null);
    setVerificationOutcome(null);
  };

  const handleTriageFinding = async (findingId: string, status: any) => {
    if (!statusRationale.trim()) {
      showToast('A security rationale is required for triage state transitions.');
      return;
    }
    try {
      const updated = await apiClient.updateFindingStatus(findingId, status, statusRationale);
      setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
      if (selectedFinding?.id === updated.id) {
        setSelectedFinding(updated);
      }
      showToast(`Finding status changed to ${status}. Recorded in audit trail.`);
      setStatusRationale('');
      if (selectedProject) {
        const logs = await apiClient.getAuditLogs();
        setAuditLogs(logs);
      }
    } catch (e: any) {
      showToast(`Triage update failed: ${e.message}`);
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
      const scanRes = await apiClient.triggerScan(selectedProject.id, finding.asset_id, finding.category === 'SAST' ? 'SAST' : 'FULL');
      const verRes = await apiClient.verifyFindingFix(finding.id, scanRes.id);
      setVerificationOutcome(verRes);
      await refreshProjectDetails(selectedProject.id);
      showToast(`Fix Verification Complete: ${verRes.outcome}`);
    } catch (e: any) {
      showToast(`Fix verification failed: ${e.message}`);
    } finally {
      setIsVerifyingFix(false);
    }
  };

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProject) return;
    if (!newAssetName.trim() || !newAssetLocator.trim()) {
      showToast('Asset name and target locator are required.');
      return;
    }

    setIsSubmittingAsset(true);
    try {
      const asset = await apiClient.createAsset(selectedProject.id, {
        name: newAssetName.trim(),
        asset_type: newAssetType,
        target_locator: newAssetLocator.trim(),
        environment: newAssetEnvironment,
        business_criticality: newAssetCriticality,
        exposure: newAssetExposure,
      });

      if (newAssetType === 'WEB_APPLICATION') {
        const domain = newAssetLocator.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
        const nextQuarter = new Date();
        nextQuarter.setDate(nextQuarter.getDate() + 90);
        await apiClient.authorizeAsset(asset.id, {
          scope_description: `Initial automated authorization for ${asset.name}`,
          allowed_domains: domain,
          expires_at: nextQuarter.toISOString(),
        }).catch(() => null);
      }

      await refreshProjectDetails(selectedProject.id);
      showToast(`Registered application '${asset.name}' under security scope.`);
      setShowAddAssetModal(false);
      setNewAssetName('');
      setNewAssetLocator('');
    } catch (err: any) {
      showToast(`Failed to register asset: ${err.message}`);
    } finally {
      setIsSubmittingAsset(false);
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
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchCwe = f.cwe_id?.toLowerCase().includes(q);
      const matchCat = f.category.toLowerCase().includes(q);
      const matchRule = f.scanner_rule_id?.toLowerCase().includes(q);
      return matchTitle || matchCwe || matchCat || matchRule;
    }
    return true;
  });

  return (
    <div className="min-h-screen flex bg-[#F8F6F0] text-[#1E252B] selection:bg-[#0D6E48]/20 selection:text-[#0D6E48]">
      {/* Toast Alert */}
      {toastMessage && (
        <div className="fixed top-5 right-5 z-50 clay-card px-4 py-3 border border-[#0D6E48]/30 flex items-center space-x-3 text-xs font-semibold shadow-2xl animate-bounce">
          <span className="w-2.5 h-2.5 rounded-full bg-[#0D6E48]"></span>
          <span className="text-[#1E252B]">{toastMessage}</span>
        </div>
      )}

      {/* LEFT NAVIGATION SIDEBAR */}
      <aside className="w-64 shrink-0 bg-[#FAF8F3] border-r border-[#EAE4D8] flex flex-col justify-between py-6 px-4 select-none min-h-screen sticky top-0 h-screen overflow-y-auto">
        <div className="space-y-6">
          {/* Brand Logo */}
          <div className="flex items-center space-x-3 px-2">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#DFC07B] to-[#B38728] flex items-center justify-center shadow-md shadow-[#C59A45]/20">
              <Shield className="w-5 h-5 text-white fill-white/20 stroke-[2.2]" />
            </div>
            <div>
              <span className="font-serif-luxury text-xl font-bold tracking-tight text-[#1E252B]">SENTINELAI</span>
              <span className="ml-1 text-[10px] font-mono font-bold bg-[#E6F4EA] text-[#0D6E48] px-1.5 py-0.5 rounded">v1.0</span>
            </div>
          </div>

          {/* Main Navigation */}
          <nav className="space-y-1">
            <button
              onClick={() => setActiveTab('overview')}
              className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-2xl text-xs font-semibold transition ${
                activeTab === 'overview'
                  ? 'bg-[#E6F4EA] text-[#0D6E48] shadow-sm'
                  : 'text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8]'
              }`}
            >
              <HomeIcon className={`w-4 h-4 ${activeTab === 'overview' ? 'text-[#0D6E48]' : 'text-[#8C96A6]'}`} />
              <span>Home</span>
            </button>

            <button
              onClick={() => setActiveTab('scans')}
              className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-2xl text-xs font-semibold transition ${
                activeTab === 'scans'
                  ? 'bg-[#E6F4EA] text-[#0D6E48] shadow-sm'
                  : 'text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8]'
              }`}
            >
              <Terminal className={`w-4 h-4 ${activeTab === 'scans' ? 'text-[#0D6E48]' : 'text-[#8C96A6]'}`} />
              <span>Scan Orchestrator</span>
            </button>

            <button
              onClick={() => setActiveTab('policy')}
              className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-2xl text-xs font-semibold transition ${
                activeTab === 'policy'
                  ? 'bg-[#E6F4EA] text-[#0D6E48] shadow-sm'
                  : 'text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8]'
              }`}
            >
              <ShieldCheck className={`w-4 h-4 ${activeTab === 'policy' ? 'text-[#0D6E48]' : 'text-[#8C96A6]'}`} />
              <span>Policy Gates & SBOM</span>
            </button>

            <button
              onClick={() => setActiveTab('reports')}
              className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-2xl text-xs font-semibold transition ${
                activeTab === 'reports'
                  ? 'bg-[#E6F4EA] text-[#0D6E48] shadow-sm'
                  : 'text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8]'
              }`}
            >
              <FileText className={`w-4 h-4 ${activeTab === 'reports' ? 'text-[#0D6E48]' : 'text-[#8C96A6]'}`} />
              <span>Reports & Exports</span>
            </button>

            <button
              onClick={() => setActiveTab('audit')}
              className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-2xl text-xs font-semibold transition ${
                activeTab === 'audit'
                  ? 'bg-[#E6F4EA] text-[#0D6E48] shadow-sm'
                  : 'text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8]'
              }`}
            >
              <Key className={`w-4 h-4 ${activeTab === 'audit' ? 'text-[#0D6E48]' : 'text-[#8C96A6]'}`} />
              <span>Audit Trail</span>
            </button>

            <button
              onClick={() => setActiveTab('findings')}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-2xl text-xs font-semibold transition ${
                activeTab === 'findings'
                  ? 'bg-[#E6F4EA] text-[#0D6E48] shadow-sm'
                  : 'text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8]'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Bug className={`w-4 h-4 ${activeTab === 'findings' ? 'text-[#0D6E48]' : 'text-[#8C96A6]'}`} />
                <span>Vulnerabilities</span>
              </div>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#FAF0E6] text-[#A57424]">
                {findings.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('assets')}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-2xl text-xs font-semibold transition ${
                activeTab === 'assets'
                  ? 'bg-[#E6F4EA] text-[#0D6E48] shadow-sm'
                  : 'text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8]'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Layers className={`w-4 h-4 ${activeTab === 'assets' ? 'text-[#0D6E48]' : 'text-[#8C96A6]'}`} />
                <span>Assets & Scope</span>
              </div>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#EBF3FC] text-[#2563EB]">
                {assets.length}
              </span>
            </button>
          </nav>

          {/* Quick Access Section */}
          <div className="pt-4 border-t border-[#EAE4D8]/80 space-y-2">
            <div className="px-3 text-[11px] font-semibold text-[#8C96A6] uppercase tracking-wider">
              Quick Access
            </div>
            
            <button
              onClick={() => {
                setActiveTab('scans');
                triggerScan();
              }}
              className="w-full flex items-center space-x-3 px-3.5 py-2 rounded-xl text-xs text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8] transition text-left"
            >
              <Zap className="w-4 h-4 text-[#A57424]" />
              <span>New Scan</span>
            </button>

            <button
              onClick={() => setShowAddAssetModal(true)}
              className="w-full flex items-center space-x-3 px-3.5 py-2 rounded-xl text-xs text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8] transition text-left"
            >
              <FolderPlus className="w-4 h-4 text-[#0D6E48]" />
              <span>Register Application</span>
            </button>

            <button
              onClick={() => setActiveTab('reports')}
              className="w-full flex items-center space-x-3 px-3.5 py-2 rounded-xl text-xs text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8] transition text-left"
            >
              <BarChart3 className="w-4 h-4 text-[#2563EB]" />
              <span>View Reports</span>
            </button>

            <button
              onClick={() => showToast('Tenant settings configured: Nexus Enterprise Services (Tenant ID: 00000000-0000-0000-0000-000000000001)')}
              className="w-full flex items-center space-x-3 px-3.5 py-2 rounded-xl text-xs text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2EFE8] transition text-left"
            >
              <Sliders className="w-4 h-4 text-[#8C96A6]" />
              <span>Settings</span>
            </button>
          </div>
        </div>

        {/* Bottom Sidebar Card */}
        <div className="clay-card-warm p-4 rounded-2xl space-y-2 border border-[#E6E0D2] shadow-sm">
          <div className="w-7 h-7 rounded-lg bg-[#FAF0E6] flex items-center justify-center">
            <Shield className="w-4 h-4 text-[#C59A45]" />
          </div>
          <div className="text-xs font-semibold text-[#1E252B] leading-tight">
            Smarter Security.<br />Safer Tomorrow.
          </div>
          <div className="w-8 h-0.5 bg-[#C59A45] rounded-full"></div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* TOP HEADER */}
        <header className="h-16 px-6 bg-[#FAF8F3]/90 backdrop-blur-md border-b border-[#EAE4D8] flex items-center justify-between sticky top-0 z-30">
          {/* Search Bar with ⌘ K */}
          <div className="flex items-center space-x-2">
            <div className="relative">
              <Search className="w-4 h-4 text-[#8C96A6] absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                ref={searchInputRef}
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search vulnerabilities, CWEs, rules..."
                className="pl-9 pr-14 py-1.5 w-80 text-xs bg-white border border-[#E0D9CB] rounded-full focus:outline-none focus:border-[#0D6E48] focus:ring-1 focus:ring-[#0D6E48] transition shadow-sm text-[#1E252B] placeholder:text-[#8C96A6]"
              />
              <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] font-mono bg-[#F2ECE0] text-[#5A6578] px-1.5 py-0.5 rounded border border-[#DFD7C7]">
                ⌘ K
              </kbd>
            </div>
          </div>

          {/* Right Header Controls */}
          <div className="flex items-center space-x-4">
            {/* Quick Role Switcher */}
            <div className="hidden md:flex items-center space-x-1 bg-[#F0ECE1] p-1 rounded-full text-xs font-medium border border-[#E2DBD0]">
              <span className="text-[#8C96A6] px-2 text-[11px] font-semibold">Role:</span>
              <button
                onClick={() => quickLogin('admin@sentinelai.io', 'AdminPass123!')}
                className={`px-3 py-1 rounded-full transition text-[11px] ${
                  currentUser?.role === 'SECURITY_ADMIN'
                    ? 'bg-[#0D6E48] text-white font-bold shadow-sm'
                    : 'text-[#5A6578] hover:text-[#1E252B]'
                }`}
              >
                SecAdmin
              </button>
              <button
                onClick={() => quickLogin('engineer@sentinelai.io', 'DevPass123!')}
                className={`px-3 py-1 rounded-full transition text-[11px] ${
                  currentUser?.role === 'ENGINEER'
                    ? 'bg-[#0D6E48] text-white font-bold shadow-sm'
                    : 'text-[#5A6578] hover:text-[#1E252B]'
                }`}
              >
                Engineer
              </button>
              <button
                onClick={() => quickLogin('auditor@sentinelai.io', 'AuditPass123!')}
                className={`px-3 py-1 rounded-full transition text-[11px] ${
                  currentUser?.role === 'AUDITOR'
                    ? 'bg-[#0D6E48] text-white font-bold shadow-sm'
                    : 'text-[#5A6578] hover:text-[#1E252B]'
                }`}
              >
                Auditor
              </button>
            </div>

            {/* Notification Bell */}
            <button
              onClick={() => showToast('Security notifications: All scanner adapters verified operational.')}
              className="relative p-2 rounded-full text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F0ECE1] transition"
              title="Notifications"
            >
              <Bell className="w-4 h-4" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[#C59A45]"></span>
            </button>

            {/* User Profile Pill */}
            {currentUser && (
              <div className="flex items-center space-x-2 pl-2 border-l border-[#EAE4D8]">
                <div className="w-8 h-8 rounded-full bg-[#FAF0E6] border border-[#E6D8C3] flex items-center justify-center font-bold text-xs text-[#A57424]">
                  {currentUser.full_name
                    .split(' ')
                    .map((n) => n[0])
                    .join('')
                    .slice(0, 2)
                    .toUpperCase()}
                </div>
                <div className="hidden lg:block text-left text-xs">
                  <div className="font-semibold text-[#1E252B] leading-tight">{currentUser.full_name}</div>
                  <div className="text-[10px] text-[#8C96A6] font-medium">{currentUser.role}</div>
                </div>
                <button
                  onClick={() => {
                    apiClient.clearToken();
                    setCurrentUser(null);
                    showToast('Signed out');
                  }}
                  className="p-1 text-[#8C96A6] hover:text-[#DC2626] transition"
                  title="Sign Out"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        </header>

        {/* Trust & Boundary Banner */}
        <div className="bg-[#FAF6EC] border-b border-[#ECE4D4] px-6 py-2 text-[11px] text-[#5A6578] flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-[#0D6E48] animate-pulse"></span>
            <span className="font-semibold text-[#1E252B]">EVIDENCE-DRIVEN SECURITY WORKSPACE:</span>
            <span>Deterministic Scanners (Semgrep, Gitleaks, OSV, ZAP) &middot; Zero Manufactured Evidence</span>
          </div>
          <div className="font-mono text-[11px] text-[#8C96A6]">
            Tenant: {selectedProject?.name || 'Nexus Enterprise Services'}
          </div>
        </div>

        {/* WORKSPACE CONTENT BODY */}
        <main className="max-w-7xl mx-auto px-6 py-8 flex-1 w-full space-y-8">
          
          {/* TAB 1: OVERVIEW & HERO */}
          {activeTab === 'overview' && (
            <div className="space-y-8">
              {/* HERO SECTION */}
              <div className="relative clay-card-warm p-8 md:p-10 rounded-3xl overflow-hidden border border-[#E6E0D2] shadow-sm">
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
                  {/* Hero Left Copy */}
                  <div className="lg:col-span-7 space-y-5 z-10">
                    <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-[#FAF0E6] border border-[#E8DAC2] text-[#A57424] text-xs font-semibold">
                      <Shield className="w-3.5 h-3.5" />
                      <span>AI-POWERED APPLICATION SECURITY</span>
                    </div>

                    <h1 className="font-serif-luxury text-4xl sm:text-5xl font-extrabold tracking-tight leading-[1.15]">
                      <span className="text-[#1E252B] block">Find Vulnerabilities</span>
                      <span className="text-[#A57424] block">Before Attackers Do.</span>
                    </h1>

                    <p className="text-sm text-[#5A6578] max-w-xl leading-relaxed">
                      SentinelAI combines the power of AI with advanced security analysis to scan, detect and fix vulnerabilities in your applications — automatically.
                    </p>

                    <div className="flex items-center space-x-4 pt-2">
                      <button
                        onClick={() => {
                          setActiveTab('scans');
                          triggerScan();
                        }}
                        className="btn-emerald px-6 py-3 text-xs flex items-center space-x-2"
                      >
                        <span>Start Free Assessment</span>
                        <ArrowRight className="w-4 h-4 stroke-[2.5]" />
                      </button>

                      <button
                        onClick={() => setShowAddAssetModal(true)}
                        className="btn-clay px-5 py-3 text-xs font-semibold flex items-center space-x-2"
                      >
                        <Plus className="w-4 h-4" />
                        <span>Register Target</span>
                      </button>
                    </div>
                  </div>

                  {/* Hero Right 3D Visual Art (from Image 1) */}
                  <div className="lg:col-span-5 flex justify-center items-center relative">
                    <div className="relative rounded-2xl overflow-hidden shadow-2xl border border-white/80 bg-gradient-to-b from-white/60 to-white/20 p-1">
                      <img
                        src="/hero-shield-art.png"
                        alt="SentinelAI 3D Shield Security Pedestal"
                        className="w-full max-w-md h-auto rounded-xl object-cover"
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* 4 KPI METRIC CARDS (Image 1 Style) */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
                {/* 10K+ Applications Scanned */}
                <div className="clay-card p-5 rounded-2xl space-y-2 border border-[#E8E2D5]">
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-xl bg-[#E6F4EA] flex items-center justify-center">
                      <Shield className="w-5 h-5 text-[#0D6E48]" />
                    </div>
                    <span className="text-xs font-bold text-[#0D6E48] bg-[#E6F4EA] px-2 py-0.5 rounded-full">
                      ↑ 12%
                    </span>
                  </div>
                  <div>
                    <div className="text-2xl font-extrabold text-[#1E252B]">10K+</div>
                    <div className="text-xs text-[#5A6578] font-medium">Applications Scanned</div>
                  </div>
                </div>

                {/* 99.9% Threat Detection Accuracy */}
                <div className="clay-card p-5 rounded-2xl space-y-2 border border-[#E8E2D5]">
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-xl bg-[#FAF0E6] flex items-center justify-center">
                      <Target className="w-5 h-5 text-[#A57424]" />
                    </div>
                    <span className="text-xs font-bold text-[#0D6E48] bg-[#E6F4EA] px-2 py-0.5 rounded-full">
                      ↑ 5%
                    </span>
                  </div>
                  <div>
                    <div className="text-2xl font-extrabold text-[#1E252B]">99.9%</div>
                    <div className="text-xs text-[#5A6578] font-medium">Threat Detection Accuracy</div>
                  </div>
                </div>

                {/* 5+ Security Frameworks */}
                <div className="clay-card p-5 rounded-2xl space-y-2 border border-[#E8E2D5]">
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-xl bg-[#EBF3FC] flex items-center justify-center">
                      <Layers className="w-5 h-5 text-[#2563EB]" />
                    </div>
                    <span className="text-xs font-bold text-[#0D6E48] bg-[#E6F4EA] px-2 py-0.5 rounded-full">
                      ↑ 2%
                    </span>
                  </div>
                  <div>
                    <div className="text-2xl font-extrabold text-[#1E252B]">5+</div>
                    <div className="text-xs text-[#5A6578] font-medium">Security Frameworks</div>
                  </div>
                </div>

                {/* 24/7 Monitoring & Support */}
                <div className="clay-card p-5 rounded-2xl space-y-2 border border-[#E8E2D5]">
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-xl bg-[#F5EEFB] flex items-center justify-center">
                      <Headphones className="w-5 h-5 text-[#8B5CF6]" />
                    </div>
                    <span className="text-xs font-bold text-[#5A6578] bg-[#F2ECE0] px-2 py-0.5 rounded-full">
                      ↑ 0%
                    </span>
                  </div>
                  <div>
                    <div className="text-2xl font-extrabold text-[#1E252B]">24/7</div>
                    <div className="text-xs text-[#5A6578] font-medium">Monitoring & Support</div>
                  </div>
                </div>
              </div>

              {/* LIVE SECURITY RISK POSTURE STRIP */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="clay-card p-4 rounded-xl border border-red-500/20 bg-red-500/[0.02]">
                  <div className="text-[11px] text-red-600 font-bold uppercase tracking-wider">Critical Risk</div>
                  <div className="text-3xl font-extrabold text-[#1E252B] mt-1">{criticalCount}</div>
                  <div className="text-[11px] text-red-500 mt-1 font-medium">Requires immediate triage</div>
                </div>
                <div className="clay-card p-4 rounded-xl border border-orange-500/20 bg-orange-500/[0.02]">
                  <div className="text-[11px] text-orange-600 font-bold uppercase tracking-wider">High Risk</div>
                  <div className="text-3xl font-extrabold text-[#1E252B] mt-1">{highCount}</div>
                  <div className="text-[11px] text-[#5A6578] mt-1">SLA target: 48h resolution</div>
                </div>
                <div className="clay-card p-4 rounded-xl border border-[#E8E2D5]">
                  <div className="text-[11px] text-[#5A6578] font-bold uppercase tracking-wider">Scoped Assets</div>
                  <div className="text-3xl font-extrabold text-[#1E252B] mt-1">{assets.length}</div>
                  <div className="text-[11px] text-[#0D6E48] mt-1 font-semibold">100% Target Authorized</div>
                </div>
                <div className="clay-card p-4 rounded-xl border border-[#E8E2D5]">
                  <div className="text-[11px] text-[#5A6578] font-bold uppercase tracking-wider">Policy Gate</div>
                  <div className="text-3xl font-extrabold text-[#0D6E48] mt-1">
                    {policyResult ? policyResult.overall_status : 'AUDITED'}
                  </div>
                  <div className="text-[11px] text-[#5A6578] mt-1">OWASP &middot; PCI-DSS &middot; SOC 2</div>
                </div>
              </div>

              {/* ASSESSMENT EXECUTION PIPELINE SECTION (Image 1 Style) */}
              <div className="clay-card p-6 rounded-3xl space-y-6 border border-[#E8E2D5]">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#EAE4D8] pb-5">
                  <div className="flex items-center space-x-3">
                    <div className="w-9 h-9 rounded-xl bg-[#FAF0E6] flex items-center justify-center">
                      <Shield className="w-5 h-5 text-[#A57424]" />
                    </div>
                    <div>
                      <h2 className="font-serif-luxury text-xl font-bold text-[#1E252B]">
                        Assessment Execution Pipeline
                      </h2>
                      <p className="text-xs text-[#5A6578]">
                        Orchestrate isolated scanner workers and review execution metadata.
                      </p>
                    </div>
                  </div>

                  {/* Sub-tab pills */}
                  <div className="flex items-center space-x-1.5 overflow-x-auto text-xs font-semibold">
                    <button
                      onClick={() => setActiveTab('scans')}
                      className="px-4 py-2 rounded-full bg-[#0D6E48] text-white shadow-sm transition"
                    >
                      Scan Orchestrator
                    </button>
                    <button
                      onClick={() => setActiveTab('policy')}
                      className="px-4 py-2 rounded-full text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2ECE0] transition"
                    >
                      Policy Gates & SBOM
                    </button>
                    <button
                      onClick={() => setActiveTab('reports')}
                      className="px-4 py-2 rounded-full text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2ECE0] transition"
                    >
                      Reports & Exports
                    </button>
                    <button
                      onClick={() => setActiveTab('audit')}
                      className="px-4 py-2 rounded-full text-[#5A6578] hover:text-[#1E252B] hover:bg-[#F2ECE0] transition"
                    >
                      Audit Trail
                    </button>
                  </div>
                </div>

                {/* 5 Scanner Adapter Cards (Image 1 Style) */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {/* Semgrep SAST */}
                  <div className="clay-card-flat p-4 rounded-2xl border border-[#EAE4D8] hover:border-[#0D6E48]/30 transition group flex flex-col justify-between">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="w-10 h-10 rounded-xl bg-[#E6F4EA] flex items-center justify-center">
                          <Cpu className="w-5 h-5 text-[#0D6E48]" />
                        </div>
                        <div className="flex items-center space-x-1.5 text-[11px] font-semibold text-[#0D6E48]">
                          <span className="w-2 h-2 rounded-full bg-[#0D6E48]"></span>
                          <span>Adapter Ready</span>
                        </div>
                      </div>
                      <div>
                        <div className="font-bold text-sm text-[#1E252B]">Semgrep SAST</div>
                        <p className="text-[11px] text-[#5A6578] mt-0.5">
                          Argument array execution &middot; Zero shell injection &middot; Timeout bounded
                        </p>
                      </div>
                    </div>
                    <div className="pt-3 border-t border-[#F0ECE1] flex items-center justify-end">
                      <button
                        onClick={() => {
                          setActiveTab('scans');
                          setScanType('SAST');
                        }}
                        className="w-7 h-7 rounded-full bg-[#F2ECE0] group-hover:bg-[#0D6E48] group-hover:text-white flex items-center justify-center transition"
                      >
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Gitleaks Secret Scanner */}
                  <div className="clay-card-flat p-4 rounded-2xl border border-[#EAE4D8] hover:border-[#8B5CF6]/30 transition group flex flex-col justify-between">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="w-10 h-10 rounded-xl bg-[#F5EEFB] flex items-center justify-center">
                          <Key className="w-5 h-5 text-[#8B5CF6]" />
                        </div>
                        <div className="flex items-center space-x-1.5 text-[11px] font-semibold text-[#0D6E48]">
                          <span className="w-2 h-2 rounded-full bg-[#0D6E48]"></span>
                          <span>Adapter Ready</span>
                        </div>
                      </div>
                      <div>
                        <div className="font-bold text-sm text-[#1E252B]">Gitleaks Secret Scanner</div>
                        <p className="text-[11px] text-[#5A6578] mt-0.5">
                          Argument array execution &middot; Zero shell injection &middot; Timeout bounded
                        </p>
                      </div>
                    </div>
                    <div className="pt-3 border-t border-[#F0ECE1] flex items-center justify-end">
                      <button
                        onClick={() => {
                          setActiveTab('scans');
                          setScanType('SECRET');
                        }}
                        className="w-7 h-7 rounded-full bg-[#F2ECE0] group-hover:bg-[#8B5CF6] group-hover:text-white flex items-center justify-center transition"
                      >
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* OSV-Scanner / pip-audit */}
                  <div className="clay-card-flat p-4 rounded-2xl border border-[#EAE4D8] hover:border-[#2563EB]/30 transition group flex flex-col justify-between">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="w-10 h-10 rounded-xl bg-[#EBF3FC] flex items-center justify-center">
                          <ShieldCheck className="w-5 h-5 text-[#2563EB]" />
                        </div>
                        <div className="flex items-center space-x-1.5 text-[11px] font-semibold text-[#0D6E48]">
                          <span className="w-2 h-2 rounded-full bg-[#0D6E48]"></span>
                          <span>Adapter Ready</span>
                        </div>
                      </div>
                      <div>
                        <div className="font-bold text-sm text-[#1E252B]">OSV-Scanner / pip-audit</div>
                        <p className="text-[11px] text-[#5A6578] mt-0.5">
                          Argument array execution &middot; Zero shell injection &middot; Timeout bounded
                        </p>
                      </div>
                    </div>
                    <div className="pt-3 border-t border-[#F0ECE1] flex items-center justify-end">
                      <button
                        onClick={() => {
                          setActiveTab('scans');
                          setScanType('SCA');
                        }}
                        className="w-7 h-7 rounded-full bg-[#F2ECE0] group-hover:bg-[#2563EB] group-hover:text-white flex items-center justify-center transition"
                      >
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* OWASP ZAP Dynamic */}
                  <div className="clay-card-flat p-4 rounded-2xl border border-[#EAE4D8] hover:border-[#A57424]/30 transition group flex flex-col justify-between">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="w-10 h-10 rounded-xl bg-[#FAF0E6] flex items-center justify-center">
                          <Zap className="w-5 h-5 text-[#A57424]" />
                        </div>
                        <div className="flex items-center space-x-1.5 text-[11px] font-semibold text-[#0D6E48]">
                          <span className="w-2 h-2 rounded-full bg-[#0D6E48]"></span>
                          <span>Adapter Ready</span>
                        </div>
                      </div>
                      <div>
                        <div className="font-bold text-sm text-[#1E252B]">OWASP ZAP Dynamic</div>
                        <p className="text-[11px] text-[#5A6578] mt-0.5">
                          Argument array execution &middot; Zero shell injection &middot; Timeout bounded
                        </p>
                      </div>
                    </div>
                    <div className="pt-3 border-t border-[#F0ECE1] flex items-center justify-end">
                      <button
                        onClick={() => {
                          setActiveTab('scans');
                          setScanType('DAST');
                        }}
                        className="w-7 h-7 rounded-full bg-[#F2ECE0] group-hover:bg-[#A57424] group-hover:text-white flex items-center justify-center transition"
                      >
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Security Config & TLS */}
                  <div className="clay-card-flat p-4 rounded-2xl border border-[#EAE4D8] hover:border-[#0D6E48]/30 transition group flex flex-col justify-between">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="w-10 h-10 rounded-xl bg-[#E6F4EA] flex items-center justify-center">
                          <Lock className="w-5 h-5 text-[#0D6E48]" />
                        </div>
                        <div className="flex items-center space-x-1.5 text-[11px] font-semibold text-[#0D6E48]">
                          <span className="w-2 h-2 rounded-full bg-[#0D6E48]"></span>
                          <span>Adapter Ready</span>
                        </div>
                      </div>
                      <div>
                        <div className="font-bold text-sm text-[#1E252B]">Security Config & TLS</div>
                        <p className="text-[11px] text-[#5A6578] mt-0.5">
                          Argument array execution &middot; Zero shell injection &middot; Timeout bounded
                        </p>
                      </div>
                    </div>
                    <div className="pt-3 border-t border-[#F0ECE1] flex items-center justify-end">
                      <button
                        onClick={() => {
                          setActiveTab('scans');
                          setScanType('CONFIG');
                        }}
                        className="w-7 h-7 rounded-full bg-[#F2ECE0] group-hover:bg-[#0D6E48] group-hover:text-white flex items-center justify-center transition"
                      >
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: VULNERABILITIES */}
          {activeTab === 'findings' && (
            <div className="clay-card p-6 rounded-3xl space-y-6 border border-[#E8E2D5]">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="font-serif-luxury text-xl font-bold text-[#1E252B]">
                    Deterministic Vulnerability Catalog
                  </h2>
                  <p className="text-xs text-[#5A6578]">
                    Raw scanner findings contextualized by the deterministic Risk Scoring Engine.
                  </p>
                </div>

                {/* Filters */}
                <div className="flex items-center space-x-2 text-xs">
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="bg-white border border-[#E0D9CB] rounded-full px-3 py-1.5 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>

                  <select
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                    className="bg-white border border-[#E0D9CB] rounded-full px-3 py-1.5 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                  >
                    <option value="ALL">All Categories</option>
                    <option value="SAST">SAST</option>
                    <option value="DAST">DAST</option>
                    <option value="SCA">SCA</option>
                    <option value="SECRET">Secrets</option>
                  </select>
                </div>
              </div>

              {/* Table */}
              <div className="overflow-x-auto rounded-2xl border border-[#EAE4D8]">
                <table className="w-full text-left text-xs bg-white">
                  <thead>
                    <tr className="bg-[#FAF7F0] border-b border-[#EAE4D8] text-[#5A6578] font-semibold">
                      <th className="py-3 px-4">Risk Level</th>
                      <th className="py-3 px-4">Vulnerability Title</th>
                      <th className="py-3 px-4">Category</th>
                      <th className="py-3 px-4">CVSS / Score</th>
                      <th className="py-3 px-4">Triage Status</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#F0ECE1]">
                    {filteredFindings.map((finding) => (
                      <tr
                        key={finding.id}
                        className="hover:bg-[#FAF7F0] transition cursor-pointer"
                        onClick={() => handleSelectFinding(finding)}
                      >
                        <td className="py-3 px-4">
                          <span
                            className={`px-2.5 py-1 rounded-full text-[10px] font-bold ${
                              finding.internal_risk_level === 'CRITICAL'
                                ? 'bg-red-100 text-red-700 border border-red-200'
                                : finding.internal_risk_level === 'HIGH'
                                ? 'bg-orange-100 text-orange-700 border border-orange-200'
                                : finding.internal_risk_level === 'MEDIUM'
                                ? 'bg-amber-100 text-amber-800 border border-amber-200'
                                : 'bg-slate-100 text-slate-700 border border-slate-200'
                            }`}
                          >
                            {finding.internal_risk_level}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-semibold text-[#1E252B]">
                          <div className="flex items-center space-x-2">
                            <span>{finding.title}</span>
                            {finding.cwe_id && (
                              <span className="font-mono text-[10px] bg-[#FAF0E6] text-[#A57424] px-1.5 py-0.5 rounded">
                                {finding.cwe_id}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded-md text-[10px] font-medium bg-[#F2ECE0] text-[#5A6578]">
                            {finding.category}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono font-semibold text-[#1E252B]">
                          {(finding.internal_risk_score / 10).toFixed(1)} &middot; {Math.round(finding.internal_risk_score)}/100
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                              finding.status === 'OPEN' || finding.status === 'TRIAGED'
                                ? 'bg-red-100 text-red-700'
                                : finding.status === 'VERIFIED_RESOLVED'
                                ? 'bg-emerald-100 text-emerald-800'
                                : 'bg-slate-100 text-slate-700'
                            }`}
                          >
                            {finding.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleSelectFinding(finding);
                            }}
                            className="p-1 rounded-lg text-[#5A6578] hover:text-[#0D6E48] hover:bg-[#E6F4EA] transition"
                            title="Inspect Finding Details"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                    {filteredFindings.length === 0 && (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-[#8C96A6] italic">
                          No vulnerabilities found matching current filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: ASSETS & SCOPE */}
          {activeTab === 'assets' && (
            <div className="clay-card p-6 rounded-3xl space-y-6 border border-[#E8E2D5]">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="font-serif-luxury text-xl font-bold text-[#1E252B]">
                    Authorized Target Application Scope
                  </h2>
                  <p className="text-xs text-[#5A6578]">
                    Strict target authorization boundary. DAST/Network scanners require cryptographically verified scope.
                  </p>
                </div>
                <button
                  onClick={() => setShowAddAssetModal(true)}
                  className="btn-emerald px-4 py-2 text-xs flex items-center space-x-1.5 self-start"
                >
                  <FolderPlus className="w-4 h-4" />
                  <span>+ Register Application</span>
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {assets.map((asset) => (
                  <div key={asset.id} className="clay-card-flat p-5 rounded-2xl border border-[#EAE4D8] space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#FAF0E6] text-[#A57424] font-semibold">
                        {asset.asset_type}
                      </span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                          asset.business_criticality === 'CRITICAL'
                            ? 'bg-red-100 text-red-700'
                            : asset.business_criticality === 'HIGH'
                            ? 'bg-orange-100 text-orange-700'
                            : 'bg-emerald-100 text-emerald-700'
                        }`}
                      >
                        {asset.business_criticality}
                      </span>
                    </div>

                    <div>
                      <h3 className="font-bold text-sm text-[#1E252B]">{asset.name}</h3>
                      <div className="text-[11px] font-mono text-[#8C96A6] break-all mt-1">
                        {asset.target_locator}
                      </div>
                    </div>

                    <div className="flex items-center justify-between pt-2 border-t border-[#F0ECE1] text-[11px]">
                      <span className="text-[#5A6578]">Env: <strong className="text-[#1E252B]">{asset.environment}</strong></span>
                      <button
                        onClick={() => {
                          setSelectedAssetId(asset.id);
                          setActiveTab('scans');
                          triggerScan(asset.id, 'FULL');
                        }}
                        className="text-[#0D6E48] hover:underline font-bold flex items-center space-x-1"
                      >
                        <span>Launch Assessment</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: SCAN ORCHESTRATOR */}
          {activeTab === 'scans' && (
            <div className="clay-card p-6 rounded-3xl space-y-6 border border-[#E8E2D5]">
              <div>
                <h2 className="font-serif-luxury text-xl font-bold text-[#1E252B]">
                  Assessment Execution Pipeline
                </h2>
                <p className="text-xs text-[#5A6578]">
                  Deterministic scan executor running Semgrep SAST, Gitleaks secrets, OSV-Scanner, and OWASP ZAP.
                </p>
              </div>

              {/* Scan Trigger Form */}
              <div className="clay-card-warm p-5 rounded-2xl border border-[#E6E0D2] space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="text-xs font-semibold text-[#1E252B] block mb-1.5">
                      Target Scoped Asset
                    </label>
                    <select
                      value={selectedAssetId}
                      onChange={(e) => setSelectedAssetId(e.target.value)}
                      className="w-full bg-white border border-[#E0D9CB] rounded-xl px-3 py-2 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                    >
                      {assets.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name} ({a.asset_type})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-xs font-semibold text-[#1E252B] block mb-1.5">
                      Scan Profile & Engines
                    </label>
                    <select
                      value={scanType}
                      onChange={(e) => setScanType(e.target.value)}
                      className="w-full bg-white border border-[#E0D9CB] rounded-xl px-3 py-2 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                    >
                      <option value="FULL">FULL (SAST + Secrets + SCA + DAST)</option>
                      <option value="SAST">Static Code Analysis (Semgrep)</option>
                      <option value="SECRET">Secret Detection (Gitleaks)</option>
                      <option value="SCA">Open Source Vulnerabilities (OSV)</option>
                      <option value="DAST">Dynamic Penetration (OWASP ZAP)</option>
                      <option value="CONFIG">Security Config & TLS</option>
                    </select>
                  </div>

                  <div className="flex items-end">
                    <button
                      onClick={() => triggerScan()}
                      disabled={isScanning}
                      className="btn-emerald w-full py-2.5 text-xs flex items-center justify-center space-x-2 disabled:opacity-50"
                    >
                      {isScanning ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Executing Scanners...</span>
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4 fill-white" />
                          <span>Launch Assessment</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* Execution Console Terminal */}
              <div className="bg-[#1A202C] text-slate-100 p-5 rounded-2xl font-mono text-xs space-y-2 shadow-inner">
                <div className="flex items-center justify-between text-slate-400 border-b border-slate-700/60 pb-2 text-[11px]">
                  <div className="flex items-center space-x-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
                    <span className="font-semibold text-slate-200">Execution Worker Terminal</span>
                  </div>
                  <span>Worker PID: isolated_runner_worker_01</span>
                </div>
                <div className="space-y-1 pt-1 text-slate-300">
                  <p className="text-emerald-400">&gt; SentinelAI Deterministic Runner Ready.</p>
                  <p>&gt; Target Scanners: Semgrep 1.x &middot; Gitleaks 8.x &middot; OSV-Scanner &middot; OWASP ZAP.</p>
                  <p>&gt; Security Boundary: Direct argument array execution without shell interpolation.</p>
                  {isScanning && (
                    <p className="text-amber-400 animate-pulse">&gt; [RUNNING] Active scan pipeline in progress...</p>
                  )}
                  {!isScanning && (
                    <p className="text-slate-400">&gt; Standing by for assessment execution command.</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: POLICY GATES & SBOM */}
          {activeTab === 'policy' && (
            <div className="clay-card p-6 rounded-3xl space-y-6 border border-[#E8E2D5]">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="font-serif-luxury text-xl font-bold text-[#1E252B]">
                    Deterministic Build Gate & SBOM
                  </h2>
                  <p className="text-xs text-[#5A6578]">
                    Strict zero-tolerance release policies and CycloneDX 1.5 Software Bill of Materials.
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={handleGenerateSBOM}
                    disabled={isGeneratingSbom}
                    className="btn-clay px-4 py-2 text-xs font-semibold flex items-center space-x-1.5"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Generate CycloneDX SBOM</span>
                  </button>
                  <button
                    onClick={handleEvaluatePolicy}
                    disabled={isEvaluatingPolicy}
                    className="btn-emerald px-4 py-2 text-xs flex items-center space-x-1.5"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    <span>Evaluate Build Gate</span>
                  </button>
                </div>
              </div>

              {/* Policy Evaluation Result */}
              {policyResult && (
                <div
                  className={`p-5 rounded-2xl border ${
                    policyResult.overall_status === 'PASSED'
                      ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                      : 'bg-red-50 border-red-300 text-red-900'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {policyResult.overall_status === 'PASSED' ? (
                        <CheckCircle className="w-5 h-5 text-emerald-600" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-red-600" />
                      )}
                      <span className="font-bold text-sm">
                        Build Gate Result: {policyResult.overall_status}
                      </span>
                    </div>
                    <span className="text-xs font-mono">
                      Violations: {policyResult.violations.length}
                    </span>
                  </div>
                  {policyResult.violations.length > 0 && (
                    <ul className="mt-3 list-disc list-inside text-xs space-y-1">
                      {policyResult.violations.map((v: string, i: number) => (
                        <li key={i}>{v}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* CycloneDX SBOM Data preview */}
              {sbomData && (
                <div className="clay-card-flat p-4 rounded-2xl border border-[#EAE4D8] space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-[#1E252B]">
                      CycloneDX 1.5 JSON &middot; {sbomData.components?.length || 0} Components
                    </span>
                    <button
                      onClick={handleDownloadSBOM}
                      className="text-xs text-[#0D6E48] hover:underline font-bold"
                    >
                      Download JSON
                    </button>
                  </div>
                  <pre className="p-3 bg-[#FAF7F0] border border-[#EAE4D8] rounded-xl text-[11px] font-mono text-[#1E252B] max-h-48 overflow-y-auto">
                    {JSON.stringify(sbomData, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* TAB 6: REPORTS & EXPORTS */}
          {activeTab === 'reports' && (
            <div className="clay-card p-6 rounded-3xl space-y-6 border border-[#E8E2D5]">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="font-serif-luxury text-xl font-bold text-[#1E252B]">
                    Security Reports & Compliance Proof
                  </h2>
                  <p className="text-xs text-[#5A6578]">
                    Executive summaries, deterministic audit chains, and audit exports.
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleDownloadReport('PDF')}
                    className="btn-emerald px-4 py-2 text-xs flex items-center space-x-1.5"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download PDF Report</span>
                  </button>
                  <button
                    onClick={() => handleDownloadReport('JSON')}
                    className="btn-clay px-4 py-2 text-xs font-semibold flex items-center space-x-1.5"
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    <span>Export JSON Raw</span>
                  </button>
                </div>
              </div>

              <div className="clay-card-warm p-6 rounded-2xl border border-[#E6E0D2] space-y-4">
                <h3 className="font-bold text-sm text-[#1E252B]">Executive Security Snapshot</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                  <div>
                    <div className="text-[#8C96A6]">Project</div>
                    <div className="font-bold text-[#1E252B] mt-0.5">{selectedProject?.name}</div>
                  </div>
                  <div>
                    <div className="text-[#8C96A6]">Total Findings</div>
                    <div className="font-bold text-[#1E252B] mt-0.5">{findings.length}</div>
                  </div>
                  <div>
                    <div className="text-[#8C96A6]">Critical / High</div>
                    <div className="font-bold text-red-600 mt-0.5">{criticalCount} / {highCount}</div>
                  </div>
                  <div>
                    <div className="text-[#8C96A6]">Compliance Status</div>
                    <div className="font-bold text-[#0D6E48] mt-0.5">SOC 2 &middot; PCI-DSS Ready</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: AUDIT TRAIL */}
          {activeTab === 'audit' && (
            <div className="clay-card p-6 rounded-3xl space-y-6 border border-[#E8E2D5]">
              <div>
                <h2 className="font-serif-luxury text-xl font-bold text-[#1E252B]">
                  Immutable Platform Audit Trail
                </h2>
                <p className="text-xs text-[#5A6578]">
                  Chronological security-sensitive event log tracking logins, scan launches, risk updates, and triage decisions.
                </p>
              </div>

              <div className="overflow-x-auto rounded-2xl border border-[#EAE4D8]">
                <table className="w-full text-left text-xs bg-white">
                  <thead>
                    <tr className="bg-[#FAF7F0] border-b border-[#EAE4D8] text-[#5A6578] font-semibold">
                      <th className="py-3 px-4">Action</th>
                      <th className="py-3 px-4">Resource</th>
                      <th className="py-3 px-4">Client IP</th>
                      <th className="py-3 px-4">Timestamp (UTC)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#F0ECE1] font-mono text-[11px]">
                    {auditLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-[#FAF7F0] transition">
                        <td className="py-3 px-4 font-bold text-[#0D6E48]">{log.action}</td>
                        <td className="py-3 px-4 text-[#1E252B]">
                          {log.resource_type} ({log.resource_id ? log.resource_id.slice(0, 8) : 'N/A'})
                        </td>
                        <td className="py-3 px-4 text-[#5A6578]">{log.client_ip || '127.0.0.1'}</td>
                        <td className="py-3 px-4 text-[#8C96A6]">
                          {log.created_at.slice(0, 19).replace('T', ' ')}
                        </td>
                      </tr>
                    ))}
                    {auditLogs.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-[#8C96A6] italic font-sans text-xs">
                          No audit logs available for current session.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* MODAL: REGISTER ASSET / APPLICATION (Warm Ivory Claymorphic) */}
      {showAddAssetModal && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 animate-fade-in">
          <div className="clay-card bg-white border border-[#E8E2D5] rounded-3xl w-full max-w-lg shadow-2xl overflow-hidden space-y-4">
            <div className="flex items-center justify-between p-6 border-b border-[#EAE4D8] bg-[#FAF8F3]">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-[#FAF0E6] flex items-center justify-center">
                  <FolderPlus className="w-5 h-5 text-[#A57424]" />
                </div>
                <div>
                  <h3 className="font-serif-luxury font-bold text-[#1E252B] text-lg">
                    Register Application / Target
                  </h3>
                  <p className="text-xs text-[#5A6578]">
                    Add a new application into the authorized security assessment scope.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowAddAssetModal(false)}
                className="p-1.5 rounded-full text-[#8C96A6] hover:text-[#1E252B] hover:bg-[#F0ECE1] transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateAsset} className="p-6 space-y-4 text-xs">
              <div className="space-y-1">
                <label className="text-[#1E252B] font-semibold">Application / Asset Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Customer Portal Web App"
                  value={newAssetName}
                  onChange={(e) => setNewAssetName(e.target.value)}
                  className="w-full bg-[#FAF8F3] border border-[#E0D9CB] rounded-xl px-3.5 py-2 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[#1E252B] font-semibold">Asset Type</label>
                  <select
                    value={newAssetType}
                    onChange={(e) => setNewAssetType(e.target.value as any)}
                    className="w-full bg-[#FAF8F3] border border-[#E0D9CB] rounded-xl px-3.5 py-2 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                  >
                    <option value="REPOSITORY">Git Repository (SAST/SCA)</option>
                    <option value="WEB_APPLICATION">Web Application (DAST)</option>
                    <option value="API_ENDPOINT">API Spec / Endpoint (BOLA)</option>
                    <option value="CONTAINER_IMAGE">Container Image (OSS)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[#1E252B] font-semibold">Environment</label>
                  <select
                    value={newAssetEnvironment}
                    onChange={(e) => setNewAssetEnvironment(e.target.value as any)}
                    className="w-full bg-[#FAF8F3] border border-[#E0D9CB] rounded-xl px-3.5 py-2 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                  >
                    <option value="PRODUCTION">Production</option>
                    <option value="STAGING">Staging</option>
                    <option value="DEVELOPMENT">Development</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[#1E252B] font-semibold">Target Locator (URL, Git, or Docker)</label>
                <input
                  type="text"
                  required
                  placeholder="https://portal.internal.company.com"
                  value={newAssetLocator}
                  onChange={(e) => setNewAssetLocator(e.target.value)}
                  className="w-full bg-[#FAF8F3] border border-[#E0D9CB] rounded-xl px-3.5 py-2 text-xs font-mono text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[#1E252B] font-semibold">Criticality</label>
                  <select
                    value={newAssetCriticality}
                    onChange={(e) => setNewAssetCriticality(e.target.value as any)}
                    className="w-full bg-[#FAF8F3] border border-[#E0D9CB] rounded-xl px-3.5 py-2 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[#1E252B] font-semibold">Network Exposure</label>
                  <select
                    value={newAssetExposure}
                    onChange={(e) => setNewAssetExposure(e.target.value as any)}
                    className="w-full bg-[#FAF8F3] border border-[#E0D9CB] rounded-xl px-3.5 py-2 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                  >
                    <option value="INTERNET_FACING">Internet Facing</option>
                    <option value="INTERNAL">Internal Network</option>
                    <option value="RESTRICTED">Restricted Enclave</option>
                  </select>
                </div>
              </div>

              <div className="p-3 bg-[#FAF8F3] rounded-xl border border-[#E8E2D5] text-[11px] text-[#5A6578] flex items-center space-x-2">
                <input type="checkbox" id="authScope" required className="accent-[#0D6E48]" />
                <label htmlFor="authScope">
                  I authorize SentinelAI to conduct automated vulnerability assessments against this target.
                </label>
              </div>

              <div className="pt-4 border-t border-[#EAE4D8] flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowAddAssetModal(false)}
                  className="btn-clay px-4 py-2 text-xs font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingAsset}
                  className="btn-emerald px-5 py-2 text-xs flex items-center space-x-1.5"
                >
                  {isSubmittingAsset ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Registering...</span>
                    </>
                  ) : (
                    <>
                      <Plus className="w-3.5 h-3.5" />
                      <span>Register & Add to Scope</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: FINDING DETAILS & AI ADVISORY */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 animate-fade-in">
          <div className="clay-card bg-white border border-[#E8E2D5] rounded-3xl w-full max-w-3xl max-h-[90vh] shadow-2xl flex flex-col overflow-hidden">
            {/* Modal Header */}
            <div className="p-6 border-b border-[#EAE4D8] bg-[#FAF8F3] flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span
                  className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                    selectedFinding.internal_risk_level === 'CRITICAL'
                      ? 'bg-red-100 text-red-700'
                      : 'bg-orange-100 text-orange-700'
                  }`}
                >
                  {selectedFinding.internal_risk_level}
                </span>
                <div>
                  <h3 className="font-serif-luxury font-bold text-[#1E252B] text-lg">
                    {selectedFinding.title}
                  </h3>
                  <div className="flex items-center space-x-2 text-xs text-[#5A6578] font-mono mt-0.5">
                    <span>{selectedFinding.scanner_rule_id}</span>
                    {selectedFinding.cwe_id && <span>&middot; {selectedFinding.cwe_id}</span>}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1.5 rounded-full text-[#8C96A6] hover:text-[#1E252B] hover:bg-[#F0ECE1] transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Scrollable Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs text-[#1E252B]">
              {/* Evidence & Location */}
              <div className="clay-card-warm p-4 rounded-2xl border border-[#E6E0D2] space-y-2">
                <div className="font-bold text-[#1E252B] text-xs">Security Evidence & Code Location</div>
                <div className="font-mono text-[11px] text-[#5A6578]">
                  {selectedFinding.evidence?.[0]?.file_path || 'Repository root'}:{selectedFinding.evidence?.[0]?.start_line || 1}
                </div>
                {selectedFinding.evidence?.[0]?.sanitized_snippet && (
                  <pre className="p-3 bg-white border border-[#EAE4D8] rounded-xl font-mono text-[11px] overflow-x-auto text-red-800">
                    {selectedFinding.evidence[0].sanitized_snippet}
                  </pre>
                )}
              </div>

              {/* AI Advisory Section */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Sparkles className="w-4 h-4 text-[#A57424]" />
                    <span className="font-bold text-xs text-[#1E252B]">
                      AI Remediation Advisory (Human-Reviewed)
                    </span>
                  </div>
                  <button
                    onClick={() => handleRequestAIExplanation(selectedFinding)}
                    disabled={isAiLoading}
                    className="btn-clay px-3 py-1 text-xs font-semibold flex items-center space-x-1"
                  >
                    {isAiLoading ? (
                      <>
                        <RefreshCw className="w-3 h-3 animate-spin" />
                        <span>Generating...</span>
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-3 h-3 text-[#A57424]" />
                        <span>Request AI Guidance</span>
                      </>
                    )}
                  </button>
                </div>

                {aiExplanation && (
                  <div className="clay-card-flat p-4 rounded-2xl border border-[#0D6E48]/30 bg-[#F4F9F6] space-y-3 text-xs">
                    <div>
                      <strong className="text-[#0D6E48]">Plain Language Summary:</strong>
                      <p className="mt-1 text-[#1E252B]">{aiExplanation.summary}</p>
                    </div>
                    <div>
                      <strong className="text-[#0D6E48]">Deterministic Remediation:</strong>
                      <p className="mt-1 text-[#1E252B]">{aiExplanation.remediation_guidance}</p>
                    </div>
                    {aiExplanation.illustrative_patch_diff && (
                      <div>
                        <strong className="text-[#0D6E48]">Recommended Patch:</strong>
                        <pre className="mt-1 p-3 bg-white border border-[#0D6E48]/20 rounded-xl font-mono text-[11px] overflow-x-auto text-emerald-900">
                          {aiExplanation.illustrative_patch_diff}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Fix Verification Trigger */}
              <div className="clay-card-warm p-4 rounded-2xl border border-[#E6E0D2] space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <CheckSquare className="w-4 h-4 text-[#0D6E48]" />
                    <span className="font-bold text-xs text-[#1E252B]">Automated Fix Verification</span>
                  </div>
                  <button
                    onClick={() => handleVerifyFix(selectedFinding)}
                    disabled={isVerifyingFix}
                    className="btn-emerald px-4 py-1.5 text-xs flex items-center space-x-1"
                  >
                    {isVerifyingFix ? (
                      <>
                        <RefreshCw className="w-3 h-3 animate-spin" />
                        <span>Verifying in sandbox...</span>
                      </>
                    ) : (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Verify Fix</span>
                      </>
                    )}
                  </button>
                </div>
                {verificationOutcome && (
                  <div
                    className={`p-3 rounded-xl text-xs font-semibold ${
                      verificationOutcome.outcome === 'VERIFIED_FIXED'
                        ? 'bg-emerald-100 text-emerald-800'
                        : 'bg-red-100 text-red-800'
                    }`}
                  >
                    Outcome: {verificationOutcome.outcome} &middot; {verificationOutcome.message}
                  </div>
                )}
              </div>

              {/* Triage Form */}
              <div className="space-y-3 pt-2 border-t border-[#EAE4D8]">
                <div className="font-bold text-xs text-[#1E252B]">Triage State & Rationale</div>
                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    placeholder="Provide mandatory security rationale for audit log..."
                    value={statusRationale}
                    onChange={(e) => setStatusRationale(e.target.value)}
                    className="flex-1 bg-[#FAF8F3] border border-[#E0D9CB] rounded-xl px-3 py-2 text-xs text-[#1E252B] focus:outline-none focus:border-[#0D6E48]"
                  />
                  <button
                    onClick={() => handleTriageFinding(selectedFinding.id, 'VERIFIED_RESOLVED')}
                    className="btn-emerald px-4 py-2 text-xs"
                  >
                    Resolve
                  </button>
                  <button
                    onClick={() => handleTriageFinding(selectedFinding.id, 'FALSE_POSITIVE')}
                    className="btn-clay px-3 py-2 text-xs font-semibold"
                  >
                    False Positive
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
