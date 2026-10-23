"""
SentinelAI Command-Line Interface (CLI).
Provides direct terminal access and CI/CD pipeline automation for:
- Evaluating Policy-as-Code build gates (exit code 0 on pass, 1 on fail)
- Exporting CycloneDX 1.5 Software Bill of Materials (SBOM)
- Triggering orchestrated scanner assessments
- Listing and inspecting active security findings
"""
import sys
import json
import argparse
from typing import Optional

from app.database import SessionLocal
from app.models.project import Project
from app.models.asset import Asset
from app.models.scan import ScanType, ScanStatus
from app.scanners.manager import ScannerManager
from app.services.policy_engine import PolicyEngine, PolicyConfig, PolicyStatus
from app.services.sbom_service import SBOMService


def cmd_policy_check(args):
    """Evaluates CI/CD build gate policy and returns exit code 0 or 1."""
    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == args.project).first()
        if not project:
            # Try lookup by name
            project = db.query(Project).filter(Project.name.ilike(f"%{args.project}%")).first()
        if not project:
            print(f"Error: Project '{args.project}' not found.", file=sys.stderr)
            sys.exit(2)

        config = PolicyConfig(
            max_critical_findings=args.max_critical,
            max_high_findings=args.max_high,
            max_risk_score=args.max_risk,
            allow_unresolved_secrets=args.allow_secrets,
            max_cvss_threshold=args.max_cvss,
            enforce_production_tls=not args.no_tls_check
        )

        res = PolicyEngine.evaluate(db=db, project_id=project.id, config=config)

        print("=" * 65)
        print(f"SENTINELAI BUILD GATE EVALUATION — Project: {project.name}")
        print("=" * 65)
        print(f"Status:            {res.overall_status.value}")
        print(f"Summary:           {res.summary}")
        print(f"Total Findings:    {res.total_active_findings}")
        print(f"Blocking Findings: {res.blocking_findings_count}")
        print("-" * 65)
        print("RULE BREAKDOWN:")
        for r in res.rule_results:
            status_symbol = "[PASS]" if r.status == "PASS" else "[FAIL]" if r.status == "FAIL" else "[WARN]"
            print(f"  {status_symbol:6} {r.title:<42} (Observed: {r.observed_value})")
        print("=" * 65)

        if args.json:
            print("\nJSON RESULT:")
            print(json.dumps(res.model_dump(), indent=2))

        if res.overall_status == PolicyStatus.FAILED:
            sys.exit(1)
        sys.exit(0)
    finally:
        db.close()


def cmd_export_sbom(args):
    """Exports CycloneDX 1.5 JSON SBOM to file or stdout."""
    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == args.project).first()
        if not project:
            project = db.query(Project).filter(Project.name.ilike(f"%{args.project}%")).first()
        if not project:
            print(f"Error: Project '{args.project}' not found.", file=sys.stderr)
            sys.exit(2)

        sbom = SBOMService.generate_cyclonedx_sbom(db=db, project_id=project.id)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(sbom, f, indent=2)
            print(f"CycloneDX 1.5 SBOM exported successfully to: {args.output}")
        else:
            print(json.dumps(sbom, indent=2))
        sys.exit(0)
    finally:
        db.close()


def cmd_list_findings(args):
    """Lists findings for a project in tabular format."""
    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == args.project).first()
        if not project:
            project = db.query(Project).filter(Project.name.ilike(f"%{args.project}%")).first()
        if not project:
            print(f"Error: Project '{args.project}' not found.", file=sys.stderr)
            sys.exit(2)

        print(f"\nActive Vulnerabilities for Project: {project.name}")
        print(f"{'RISK':<10} {'SCORE':<7} {'CATEGORY':<8} {'CWE':<10} {'TITLE'}")
        print("-" * 80)
        for f in project.findings:
            cwe = f.cwe_id or "N/A"
            print(f"{f.internal_risk_level.value:<10} {f.internal_risk_score:<7.1f} {f.category.value:<8} {cwe:<10} {f.title[:40]}")
        print("-" * 80)
        print(f"Total: {len(project.findings)} finding(s)")
        sys.exit(0)
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SentinelAI DevSecOps Command Line Interface"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. Policy check
    p_check = subparsers.add_parser("policy-check", help="Evaluate CI/CD build gate policy")
    p_check.add_argument("--project", "-p", required=True, help="Project UUID or name substring")
    p_check.add_argument("--max-critical", type=int, default=0, help="Max critical findings permitted (default: 0)")
    p_check.add_argument("--max-high", type=int, default=2, help="Max high findings permitted (default: 2)")
    p_check.add_argument("--max-risk", type=float, default=60.0, help="Max project risk score ceiling (default: 60.0)")
    p_check.add_argument("--allow-secrets", action="store_true", default=False, help="Allow open credential leaks")
    p_check.add_argument("--max-cvss", type=float, default=8.5, help="Max single CVSS score allowed (default: 8.5)")
    p_check.add_argument("--no-tls-check", action="store_true", default=False, help="Disable TLS requirement on public assets")
    p_check.add_argument("--json", action="store_true", default=False, help="Output evaluation result as JSON")
    p_check.set_defaults(func=cmd_policy_check)

    # 2. Export SBOM
    p_sbom = subparsers.add_parser("export-sbom", help="Generate and export CycloneDX 1.5 JSON SBOM")
    p_sbom.add_argument("--project", "-p", required=True, help="Project UUID or name substring")
    p_sbom.add_argument("--output", "-o", help="Target output file path (prints to stdout if omitted)")
    p_sbom.set_defaults(func=cmd_export_sbom)

    # 3. List findings
    p_list = subparsers.add_parser("list-findings", help="List security findings for a project")
    p_list.add_argument("--project", "-p", required=True, help="Project UUID or name substring")
    p_list.set_defaults(func=cmd_list_findings)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
