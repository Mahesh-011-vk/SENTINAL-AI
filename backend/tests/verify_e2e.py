import sys
from fastapi.testclient import TestClient
from app.main import app


def run_e2e_verification():
    client = TestClient(app)

    # 1. Health live
    r = client.get("/api/v1/health/live")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    print("1. Health live:", r.json())

    # 2. Login
    login_payload = {"email": "admin@sentinelai.io", "password": "AdminPass123!"}
    r = client.post("/api/v1/auth/login", json=login_payload)
    assert r.status_code == 200, f"Login failed: {r.text}"
    token = r.json()["access_token"]
    print("2. Login OK. Token received (len:", len(token), ")")

    # 3. List projects
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/v1/projects", headers=headers)
    assert r.status_code == 200, f"List projects failed: {r.text}"
    projects = r.json()
    assert len(projects) > 0, "No projects returned"
    project_id = projects[0]["id"]
    print(f"3. Projects retrieved: {len(projects)} (ID: {project_id}, Name: '{projects[0]['name']}')")

    # 4. List findings
    r = client.get(f"/api/v1/projects/{project_id}/findings", headers=headers)
    assert r.status_code == 200, f"List findings failed: {r.text}"
    findings = r.json()
    assert len(findings) >= 3, f"Expected >= 3 findings, got {len(findings)}"
    print(f"4. Normalized Findings count: {len(findings)}")
    for f in findings:
        evidence_snippet = f["evidence"][0]["sanitized_snippet"] if f.get("evidence") else "None"
        print(f"   [{f['internal_risk_level']}] Score {f['internal_risk_score']}: {f['title']}")
        print(f"     Evidence: {evidence_snippet[:70]}...")

    # 5. Recalculate risk on finding
    finding_id = findings[0]["id"]
    r = client.post(f"/api/v1/risk/findings/{finding_id}/recalculate", headers=headers)
    assert r.status_code == 200, f"Recalculate risk failed: {r.text}"
    res = r.json()
    print(f"5. Recalculated Risk Score: {res['calculated_score']} ({res['risk_level']}) via Engine v{res['engine_version']}")

    # 6. Check audit log
    r = client.get("/api/v1/audit", headers=headers)
    assert r.status_code == 200, f"Audit log retrieval failed: {r.text}"
    logs = r.json()
    assert len(logs) > 0, "No audit logs returned"
    print(f"6. Audit Trail verified: {len(logs)} log entries recorded. Latest action: '{logs[0]['action']}'")

    print("\nALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_e2e_verification()
