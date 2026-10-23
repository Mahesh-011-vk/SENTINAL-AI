from datetime import datetime, timedelta, timezone


def test_tenant_isolation_projects(client, engineer_token, beta_token):
    # Engineer A in Tenant Alpha creates a project
    headers_alpha = {"Authorization": f"Bearer {engineer_token}"}
    create_payload = {
        "name": "Alpha Core Services",
        "description": "Tenant Alpha proprietary platform"
    }
    create_res = client.post("/api/v1/projects", json=create_payload, headers=headers_alpha)
    assert create_res.status_code == 201
    project_id = create_res.json()["id"]

    # Engineer A can access project
    get_res_alpha = client.get(f"/api/v1/projects/{project_id}", headers=headers_alpha)
    assert get_res_alpha.status_code == 200
    assert get_res_alpha.json()["name"] == "Alpha Core Services"

    # Engineer B in Tenant Beta attempts to access Tenant Alpha's project
    headers_beta = {"Authorization": f"Bearer {beta_token}"}
    get_res_beta = client.get(f"/api/v1/projects/{project_id}", headers=headers_beta)
    assert get_res_beta.status_code == 403
    assert "Cross-tenant access prohibited" in get_res_beta.json()["detail"]


def test_rbac_audit_log_access(client, engineer_token, secadmin_token):
    # Engineer role should be denied audit log access
    headers_eng = {"Authorization": f"Bearer {engineer_token}"}
    eng_res = client.get("/api/v1/audit", headers=headers_eng)
    assert eng_res.status_code == 403

    # Security Admin should be permitted
    headers_admin = {"Authorization": f"Bearer {secadmin_token}"}
    admin_res = client.get("/api/v1/audit", headers=headers_admin)
    assert admin_res.status_code == 200
    assert isinstance(admin_res.json(), list)


def test_dast_authorization_permission_enforcement(client, engineer_token, secadmin_token):
    headers_admin = {"Authorization": f"Bearer {secadmin_token}"}
    
    # Create project and web asset
    p_res = client.post("/api/v1/projects", json={"name": "Payment Gateway"}, headers=headers_admin)
    project_id = p_res.json()["id"]

    a_res = client.post(
        f"/api/v1/projects/{project_id}/assets",
        json={
            "name": "Checkout API",
            "asset_type": "WEB_APPLICATION",
            "target_locator": "https://checkout.example.com",
            "environment": "STAGING",
            "business_criticality": "HIGH",
            "exposure": "INTERNET_FACING"
        },
        headers=headers_admin
    )
    asset_id = a_res.json()["id"]

    auth_payload = {
        "scope_description": "Authorized staging payment service penetration test",
        "allowed_domains": "checkout.example.com",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    }

    # Engineer cannot issue asset authorization
    headers_eng = {"Authorization": f"Bearer {engineer_token}"}
    eng_auth_res = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        json=auth_payload,
        headers=headers_eng
    )
    assert eng_auth_res.status_code == 403

    # Security Admin CAN issue asset authorization
    admin_auth_res = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        json=auth_payload,
        headers=headers_admin
    )
    assert admin_auth_res.status_code == 201
    assert admin_auth_res.json()["asset_id"] == asset_id
