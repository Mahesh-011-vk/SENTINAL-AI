def test_user_registration(client):
    payload = {
        "email": "newuser@example.com",
        "password": "ValidPassword123!",
        "full_name": "Test User",
        "tenant_name": "Acme Security",
        "role": "ENGINEER"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert data["full_name"] == "Test User"
    assert "id" in data
    assert "tenant_id" in data


def test_duplicate_registration_rejected(client):
    payload = {
        "email": "duplicate@example.com",
        "password": "ValidPassword123!",
        "full_name": "First User",
        "tenant_name": "Acme Inc"
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"]


def test_user_login_success(client, engineer_user):
    login_data = {
        "email": "engineer@alpha.com",
        "password": "SecurePassword123!"
    }
    response = client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["email"] == "engineer@alpha.com"
    assert data["role"] == "ENGINEER"


def test_user_login_invalid_password(client, engineer_user):
    login_data = {
        "email": "engineer@alpha.com",
        "password": "WrongPassword!"
    }
    response = client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]


def test_get_current_user_profile(client, engineer_token):
    headers = {"Authorization": f"Bearer {engineer_token}"}
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "engineer@alpha.com"
    assert data["role"] == "ENGINEER"
