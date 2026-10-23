import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.core.security import hash_password, create_access_token

# In-memory SQLite database specifically for test execution
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db() -> Generator[Session, None, None]:
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db: Session) -> Generator[TestClient, None, None]:
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def tenant_alpha(db: Session) -> Tenant:
    tenant = Tenant(name="Alpha Corp", slug="alpha-corp")
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


@pytest.fixture
def tenant_beta(db: Session) -> Tenant:
    tenant = Tenant(name="Beta Industries", slug="beta-ind")
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


@pytest.fixture
def engineer_user(db: Session, tenant_alpha: Tenant) -> User:
    user = User(
        tenant_id=tenant_alpha.id,
        email="engineer@alpha.com",
        hashed_password=hash_password("SecurePassword123!"),
        full_name="Alice Engineer",
        role=UserRole.ENGINEER,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def secadmin_user(db: Session, tenant_alpha: Tenant) -> User:
    user = User(
        tenant_id=tenant_alpha.id,
        email="secadmin@alpha.com",
        hashed_password=hash_password("SecAdminPass123!"),
        full_name="Bob Security Admin",
        role=UserRole.SECURITY_ADMIN,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def engineer_beta_user(db: Session, tenant_beta: Tenant) -> User:
    user = User(
        tenant_id=tenant_beta.id,
        email="engineer@beta.com",
        hashed_password=hash_password("BetaPass123!"),
        full_name="Charlie Beta",
        role=UserRole.ENGINEER,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def engineer_token(engineer_user: User) -> str:
    return create_access_token(
        subject=engineer_user.id,
        tenant_id=engineer_user.tenant_id,
        role=engineer_user.role.value
    )


@pytest.fixture
def secadmin_token(secadmin_user: User) -> str:
    return create_access_token(
        subject=secadmin_user.id,
        tenant_id=secadmin_user.tenant_id,
        role=secadmin_user.role.value
    )


@pytest.fixture
def beta_token(engineer_beta_user: User) -> str:
    return create_access_token(
        subject=engineer_beta_user.id,
        tenant_id=engineer_beta_user.tenant_id,
        role=engineer_beta_user.role.value
    )
