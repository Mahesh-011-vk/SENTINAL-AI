import re
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.auth import UserRegister, UserLogin, TokenResponse, UserResponse
from app.core.security import hash_password, verify_password, create_access_token
from app.services.audit_service import AuditService

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserRegister,
    request: Request,
    db: Session = Depends(get_db)
):
    """Register a new user and either create an organization or join an existing tenant."""
    # Check if email is already taken
    existing_user = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address already exists"
        )

    # Resolve or create tenant
    if payload.tenant_id:
        tenant = db.query(Tenant).filter(Tenant.id == payload.tenant_id).first()
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Specified tenant organization does not exist"
            )
    else:
        tenant_name = payload.tenant_name or f"{payload.full_name}'s Organization"
        slug = re.sub(r"[^a-zA-Z0-9-]", "-", tenant_name.lower().strip())
        
        # Ensure unique slug
        base_slug = slug
        counter = 1
        while db.query(Tenant).filter(Tenant.slug == slug).first():
            slug = f"{base_slug}-{counter}"
            counter += 1

        tenant = Tenant(name=tenant_name, slug=slug)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

    # Hash password with bcrypt
    hashed_pw = hash_password(payload.password)

    user = User(
        tenant_id=tenant.id,
        email=payload.email.lower(),
        hashed_password=hashed_pw,
        full_name=payload.full_name,
        role=payload.role,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Record audit event
    AuditService.log_event(
        db=db,
        tenant_id=tenant.id,
        actor=user,
        action="USER_REGISTERED",
        resource_type="USER",
        resource_id=user.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"email": user.email, "role": user.role.value}
    )

    return user


@router.post("/login", response_model=TokenResponse)
def login(
    payload: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """Authenticate with email and password, issuing an HS256 JWT access token."""
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        # Log failed attempt if user exists
        if user:
            AuditService.log_event(
                db=db,
                tenant_id=user.tenant_id,
                action="AUTH_LOGIN_FAILED",
                resource_type="USER",
                resource_id=user.id,
                client_ip=get_client_ip(request),
                user_agent=get_user_agent(request),
                details={"reason": "Invalid password"}
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )

    # Generate token
    token = create_access_token(
        subject=user.id,
        tenant_id=user.tenant_id,
        role=user.role.value
    )

    # Record login audit event
    AuditService.log_event(
        db=db,
        tenant_id=user.tenant_id,
        actor=user,
        action="AUTH_LOGIN_SUCCESS",
        resource_type="USER",
        resource_id=user.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request)
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Retrieve profile of currently authenticated user."""
    return current_user
