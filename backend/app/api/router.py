from fastapi import APIRouter
from app.api.v1 import (
    health,
    auth,
    projects,
    assets,
    scans,
    findings,
    risk,
    audit
)

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["Health Checks"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(projects.router, prefix="/projects", tags=["Projects"])
api_router.include_router(assets.router, tags=["Assets & Scope Authorizations"])
api_router.include_router(scans.router, tags=["Assessment Orchestration"])
api_router.include_router(findings.router, tags=["Vulnerability Intelligence"])
api_router.include_router(risk.router, prefix="/risk", tags=["Deterministic Risk Engine"])
api_router.include_router(audit.router, prefix="/audit", tags=["Security Audit Trail"])
