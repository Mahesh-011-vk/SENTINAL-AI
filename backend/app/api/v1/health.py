from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.api.deps import get_db

router = APIRouter()


@router.get("/live", status_code=status.HTTP_200_OK)
def liveness_check():
    """Kubernetes / container liveness probe."""
    return {"status": "alive", "service": "sentinelai-backend"}


@router.get("/ready", status_code=status.HTTP_200_OK)
def readiness_check(db: Session = Depends(get_db)):
    """Readiness probe checking database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "ready",
            "service": "sentinelai-backend",
            "database": "healthy"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database readiness probe failed: {str(e)}"
        )
