from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import settings
from app.database import Base, engine
import app.models  # Ensure all models are registered
from app.api.router import api_router


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds hardened defense-in-depth security headers to all HTTP responses.
    Permits necessary CDN scripts and styles on interactive documentation endpoints.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Permit Swagger UI & ReDoc CDNs on documentation routes
        if path in ("/docs", "/api/v1/docs", "/redoc", "/api/v1/redoc", "/openapi.json", "/api/v1/openapi.json"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self' https://cdn.jsdelivr.net https://fastapi.tiangolo.com 'unsafe-inline'; "
                "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "img-src 'self' https://fastapi.tiangolo.com data:; "
                "frame-ancestors 'none';"
            )
        else:
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"

        return response


# Initialize database schema tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Production-Oriented Evidence-Driven Multi-Agent Application Security Intelligence Platform",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Apply middlewares
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount primary API router
app.include_router(api_router, prefix=settings.API_V1_STR)


# Dual documentation routes (support both /docs and /api/v1/docs)
@app.get("/api/v1/docs", include_in_schema=False)
def api_v1_docs_alias():
    return RedirectResponse(url="/docs")


@app.get("/api/v1/redoc", include_in_schema=False)
def api_v1_redoc_alias():
    return RedirectResponse(url="/redoc")


@app.get("/api/v1/openapi.json", include_in_schema=False)
def api_v1_openapi_alias():
    return RedirectResponse(url="/openapi.json")


@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": "1.0.0",
        "status": "operational",
        "interactive_docs": "/docs",
        "api_v1_docs": "/api/v1/docs",
        "health_check": f"{settings.API_V1_STR}/health/live"
    }
