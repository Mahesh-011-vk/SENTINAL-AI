import uuid
from datetime import datetime, timezone
from typing import Generator
from sqlalchemy import create_engine, DateTime, String
from sqlalchemy.orm import declarative_base, sessionmaker, Session, Mapped, mapped_column
from app.config import settings

# Engine configuration with dialect-specific options
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    future=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class TimestampMixin:
    """Standardized timestamp mixin for auditability."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )


def generate_uuid() -> str:
    """Generate RFC 4122 UUID4 string."""
    return str(uuid.uuid4())


def get_db() -> Generator[Session, None, None]:
    """FastAPI database dependency yielding an isolated session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
