"""Database engine and session factory."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from database.models import Base

# Default: project root / data / netguard.db
_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DB = _ROOT / "data" / "netguard.db"
os.environ.setdefault("NETGUARD_DB_PATH", str(_DEFAULT_DB))

DB_URL = os.environ.get("NETGUARD_DATABASE_URL") or f"sqlite:///{os.environ['NETGUARD_DB_PATH']}"


def _ensure_parent(path: str) -> None:
    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)


_ensure_parent(os.environ["NETGUARD_DB_PATH"])

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    """Create all tables (idempotent)."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
