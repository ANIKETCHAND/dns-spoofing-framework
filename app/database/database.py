"""
Database configuration and session management for DNS Spoofing Framework.
"""
import os
import tempfile
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from app.database.models import Base

# Default database path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "data", "dns_framework.db")

# Fallback to /tmp for Vercel / serverless read-only filesystems
data_dir = os.path.dirname(DEFAULT_DB_PATH)
if os.environ.get("VERCEL") or not os.access(data_dir if os.path.exists(data_dir) else BASE_DIR, os.W_OK):
    DEFAULT_DB_PATH = os.path.join(tempfile.gettempdir(), "dns_framework.db")

DB_PATH = os.environ.get("DNS_FRAMEWORK_DB", DEFAULT_DB_PATH)

# Ensure data directory exists
try:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
except Exception:
    pass

# Create engine with SQLite
# StaticPool is used for SQLite in-memory/thread safety
# For production workloads, consider using QueuePool with appropriate settings
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    pool_pre_ping=True,  # Verify connections before use
    echo=False
)

# Apply SQLite performance optimizations
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA cache_size=-64000;")  # 64MB cache
        cursor.execute("PRAGMA temp_store=MEMORY;")
        cursor.execute("PRAGMA mmap_size=268435456;")  # 256MB mmap
        cursor.execute("PRAGMA page_size=4096;")
        cursor.execute("PRAGMA auto_vacuum=INCREMENTAL;")
    except Exception:
        pass
    finally:
        cursor.close()

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    bind=engine
)


def init_database() -> None:
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)

    # Create additional indexes for query performance
    from sqlalchemy import text
    with engine.connect() as conn:
        try:
            # Composite indexes for common query patterns
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_dns_events_domain_severity_ts ON dns_events(domain, severity, timestamp)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_dns_events_src_ip_ts ON dns_events(source_ip, timestamp)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_dns_events_dns_server_ts ON dns_events(dns_server, timestamp)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_dns_events_is_sim_ts ON dns_events(is_simulation, timestamp)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_alerts_severity_ts ON alerts(severity, timestamp)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_trusted_domains_active ON trusted_domains(is_active, domain)"))
            conn.commit()
        except Exception:
            pass


def get_db() -> Session:
    """Get a database session (for dependency injection)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session() -> Session:
    """Context manager for database sessions."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def drop_database() -> None:
    """Drop all tables (use with caution!)."""
    Base.metadata.drop_all(bind=engine)


def reset_database() -> None:
    """Reset database - drop and recreate all tables."""
    drop_database()
    init_database()