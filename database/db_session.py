"""
Database session management with SQLite and SQLAlchemy.
Includes safe automatic schema migration for SQLite.
"""
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.config import settings

DB_DIR = settings.DATABASE_PATH.parent
DB_DIR.mkdir(parents=True, exist_ok=True)

SQLALCHEMY_DATABASE_URL = f"sqlite:///{settings.DATABASE_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    """Initializes tables and applies lightweight schema migrations for existing SQLite files."""
    Base.metadata.create_all(bind=engine)
    
    # Check and add new columns if they do not exist in existing sqlite table
    with engine.connect() as conn:
        try:
            result = conn.execute(text("PRAGMA table_info(threat_analyses)"))
            existing_columns = {row[1] for row in result.fetchall()}
            
            if existing_columns:
                if "highlighted_spans" not in existing_columns:
                    conn.execute(text("ALTER TABLE threat_analyses ADD COLUMN highlighted_spans JSON"))
                    conn.commit()
                if "detector_probabilities" not in existing_columns:
                    conn.execute(text("ALTER TABLE threat_analyses ADD COLUMN detector_probabilities JSON"))
                    conn.commit()
                if "download_source_url" not in existing_columns:
                    conn.execute(text("ALTER TABLE threat_analyses ADD COLUMN download_source_url VARCHAR(2048)"))
                    conn.commit()
                if "download_url" not in existing_columns:
                    conn.execute(text("ALTER TABLE threat_analyses ADD COLUMN download_url VARCHAR(2048)"))
                    conn.commit()
                if "context_score" not in existing_columns:
                    conn.execute(text("ALTER TABLE threat_analyses ADD COLUMN context_score FLOAT DEFAULT 0.0"))
                    conn.commit()
        except Exception:
            pass

def get_db():
    """Dependency for obtaining database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
