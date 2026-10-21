from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
class Base(DeclarativeBase): pass
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()


def migrate_policy_columns():
    """Add protected-resource fields to existing SQLite Policy tables, idempotently."""
    additions = {
        "resource_classification": "VARCHAR(16)",
        "enabled": "BOOLEAN",
        "created_at": "DATETIME",
        "updated_at": "DATETIME",
        "name": "VARCHAR(160)",
        "action_type": "VARCHAR(128)",
        "risk_level": "VARCHAR(16)",
        "rationale": "TEXT",
        "reference_name": "VARCHAR(200)",
        "reference_url": "TEXT",
        "version": "VARCHAR(40)",
    }
    with engine.begin() as connection:
        columns = {row[1] for row in connection.exec_driver_sql("PRAGMA table_info(policies)")}
        if not columns:
            return
        for name, sql_type in additions.items():
            if name not in columns:
                connection.exec_driver_sql(f"ALTER TABLE policies ADD COLUMN {name} {sql_type}")
