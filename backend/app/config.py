from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = (ROOT / "controlled_workspace").resolve()
DATABASE_URL = f"sqlite:///{(ROOT / 'agentgate.db').as_posix()}"
CORS_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]
