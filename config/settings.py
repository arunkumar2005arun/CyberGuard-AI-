from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "cyberguard.db"
DATABASE_SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"