import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from config.settings import DATABASE_SCHEMA_PATH
from database.connection import get_connection


@dataclass(frozen=True)
class ScanCounts:
    total: int
    safe: int
    suspicious: int
    high_risk: int


@dataclass(frozen=True)
class ScanRecord:
    id: int
    scan_type: str
    target: str
    risk_level: str
    summary: str
    created_at: str


def initialize_history() -> None:
    schema = DATABASE_SCHEMA_PATH.read_text(encoding="utf-8")
    with get_connection() as connection:
        connection.executescript(schema)


def get_scan_counts() -> ScanCounts:
    query = """
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END), 0) AS safe,
            COALESCE(SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END), 0) AS suspicious,
            COALESCE(SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END), 0) AS high_risk
        FROM scan_history
    """
    with get_connection() as connection:
        row = connection.execute(query).fetchone()
    return ScanCounts(
        total=row["total"],
        safe=row["safe"],
        suspicious=row["suspicious"],
        high_risk=row["high_risk"],
    )


def get_recent_scans(limit: int | None = 8) -> list[ScanRecord]:
    query = """
        SELECT id, scan_type, target, risk_level, summary, created_at
        FROM scan_history
        ORDER BY created_at DESC, id DESC
    """
    if limit is None:
        with get_connection() as connection:
            rows = connection.execute(query).fetchall()
    else:
        if limit < 1:
            raise ValueError("The recent scan limit must be at least 1 or None.")
        with get_connection() as connection:
            rows = connection.execute(f"{query} LIMIT ?", (limit,)).fetchall()
    return [ScanRecord(**dict(row)) for row in rows]


def record_scan(
    scan_type: str,
    target: str,
    risk_level: str,
    summary: str = "",
) -> int:
    normalized_type = scan_type.strip().lower()
    normalized_risk = risk_level.strip().upper()
    if normalized_type not in {"url", "message", "email", "file"}:
        raise ValueError("scan_type must be url, message, email, or file.")
    if normalized_risk not in {"LOW", "MEDIUM", "HIGH"}:
        raise ValueError("risk_level must be LOW, MEDIUM, or HIGH.")
    if not target.strip():
        raise ValueError("target must not be empty.")

    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scan_history (scan_type, target, risk_level, summary, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (normalized_type, target.strip(), normalized_risk, summary.strip(), created_at),
        )
        return cursor.lastrowid