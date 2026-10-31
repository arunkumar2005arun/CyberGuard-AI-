from dataclasses import dataclass

from database.history_repository import (
    ScanCounts,
    ScanRecord,
    get_recent_scans,
    get_scan_counts,
    initialize_history,
)


@dataclass(frozen=True)
class DashboardData:
    counts: ScanCounts
    recent_scans: list[ScanRecord]


def load_dashboard_data(recent_limit: int = 8) -> DashboardData:
    initialize_history()
    return DashboardData(
        counts=get_scan_counts(),
        recent_scans=get_recent_scans(limit=recent_limit),
    )
