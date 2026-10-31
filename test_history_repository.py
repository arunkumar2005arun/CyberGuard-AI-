import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database.connection as database_connection
from database.history_repository import (
    get_recent_scans,
    initialize_history,
    record_scan,
)
from services.dashboard_service import load_dashboard_data
from streamlit.testing.v1 import AppTest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class DashboardHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path_patcher = patch.object(
            database_connection,
            "DATABASE_PATH",
            Path(self.temporary_directory.name) / "cyberguard.db",
        )
        self.database_path_patcher.start()
        initialize_history()

    def tearDown(self) -> None:
        self.database_path_patcher.stop()
        self.temporary_directory.cleanup()

    def test_dashboard_counts_and_recent_scans_use_saved_records(self) -> None:
        record_scan("url", "https://safe.example", "LOW", "No indicators found.")
        record_scan("email", "invoice.eml", "MEDIUM", "Unexpected attachment.")
        record_scan("file", "archive.zip", "HIGH", "Known indicator match.")

        data = load_dashboard_data()

        self.assertEqual(
            (data.counts.total, data.counts.safe, data.counts.suspicious, data.counts.high_risk),
            (3, 1, 1, 1),
        )
        self.assertEqual([scan.target for scan in data.recent_scans], [
            "archive.zip",
            "invoice.eml",
            "https://safe.example",
        ])

    def test_rejects_unknown_scan_categories(self) -> None:
        with self.assertRaises(ValueError):
            record_scan("unknown", "item", "LOW")

    def test_recent_scan_limit_is_applied(self) -> None:
        record_scan("message", "message one", "LOW")
        record_scan("message", "message two", "LOW")

        self.assertEqual(len(get_recent_scans(limit=1)), 1)

    def test_recent_scans_none_returns_all_records(self) -> None:
        for index in range(10):
            record_scan("url", f"https://example-{index}.com", "LOW")

        self.assertEqual(len(get_recent_scans(limit=None)), 10)

    def test_recent_scans_zero_limit_raises_value_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 1"):
            get_recent_scans(limit=0)


class ScanHistoryPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path_patcher = patch.object(
            database_connection,
            "DATABASE_PATH",
            Path(self.temporary_directory.name) / "cyberguard.db",
        )
        self.database_path_patcher.start()
        initialize_history()
        self.app = AppTest.from_file(PROJECT_ROOT / "pages" / "5_Scan_History.py").run(timeout=10)
        self.assertFalse(self.app.exception)

    def tearDown(self) -> None:
        self.database_path_patcher.stop()
        self.temporary_directory.cleanup()

    def test_empty_history_shows_empty_state_and_zero_total(self) -> None:
        rendered = "\n".join(element.value for element in self.app.markdown)

        self.assertIn("No scans yet", rendered)
        self.assertIn("TOTAL SCAN RECORDS", rendered)
        self.assertIn("Showing", rendered)

    def test_table_shows_all_records_and_filter_search_controls(self) -> None:
        record_scan("url", "https://example.com/login", "HIGH", "Phishing indicators.")
        record_scan("email", "sender@example.com | Invoice", "MEDIUM", "Unexpected request.")
        record_scan("file", "report.txt", "LOW", "No configured warning indicators.")

        self.app.run(timeout=10)

        self.assertEqual(len(self.app.dataframe), 1)
        self.assertEqual(len(self.app.multiselect), 2)
        self.assertEqual(len(self.app.text_input), 1)
        rendered = "\n".join(element.value for element in self.app.markdown)
        self.assertIn("3", rendered)
        self.assertIn("Showing", rendered)

    def test_scan_type_and_risk_filters_can_be_applied(self) -> None:
        record_scan("url", "https://example.com", "HIGH", "URL finding.")
        record_scan("email", "sender@example.com", "LOW", "Email finding.")
        self.app.run(timeout=10)

        self.app.multiselect[0].set_value(["Email"])
        self.app.multiselect[1].set_value(["LOW"])
        self.app.run(timeout=10)

        rendered = "\n".join(element.value for element in self.app.markdown)
        self.assertIn("Showing", rendered)
        self.assertIn("1", rendered)
        self.assertEqual(len(self.app.dataframe), 1)

    def test_target_search_filters_records(self) -> None:
        record_scan("url", "https://alpha.example", "LOW", "First.")
        record_scan("url", "https://beta.example", "HIGH", "Second.")
        self.app.run(timeout=10)

        self.app.text_input[0].set_value("beta")
        self.app.run()

        rendered = "\n".join(element.value for element in self.app.markdown)
        self.assertIn("Showing", rendered)
        self.assertEqual(len(self.app.dataframe), 1)

    def test_database_error_is_displayed(self) -> None:
        database_connection.DATABASE_PATH = Path(self.temporary_directory.name) / "missing" / "history.db"
        self.app.run()

        self.assertTrue(self.app.error)
        self.assertIn("Unable to load scan history", self.app.error[0].value)


if __name__ == "__main__":
    unittest.main()