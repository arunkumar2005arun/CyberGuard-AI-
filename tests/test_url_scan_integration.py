import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database.connection as database_connection
from database.history_repository import get_recent_scans, initialize_history
from scanners.url_scanner import extract_url_features
from streamlit.testing.v1 import AppTest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class URLFeatureExtractionTests(unittest.TestCase):
    def test_extracts_host_scheme_and_risk_features(self) -> None:
        features = extract_url_features("http://192.0.2.10/account/verify")

        self.assertEqual(features.domain, "192.0.2.10")
        self.assertFalse(features.https_enabled)
        self.assertTrue(features.uses_ip_address)
        self.assertFalse(features.has_credentials)
        self.assertEqual(features.suspicious_keywords, ("verify",))

    def test_detects_user_info_without_retaining_it_in_features(self) -> None:
        features = extract_url_features(
            "https://user:secret@example.com/private?token=secret"
        )

        self.assertEqual(features.domain, "example.com")
        self.assertTrue(features.has_credentials)
        self.assertNotIn("secret", features.domain)

    def test_rejects_malformed_and_unsupported_urls(self) -> None:
        for value in ("", "not a URL", "ftp://example.com", "https://example.com:bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                extract_url_features(value)


class URLScanDatabaseIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path_patcher = patch.object(
            database_connection,
            "DATABASE_PATH",
            Path(self.temporary_directory.name) / "cyberguard.db",
        )
        self.database_path_patcher.start()
        initialize_history()
        self.app = AppTest.from_file(PROJECT_ROOT / "pages" / "1_URL_Scanner.py").run()
        self.assertFalse(self.app.exception)

    def tearDown(self) -> None:
        self.database_path_patcher.stop()
        self.temporary_directory.cleanup()

    def _submit_url(self, url: str) -> None:
        self.app.text_input[0].set_value(url)
        self.app.button[0].click().run()
        self.assertFalse(self.app.exception)

    def test_successful_url_scan_is_saved_once_with_risk_summary(self) -> None:
        url = "https://example.com/account"
        self._submit_url(url)

        rendered_markdown = [element.value for element in self.app.markdown]
        self.assertNotIn("`None`", rendered_markdown)
        self.assertTrue(any("None detected" in value for value in rendered_markdown))

        scans = get_recent_scans()
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].scan_type, "url")
        self.assertEqual(scans[0].target, "https://example.com")
        self.assertEqual(scans[0].risk_level, "LOW")
        self.assertIn("Low Risk (0/100)", scans[0].summary)

        self.app.run()
        self.assertEqual(len(get_recent_scans()), 1)

    def test_history_does_not_store_url_path_or_query_secrets(self) -> None:
        self._submit_url("https://user:secret@example.com/private?token=secret")

        scans = get_recent_scans()
        self.assertEqual(scans[0].target, "https://example.com")
        self.assertNotIn("secret", scans[0].target)

    def test_invalid_url_is_not_saved(self) -> None:
        self._submit_url("not a valid URL")

        self.assertEqual(get_recent_scans(), [])

    def test_database_error_does_not_crash_scan_page(self) -> None:
        database_connection.DATABASE_PATH = Path(self.temporary_directory.name) / "missing" / "cyberguard.db"
        self._submit_url("https://example.com")

        self.assertFalse(self.app.exception)
        self.assertTrue(
            any("could not be saved" in warning.value for warning in self.app.warning)
        )


if __name__ == "__main__":
    unittest.main()
