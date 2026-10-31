import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database.connection as database_connection
from database.history_repository import initialize_history
from streamlit.testing.v1 import AppTest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class AppStartupTests(unittest.TestCase):
    def test_dashboard_starts_and_exposes_scanner_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path_patcher = patch.object(
                database_connection,
                "DATABASE_PATH",
                Path(temporary_directory) / "cyberguard.db",
            )
            with database_path_patcher:
                initialize_history()
                app = AppTest.from_file(PROJECT_ROOT / "app.py").run(timeout=20)

        self.assertFalse(app.exception)
        self.assertEqual(len(app.page_link), 4)


if __name__ == "__main__":
    unittest.main()