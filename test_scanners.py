import tempfile
import unittest
import hashlib
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

import database.connection as database_connection
from database.history_repository import get_recent_scans, initialize_history
from scanners.email_scanner import analyze_email
from scanners.file_scanner import MAX_FILE_SIZE, analyze_file
from scanners.message_scanner import analyze_message
from streamlit.testing.v1 import AppTest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class MessageScannerTests(unittest.TestCase):
    def test_empty_message_is_rejected(self) -> None:
        for message in ("", "  \n"):
            with self.subTest(message=message), self.assertRaises(ValueError):
                analyze_message(message)

    def test_plain_message_has_no_indicators(self) -> None:
        result = analyze_message("The team meeting is at 10 tomorrow.")

        self.assertEqual((result.score, result.level), (0, "LOW"))
        self.assertEqual(result.indicators, ())
        self.assertEqual(result.links_found, ())
        self.assertTrue(result.recommendations)

    def test_detects_phishing_urgency_threat_sensitive_request_and_link(self) -> None:
        message = (
            "URGENT: Verify your account immediately or your account will be suspended. "
            "Reply with your password at http://192.0.2.10/login"
        )
        result = analyze_message(message)
        categories = {indicator.category for indicator in result.indicators}

        self.assertEqual(result.level, "HIGH")
        self.assertLessEqual(result.score, 100)
        self.assertTrue(
            {
                "Phishing language",
                "Urgency",
                "Threats or account consequences",
                "Sensitive information request",
                "Suspicious link",
            }.issubset(categories)
        )
        self.assertEqual(result.links_found, ("http://192.0.2.10/login",))
        self.assertEqual(result.suspicious_links, result.links_found)
        self.assertTrue(all(indicator.evidence for indicator in result.indicators))
        self.assertTrue(result.recommendations)

    def test_detects_prize_and_fake_offer_language(self) -> None:
        result = analyze_message(
            "Congratulations, you've won a prize. Claim your reward with this limited-time offer."
        )
        categories = {indicator.category for indicator in result.indicators}

        self.assertIn("Prize or lottery claim", categories)
        self.assertIn("Suspicious offer", categories)

    def test_https_regular_link_is_reported_but_not_flagged_by_link_rule(self) -> None:
        result = analyze_message("See the notes at https://example.com/meeting.")

        self.assertEqual(result.links_found, ("https://example.com/meeting",))
        self.assertEqual(result.suspicious_links, ())
        self.assertEqual(result.score, 0)

    def test_score_is_capped_at_100(self) -> None:
        message = (
            "Congratulations, you won a prize! Claim your prize immediately. "
            "Your account will be closed within 2 hours. Verify your account and "
            "reply with your OTP at http://bit.ly/login"
        )
        result = analyze_message(message)

        self.assertEqual(result.score, 100)
        self.assertEqual(result.level, "HIGH")


class EmailScannerTests(unittest.TestCase):
    def test_requires_valid_sender_and_content(self) -> None:
        invalid_cases = (
            ("not-an-address", "Subject", "Body"),
            ("person@example.com", "", ""),
        )
        for sender, subject, body in invalid_cases:
            with self.subTest(sender=sender), self.assertRaises(ValueError):
                analyze_email(sender, subject, body)

    def test_detects_sender_mismatch_and_reuses_message_rules(self) -> None:
        assessment = analyze_email(
            "security1234@not-paypal.example",
            "Urgent PayPal account verification",
            "Verify your account immediately. Your account will be suspended. "
            "Reply with your password at http://192.0.2.10/login",
        )
        categories = {indicator.category for indicator in assessment.indicators}

        self.assertEqual(assessment.level, "HIGH")
        self.assertLessEqual(assessment.score, 100)
        self.assertTrue(
            {
                "Unusual sender address pattern",
                "Sender and brand domain mismatch",
                "Phishing language",
                "Urgency",
                "Threats or account consequences",
                "Sensitive information request",
                "Suspicious link",
            }.issubset(categories)
        )
        self.assertEqual(assessment.links_found, ("http://192.0.2.10/login",))
        self.assertTrue(assessment.recommendations)

    def test_detects_punycode_sender_domain(self) -> None:
        assessment = analyze_email(
            "support@xn--paypl-3ve.example",
            "Account update",
            "Please review your account.",
        )

        self.assertIn(
            "Internationalized sender domain",
            {indicator.category for indicator in assessment.indicators},
        )

    def test_detects_prize_and_offer_in_subject_and_body(self) -> None:
        assessment = analyze_email(
            "offers@example.com",
            "Congratulations, you won a prize",
            "Claim your reward with this limited-time offer.",
        )

        categories = {indicator.category for indicator in assessment.indicators}
        self.assertIn("Prize or lottery claim", categories)
        self.assertIn("Suspicious offer", categories)

    def test_known_matching_brand_domain_does_not_trigger_mismatch(self) -> None:
        assessment = analyze_email(
            "billing@paypal.com",
            "PayPal account notice",
            "Please review your recent activity.",
        )

        self.assertNotIn(
            "Sender and brand domain mismatch",
            {indicator.category for indicator in assessment.indicators},
        )


class MessageScannerDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path_patcher = patch.object(
            database_connection,
            "DATABASE_PATH",
            Path(self.temporary_directory.name) / "cyberguard.db",
        )
        self.database_path_patcher.start()
        initialize_history()
        self.app = AppTest.from_file(PROJECT_ROOT / "pages" / "2_Message_Scanner.py").run()
        self.assertFalse(self.app.exception)

    def tearDown(self) -> None:
        self.database_path_patcher.stop()
        self.temporary_directory.cleanup()

    def _submit_message(self, message: str) -> None:
        self.app.text_area[0].set_value(message)
        self.app.button[0].click().run()
        self.assertFalse(self.app.exception)

    def test_successful_scan_is_saved_once_with_message_risk(self) -> None:
        message = "You won a prize! Claim your reward immediately."
        self._submit_message(message)

        scans = get_recent_scans()
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].scan_type, "message")
        self.assertEqual(scans[0].target, message)
        self.assertEqual(scans[0].risk_level, "MEDIUM")
        self.assertIn("Prize or lottery claim", scans[0].summary)

        self.app.run()
        self.assertEqual(len(get_recent_scans()), 1)

    def test_empty_message_is_not_saved(self) -> None:
        self._submit_message("   ")

        self.assertEqual(get_recent_scans(), [])
        self.assertTrue(self.app.error)

    def test_database_failure_does_not_crash_page(self) -> None:
        database_connection.DATABASE_PATH = Path(self.temporary_directory.name) / "missing" / "history.db"
        self._submit_message("Ordinary message content.")

        self.assertFalse(self.app.exception)
        self.assertTrue(any("could not be saved" in warning.value for warning in self.app.warning))


class EmailScannerDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path_patcher = patch.object(
            database_connection,
            "DATABASE_PATH",
            Path(self.temporary_directory.name) / "cyberguard.db",
        )
        self.database_path_patcher.start()
        initialize_history()
        self.app = AppTest.from_file(PROJECT_ROOT / "pages" / "3_Email_Scanner.py").run()
        self.assertFalse(self.app.exception)

    def tearDown(self) -> None:
        self.database_path_patcher.stop()
        self.temporary_directory.cleanup()

    def _submit_email(self, sender: str, subject: str, body: str) -> None:
        self.app.text_input[0].set_value(sender)
        self.app.text_input[1].set_value(subject)
        self.app.text_area[0].set_value(body)
        self.app.button[0].click().run()
        self.assertFalse(self.app.exception)

    def test_email_scan_is_saved_once(self) -> None:
        self._submit_email(
            "sender@example.com",
            "Congratulations, you won a prize",
            "Claim your reward immediately.",
        )
        scans = get_recent_scans()

        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].scan_type, "email")
        self.assertEqual(scans[0].target, "sender@example.com | Congratulations, you won a prize")
        self.assertEqual(scans[0].risk_level, "MEDIUM")
        self.assertIn("Prize or lottery claim", scans[0].summary)

        self.app.run()
        self.assertEqual(len(get_recent_scans()), 1)

    def test_invalid_sender_is_not_saved(self) -> None:
        self._submit_email("invalid sender", "Subject", "Body")

        self.assertEqual(get_recent_scans(), [])
        self.assertTrue(self.app.error)

    def test_database_failure_does_not_crash_email_page(self) -> None:
        database_connection.DATABASE_PATH = Path(self.temporary_directory.name) / "missing" / "history.db"
        self._submit_email("sender@example.com", "Subject", "Ordinary message content.")

        self.assertFalse(self.app.exception)
        self.assertTrue(any("could not be saved" in warning.value for warning in self.app.warning))


class FileScannerTests(unittest.TestCase):
    def test_hash_and_supported_text_file_analysis(self) -> None:
        content = b"Project notes for the weekly meeting."
        assessment = analyze_file("notes.txt", "text/plain", content)

        self.assertEqual(assessment.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual((assessment.score, assessment.level), (0, "LOW"))
        self.assertEqual(assessment.size_bytes, len(content))
        self.assertEqual(assessment.extracted_text, content.decode())

    def test_detects_scams_and_dangerous_text(self) -> None:
        content = (
            b"URGENT: Verify your account immediately. Reply with your password. "
            b"<script>eval('x')</script> powershell.exe"
        )
        assessment = analyze_file("message.txt", "text/plain", content)
        categories = {indicator.category for indicator in assessment.indicators}

        self.assertEqual(assessment.level, "HIGH")
        self.assertLessEqual(assessment.score, 100)
        self.assertTrue(
            {
                "Phishing language",
                "Urgency",
                "Sensitive information request",
                "Embedded script or active content",
                "Executable or command content",
            }.issubset(categories)
        )
        self.assertTrue(assessment.recommendations)

    def test_detects_pdf_active_content(self) -> None:
        assessment = analyze_file(
            "document.pdf",
            "application/pdf",
            b"%PDF-1.7\n/JavaScript /OpenAction",
        )

        self.assertIn(
            "PDF active content",
            {indicator.category for indicator in assessment.indicators},
        )

    def test_scans_docx_text_without_extracting_or_executing(self) -> None:
        memory_file = BytesIO()
        with ZipFile(memory_file, "w", ZIP_DEFLATED) as archive:
            archive.writestr(
                "word/document.xml",
                "<w:document><w:p><w:t>Verify your account immediately</w:t></w:p></w:document>",
            )
        assessment = analyze_file(
            "notice.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            memory_file.getvalue(),
        )

        self.assertIn("verify your account immediately", assessment.extracted_text.lower())
        self.assertIn(
            "Phishing language",
            {indicator.category for indicator in assessment.indicators},
        )

    def test_detects_macro_payload_in_docx_archive(self) -> None:
        memory_file = BytesIO()
        with ZipFile(memory_file, "w", ZIP_DEFLATED) as archive:
            archive.writestr("word/document.xml", "<document><p>Normal content</p></document>")
            archive.writestr("word/vbaProject.bin", b"macro data")
        assessment = analyze_file(
            "document.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            memory_file.getvalue(),
        )

        self.assertIn("Macro-related content", {item.category for item in assessment.indicators})

    def test_detects_malformed_docx_archive(self) -> None:
        assessment = analyze_file(
            "broken.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            b"PK\x03\x04not a valid document archive",
        )

        self.assertIn("Invalid DOCX structure", {item.category for item in assessment.indicators})

    def test_detects_mime_and_signature_mismatch(self) -> None:
        assessment = analyze_file("photo.png", "text/plain", b"not a PNG image")
        categories = {item.category for item in assessment.indicators}

        self.assertIn("MIME type and extension mismatch", categories)
        self.assertIn("File signature and extension mismatch", categories)

    def test_accepts_common_image_signature(self) -> None:
        assessment = analyze_file(
            "picture.png",
            "image/png",
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 8,
        )

        self.assertEqual(assessment.level, "LOW")
        self.assertEqual(assessment.extension, ".png")

    def test_rejects_unsupported_empty_and_oversized_files(self) -> None:
        invalid_files = (
            ("program.exe", "application/octet-stream", b"binary"),
            ("empty.txt", "text/plain", b""),
            ("large.txt", "text/plain", b"x" * (MAX_FILE_SIZE + 1)),
        )
        for filename, mime_type, content in invalid_files:
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                analyze_file(filename, mime_type, content)

    def test_misleading_double_extension_is_flagged(self) -> None:
        assessment = analyze_file("report.exe.txt", "text/plain", b"Please review.")

        self.assertIn(
            "Misleading double extension",
            {item.category for item in assessment.indicators},
        )


class FileScannerDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path_patcher = patch.object(
            database_connection,
            "DATABASE_PATH",
            Path(self.temporary_directory.name) / "cyberguard.db",
        )
        self.database_path_patcher.start()
        initialize_history()
        self.app = AppTest.from_file(PROJECT_ROOT / "pages" / "4_File_Scanner.py").run()
        self.assertFalse(self.app.exception)

    def tearDown(self) -> None:
        self.database_path_patcher.stop()
        self.temporary_directory.cleanup()

    def _upload_and_scan(self, filename: str, content: bytes, mime_type: str) -> None:
        self.app.file_uploader[0].set_value((filename, content, mime_type))
        self.app.run()
        self.app.button[0].click().run()
        self.assertFalse(self.app.exception)

    def test_successful_file_scan_saves_result_once(self) -> None:
        content = b"Meeting notes."
        self._upload_and_scan("notes.txt", content, "text/plain")

        scans = get_recent_scans()
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].scan_type, "file")
        self.assertIn("notes.txt", scans[0].target)
        self.assertIn(hashlib.sha256(content).hexdigest(), scans[0].target)
        self.assertEqual(scans[0].risk_level, "LOW")

        self.app.run()
        self.assertEqual(len(get_recent_scans()), 1)

    def test_database_failure_does_not_crash_file_page(self) -> None:
        database_connection.DATABASE_PATH = Path(self.temporary_directory.name) / "missing" / "history.db"
        self._upload_and_scan("notes.txt", b"Meeting notes.", "text/plain")

        self.assertFalse(self.app.exception)
        self.assertTrue(any("could not be saved" in warning.value for warning in self.app.warning))


if __name__ == "__main__":
    unittest.main()