import hashlib
import html
import mimetypes
import re
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePath

from scanners.message_scanner import MessageIndicator, analyze_message


MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 1000
MAX_ARCHIVE_EXPANDED_SIZE = 20 * 1024 * 1024
MAX_TEXT_SCAN_SIZE = 2 * 1024 * 1024

_SUPPORTED_MIME_TYPES = {
    ".pdf": frozenset({"application/pdf"}),
    ".txt": frozenset({"text/plain"}),
    ".docx": frozenset(
        {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    ),
    ".png": frozenset({"image/png"}),
    ".jpg": frozenset({"image/jpeg"}),
    ".jpeg": frozenset({"image/jpeg"}),
    ".gif": frozenset({"image/gif"}),
    ".bmp": frozenset({"image/bmp", "image/x-ms-bmp"}),
    ".tif": frozenset({"image/tiff"}),
    ".tiff": frozenset({"image/tiff"}),
    ".webp": frozenset({"image/webp"}),
}
_SUSPICIOUS_TEXT_PATTERNS: tuple[tuple[str, int, tuple[str, ...], str], ...] = (
    (
        "Embedded script or active content",
        30,
        (r"<\s*script\b", r"<\s*iframe\b", r"javascript\s*:", r"\beval\s*\("),
        "Do not open or enable active content in an untrusted file. Verify its source first.",
    ),
    (
        "Executable or command content",
        35,
        (
            r"\bpowershell(?:\.exe)?\b",
            r"\bcmd(?:\.exe)?\s*/c\b",
            r"\bwscript(?:\.exe)?\b",
            r"\b(?:curl|wget)\b.{0,80}\b(?:https?://|-[oO])",
        ),
        "Do not run commands or executables described in an untrusted document.",
    ),
    (
        "Sensitive information request",
        20,
        (
            r"\b(?:send|share|provide|reply with|enter)\s+(?:your\s+)?"
            r"(?:password|passcode|otp|one[- ]time code|pin|bank details|card number)\b",
        ),
        "Never provide passwords, one-time codes, PINs, or payment details in response to an "
        "untrusted file or its instructions.",
    ),
)
_DANGEROUS_SUFFIXES = frozenset(
    {".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".vbs", ".ps1", ".msi", ".lnk"}
)
_PDF_ACTIVE_MARKERS = {
    b"/javascript": "PDF JavaScript action",
    b"/js": "PDF JavaScript action",
    b"/openaction": "PDF automatic open action",
    b"/aa": "PDF additional action",
    b"/launch": "PDF launch action",
    b"/embeddedfile": "PDF embedded file",
    b"/richmedia": "PDF rich media content",
}


@dataclass(frozen=True)
class FileAssessment:
    filename: str
    extension: str
    mime_type: str
    size_bytes: int
    sha256: str
    score: int
    level: str
    indicators: tuple[MessageIndicator, ...]
    extracted_text: str

    @property
    def recommendations(self) -> tuple[str, ...]:
        if not self.indicators:
            return (
                "No configured warning indicators were detected. Keep the file protected "
                "and open it only if you trust its source.",
            )
        return tuple(dict.fromkeys(item.recommendation for item in self.indicators))


def _indicator(
    category: str,
    points: int,
    evidence: str,
    explanation: str,
    recommendation: str,
) -> MessageIndicator:
    return MessageIndicator(
        category=category,
        points=points,
        evidence=(evidence,),
        explanation=explanation,
        recommendation=recommendation,
    )


def _signature_matches(extension: str, data: bytes) -> bool:
    if extension == ".pdf":
        return data.lstrip()[:5] == b"%PDF-"
    if extension == ".docx":
        return data.startswith(b"PK\x03\x04")
    if extension == ".png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in {".jpg", ".jpeg"}:
        return data.startswith(b"\xff\xd8\xff")
    if extension == ".gif":
        return data.startswith((b"GIF87a", b"GIF89a"))
    if extension == ".bmp":
        return data.startswith(b"BM")
    if extension in {".tif", ".tiff"}:
        return data.startswith((b"II*\x00", b"MM\x00*"))
    if extension == ".webp":
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    return True


def _decode_text(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            return data[:MAX_TEXT_SCAN_SIZE].decode(encoding)
        except UnicodeError:
            continue
    return data[:MAX_TEXT_SCAN_SIZE].decode("latin-1", errors="replace")


def _extract_docx_text(data: bytes) -> tuple[str, bool, bool, bool]:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            if (
                len(entries) > MAX_ARCHIVE_ENTRIES
                or sum(entry.file_size for entry in entries) > MAX_ARCHIVE_EXPANDED_SIZE
            ):
                return "", False, True, False
            names = {entry.filename for entry in entries}
            has_macro = any(
                name.lower().endswith(("vbaproject.bin", "vbadata.xml"))
                for name in names
            )
            document = archive.getinfo("word/document.xml") if "word/document.xml" in names else None
            if document is None or document.file_size > MAX_TEXT_SCAN_SIZE:
                return "", has_macro, False, True
            xml_content = archive.read(document)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError):
        return "", False, False, True

    text = html.unescape(re.sub(r"<[^>]*>", " ", xml_content.decode("utf-8", errors="replace")))
    text = re.sub(r"\s+", " ", text)
    return text, has_macro, False, False


def _extract_pdf_text(data: bytes) -> str:
    readable = re.findall(rb"[\x20-\x7e]{4,}", data[:MAX_TEXT_SCAN_SIZE])
    return "\n".join(chunk.decode("latin-1", errors="replace") for chunk in readable)


def _add_text_indicators(text: str, findings: list[MessageIndicator]) -> None:
    if not text:
        return
    message_assessment = analyze_message(text)
    findings.extend(message_assessment.indicators)
    lowered_text = text.lower()
    for category, points, patterns, recommendation in _SUSPICIOUS_TEXT_PATTERNS:
        evidence = tuple(
            dict.fromkeys(
                match.group(0)
                for pattern in patterns
                for match in re.finditer(pattern, lowered_text, flags=re.IGNORECASE)
            )
        )
        if evidence:
            findings.append(
                MessageIndicator(
                    category=category,
                    points=points,
                    evidence=evidence,
                    explanation=f"Matched potentially dangerous content: {', '.join(evidence)}.",
                    recommendation=recommendation,
                )
            )


def analyze_file(filename: str, mime_type: str, data: bytes) -> FileAssessment:
    """Perform bounded local static checks; never extracts, executes, or uploads a file."""
    safe_name = PurePath(filename.replace("\\", "/")).name
    extension = PurePath(safe_name).suffix.lower()
    if extension not in _SUPPORTED_MIME_TYPES:
        raise ValueError("Unsupported file type. Upload PDF, TXT, DOCX, or a common image.")
    if not isinstance(data, bytes) or not data:
        raise ValueError("The uploaded file is empty or unreadable.")
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("The file exceeds the 10 MB maximum size.")

    declared_mime = (mime_type or "").split(";", maxsplit=1)[0].strip().lower()
    expected_mimes = _SUPPORTED_MIME_TYPES[extension]
    findings: list[MessageIndicator] = []
    if declared_mime and declared_mime not in expected_mimes:
        findings.append(
            _indicator(
                "MIME type and extension mismatch",
                20,
                f"{declared_mime} for {extension}",
                "The uploaded MIME type does not match the file extension.",
                "Confirm the file type and source. Do not trust a file solely because its name "
                "has a familiar extension.",
            )
        )

    signature_matches = _signature_matches(extension, data)
    if not signature_matches:
        findings.append(
            _indicator(
                "File signature and extension mismatch",
                35,
                extension,
                "The file contents do not begin with the expected signature for this extension.",
                "Do not open the file. Verify its true format with the sender using a trusted "
                "channel.",
            )
        )

    name_parts = PurePath(safe_name).suffixes
    if len(name_parts) > 1 and any(part.lower() in _DANGEROUS_SUFFIXES for part in name_parts[:-1]):
        findings.append(
            _indicator(
                "Misleading double extension",
                30,
                safe_name,
                "The filename includes a potentially executable extension before its final suffix.",
                "Do not open files with misleading multiple extensions; confirm the actual file "
                "type with the sender.",
            )
        )

    if len(data) > 5 * 1024 * 1024:
        findings.append(
            _indicator(
                "Large file",
                10,
                f"{len(data) / (1024 * 1024):.1f} MB",
                "The file is larger than 5 MB, which warrants extra caution for an unexpected attachment.",
                "Confirm that you expected a file of this size before opening it.",
            )
        )

    extracted_text = ""
    if extension == ".txt":
        extracted_text = _decode_text(data)
    elif extension == ".pdf":
        raw_lower = data[:MAX_TEXT_SCAN_SIZE].lower()
        active_actions = tuple(
            label for marker, label in _PDF_ACTIVE_MARKERS.items() if marker in raw_lower
        )
        if active_actions:
            findings.append(
                _indicator(
                    "PDF active content",
                    30,
                    ", ".join(dict.fromkeys(active_actions)),
                    "The PDF contains JavaScript, an automatic action, a launch action, embedded "
                    "files, or rich media.",
                    "Do not enable or follow active PDF content. Open unexpected PDFs only in a "
                    "protected viewer with scripts and actions disabled.",
                )
            )
        if signature_matches:
            extracted_text = _extract_pdf_text(data)
    elif extension == ".docx" and signature_matches:
        extracted_text, has_macro, archive_limited, invalid_archive = _extract_docx_text(data)
        if archive_limited:
            findings.append(
                _indicator(
                    "Oversized document archive",
                    25,
                    "DOCX archive limits exceeded",
                    "The document has excessive archive entries or expanded content and was not "
                    "fully inspected.",
                    "Do not open this document unless you can verify its source and expected contents.",
                )
            )
        if invalid_archive:
            findings.append(
                _indicator(
                    "Invalid DOCX structure",
                    35,
                    "Required DOCX document content missing or malformed",
                    "The ZIP container does not contain a readable Word document structure.",
                    "Do not open the file. Request a fresh copy from a trusted source.",
                )
            )
        if has_macro:
            findings.append(
                _indicator(
                    "Macro-related content",
                    40,
                    "VBA project data found in DOCX archive",
                    "The document archive contains VBA project data. Macros were not executed.",
                    "Do not enable macros. Request a macro-free copy from a trusted sender.",
                )
            )

    if signature_matches and extension in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"}:
        raw_lower = data[:MAX_TEXT_SCAN_SIZE].lower()
        if b"<script" in raw_lower or b"javascript:" in raw_lower:
            findings.append(
                _indicator(
                    "Active content marker in image",
                    30,
                    "Script-like marker found in image bytes",
                    "The image contains script-like text in its raw data, which may indicate "
                    "unexpected embedded content.",
                    "Do not open or preview this unexpected image in an untrusted application.",
                )
            )

    if extracted_text:
        _add_text_indicators(extracted_text, findings)

    score = min(sum(finding.points for finding in findings), 100)
    level = "LOW" if score <= 30 else "MEDIUM" if score <= 60 else "HIGH"
    guessed_mime = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    return FileAssessment(
        filename=safe_name,
        extension=extension,
        mime_type=declared_mime or guessed_mime,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        score=score,
        level=level,
        indicators=tuple(findings),
        extracted_text=extracted_text[:500],
    )