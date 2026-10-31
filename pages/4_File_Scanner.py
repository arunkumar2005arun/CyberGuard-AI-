import html
import sqlite3

import streamlit as st

from database.history_repository import initialize_history, record_scan
from scanners.file_scanner import FileAssessment, analyze_file


def _render_assessment(assessment: FileAssessment) -> None:
    level = assessment.level.lower()
    st.markdown(
        f"""
        <div class="file-score-card">
            <div class="file-score-label">FILE RISK SCORE</div>
            <div class="file-score-value file-risk-{level}">
                {assessment.score}<span> / 100</span>
            </div>
            <div class="file-risk-pill file-risk-{level}">{assessment.level} RISK</div>
            <div class="file-score-track">
                <div class="file-score-fill fill-{level}" style="width: {assessment.score}%"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="file-section-title">File details</div>', unsafe_allow_html=True)
    details = st.columns(3)
    with details[0]:
        st.markdown(
            f'<div class="file-detail-card"><span>FILE TYPE</span><strong>{html.escape(assessment.extension.upper()[1:])}</strong></div>',
            unsafe_allow_html=True,
        )
    with details[1]:
        st.markdown(
            f'<div class="file-detail-card"><span>SIZE</span><strong>{assessment.size_bytes:,} bytes</strong></div>',
            unsafe_allow_html=True,
        )
    with details[2]:
        st.markdown(
            f'<div class="file-detail-card"><span>MIME TYPE</span><strong>{html.escape(assessment.mime_type)}</strong></div>',
            unsafe_allow_html=True,
        )
    st.markdown(
        f'<div class="file-hash-card"><span>SHA-256</span><code>{assessment.sha256}</code></div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="file-section-title">Detected indicators</div>', unsafe_allow_html=True)
    if assessment.indicators:
        for indicator in assessment.indicators:
            st.markdown(
                f"""
                <div class="file-indicator">
                    <div class="file-indicator-heading">
                        <strong>{html.escape(indicator.category)}</strong>
                        <span>+{indicator.points} points</span>
                    </div>
                    <div class="file-indicator-copy">{html.escape(indicator.explanation)}</div>
                    <div class="file-evidence">Evidence: {html.escape(", ".join(indicator.evidence))}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div class="file-empty">No configured warning indicators were detected.</div>',
            unsafe_allow_html=True,
        )

    if assessment.extracted_text:
        with st.expander("View limited text extracted for static checks"):
            st.code(assessment.extracted_text, language=None)

    st.markdown('<div class="file-section-title">Security recommendations</div>', unsafe_allow_html=True)
    for recommendation in assessment.recommendations:
        st.markdown(
            f'<div class="file-recommendation">{html.escape(recommendation)}</div>',
            unsafe_allow_html=True,
        )
    st.caption(
        "Local static analysis only. The file is not executed, macros are never run, and "
        "nothing is uploaded to an external service. This check cannot guarantee a file is safe."
    )


def _risk_summary(assessment: FileAssessment) -> str:
    categories = (
        ", ".join(indicator.category for indicator in assessment.indicators)
        if assessment.indicators
        else "no configured warning indicators"
    )
    return f"File scan {assessment.level} ({assessment.score}/100): {categories}"[:240]


st.set_page_config(
    page_title="File Scanner | CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <div class="file-page-heading">
        <div class="file-eyebrow">CYBERGUARD AI &nbsp; / &nbsp; FILE ANALYSIS</div>
        <h1>File security scanner</h1>
        <p>Inspect supported files for suspicious content using safe, local static checks.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

uploaded_file = st.file_uploader(
    "Choose a PDF, TXT, DOCX, or common image file",
    type=["pdf", "txt", "docx", "png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp"],
    max_upload_size=10,
    help="Maximum file size: 10 MB. Files are analyzed locally and are never executed or uploaded elsewhere.",
)

if uploaded_file is not None:
    st.caption(
        f"Selected: {uploaded_file.name} · {uploaded_file.size:,} bytes · "
        f"{uploaded_file.type or 'MIME type not provided'}"
    )

if st.button("Scan file", use_container_width=True, disabled=uploaded_file is None):
    try:
        file_content = uploaded_file.getvalue()
        assessment = analyze_file(
            filename=uploaded_file.name,
            mime_type=uploaded_file.type,
            data=file_content,
        )
    except ValueError as error:
        st.error(str(error))
    else:
        _render_assessment(assessment)
        try:
            initialize_history()
            record_scan(
                scan_type="file",
                target=f"{assessment.filename} | SHA-256 {assessment.sha256}",
                risk_level=assessment.level,
                summary=_risk_summary(assessment),
            )
        except (OSError, sqlite3.Error) as error:
            st.warning(f"The file was analyzed, but its result could not be saved to scan history: {error}")
        else:
            st.success("File scan saved to local scan history.")