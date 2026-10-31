import html
import sqlite3

import streamlit as st

from database.history_repository import initialize_history, record_scan
from scanners.message_scanner import MAX_MESSAGE_LENGTH, MessageAssessment, analyze_message


def _render_assessment(assessment: MessageAssessment) -> None:
    level_class = assessment.level.lower()
    st.markdown(
        f"""
        <div class="message-score-card">
            <div class="message-score-label">MESSAGE RISK SCORE</div>
            <div class="message-score-value risk-{level_class}">
                {assessment.score}<span> / 100</span>
            </div>
            <div class="message-risk-pill risk-{level_class}">{assessment.level} RISK</div>
            <div class="message-score-track">
                <div class="message-score-fill fill-{level_class}" style="width: {assessment.score}%"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="message-section-title">Detected indicators</div>', unsafe_allow_html=True)
    if assessment.indicators:
        for indicator in assessment.indicators:
            evidence = html.escape(", ".join(indicator.evidence))
            st.markdown(
                f"""
                <div class="message-indicator">
                    <div class="message-indicator-heading">
                        <strong>{html.escape(indicator.category)}</strong>
                        <span>+{indicator.points} points</span>
                    </div>
                    <div class="message-indicator-copy">{html.escape(indicator.explanation)}</div>
                    <div class="message-evidence">Evidence: {evidence}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div class="message-empty">No configured warning indicators were detected.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="message-section-title">Links found in message</div>', unsafe_allow_html=True)
    if assessment.links_found:
        for link in assessment.links_found:
            status = "Suspicious" if link in assessment.suspicious_links else "Review"
            status_class = "high" if status == "Suspicious" else "neutral"
            st.markdown(
                f"""
                <div class="message-link-row">
                    <code>{html.escape(link)}</code>
                    <span class="message-link-status status-{status_class}">{status}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown('<div class="message-empty">No links detected.</div>', unsafe_allow_html=True)

    st.markdown('<div class="message-section-title">Safety recommendations</div>', unsafe_allow_html=True)
    for recommendation in assessment.recommendations:
        st.markdown(
            f'<div class="message-recommendation">{html.escape(recommendation)}</div>',
            unsafe_allow_html=True,
        )
    st.caption(
        "Rule-based local analysis only. Links are not visited. A low score does not guarantee "
        "that a message is safe."
    )


def _risk_summary(assessment: MessageAssessment) -> str:
    if assessment.indicators:
        categories = ", ".join(indicator.category for indicator in assessment.indicators)
    else:
        categories = "no configured warning indicators"
    return f"Message scan {assessment.level} ({assessment.score}/100): {categories}"[:240]


st.set_page_config(
    page_title="Message Scanner | CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <div class="message-page-heading">
        <div class="message-eyebrow">CYBERGUARD AI &nbsp; / &nbsp; MESSAGE ANALYSIS</div>
        <h1>Message security scanner</h1>
        <p>Check messages for common scam language, suspicious links, and requests for sensitive information.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.form("message_scan_form"):
    message_text = st.text_area(
        "Paste or enter a text message",
        height=190,
        max_chars=MAX_MESSAGE_LENGTH,
        placeholder="Paste the message you want to check...",
        help="Analysis runs locally using rules. Links in the text are never opened.",
    )
    submitted = st.form_submit_button("Analyze message", width="stretch")

if submitted:
    try:
        assessment = analyze_message(message_text)
    except ValueError as error:
        st.error(str(error))
    else:
        _render_assessment(assessment)
        try:
            initialize_history()
            record_scan(
                scan_type="message",
                target=f"Message ({len(message_text.strip()):,} characters)",
                risk_level=assessment.level,
                summary=_risk_summary(assessment),
            )
        except (OSError, sqlite3.Error) as error:
            st.warning(f"The message was analyzed, but its result could not be saved to scan history: {error}")
        else:
            st.success("Message scan saved to local scan history.")