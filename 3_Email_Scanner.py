import html
import sqlite3

import streamlit as st

from database.history_repository import initialize_history, record_scan
from scanners.email_scanner import EmailAssessment, analyze_email


def _render_assessment(assessment: EmailAssessment) -> None:
    level = assessment.level.lower()
    st.markdown(
        f"""
        <div class="email-score-card">
            <div class="email-score-label">EMAIL RISK SCORE</div>
            <div class="email-score-value email-risk-{level}">
                {assessment.score}<span> / 100</span>
            </div>
            <div class="email-risk-pill email-risk-{level}">{assessment.level} RISK</div>
            <div class="email-score-track">
                <div class="email-score-fill fill-{level}" style="width: {assessment.score}%"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="email-section-title">Detected indicators</div>', unsafe_allow_html=True)
    if assessment.indicators:
        for indicator in assessment.indicators:
            st.markdown(
                f"""
                <div class="email-indicator">
                    <div class="email-indicator-heading">
                        <strong>{html.escape(indicator.category)}</strong>
                        <span>+{indicator.points} points</span>
                    </div>
                    <div class="email-indicator-copy">{html.escape(indicator.explanation)}</div>
                    <div class="email-evidence">Evidence: {html.escape(", ".join(indicator.evidence))}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div class="email-empty">No configured warning indicators were detected.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="email-section-title">Links found in email</div>', unsafe_allow_html=True)
    if assessment.links_found:
        for link in assessment.links_found:
            suspicious = link in assessment.suspicious_links
            status = "Suspicious" if suspicious else "Review"
            tone = "high" if suspicious else "neutral"
            st.markdown(
                f"""
                <div class="email-link-row">
                    <code>{html.escape(link)}</code>
                    <span class="email-link-status status-{tone}">{status}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown('<div class="email-empty">No links detected.</div>', unsafe_allow_html=True)

    st.markdown('<div class="email-section-title">Security recommendations</div>', unsafe_allow_html=True)
    for recommendation in assessment.recommendations:
        st.markdown(
            f'<div class="email-recommendation">{html.escape(recommendation)}</div>',
            unsafe_allow_html=True,
        )
    st.caption(
        "Local rule-based analysis only. Links are not visited. A low score does not guarantee "
        "that an email is safe."
    )


def _risk_summary(assessment: EmailAssessment) -> str:
    categories = (
        ", ".join(indicator.category for indicator in assessment.indicators)
        if assessment.indicators
        else "no configured warning indicators"
    )
    return f"Email scan {assessment.level} ({assessment.score}/100): {categories}"[:240]


st.set_page_config(
    page_title="Email Scanner | CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <div class="email-page-heading">
        <div class="email-eyebrow">CYBERGUARD AI &nbsp; / &nbsp; EMAIL ANALYSIS</div>
        <h1>Email security scanner</h1>
        <p>Review sender details and email content for common phishing and scam indicators.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.form("email_scan_form"):
    sender_address = st.text_input(
        "Sender email address",
        placeholder="sender@example.com",
    )
    email_subject = st.text_input(
        "Email subject",
        placeholder="Your account requires attention",
    )
    email_body = st.text_area(
        "Email body",
        height=200,
        placeholder="Paste the email body here...",
        help="Email content is analyzed locally. Links are extracted but never opened.",
    )
    submitted = st.form_submit_button("Analyze email", use_container_width=True)

if submitted:
    try:
        assessment = analyze_email(sender_address, email_subject, email_body)
    except ValueError as error:
        st.error(str(error))
    else:
        _render_assessment(assessment)
        try:
            initialize_history()
            history_target = f"{assessment.sender} | {assessment.subject or '(no subject)'}"
            record_scan(
                scan_type="email",
                target=history_target[:500],
                risk_level=assessment.level,
                summary=_risk_summary(assessment),
            )
        except (OSError, sqlite3.Error) as error:
            st.warning(f"The email was analyzed, but its result could not be saved to scan history: {error}")
        else:
            st.success("Email scan saved to local scan history.")