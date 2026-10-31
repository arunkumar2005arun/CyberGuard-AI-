import html
import sqlite3

import streamlit as st

from core.risk_scoring import RiskAssessment, score_url_features
from database.history_repository import initialize_history, record_scan
from scanners.url_scanner import MAX_URL_LENGTH, URLFeatures, extract_url_features


def _render_feature(label: str, value: str, detail: str, tone: str = "purple") -> None:
    st.markdown(
        f"""
        <div class="url-feature-card">
            <div class="url-feature-label">{html.escape(label)}</div>
            <div class="url-feature-value tone-{tone}">{html.escape(value)}</div>
            <div class="url-feature-detail">{html.escape(detail)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_features(features: URLFeatures) -> None:
    keywords = ", ".join(features.suspicious_keywords) or "None detected"
    keyword_detail = (
        f"{len(features.suspicious_keywords)} keyword(s) found in the URL"
        if features.suspicious_keywords
        else "No configured keywords found"
    )
    first_row = st.columns(3, gap="medium")
    with first_row[0]:
        _render_feature("DOMAIN", features.domain, "Host name extracted from the URL")
    with first_row[1]:
        _render_feature(
            "HTTPS",
            "Enabled" if features.https_enabled else "Not enabled",
            "Connection scheme",
            "green" if features.https_enabled else "amber",
        )
    with first_row[2]:
        _render_feature("URL LENGTH", f"{features.total_length} characters", "Total entered URL length")

    second_row = st.columns(3, gap="medium")
    with second_row[0]:
        _render_feature(
            "IP ADDRESS HOST",
            "Yes" if features.uses_ip_address else "No",
            "Whether the host is an IP address instead of a domain",
            "amber" if features.uses_ip_address else "green",
        )
    with second_row[1]:
        _render_feature("SUSPICIOUS KEYWORDS", keywords, keyword_detail, "amber" if features.suspicious_keywords else "green")
    with second_row[2]:
        _render_feature(
            "CREDENTIALS IN URL",
            "Yes" if features.has_credentials else "No",
            "Whether the URL contains embedded user information",
            "amber" if features.has_credentials else "green",
        )


def _render_risk_assessment(assessment: RiskAssessment) -> None:
    level_class = assessment.level.lower().replace(" ", "-")
    st.markdown('<div class="url-section-title">Risk assessment</div>', unsafe_allow_html=True)
    st.markdown(
        f"""
        <div class="risk-assessment-card">
            <div class="risk-assessment-heading">Heuristic risk score</div>
            <div class="risk-assessment-value risk-{level_class}">
                {assessment.score}<span> / 100</span>
            </div>
            <div class="risk-assessment-level risk-{level_class}">{html.escape(assessment.level)}</div>
            <div class="risk-score-track">
                <div class="risk-score-fill risk-fill-{level_class}" style="width: {assessment.score}%"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="url-section-title">Indicators affecting this score</div>', unsafe_allow_html=True)
    if assessment.findings:
        for finding in assessment.findings:
            st.markdown(
                f"""
                <div class="risk-finding">
                    <div class="risk-finding-topline">
                        <strong>{html.escape(finding.indicator)}</strong>
                        <span>+{finding.points} points</span>
                    </div>
                    <div class="risk-finding-explanation">{html.escape(finding.explanation)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div class="risk-finding">No configured risk indicators increased this score.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="url-section-title">Security recommendations</div>', unsafe_allow_html=True)
    for recommendation in assessment.recommendations:
        st.markdown(
            f'<div class="risk-recommendation">{html.escape(recommendation)}</div>',
            unsafe_allow_html=True,
        )
    if sum(finding.points for finding in assessment.findings) > assessment.score:
        st.caption("The combined indicator points were capped at 100.")
    st.caption(
        "This is a heuristic estimate, not a guarantee that a URL is malicious or safe. "
        "Analysis is local; the submitted URL is never visited."
    )


def _build_risk_summary(assessment: RiskAssessment) -> str:
    if assessment.findings:
        indicators = ", ".join(finding.indicator for finding in assessment.findings)
    else:
        indicators = "no configured indicators detected"
    return f"{assessment.level} ({assessment.score}/100): {indicators}"[:240]


st.set_page_config(
    page_title="URL Scanner | CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <div class="url-page-heading">
        <div class="url-eyebrow">CYBERGUARD AI &nbsp; / &nbsp; URL ANALYSIS</div>
        <h1>URL feature extraction</h1>
        <p>Inspect URL structure and indicators with local, offline analysis.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="url-section-title">Analyze a URL</div>', unsafe_allow_html=True)
with st.form("url_feature_form"):
    url_input = st.text_input(
        "Website URL",
        placeholder="https://example.com/account",
        max_chars=MAX_URL_LENGTH,
        help="Enter a complete URL beginning with http:// or https://.",
    )
    submitted = st.form_submit_button("Extract URL features", width="stretch")

if submitted:
    try:
        extracted_features = extract_url_features(url_input)
    except ValueError as error:
        st.error(str(error))
    else:
        assessment = score_url_features(extracted_features)
        st.markdown('<div class="url-section-title">Extracted features</div>', unsafe_allow_html=True)
        _render_features(extracted_features)
        _render_risk_assessment(assessment)
        try:
            initialize_history()
            history_target = (
                f"{'https' if extracted_features.https_enabled else 'http'}://"
                f"{extracted_features.domain}"
            )
            record_scan(
                scan_type="url",
                target=history_target,
                risk_level=assessment.level.split()[0].upper(),
                summary=_build_risk_summary(assessment),
            )
        except (OSError, sqlite3.Error) as error:
            st.warning(f"The URL was analyzed, but its result could not be saved to scan history: {error}")
        else:
            st.success("Scan result saved to local scan history.")
        st.markdown(
            '<div class="url-notice">This check only parses the text you entered. It does not visit or execute the URL.</div>',
            unsafe_allow_html=True,
        )
