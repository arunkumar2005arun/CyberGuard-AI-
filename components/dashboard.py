import sqlite3

import streamlit as st

from components.activity_feed import render_activity_feed
from components.header import render_header
from components.metric_card import render_metric_card
from components.security_overview import render_security_overview
from services.dashboard_service import load_dashboard_data


def render_dashboard() -> None:
    try:
        data = load_dashboard_data()
    except (OSError, sqlite3.Error) as error:
        st.error(f"Unable to load scan history from the local database: {error}")
        st.stop()

    render_header(
        "Security dashboard",
        "Your local security activity, risk signals, and recent scan results.",
    )

    left, right = st.columns([5, 1])
    with left:
        st.markdown(
            """
            <section class="dashboard-hero">
                <div class="hero-copy">
                    <div class="hero-eyebrow">YOUR SECURITY, AT A GLANCE</div>
                    <h2>Stay one step ahead<br>of digital threats.</h2>
                    <p>Run a quick local check on a link, message, email, or file.</p>
                    <div class="hero-status"><span class="live-dot"></span>LOCAL ANALYSIS ACTIVE</div>
                </div>
                <div class="hero-shield" aria-hidden="true">
                    <svg viewBox="0 0 160 180" role="img">
                        <path d="M80 8 143 31v47c0 43-25 73-63 94C42 151 17 121 17 78V31L80 8Z"
                              fill="url(#shieldFill)" stroke="#168BFF" stroke-width="4"/>
                        <path d="M80 25 126 42v36c0 33-18 56-46 73-28-17-46-40-46-73V42l46-17Z"
                              fill="#061B49" stroke="#FF8A00" stroke-width="2"/>
                        <path d="m55 84 17 17 34-38" fill="none" stroke="#fff" stroke-linecap="round"
                              stroke-linejoin="round" stroke-width="8"/>
                        <defs>
                            <linearGradient id="shieldFill" x1="20" y1="15" x2="140" y2="160">
                                <stop stop-color="#168BFF"/><stop offset="1" stop-color="#061B49"/>
                            </linearGradient>
                        </defs>
                    </svg>
                    <span>PROTECTED<br>BY LOCAL ANALYSIS</span>
                </div>
            </section>
            """,
            unsafe_allow_html=True,
        )
    with right:
        if st.button("↻  Refresh", width="stretch"):
            st.rerun()

    metric_columns = st.columns(4, gap="medium")
    metrics = (
        ("Total scans", data.counts.total, "⌕", "total"),
        ("Safe", data.counts.safe, "✓", "safe"),
        ("Suspicious", data.counts.suspicious, "◈", "suspicious"),
        ("High risk", data.counts.high_risk, "!", "high"),
    )
    for column, metric in zip(metric_columns, metrics):
        with column:
            render_metric_card(*metric)

    st.markdown('<div class="section-title">Quick scan</div>', unsafe_allow_html=True)
    scanner_columns = st.columns(4, gap="medium")
    scanners = (
        ("pages/1_URL_Scanner.py", "URL Scanner", "🔗", "Check a link for suspicious patterns."),
        ("pages/2_Message_Scanner.py", "Message Scanner", "💬", "Review text for scam signals."),
        ("pages/3_Email_Scanner.py", "Email Scanner", "✉️", "Inspect sender details and content."),
        ("pages/4_File_Scanner.py", "File Scanner", "📁", "Analyze a file using static checks."),
    )
    for column, (page, label, icon, description) in zip(scanner_columns, scanners):
        with column:
            with st.container(border=True):
                st.page_link(page, label=label, icon=icon)
                st.markdown(
                    f'<div class="quick-scan-copy">{description}</div>',
                    unsafe_allow_html=True,
                )

    activity_column, overview_column = st.columns([1.65, 1], gap="large")
    with activity_column:
        render_activity_feed(data)
    with overview_column:
        render_security_overview(data.counts)
        st.markdown(
            """
            <div class="tips-panel">
                <div class="tips-heading"><span>✦</span> Security tips</div>
                <ul>
                    <li>Pause before acting on urgent messages or unexpected offers.</li>
                    <li>Check a link's domain before entering account information.</li>
                    <li>Only open files you expected from a trusted source.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        '<div class="footer-note">Scan records are stored locally on this device. '
        'Risk estimates are heuristic and may not identify every threat.</div>',
        unsafe_allow_html=True,
    )
