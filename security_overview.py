import streamlit as st

from database.history_repository import ScanCounts


def render_security_overview(counts: ScanCounts) -> None:
    st.markdown('<div class="section-title">Security overview</div>', unsafe_allow_html=True)
    safe_rate = round((counts.safe / counts.total) * 100) if counts.total else 0
    st.markdown(
        f"""
        <div class="overview-card">
            <div class="overview-heading">Safe scan rate</div>
            <div class="overview-value">{safe_rate}<span>%</span></div>
            <div class="overview-copy">of all analyzed items were rated low risk</div>
            <progress class="overview-progress" value="{safe_rate}" max="100"></progress>
        </div>
        """,
        unsafe_allow_html=True,
    )

    breakdown = (
        ("Safe", counts.safe, "safe"),
        ("Suspicious", counts.suspicious, "suspicious"),
        ("High risk", counts.high_risk, "high"),
    )
    for label, count, tone in breakdown:
        share = round((count / counts.total) * 100) if counts.total else 0
        st.markdown(
            f"""
            <div class="risk-breakdown">
                <div class="breakdown-label">
                    <span><i class="legend-dot dot-{tone}"></i>{label}</span>
                    <strong>{count:,}</strong>
                </div>
                <progress class="breakdown-progress fill-{tone}" value="{share}" max="100"></progress>
            </div>
            """,
            unsafe_allow_html=True,
        )
