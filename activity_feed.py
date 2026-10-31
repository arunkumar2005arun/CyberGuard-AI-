import html
from datetime import datetime

import streamlit as st

from components.risk_badge import risk_badge_html
from services.dashboard_service import DashboardData


def _format_timestamp(value: str) -> str:
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return value
    return timestamp.astimezone().strftime("%b %d, %Y · %I:%M %p")


def render_activity_feed(data: DashboardData) -> None:
    st.markdown('<div class="section-title">Recent scan activity</div>', unsafe_allow_html=True)
    if not data.recent_scans:
        st.markdown(
            """
            <div class="empty-state">
                <div class="empty-state-icon">⌁</div>
                <div class="empty-state-title">No scans yet</div>
                <div class="empty-state-copy">
                    Your latest security checks will appear here after your first scan.
                    Choose a scanner from the sidebar to get started.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    for scan in data.recent_scans:
        target = html.escape(scan.target)
        scan_type = html.escape(scan.scan_type.replace("_", " ").title())
        summary = html.escape(scan.summary or "Analysis completed.")
        timestamp = html.escape(_format_timestamp(scan.created_at))
        st.markdown(
            f"""
            <div class="activity-row">
                <div class="activity-main">
                    <div class="activity-type">{scan_type}</div>
                    <div class="activity-target" title="{target}">{target}</div>
                    <div class="activity-summary">{summary}</div>
                </div>
                <div class="activity-meta">
                    {risk_badge_html(scan.risk_level)}
                    <span class="activity-time">{timestamp}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
