import html

import streamlit as st


def risk_badge_html(risk_level: str) -> str:
    normalized = risk_level.strip().upper()
    if normalized not in {"LOW", "MEDIUM", "HIGH"}:
        normalized = "UNKNOWN"
    label = html.escape(normalized.title())
    return f'<span class="risk-badge risk-{normalized.lower()}">{label}</span>'


def render_risk_badge(risk_level: str) -> None:
    st.markdown(risk_badge_html(risk_level), unsafe_allow_html=True)