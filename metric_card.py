import html

import streamlit as st


def render_metric_card(label: str, value: int, icon: str, tone: str) -> None:
    st.markdown(
        f"""
        <div class="metric-card metric-{tone}">
            <div class="metric-topline">
                <span class="metric-label">{html.escape(label)}</span>
                <span class="metric-icon">{icon}</span>
            </div>
            <div class="metric-value">{value:,}</div>
            <div class="metric-caption">All-time scan count</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
