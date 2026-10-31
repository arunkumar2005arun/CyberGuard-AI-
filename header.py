import html

import streamlit as st


def render_header(title: str, subtitle: str) -> None:
    safe_title = html.escape(title)
    safe_subtitle = html.escape(subtitle)
    st.markdown(
        f"""
        <div class="page-heading">
            <div class="eyebrow">CYBERGUARD AI &nbsp; / &nbsp; SECURITY CENTER</div>
            <h1>{safe_title}</h1>
            <p>{safe_subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )