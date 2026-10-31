from collections.abc import Callable

import streamlit as st


def get_pages(dashboard: Callable[[], None]) -> list[st.Page]:
    return [
        st.Page(dashboard, title="Dashboard", icon="🛡️", default=True),
        st.Page("pages/1_URL_Scanner.py", title="URL Scanner", icon="🔗"),
        st.Page("pages/2_Message_Scanner.py", title="Message Scanner", icon="💬"),
        st.Page("pages/3_Email_Scanner.py", title="Email Scanner", icon="✉️"),
        st.Page("pages/4_File_Scanner.py", title="File Scanner", icon="📁"),
        st.Page("pages/5_Scan_History.py", title="Scan History", icon="🕘"),
    ]


def render_sidebar_brand() -> None:
    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-brand">
                <div class="sidebar-brand-icon">🛡</div>
                <div><strong>CyberGuard</strong><span>AI SECURITY CENTER</span></div>
            </div>
            <div class="sidebar-nav-label">WORKSPACE</div>
            """,
            unsafe_allow_html=True,
        )


def render_sidebar_status() -> None:
    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-status">
                <span class="sidebar-status-dot"></span>
                <div><strong>System status</strong><span>Local analysis active</span></div>
                <b>READY</b>
            </div>
            """,
            unsafe_allow_html=True,
        )
