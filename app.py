from pathlib import Path

import streamlit as st

from components.dashboard import render_dashboard
from components.navigation import get_pages, render_sidebar_brand, render_sidebar_status


def load_stylesheet() -> None:
    stylesheet_path = Path(__file__).parent / "assets" / "style.css"
    try:
        stylesheet = stylesheet_path.read_text(encoding="utf-8")
    except OSError as error:
        st.error(f"Could not load the dashboard stylesheet: {error}")
        st.stop()
    st.markdown(f"<style>{stylesheet}</style>", unsafe_allow_html=True)


st.set_page_config(
    page_title="CyberGuard AI | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto",
)

load_stylesheet()
pages = get_pages(render_dashboard)
render_sidebar_brand()
navigation = st.navigation(pages)
navigation.run()
render_sidebar_status()
