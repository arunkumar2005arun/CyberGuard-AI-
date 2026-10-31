import sqlite3
from datetime import datetime

import pandas as pd
import streamlit as st

from database.history_repository import ScanRecord, get_recent_scans, initialize_history


SCAN_TYPES = {
    "URL": "url",
    "Message": "message",
    "Email": "email",
    "File": "file",
}
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH")


def _format_timestamp(value: str) -> str:
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return value
    return timestamp.astimezone().strftime("%b %d, %Y · %I:%M %p")


def _to_table_rows(records: list[ScanRecord]) -> list[dict[str, str]]:
    return [
        {
            "Date / Time": _format_timestamp(record.created_at),
            "Scan Type": record.scan_type.title(),
            "Target": record.target,
            "Risk Level": record.risk_level,
            "Summary": record.summary,
        }
        for record in records
    ]


def render_history_page() -> None:
    st.markdown(
        """
        <div class="history-page-heading">
            <div class="history-eyebrow">CYBERGUARD AI &nbsp; / &nbsp; ACTIVITY</div>
            <h1>Scan history</h1>
            <p>Review and search results from your previous local security scans.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    try:
        initialize_history()
        records = get_recent_scans(limit=None)
    except (OSError, sqlite3.Error) as error:
        st.error(f"Unable to load scan history from the local database: {error}")
        return

    st.markdown(
        f"""
        <div class="history-total-card">
            <span class="history-total-label">TOTAL SCAN RECORDS</span>
            <strong>{len(records):,}</strong>
            <span class="history-total-footnote">saved on this device</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    filter_columns = st.columns([1.2, 1, 1.5], gap="medium")
    with filter_columns[0]:
        selected_types = st.multiselect(
            "Scan type",
            options=list(SCAN_TYPES),
            default=list(SCAN_TYPES),
            help="Choose one or more scanner types.",
        )
    with filter_columns[1]:
        selected_risks = st.multiselect(
            "Risk level",
            options=list(RISK_LEVELS),
            default=list(RISK_LEVELS),
        )
    with filter_columns[2]:
        target_query = st.text_input(
            "Search targets",
            placeholder="Search URL, filename, address, or message...",
        )

    allowed_types = {SCAN_TYPES[label] for label in selected_types}
    query = target_query.strip().casefold()
    filtered_records = [
        record
        for record in records
        if record.scan_type in allowed_types
        and record.risk_level in selected_risks
        and query in record.target.casefold()
    ]

    st.markdown(
        f'<div class="history-results-count">Showing <strong>{len(filtered_records):,}</strong> '
        f'of {len(records):,} records</div>',
        unsafe_allow_html=True,
    )

    if not records:
        st.markdown(
            """
            <div class="history-empty">
                <strong>No scans yet</strong>
                <span>Completed URL, message, email, and file scans will appear here.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return
    if not filtered_records:
        st.info("No scan records match the selected filters. Try changing the filters or search term.")
        return

    st.dataframe(
        pd.DataFrame(_to_table_rows(filtered_records)),
        hide_index=True,
        use_container_width=True,
        column_config={
            "Date / Time": st.column_config.TextColumn("Date / Time", width="medium"),
            "Scan Type": st.column_config.TextColumn("Scan Type", width="small"),
            "Target": st.column_config.TextColumn("Target", width="large"),
            "Risk Level": st.column_config.TextColumn("Risk Level", width="small"),
            "Summary": st.column_config.TextColumn("Summary", width="large"),
        },
    )


st.set_page_config(
    page_title="Scan History | CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
)

render_history_page()