"""
📋 Investigation Log Page
View and export the conversation history and enrichment results.
"""

import streamlit as st
import json
import csv
import io
from datetime import datetime

st.set_page_config(page_title="Investigation Log", page_icon="📋", layout="wide")
st.title("📋 Investigation Log")
st.markdown("Review, search, and export your threat hunting session history.")

# ── Session Log ─────────────────────────────────────────────────────
if "investigation_log" not in st.session_state or not st.session_state.investigation_log:
    st.info("No investigation activity yet. Start chatting on the main page!")
else:
    logs = st.session_state.investigation_log

    # Search filter
    search = st.text_input("🔍 Filter logs", placeholder="Search by query or response...")

    filtered = logs
    if search:
        filtered = [
            log for log in logs
            if search.lower() in log.get("query", "").lower()
            or search.lower() in log.get("response_preview", "").lower()
        ]

    st.markdown(f"**{len(filtered)} entries**")

    for i, log in enumerate(reversed(filtered)):
        with st.expander(f"🕐 {log['timestamp']} — {log['query'][:80]}...", expanded=(i == 0)):
            st.markdown(f"**Query:** {log['query']}")
            st.markdown(f"**Response Preview:** {log['response_preview']}...")

    # ── Export ───────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### Export")

    col1, col2 = st.columns(2)

    with col1:
        json_export = json.dumps(logs, indent=2)
        st.download_button(
            "⬇️ Export as JSON",
            json_export,
            file_name=f"investigation_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

    with col2:
        # CSV export
        output = io.StringIO()
        if logs:
            writer = csv.DictWriter(output, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)
        st.download_button(
            "⬇️ Export as CSV",
            output.getvalue(),
            file_name=f"investigation_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

# ── Chat History ────────────────────────────────────────────────────
st.markdown("---")
st.markdown("### 💬 Full Chat History")

if "messages" not in st.session_state or not st.session_state.messages:
    st.info("No chat messages yet.")
else:
    for msg in st.session_state.messages:
        role = "🕵️ Assistant" if msg["role"] == "assistant" else "👤 You"
        with st.expander(f"{role}: {msg['content'][:100]}..."):
            st.markdown(msg["content"])
