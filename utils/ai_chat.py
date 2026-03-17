"""
AI Analysis Chat Component
===========================
Reusable component that adds "Ask AI to analyze" to any page.
Uses text_input + button (not chat_input) so multiple instances
can coexist on the same page across tabs.
"""

import streamlit as st
import os
import json
from openai import OpenAI


def get_openai_client():
    api_key = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
    return OpenAI(api_key=api_key) if api_key else None


def render_ai_analysis(
    results_data,
    context_label: str = "analysis results",
    page_key: str = "default",
    system_context: str = "",
):
    """
    Renders an AI analysis section with a button + follow-up input.

    Args:
        results_data: The data to analyze (dict, str, or DataFrame)
        context_label: Label for what was analyzed
        page_key: Unique key to avoid widget conflicts across tabs/pages
        system_context: Extra system prompt context
    """
    st.markdown("---")
    st.markdown("### 🤖 AI-Powered Analysis")

    client = get_openai_client()
    if client is None:
        st.info("OpenAI API key not configured. Add it to use AI-powered analysis.")
        return

    # Convert results to string context
    if hasattr(results_data, "to_string"):
        results_str = results_data.head(50).to_string()
    elif isinstance(results_data, (dict, list)):
        results_str = json.dumps(results_data, indent=2, default=str)[:8000]
    else:
        results_str = str(results_data)[:8000]

    # Session keys
    chat_key = f"ai_chat_{page_key}"
    if chat_key not in st.session_state:
        st.session_state[chat_key] = []

    # Auto-analyze button (only shows if no chat yet)
    if not st.session_state[chat_key]:
        if st.button(f"🧠 Ask AI to analyze these {context_label}", key=f"ai_btn_{page_key}"):
            auto_prompt = (
                f"Analyze the following {context_label} and provide:\n"
                f"1. Key findings and observations\n"
                f"2. Potential security concerns or threats identified\n"
                f"3. Recommended actions for a SOC analyst\n"
                f"4. Any patterns or anomalies worth investigating further\n\n"
                f"Be concise and actionable."
            )
            _run_ai_query(client, chat_key, auto_prompt, results_str, context_label, system_context)
            st.rerun()
    else:
        # Display conversation history
        for msg in st.session_state[chat_key]:
            avatar = "🕵️" if msg["role"] == "assistant" else "👤"
            with st.chat_message(msg["role"], avatar=avatar):
                st.markdown(msg["content"])

        # Follow-up input
        col_input, col_send, col_clear = st.columns([7, 1, 1])
        with col_input:
            followup = st.text_input(
                "Ask a follow-up question",
                placeholder=f"Ask about the {context_label}...",
                key=f"ai_followup_{page_key}",
                label_visibility="collapsed",
            )
        with col_send:
            send = st.button("Send", key=f"ai_send_{page_key}", use_container_width=True)
        with col_clear:
            clear = st.button("Clear", key=f"ai_clear_{page_key}", use_container_width=True)

        if send and followup:
            _run_ai_query(client, chat_key, followup, results_str, context_label, system_context)
            st.rerun()

        if clear:
            st.session_state[chat_key] = []
            st.rerun()


def _run_ai_query(client, chat_key, user_message, results_str, context_label, system_context):
    """Execute an AI query and store the result in session state."""
    st.session_state[chat_key].append({"role": "user", "content": user_message})

    system_prompt = (
        "You are a Senior Cyber Threat Intelligence Analyst reviewing security analysis data. "
        "Be concise, structured, and actionable. Use markdown formatting with headers and bullet points. "
        f"{system_context}\n\n"
        f"Here is the {context_label} data:\n"
        f"```\n{results_str}\n```"
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                *st.session_state[chat_key],
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        reply = response.choices[0].message.content
        st.session_state[chat_key].append({"role": "assistant", "content": reply})
    except Exception as e:
        error_msg = f"⚠️ Error communicating with AI: {str(e)}"
        st.session_state[chat_key].append({"role": "assistant", "content": error_msg})
