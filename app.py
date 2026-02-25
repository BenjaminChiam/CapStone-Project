"""
🛡️ Cyber Security Threat Hunt Assistant
Main Streamlit Application

A conversational AI-powered threat hunting assistant that helps SOC analysts
with IOC analysis, MITRE ATT&CK mapping, and Sigma rule generation.
"""

import streamlit as st
import json
import os
from datetime import datetime
from openai import OpenAI
from utils.ioc_enrich import IOCEnricher
from utils.mitre_mapper import MITREMapper
from utils.sigma_generator import SigmaGenerator
from utils.ml_engine import ThreatClusterer

# ── Page Configuration ──────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Hunt Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS (Glass-morphism SOC dark theme) ──────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');

    /* Global */
    .stApp {
        background: linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0d1321 100%);
    }

    /* Chat messages */
    .stChatMessage {
        background: rgba(17, 24, 39, 0.7) !important;
        backdrop-filter: blur(12px);
        border: 1px solid rgba(56, 189, 248, 0.08);
        border-radius: 12px;
        padding: 1rem;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: rgba(15, 23, 42, 0.95);
        border-right: 1px solid rgba(56, 189, 248, 0.1);
    }

    /* Headers */
    h1, h2, h3 {
        font-family: 'Inter', sans-serif !important;
    }

    /* Code blocks */
    code, .stCode {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #1e3a5f, #0ea5e9) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.3s ease !important;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #0ea5e9, #38bdf8) !important;
        box-shadow: 0 0 20px rgba(14, 165, 233, 0.3) !important;
    }

    /* Text inputs */
    .stTextInput > div > div > input,
    .stChatInput > div > div > textarea {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(56, 189, 248, 0.2) !important;
        color: #e2e8f0 !important;
        border-radius: 8px !important;
    }

    /* JSON display */
    .stJson {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid rgba(56, 189, 248, 0.1) !important;
        border-radius: 8px !important;
    }

    /* Metrics */
    [data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(56, 189, 248, 0.1);
        border-radius: 10px;
        padding: 12px;
    }

    /* Status banner */
    .status-banner {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-radius: 8px;
        padding: 8px 16px;
        color: #6ee7b7;
        font-size: 0.85rem;
        text-align: center;
        margin-bottom: 1rem;
    }

    /* Threat level badges */
    .threat-critical { color: #ef4444; font-weight: 700; }
    .threat-high { color: #f97316; font-weight: 700; }
    .threat-medium { color: #eab308; font-weight: 700; }
    .threat-low { color: #22c55e; font-weight: 700; }
</style>
""", unsafe_allow_html=True)


# ── Initialize Services ─────────────────────────────────────────────
@st.cache_resource
def init_openai():
    """Initialize OpenAI client from Streamlit secrets or env."""
    api_key = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
    if not api_key:
        return None
    return OpenAI(api_key=api_key)


@st.cache_resource
def init_enricher():
    """Initialize IOC Enricher with API keys."""
    return IOCEnricher(
        vt_api_key=st.secrets.get("VIRUSTOTAL_API_KEY", os.getenv("VIRUSTOTAL_API_KEY", "")),
        shodan_api_key=st.secrets.get("SHODAN_API_KEY", os.getenv("SHODAN_API_KEY", "")),
        abuseipdb_api_key=st.secrets.get("ABUSEIPDB_API_KEY", os.getenv("ABUSEIPDB_API_KEY", "")),
    )


@st.cache_resource
def init_mitre_mapper():
    """Initialize MITRE Mapper."""
    api_key = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
    return MITREMapper(openai_api_key=api_key)


@st.cache_resource
def init_sigma_generator():
    """Initialize Sigma Rule Generator."""
    return SigmaGenerator()


@st.cache_resource
def init_clusterer():
    """Initialize ML Threat Clusterer."""
    return ThreatClusterer()


client = init_openai()
enricher = init_enricher()
mitre_mapper = init_mitre_mapper()
sigma_gen = init_sigma_generator()
clusterer = init_clusterer()

# ── System Prompt ───────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a Senior Cyber Threat Intelligence (CTI) Analyst embedded in a Security Operations Centre (SOC). Your name is **HuntBot**.

Your capabilities:
1. **IOC Analysis** — Analyze IPs, domains, file hashes, and URLs for malicious indicators.
2. **MITRE ATT&CK Mapping** — Map observed behaviors to MITRE Tactics, Techniques, and Procedures (TTPs) with clear reasoning.
3. **Threat Hunting Hypotheses** — Generate data-driven threat hunting hypotheses based on IOCs and TTPs.
4. **Detection Engineering** — Draft Sigma rules, YARA rules, and KQL/SPL queries.
5. **Threat Actor Profiling** — Provide intelligence on known APT groups, malware families, and campaigns.
6. **Incident Response Guidance** — Advise on containment, eradication, and recovery steps.

Response guidelines:
- Always be structured and actionable. SOC analysts need clarity, not essays.
- When analyzing IOCs, consider: reputation scores, open ports, passive DNS, WHOIS, SSL/TLS certificates, geolocation, ASN, and behavioral indicators.
- When mapping to MITRE ATT&CK, ALWAYS provide a "Reasoning" explanation.
- Use markdown formatting: headers, tables, and code blocks for detection rules.
- If you are unsure, say so. Never fabricate MITRE Technique IDs or threat intel.
- Prioritize actionable output: detection rules, hunting queries, and IOC verdicts.

Current date: """ + datetime.now().strftime("%Y-%m-%d")


# ── Session State ───────────────────────────────────────────────────
if "messages" not in st.session_state:
    st.session_state.messages = []
if "enrichment_results" not in st.session_state:
    st.session_state.enrichment_results = None
if "investigation_log" not in st.session_state:
    st.session_state.investigation_log = []


# ── Sidebar: Quick IOC Tools ───────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Threat Hunt Assistant")
    st.markdown('<div class="status-banner">🟢 System Online</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🔧 Quick IOC Tools")

    ioc_input = st.text_input(
        "Enter IOC",
        placeholder="IP / Domain / Hash / URL",
        help="Paste an indicator of compromise for instant analysis",
    )

    col1, col2 = st.columns(2)

    with col1:
        enrich_btn = st.button("🔍 Enrich", use_container_width=True)
    with col2:
        mitre_btn = st.button("🎯 MITRE Map", use_container_width=True)

    col3, col4 = st.columns(2)
    with col3:
        sigma_btn = st.button("📝 Sigma Rule", use_container_width=True)
    with col4:
        clear_btn = st.button("🗑️ Clear Chat", use_container_width=True)

    # ── Handle sidebar actions ──
    if enrich_btn and ioc_input:
        with st.spinner("Enriching IOC..."):
            results = enricher.enrich(ioc_input)
            st.session_state.enrichment_results = results
            st.json(results)

            # Also push to chat
            summary = f"**IOC Enrichment Results for `{ioc_input}`:**\n```json\n{json.dumps(results, indent=2)}\n```"
            st.session_state.messages.append({"role": "assistant", "content": summary})

    if mitre_btn and ioc_input:
        with st.spinner("Mapping to MITRE ATT&CK..."):
            mapping = mitre_mapper.map_ioc(ioc_input, st.session_state.enrichment_results)
            st.json(mapping)

    if sigma_btn and ioc_input:
        with st.spinner("Generating Sigma rule..."):
            rule = sigma_gen.generate(ioc_input)
            st.code(rule, language="yaml")
            st.download_button(
                "⬇️ Download .yml",
                rule,
                file_name=f"sigma_{ioc_input.replace('.', '_')}.yml",
                mime="text/yaml",
            )

    if clear_btn:
        st.session_state.messages = []
        st.session_state.enrichment_results = None
        st.rerun()

    # ── Sidebar footer ──
    st.markdown("---")
    st.markdown("### ⚙️ Configuration")
    model_choice = st.selectbox("LLM Model", ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"])
    temperature = st.slider("Temperature", 0.0, 1.0, 0.1, 0.05)
    st.markdown("---")
    st.caption("Built for Ensign InfoSecurity SOC · Capstone Project 2025-2026")


# ── Main Chat Interface ─────────────────────────────────────────────
st.markdown("# 🛡️ Threat Hunt Assistant")
st.markdown("Ask me about IOCs, threat actors, MITRE ATT&CK techniques, detection rules, or paste indicators for analysis.")

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"], avatar="🕵️" if message["role"] == "assistant" else "👤"):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Paste an IOC or ask a threat hunting question..."):
    # Add user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user", avatar="👤"):
        st.markdown(prompt)

    # Generate response
    with st.chat_message("assistant", avatar="🕵️"):
        if client is None:
            st.warning(
                "⚠️ OpenAI API key not configured. Add it to `.streamlit/secrets.toml` "
                "or set the `OPENAI_API_KEY` environment variable."
            )
            response_text = "I need an OpenAI API key to function. Please configure it in the settings."
        else:
            # Build messages payload
            api_messages = [{"role": "system", "content": SYSTEM_PROMPT}]

            # Include enrichment context if available
            if st.session_state.enrichment_results:
                context = (
                    f"[ENRICHMENT CONTEXT] The user previously enriched this IOC. "
                    f"Results: {json.dumps(st.session_state.enrichment_results, indent=2)}"
                )
                api_messages.append({"role": "system", "content": context})

            # Add conversation history (keep last 20 messages for context window)
            for msg in st.session_state.messages[-20:]:
                api_messages.append({"role": msg["role"], "content": msg["content"]})

            try:
                stream = client.chat.completions.create(
                    model=model_choice,
                    messages=api_messages,
                    stream=True,
                    temperature=temperature,
                    max_tokens=4096,
                )
                response_text = st.write_stream(stream)
            except Exception as e:
                response_text = f"⚠️ Error communicating with OpenAI: {str(e)}"
                st.error(response_text)

    st.session_state.messages.append({"role": "assistant", "content": response_text})

    # Log investigation activity
    st.session_state.investigation_log.append({
        "timestamp": datetime.now().isoformat(),
        "query": prompt,
        "response_preview": response_text[:200],
    })
