"""
🧠 CognitiveHunt — AI-Enhanced Threat Intelligence Platform
Main Streamlit Application — Chatbot with Triaging, Environment Awareness,
DGA Detection, Anomaly Detection, and Multi-Source IOC Enrichment.
"""

import streamlit as st
import json
import os
from datetime import datetime
from openai import OpenAI
from utils.ioc_enrich import IOCEnricher
from utils.mitre_mapper import MITREMapper
from utils.sigma_generator import SigmaGenerator
from utils.ml_engine import ThreatClusterer, AnomalyDetector, DGADetector
from utils.mitre_attack_data import TACTICS, get_parent_techniques_by_tactic

# ── Page Configuration ──────────────────────────────────────────────
st.set_page_config(
    page_title="CognitiveHunt",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS (Glass-morphism SOC dark theme) ──────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');
    .stApp {
        background: linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0d1321 100%);
    }
    .stChatMessage {
        background: rgba(17, 24, 39, 0.7) !important;
        backdrop-filter: blur(12px);
        border: 1px solid rgba(56, 189, 248, 0.08);
        border-radius: 12px;
        padding: 1rem;
    }
    section[data-testid="stSidebar"] {
        background: rgba(15, 23, 42, 0.95);
        border-right: 1px solid rgba(56, 189, 248, 0.1);
    }
    h1, h2, h3 { font-family: 'Inter', sans-serif !important; }
    code, .stCode { font-family: 'JetBrains Mono', monospace !important; }
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
    .stTextInput > div > div > input,
    .stChatInput > div > div > textarea {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(56, 189, 248, 0.2) !important;
        color: #e2e8f0 !important;
        border-radius: 8px !important;
    }
    [data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(56, 189, 248, 0.1);
        border-radius: 10px;
        padding: 12px;
    }
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
    .env-badge {
        background: rgba(139, 92, 246, 0.15);
        border: 1px solid rgba(139, 92, 246, 0.3);
        border-radius: 6px;
        padding: 4px 10px;
        color: #c4b5fd;
        font-size: 0.78rem;
        display: inline-block;
        margin: 2px;
    }

    /* Rename 'app' to 'Chatbot' in sidebar navigation */
    [data-testid="stSidebarNav"] li:first-child a span {
        font-size: 0;
    }
    [data-testid="stSidebarNav"] li:first-child a span::before {
        content: "Chatbot";
        font-size: 0.875rem;
        visibility: visible;
    }
</style>
""", unsafe_allow_html=True)


# ── Initialize Services ─────────────────────────────────────────────
@st.cache_resource
def init_openai():
    api_key = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
    return OpenAI(api_key=api_key) if api_key else None


@st.cache_resource
def init_enricher():
    return IOCEnricher(
        vt_api_key=st.secrets.get("VIRUSTOTAL_API_KEY", os.getenv("VIRUSTOTAL_API_KEY", "")),
        shodan_api_key=st.secrets.get("SHODAN_API_KEY", os.getenv("SHODAN_API_KEY", "")),
        abuseipdb_api_key=st.secrets.get("ABUSEIPDB_API_KEY", os.getenv("ABUSEIPDB_API_KEY", "")),
    )


@st.cache_resource
def init_mitre_mapper():
    api_key = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
    return MITREMapper(openai_api_key=api_key)


@st.cache_resource
def init_sigma_generator():
    return SigmaGenerator()


client = init_openai()
enricher = init_enricher()
mitre_mapper = init_mitre_mapper()
sigma_gen = init_sigma_generator()
dga_detector = DGADetector()


# ── Build Environment-Aware System Prompt ───────────────────────────
def build_system_prompt() -> str:
    """
    Constructs the system prompt dynamically based on the
    user's configured corporate environment profile.
    """
    env = st.session_state.get("environment", {})

    # Base persona and capabilities
    prompt = """You are **HuntBot**, a Senior Cyber Threat Intelligence (CTI) Analyst and Incident Response specialist embedded in a Security Operations Centre (SOC).

## YOUR CAPABILITIES:
1. **IOC Analysis** — Analyze IPs, domains, file hashes, and URLs for malicious indicators.
2. **MITRE ATT&CK Mapping** — Map observed behaviors to MITRE TTPs with clear reasoning.
3. **Threat Hunting Hypotheses** — Generate data-driven hunting hypotheses based on IOCs and TTPs.
4. **Detection Engineering** — Draft Sigma rules, YARA rules, and SIEM-specific queries (KQL, SPL, EQL).
5. **Threat Actor Profiling** — Provide intelligence on known APT groups, malware families, and campaigns.
6. **Incident Triaging & Response** — Classify severity, recommend containment/eradication/recovery steps.
7. **DGA Detection** — Analyze domains for Domain Generation Algorithm characteristics.
8. **Anomaly Analysis** — Identify statistically unusual IOCs that may indicate novel threats.

## TRIAGING GUIDELINES:
When an analyst presents an alert or IOC, ALWAYS provide structured triage advice:

### Severity Classification:
- **P1 — CRITICAL**: Active breach, ransomware execution, confirmed C2 beaconing, data exfiltration in progress. Immediate escalation required.
- **P2 — HIGH**: Confirmed malicious IOC, lateral movement detected, credential theft, privilege escalation. Escalate within 30 minutes.
- **P3 — MEDIUM**: Suspicious but unconfirmed activity, policy violations, reconnaissance indicators. Investigate within 4 hours.
- **P4 — LOW**: Informational alerts, known false positives, benign anomalies. Review during next shift.

### For EVERY triaging response, include:
1. **Severity**: P1/P2/P3/P4 with justification
2. **Immediate Actions**: What to do RIGHT NOW (isolate host? block IP? preserve evidence?)
3. **Investigation Steps**: Specific queries to run, logs to check, artifacts to collect
4. **Escalation Criteria**: When and to whom this should be escalated
5. **Containment Recommendations**: Network isolation, account disabling, firewall rules
6. **Evidence Preservation**: What to capture before it's lost (memory dump, disk image, logs)

### Response guidelines:
- Always be structured and actionable. SOC analysts need clarity, not essays.
- When mapping to MITRE ATT&CK, ALWAYS provide a "Reasoning" explanation.
- Use markdown: headers, tables, and code blocks for detection rules.
- If unsure, say so. Never fabricate MITRE Technique IDs or threat intel.
- Prioritize actionable output: detection rules, hunting queries, IOC verdicts.
- When writing SIEM queries, use the analyst's specific SIEM platform syntax.
- Consider the analyst's environment when recommending tools and procedures.

"""

    # ── Inject environment context ──────────────────────────────────
    env_details = []

    if env.get("siem") and env["siem"] != "Not Set":
        env_details.append(f"- **SIEM Platform**: {env['siem']} — Write all detection queries in {env['siem']}-native syntax (e.g., SPL for Splunk, KQL for Sentinel).")
    if env.get("edr") and env["edr"] != "Not Set":
        env_details.append(f"- **EDR Solution**: {env['edr']} — Reference {env['edr']}-specific telemetry and response actions.")
    if env.get("firewall") and env["firewall"] != "Not Set":
        env_details.append(f"- **Firewall**: {env['firewall']}")
    if env.get("email_security") and env["email_security"] != "Not Set":
        env_details.append(f"- **Email Security**: {env['email_security']}")
    if env.get("identity_provider") and env["identity_provider"] != "Not Set":
        env_details.append(f"- **Identity Provider**: {env['identity_provider']}")
    if env.get("cloud_providers"):
        env_details.append(f"- **Cloud Providers**: {', '.join(env['cloud_providers'])}")
    if env.get("os_types"):
        env_details.append(f"- **Operating Systems**: {', '.join(env['os_types'])}")
    if env.get("log_sources"):
        env_details.append(f"- **Log Sources in SIEM**: {', '.join(env['log_sources'])}")
    if env.get("network_segments"):
        env_details.append(f"- **Network Segments**: {', '.join(env['network_segments'])}")
    if env.get("network_size") and env["network_size"] != "Not Set":
        env_details.append(f"- **Network Size**: {env['network_size']}")
    if env.get("dns_provider") and env["dns_provider"] != "Not Set":
        env_details.append(f"- **DNS Protection**: {env['dns_provider']}")
    if env.get("proxy") and env["proxy"] != "Not Set":
        env_details.append(f"- **Web Proxy**: {env['proxy']}")
    if env.get("vpn") and env["vpn"] != "Not Set":
        env_details.append(f"- **VPN**: {env['vpn']}")
    if env.get("compliance"):
        env_details.append(f"- **Compliance Frameworks**: {', '.join(env['compliance'])}")
    if env.get("soc_model") and env["soc_model"] != "Not Set":
        env_details.append(f"- **SOC Model**: {env['soc_model']}")
    if env.get("soc_hours") and env["soc_hours"] != "Not Set":
        env_details.append(f"- **SOC Hours**: {env['soc_hours']}")
    if env.get("ticketing") and env["ticketing"] != "Not Set":
        env_details.append(f"- **Ticketing System**: {env['ticketing']}")
    if env.get("critical_assets"):
        env_details.append(f"- **Critical Assets**: {env['critical_assets']}")
    if env.get("additional_context"):
        env_details.append(f"- **Additional Context**: {env['additional_context']}")

    if env_details:
        prompt += "\n## ANALYST'S CORPORATE ENVIRONMENT:\n"
        prompt += "The analyst has configured the following environment details. "
        prompt += "ALWAYS tailor your advice, detection rules, and hunting queries to this specific environment.\n\n"
        prompt += "\n".join(env_details)
        prompt += "\n"
    else:
        prompt += "\n## ENVIRONMENT NOTE:\n"
        prompt += "The analyst has NOT configured their environment profile yet. "
        prompt += "At the START of the conversation, ask them about their environment: "
        prompt += "What SIEM they use, what EDR they have, what OS their endpoints run, "
        prompt += "what cloud providers they use, and what log sources they ingest. "
        prompt += "This helps you provide tailored detection rules and triaging advice. "
        prompt += "Direct them to the '🏢 Environment Profile' page in the sidebar to configure this.\n"

    prompt += f"\nCurrent date: {datetime.now().strftime('%Y-%m-%d')}"

    return prompt


# ── Session State ───────────────────────────────────────────────────
if "messages" not in st.session_state:
    st.session_state.messages = []
if "enrichment_results" not in st.session_state:
    st.session_state.enrichment_results = None
if "investigation_log" not in st.session_state:
    st.session_state.investigation_log = []
if "environment" not in st.session_state:
    st.session_state.environment = {}
if "tool_output" not in st.session_state:
    st.session_state.tool_output = None


# ── Sidebar ─────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🧠 CognitiveHunt")
    st.markdown('<div class="status-banner">🟢 System Online</div>', unsafe_allow_html=True)

    # Show environment badges
    env = st.session_state.environment
    active_env = {k: v for k, v in env.items() if v and v != "Not Set" and k not in ("additional_context", "critical_assets")}
    if active_env:
        badges = ""
        for k, v in active_env.items():
            display = ", ".join(v) if isinstance(v, list) else str(v)
            badges += f'<span class="env-badge">{display}</span> '
        st.markdown(f"**Environment:** {badges}", unsafe_allow_html=True)
    else:
        st.info("💡 Configure your environment in the **Environment Profile** page for tailored advice.")

    st.markdown("---")
    st.markdown("### 🔧 Quick IOC Tools")

    ioc_input = st.text_input(
        "Enter IOC",
        placeholder="IP / Domain / Hash / URL",
        help="Paste an indicator of compromise for instant analysis",
    )

    tool_cols = st.columns(3)

    with tool_cols[0]:
        enrich_btn = st.button("🔍 Enrich", use_container_width=True)
    with tool_cols[1]:
        mitre_btn = st.button("🎯 MITRE", use_container_width=True)
    with tool_cols[2]:
        sigma_btn = st.button("📝 Sigma", use_container_width=True)

    tool_cols2 = st.columns(3)
    with tool_cols2[0]:
        dga_btn = st.button("🧬 DGA", use_container_width=True)
    with tool_cols2[1]:
        triage_btn = st.button("🚨 Triage", use_container_width=True)
    with tool_cols2[2]:
        clear_btn = st.button("🗑️ Clear", use_container_width=True)

    # ── Handle sidebar actions ──────────────────────────────────────
    # Compute disabled sources from toggles
    disabled_sources = {name for name, enabled in st.session_state.get("api_toggles", {}).items() if not enabled}
    active_count = len(st.session_state.get("api_toggles", {})) - len(disabled_sources)

    if enrich_btn and ioc_input:
        with st.spinner(f"Enriching IOC across {active_count} source(s)..."):
            results = enricher.enrich(ioc_input, disabled_sources=disabled_sources)
            st.session_state.enrichment_results = results
            st.session_state.tool_output = {"type": "enrich", "ioc": ioc_input, "data": results}

    if mitre_btn and ioc_input:
        if st.session_state.get("llm_enabled", True):
            with st.spinner("Mapping to MITRE ATT&CK..."):
                mapping = mitre_mapper.map_ioc(ioc_input, st.session_state.enrichment_results)
                st.session_state.tool_output = {"type": "mitre", "ioc": ioc_input, "data": mapping}
        else:
            st.warning("OpenAI GPT is disabled. Enable it in API Sources to use MITRE mapping.")

    if sigma_btn and ioc_input:
        with st.spinner("Generating Sigma rule..."):
            rule = sigma_gen.generate(ioc_input)
            st.session_state.tool_output = {"type": "sigma", "ioc": ioc_input, "data": rule}

    if dga_btn and ioc_input:
        with st.spinner("Analyzing for DGA patterns..."):
            dga_result = dga_detector.detect(ioc_input)
            st.session_state.tool_output = {"type": "dga", "ioc": ioc_input, "data": dga_result}

    if triage_btn and ioc_input:
        triage_prompt = (
            f"I need you to triage this IOC: **{ioc_input}**\n\n"
            f"Please provide: severity classification (P1-P4), immediate actions, "
            f"investigation steps with specific SIEM queries for my environment, "
            f"escalation criteria, containment recommendations, and evidence preservation steps."
        )
        st.session_state.messages.append({"role": "user", "content": triage_prompt})
        st.session_state.tool_output = None
        st.rerun()

    if clear_btn:
        st.session_state.messages = []
        st.session_state.enrichment_results = None
        st.session_state.tool_output = None
        st.rerun()

    # ── Sidebar footer ──────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### ⚙️ Configuration")
    model_choice = st.selectbox("LLM Model", ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"])
    temperature = st.slider("Temperature", 0.0, 1.0, 0.1, 0.05)
    st.caption("Lower = more precise & consistent (best for analysis). Higher = more creative & varied.")

    # ── API Source Toggles ──────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🔌 API Sources")
    st.caption("Enable or disable enrichment APIs")

    # Detect which APIs have keys configured
    api_status = {
        "virustotal": bool(st.secrets.get("VIRUSTOTAL_API_KEY", os.getenv("VIRUSTOTAL_API_KEY", ""))),
        "shodan": bool(st.secrets.get("SHODAN_API_KEY", os.getenv("SHODAN_API_KEY", ""))),
        "abuseipdb": bool(st.secrets.get("ABUSEIPDB_API_KEY", os.getenv("ABUSEIPDB_API_KEY", ""))),
        "urlhaus": True,       # No key needed
        "malwarebazaar": True,  # No key needed
    }

    # Initialize toggle state
    if "api_toggles" not in st.session_state:
        st.session_state.api_toggles = {name: True for name in api_status}

    api_labels = {
        "virustotal": "🦠 VirusTotal",
        "shodan": "🔍 Shodan",
        "abuseipdb": "🚨 AbuseIPDB",
        "urlhaus": "🔗 URLhaus (free)",
        "malwarebazaar": "🧬 MalwareBazaar (free)",
    }

    for api_name, label in api_labels.items():
        has_key = api_status[api_name]
        if has_key:
            st.session_state.api_toggles[api_name] = st.checkbox(
                f"{label} ✅", value=st.session_state.api_toggles.get(api_name, True),
                key=f"toggle_{api_name}",
            )
        else:
            st.checkbox(f"{label} ❌ No key", value=False, disabled=True, key=f"toggle_{api_name}")
            st.session_state.api_toggles[api_name] = False

    # LLM toggle
    st.markdown("---")
    openai_configured = bool(st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", "")))
    if openai_configured:
        if "llm_enabled" not in st.session_state:
            st.session_state.llm_enabled = True
        st.session_state.llm_enabled = st.checkbox(
            "🤖 OpenAI GPT (Chat + MITRE) ✅",
            value=st.session_state.get("llm_enabled", True),
            key="toggle_openai",
        )
    else:
        st.checkbox("🤖 OpenAI GPT ❌ No key", value=False, disabled=True, key="toggle_openai")

    # Count enabled
    enabled_count = sum(1 for v in st.session_state.api_toggles.values() if v)
    total_count = len(api_labels)
    st.caption(f"{enabled_count}/{total_count} enrichment APIs active")

    st.markdown("---")
    st.caption("Built for Singapore Institute of Technology: University of Applied Learning · Capstone Project 2025-2026")


# ── Main Chat Interface ─────────────────────────────────────────────
st.markdown("# 🧠 CognitiveHunt — AI-Enhanced Threat Intelligence Platform")
st.markdown(
    "Ask me about IOCs, threat actors, MITRE ATT&CK techniques, detection rules, "
    "or paste indicators for analysis. I provide **triaging advice** tailored to your environment."
)

# ── Display Quick IOC Tool Results in Main Area ─────────────────────
if st.session_state.tool_output:
    _tool = st.session_state.tool_output
    st.markdown("---")

    if _tool["type"] == "enrich":
        results = _tool["data"]
        consensus = results.get("consensus", {})
        level = consensus.get("threat_level", "UNKNOWN")
        score = consensus.get("consensus_score", 0)
        level_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

        st.markdown(f"### {level_colors.get(level, '⚪')} IOC Enrichment: `{_tool['ioc']}` — {level} ({score}/100)")
        for factor in consensus.get("scoring_factors", []):
            st.caption(factor)
        with st.expander("📋 Full Enrichment Data", expanded=True):
            st.json(results)

    elif _tool["type"] == "mitre":
        mapping = _tool["data"]
        st.markdown(f"### 🎯 MITRE ATT&CK Mapping: `{_tool['ioc']}`")
        if mapping.get("overall_assessment"):
            st.markdown(f"**Assessment:** {mapping['overall_assessment']}")
        for m in mapping.get("mappings", []):
            conf_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(m.get("confidence", ""), "⚪")
            st.markdown(f"{conf_icon} **{m.get('technique_id', 'N/A')}** — {m.get('technique_name', 'Unknown')} ({m.get('tactic', '')})")
            st.caption(f"Reasoning: {m.get('reasoning', 'N/A')}")

        # Extract matched technique IDs for highlighting
        _matched_ids = {m.get("technique_id", "") for m in mapping.get("mappings", [])}
        # Also match parent IDs (e.g., T1071 from T1071.001)
        _matched_parents = {tid.split(".")[0] for tid in _matched_ids if "." in tid}
        _all_matched = _matched_ids | _matched_parents

        # Mini ATT&CK Matrix Grid View with highlights
        st.markdown("#### 🗺️ ATT&CK Matrix — Detected Techniques Highlighted")
        _matrix_cols = st.columns(len(TACTICS))
        for _i, _tactic in enumerate(sorted(TACTICS, key=lambda t: t.order)):
            with _matrix_cols[_i]:
                st.markdown(f"**{_tactic.name}**")
                _techs = get_parent_techniques_by_tactic(_tactic.id)
                for _tech in _techs[:8]:
                    if _tech.id in _all_matched:
                        st.markdown(f"🔴 `{_tech.id}` **{_tech.name[:22]}**")
                    else:
                        st.caption(f"`{_tech.id}` {_tech.name[:22]}")
                if len(_techs) > 8:
                    with st.expander(f"+{len(_techs)-8} more"):
                        for _tech in _techs[8:]:
                            if _tech.id in _all_matched:
                                st.markdown(f"🔴 `{_tech.id}` **{_tech.name[:22]}**")
                            else:
                                st.caption(f"`{_tech.id}` {_tech.name[:22]}")

        with st.expander("📋 Full Mapping Data"):
            st.json(mapping)

    elif _tool["type"] == "sigma":
        st.markdown(f"### 📝 Sigma Rule: `{_tool['ioc']}`")
        st.code(_tool["data"], language="yaml")
        st.download_button("⬇️ Download .yml", _tool["data"],
                           file_name=f"sigma_{_tool['ioc'].replace('.', '_').replace(':', '_')}.yml",
                           mime="text/yaml")

    elif _tool["type"] == "dga":
        dga_result = _tool["data"]
        verdict = dga_result["verdict"]
        dga_score = dga_result["dga_score"]
        v_colors = {"LIKELY DGA": "🔴", "SUSPICIOUS": "🟡", "LIKELY LEGITIMATE": "🟢"}
        st.markdown(f"### {v_colors.get(verdict, '⚪')} DGA Analysis: `{_tool['ioc']}` — {verdict} ({dga_score}/100)")
        feat = dga_result.get("features", {})
        feat_cols = st.columns(5)
        with feat_cols[0]:
            st.metric("Entropy", feat.get("entropy", "N/A"))
        with feat_cols[1]:
            st.metric("Bigram Score", feat.get("bigram_score", "N/A"))
        with feat_cols[2]:
            st.metric("Vowel Ratio", feat.get("vowel_consonant_ratio", "N/A"))
        with feat_cols[3]:
            st.metric("Digit Ratio", feat.get("digit_ratio", "N/A"))
        with feat_cols[4]:
            st.metric("Body Length", feat.get("body_length", "N/A"))

    st.markdown("---")

# Display chat history
for message in st.session_state.messages:
    avatar = "🕵️" if message["role"] == "assistant" else "👤"
    with st.chat_message(message["role"], avatar=avatar):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Paste an IOC, describe an alert, or ask a threat hunting question..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user", avatar="👤"):
        st.markdown(prompt)

    with st.chat_message("assistant", avatar="🕵️"):
        if client is None:
            st.warning(
                "⚠️ OpenAI API key not configured. Add it to `.streamlit/secrets.toml` "
                "or set the `OPENAI_API_KEY` environment variable."
            )
            response_text = "I need an OpenAI API key to function. Please configure it in the settings."
        elif not st.session_state.get("llm_enabled", True):
            st.warning("⚠️ OpenAI GPT is disabled. Enable it in the **API Sources** section in the sidebar.")
            response_text = "The LLM chatbot is currently disabled. Toggle it on in the sidebar under API Sources."
        else:
            # Build dynamic system prompt with environment context
            system_prompt = build_system_prompt()
            api_messages = [{"role": "system", "content": system_prompt}]

            # Include enrichment context if available
            if st.session_state.enrichment_results:
                context = (
                    f"[ENRICHMENT CONTEXT] The user previously enriched an IOC. "
                    f"Results:\n{json.dumps(st.session_state.enrichment_results, indent=2)}"
                )
                api_messages.append({"role": "system", "content": context})

            # Add conversation history (last 20 messages)
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

    st.session_state.investigation_log.append({
        "timestamp": datetime.now().isoformat(),
        "query": prompt,
        "response_preview": response_text[:200] if isinstance(response_text, str) else "",
    })
