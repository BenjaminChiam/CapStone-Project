"""
🏢 Environment Profiler Page
Collects the user's corporate environment details so the chatbot
can provide contextual, environment-aware triaging and hunting advice.
"""

import streamlit as st
import json

st.set_page_config(page_title="Environment Profile", page_icon="🏢", layout="wide")
st.title("🏢 Environment Profiler")
st.markdown(
    "Configure your corporate environment so the assistant can provide "
    "**tailored triaging advice**, accurate detection rules, and environment-specific hunting queries."
)

# ── Initialize environment state ────────────────────────────────────
if "environment" not in st.session_state:
    st.session_state.environment = {}

env = st.session_state.environment

st.markdown("---")

# ════════════════════════════════════════════════════════════════════
# SECTION 1: SIEM & Security Stack
# ════════════════════════════════════════════════════════════════════
st.markdown("### 🛡️ Security Stack")

col1, col2 = st.columns(2)

with col1:
    env["siem"] = st.selectbox(
        "SIEM Platform",
        ["Not Set", "Splunk", "Microsoft Sentinel", "Elastic SIEM", "IBM QRadar",
         "Google Chronicle", "LogRhythm", "Sumo Logic", "Wazuh", "Other"],
        index=["Not Set", "Splunk", "Microsoft Sentinel", "Elastic SIEM", "IBM QRadar",
               "Google Chronicle", "LogRhythm", "Sumo Logic", "Wazuh", "Other"].index(env.get("siem", "Not Set")),
    )

    env["edr"] = st.selectbox(
        "EDR Solution",
        ["Not Set", "CrowdStrike Falcon", "Microsoft Defender for Endpoint",
         "SentinelOne", "Carbon Black", "Cortex XDR", "Trend Micro Vision One",
         "Cybereason", "Elastic Defend", "Other"],
        index=0,
    )

    env["firewall"] = st.selectbox(
        "Primary Firewall / NGFW",
        ["Not Set", "Palo Alto Networks", "Fortinet FortiGate", "Cisco Firepower",
         "Check Point", "Sophos XG", "pfSense", "Zscaler", "Other"],
        index=0,
    )

with col2:
    env["email_security"] = st.selectbox(
        "Email Security Gateway",
        ["Not Set", "Microsoft Defender for Office 365", "Proofpoint",
         "Mimecast", "Barracuda", "Cisco Email Security", "Google Workspace Security", "Other"],
        index=0,
    )

    env["identity_provider"] = st.selectbox(
        "Identity Provider (IdP)",
        ["Not Set", "Microsoft Entra ID (Azure AD)", "Okta", "Ping Identity",
         "CyberArk", "Google Workspace", "On-Prem Active Directory Only", "Other"],
        index=0,
    )

    env["vulnerability_scanner"] = st.selectbox(
        "Vulnerability Scanner",
        ["Not Set", "Tenable Nessus", "Qualys", "Rapid7 InsightVM",
         "Microsoft Defender Vulnerability Management", "OpenVAS", "Other"],
        index=0,
    )

st.markdown("---")

# ════════════════════════════════════════════════════════════════════
# SECTION 2: Network & Infrastructure
# ════════════════════════════════════════════════════════════════════
st.markdown("### 🌐 Network & Infrastructure")

col3, col4 = st.columns(2)

with col3:
    env["cloud_providers"] = st.multiselect(
        "Cloud Providers in Use",
        ["AWS", "Microsoft Azure", "Google Cloud (GCP)", "Oracle Cloud",
         "On-Premises Only", "Hybrid (On-Prem + Cloud)"],
        default=env.get("cloud_providers", []),
    )

    env["network_segments"] = st.multiselect(
        "Network Segmentation",
        ["DMZ", "Corporate LAN", "Guest WiFi", "OT/SCADA Network",
         "Development/Staging", "PCI Zone", "VPN/Remote Access"],
        default=env.get("network_segments", []),
    )

    env["dns_provider"] = st.selectbox(
        "DNS Filtering / Protection",
        ["Not Set", "Cisco Umbrella", "Cloudflare Gateway", "Infoblox",
         "Zscaler Internet Access", "None", "Other"],
        index=0,
    )

with col4:
    env["proxy"] = st.selectbox(
        "Web Proxy / Secure Web Gateway",
        ["Not Set", "Zscaler", "Netskope", "Symantec ProxySG",
         "McAfee Web Gateway", "Squid Proxy", "None", "Other"],
        index=0,
    )

    env["vpn"] = st.selectbox(
        "VPN Solution",
        ["Not Set", "Cisco AnyConnect", "Palo Alto GlobalProtect",
         "Fortinet FortiClient", "Zscaler Private Access", "WireGuard",
         "OpenVPN", "None", "Other"],
        index=0,
    )

    env["network_size"] = st.selectbox(
        "Approximate Network Size",
        ["Not Set", "Small (< 100 endpoints)", "Medium (100-1,000 endpoints)",
         "Large (1,000-10,000 endpoints)", "Enterprise (10,000+ endpoints)"],
        index=0,
    )

st.markdown("---")

# ════════════════════════════════════════════════════════════════════
# SECTION 3: Operating Systems & Endpoints
# ════════════════════════════════════════════════════════════════════
st.markdown("### 💻 Endpoints & Operating Systems")

col5, col6 = st.columns(2)

with col5:
    env["os_types"] = st.multiselect(
        "Operating Systems in Environment",
        ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022",
         "Ubuntu Linux", "CentOS/RHEL", "macOS", "iOS (Mobile)", "Android (Mobile)"],
        default=env.get("os_types", []),
    )

    env["log_sources"] = st.multiselect(
        "Log Sources Ingested into SIEM",
        ["Windows Event Logs", "Sysmon", "Linux Auditd", "Firewall Logs",
         "DNS Logs", "Proxy/Web Logs", "Cloud Trail / Activity Logs",
         "EDR Telemetry", "Email Gateway Logs", "VPN Logs",
         "Authentication Logs (AD/LDAP)", "IDS/IPS Alerts", "NetFlow/PCAP"],
        default=env.get("log_sources", []),
    )

with col6:
    env["critical_assets"] = st.text_area(
        "Critical Assets / Crown Jewels",
        value=env.get("critical_assets", ""),
        placeholder="e.g., Domain Controllers, SQL databases with PII, "
                    "payment processing servers, executive laptops...",
        height=100,
    )

    env["compliance"] = st.multiselect(
        "Compliance Frameworks",
        ["PCI-DSS", "HIPAA", "SOC 2", "ISO 27001", "NIST CSF",
         "GDPR", "MAS TRM (Singapore)", "PDPA (Singapore)", "CIS Controls"],
        default=env.get("compliance", []),
    )

st.markdown("---")

# ════════════════════════════════════════════════════════════════════
# SECTION 4: SOC Configuration
# ════════════════════════════════════════════════════════════════════
st.markdown("### 🏗️ SOC Configuration")

col7, col8 = st.columns(2)

with col7:
    env["soc_model"] = st.selectbox(
        "SOC Operating Model",
        ["Not Set", "In-House SOC", "Managed SOC (MSSP)", "Hybrid SOC",
         "Virtual SOC (part-time)", "No dedicated SOC"],
        index=0,
    )

    env["soc_hours"] = st.selectbox(
        "SOC Operating Hours",
        ["Not Set", "24/7", "Business Hours Only (e.g., 9am-6pm)",
         "Extended Hours (e.g., 7am-11pm)", "On-Call After Hours"],
        index=0,
    )

with col8:
    env["ticketing"] = st.selectbox(
        "Ticketing / Case Management",
        ["Not Set", "ServiceNow", "Jira", "TheHive", "Splunk SOAR",
         "Microsoft Sentinel Incidents", "PagerDuty", "Other"],
        index=0,
    )

    env["threat_intel_feeds"] = st.multiselect(
        "Threat Intelligence Feeds",
        ["AlienVault OTX", "MISP", "VirusTotal", "Recorded Future",
         "Mandiant", "CrowdStrike Intel", "ThreatConnect",
         "Anomali ThreatStream", "Open Source Feeds", "Custom Internal Feeds"],
        default=env.get("threat_intel_feeds", []),
    )

st.markdown("---")

# ════════════════════════════════════════════════════════════════════
# SECTION 5: Additional Context
# ════════════════════════════════════════════════════════════════════
st.markdown("### 📝 Additional Context")

env["additional_context"] = st.text_area(
    "Any other details about your environment",
    value=env.get("additional_context", ""),
    placeholder="e.g., We recently migrated to Azure. Our OT network is air-gapped. "
                "We use Sysmon with a SwiftOnSecurity config. "
                "Our analysts are Tier 1-2 level...",
    height=120,
)

# ════════════════════════════════════════════════════════════════════
# Save & Summary
# ════════════════════════════════════════════════════════════════════
st.markdown("---")

if st.button("💾 Save Environment Profile", use_container_width=True, type="primary"):
    st.session_state.environment = env
    st.success("Environment profile saved! The chatbot will now use this context for tailored advice.")

# Show current profile summary
if any(v for k, v in env.items() if v and v != "Not Set"):
    with st.expander("📋 Current Environment Summary", expanded=False):
        # Filter out empty values
        display = {k: v for k, v in env.items() if v and v != "Not Set"}
        st.json(display)

    # Export option
    profile_json = json.dumps(env, indent=2)
    st.download_button(
        "⬇️ Export Profile as JSON",
        profile_json,
        file_name="environment_profile.json",
        mime="application/json",
    )
