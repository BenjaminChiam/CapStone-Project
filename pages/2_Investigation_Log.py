"""
📋 Investigation Log & Log Analyzer Page
==========================================
Features:
1. Upload and parse log files (CSV, CSV.GZ, JSON)
2. Auto-detect log type (FortiGate, ICMP, MAPI, WinRegistry, Sysmon, etc.)
3. Statistical analysis with top-talker and timeline visualizations
4. IOC extraction (IPs, domains, hashes, URLs) from log data
5. Rule-based MITRE ATT&CK technique detection from log patterns
6. ML anomaly detection on traffic volumes and patterns
7. Chat history and investigation export
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import json
import csv
import io
from datetime import datetime
from utils.log_analyzer import (
    load_log_file, detect_log_type, parse_raw_field,
    extract_iocs_from_df, map_logs_to_mitre,
    compute_top_talkers, compute_time_series,
)
from utils.ml_engine import AnomalyDetector, ThreatClusterer

st.set_page_config(page_title="Investigation Log", page_icon="📋", layout="wide")
st.title("📋 Investigation Log & Log Analyzer")

tab_upload, tab_chat = st.tabs(["📂 Log File Analysis", "💬 Chat History"])

# ════════════════════════════════════════════════════════════════════
# TAB 1: Log File Analysis
# ════════════════════════════════════════════════════════════════════
with tab_upload:
    st.markdown("Upload security log files for automated parsing, IOC extraction, MITRE mapping, and ML-powered analysis.")

    uploaded_files = st.file_uploader(
        "Upload Log Files",
        type=["csv", "gz", "json", "jsonl", "log", "txt"],
        accept_multiple_files=True,
        help="Supported: CSV, CSV.GZ, JSON/JSONL, plain text. Splunk exports, FortiGate, Sysmon, Windows Event Logs, network streams.",
    )

    if uploaded_files:
        for uploaded_file in uploaded_files:
            st.markdown(f"---")
            st.markdown(f"## 📄 {uploaded_file.name}")
            st.caption(f"Size: {uploaded_file.size / 1024:.1f} KB")

            with st.spinner(f"Loading and parsing {uploaded_file.name}..."):
                # Load raw data
                raw_df = load_log_file(uploaded_file)

                if "error" in raw_df.columns:
                    st.error(f"Failed to load: {raw_df['error'].iloc[0]}")
                    continue

                st.success(f"Loaded **{len(raw_df):,}** rows, **{len(raw_df.columns)}** columns")

                # Detect log type
                log_type = detect_log_type(raw_df)
                type_labels = {
                    "fortigate_utm": "🔥 FortiGate UTM (Firewall)",
                    "stream_icmp": "🌐 ICMP Network Stream",
                    "stream_mapi": "📧 MAPI Email Stream",
                    "stream_dns": "🔤 DNS Stream",
                    "stream_http": "🌍 HTTP Stream",
                    "winregistry": "🪟 Windows Registry",
                    "sysmon": "🔍 Sysmon",
                    "wineventlog": "📝 Windows Event Log",
                    "network_flow": "📡 Network Flow",
                    "firewall": "🧱 Firewall",
                    "generic": "📄 Generic CSV",
                }
                st.info(f"**Detected Log Type:** {type_labels.get(log_type, log_type)}")

                # Parse raw field into structured columns
                with st.spinner("Parsing raw log data..."):
                    parsed_df = parse_raw_field(raw_df, log_type)

                # ── Sub-tabs for analysis ────────────────────────────
                atab1, atab2, atab3, atab4, atab5, atab6 = st.tabs([
                    "📊 Overview", "🕐 Timeline", "🔍 IOC Extraction",
                    "🎯 MITRE Mapping", "⚠️ Anomaly Detection", "📋 Raw Data"
                ])

                # ════════════════════════════════════════════════════
                # OVERVIEW TAB
                # ════════════════════════════════════════════════════
                with atab1:
                    st.markdown("### Log Overview & Top Talkers")

                    # Key metrics
                    mcols = st.columns(4)
                    with mcols[0]:
                        st.metric("Total Events", f"{len(parsed_df):,}")
                    with mcols[1]:
                        st.metric("Columns Parsed", len(parsed_df.columns))
                    with mcols[2]:
                        if "_time" in parsed_df.columns:
                            times = pd.to_datetime(parsed_df["_time"].head(100), errors="coerce").dropna()
                            if len(times) > 1:
                                span = times.max() - times.min()
                                st.metric("Time Span", str(span).split(".")[0])
                            else:
                                st.metric("Time Span", "N/A")
                        else:
                            st.metric("Time Span", "N/A")
                    with mcols[3]:
                        unique_hosts = parsed_df["host"].nunique() if "host" in parsed_df.columns else "N/A"
                        st.metric("Unique Hosts", unique_hosts)

                    # Top talkers
                    top_data = compute_top_talkers(parsed_df)

                    col1, col2 = st.columns(2)

                    with col1:
                        if "top_source_ips" in top_data:
                            fig = px.bar(
                                top_data["top_source_ips"].head(10),
                                x="Count", y="IP", orientation="h",
                                title="Top Source IPs",
                                color="Count", color_continuous_scale="Reds",
                            )
                            fig.update_layout(template="plotly_dark",
                                              plot_bgcolor="rgba(10,14,23,0.8)",
                                              paper_bgcolor="rgba(10,14,23,0.8)",
                                              height=350, yaxis=dict(autorange="reversed"))
                            st.plotly_chart(fig, use_container_width=True)

                        if "top_processes" in top_data:
                            fig = px.bar(
                                top_data["top_processes"].head(10),
                                x="Count", y="Process", orientation="h",
                                title="Top Processes",
                                color="Count", color_continuous_scale="Oranges",
                            )
                            fig.update_layout(template="plotly_dark",
                                              plot_bgcolor="rgba(10,14,23,0.8)",
                                              paper_bgcolor="rgba(10,14,23,0.8)",
                                              height=350, yaxis=dict(autorange="reversed"))
                            st.plotly_chart(fig, use_container_width=True)

                    with col2:
                        if "top_dest_ips" in top_data:
                            fig = px.bar(
                                top_data["top_dest_ips"].head(10),
                                x="Count", y="IP", orientation="h",
                                title="Top Destination IPs",
                                color="Count", color_continuous_scale="Blues",
                            )
                            fig.update_layout(template="plotly_dark",
                                              plot_bgcolor="rgba(10,14,23,0.8)",
                                              paper_bgcolor="rgba(10,14,23,0.8)",
                                              height=350, yaxis=dict(autorange="reversed"))
                            st.plotly_chart(fig, use_container_width=True)

                        if "top_dest_ports" in top_data:
                            fig = px.bar(
                                top_data["top_dest_ports"].head(10),
                                x="Count", y="Port", orientation="h",
                                title="Top Destination Ports",
                                color="Count", color_continuous_scale="Purples",
                            )
                            fig.update_layout(template="plotly_dark",
                                              plot_bgcolor="rgba(10,14,23,0.8)",
                                              paper_bgcolor="rgba(10,14,23,0.8)",
                                              height=350, yaxis=dict(autorange="reversed"))
                            st.plotly_chart(fig, use_container_width=True)

                    # Action distribution / Registry operations
                    col3, col4 = st.columns(2)
                    with col3:
                        if "action_distribution" in top_data:
                            fig = px.pie(
                                top_data["action_distribution"],
                                values="Count", names="Action",
                                title="Action Distribution",
                                color_discrete_sequence=px.colors.qualitative.Set2,
                            )
                            fig.update_layout(template="plotly_dark",
                                              paper_bgcolor="rgba(10,14,23,0.8)", height=350)
                            st.plotly_chart(fig, use_container_width=True)

                    with col4:
                        if "registry_operations" in top_data:
                            fig = px.pie(
                                top_data["registry_operations"],
                                values="Count", names="Operation",
                                title="Registry Operation Types",
                                color_discrete_sequence=px.colors.qualitative.Set1,
                            )
                            fig.update_layout(template="plotly_dark",
                                              paper_bgcolor="rgba(10,14,23,0.8)", height=350)
                            st.plotly_chart(fig, use_container_width=True)

                    if "top_hostnames" in top_data:
                        st.markdown("### Top Hostnames / Domains Accessed")
                        st.dataframe(top_data["top_hostnames"].head(20),
                                     use_container_width=True, hide_index=True)

                # ════════════════════════════════════════════════════
                # TIMELINE TAB
                # ════════════════════════════════════════════════════
                with atab2:
                    st.markdown("### Event Timeline")

                    ts_df = compute_time_series(parsed_df)
                    if ts_df is not None and len(ts_df) > 1:
                        fig = go.Figure()
                        fig.add_trace(go.Scatter(
                            x=ts_df["time"], y=ts_df["event_count"],
                            mode="lines", fill="tozeroy",
                            line=dict(color="#0ea5e9", width=1),
                            fillcolor="rgba(14,165,233,0.15)",
                            name="Events",
                        ))

                        # Highlight spikes (Z-score > 2)
                        mean = ts_df["event_count"].mean()
                        std = ts_df["event_count"].std()
                        if std > 0:
                            spikes = ts_df[ts_df["event_count"] > mean + 2 * std]
                            if len(spikes) > 0:
                                fig.add_trace(go.Scatter(
                                    x=spikes["time"], y=spikes["event_count"],
                                    mode="markers",
                                    marker=dict(color="#ef4444", size=10, symbol="triangle-up"),
                                    name="Spike (Z > 2)",
                                ))

                        fig.update_layout(
                            template="plotly_dark",
                            plot_bgcolor="rgba(10,14,23,0.8)",
                            paper_bgcolor="rgba(10,14,23,0.8)",
                            title="Event Frequency Over Time",
                            xaxis_title="Time", yaxis_title="Event Count",
                            height=450,
                        )
                        st.plotly_chart(fig, use_container_width=True)

                        # Spike details
                        if std > 0 and len(spikes) > 0:
                            st.markdown(f"### 🔴 {len(spikes)} Spike(s) Detected")
                            st.caption(f"Events exceeding {mean + 2*std:.0f} per interval (mean={mean:.1f}, σ={std:.1f})")
                            st.dataframe(spikes, use_container_width=True, hide_index=True)
                    else:
                        st.info("Could not generate timeline — no parseable timestamp column found.")

                # ════════════════════════════════════════════════════
                # IOC EXTRACTION TAB
                # ════════════════════════════════════════════════════
                with atab3:
                    st.markdown("### Extracted IOCs from Log Data")
                    st.markdown("Automatically extracted indicators that can be enriched via the sidebar tools on the main page.")

                    with st.spinner("Extracting IOCs..."):
                        iocs = extract_iocs_from_df(parsed_df)

                    # Summary metrics
                    ioc_cols = st.columns(4)
                    with ioc_cols[0]:
                        st.metric("Public IPs", len(iocs["public_ips"]))
                    with ioc_cols[1]:
                        st.metric("Domains", len(iocs["domains"]))
                    with ioc_cols[2]:
                        total_hashes = len(iocs["md5_hashes"]) + len(iocs["sha1_hashes"]) + len(iocs["sha256_hashes"])
                        st.metric("File Hashes", total_hashes)
                    with ioc_cols[3]:
                        st.metric("URLs", len(iocs["urls"]))

                    col_a, col_b = st.columns(2)
                    with col_a:
                        if iocs["public_ips"]:
                            st.markdown("#### 🌐 Public IP Addresses")
                            ip_df = pd.DataFrame({"IP": iocs["public_ips"]})
                            st.dataframe(ip_df, use_container_width=True, hide_index=True, height=300)

                        if iocs["domains"]:
                            st.markdown("#### 🔗 Domains")
                            dom_df = pd.DataFrame({"Domain": iocs["domains"][:50]})
                            st.dataframe(dom_df, use_container_width=True, hide_index=True, height=300)

                    with col_b:
                        if iocs["private_ips"]:
                            st.markdown("#### 🏠 Internal IPs")
                            priv_df = pd.DataFrame({"IP": iocs["private_ips"]})
                            st.dataframe(priv_df, use_container_width=True, hide_index=True, height=300)

                        if iocs["urls"]:
                            st.markdown("#### 🔗 URLs")
                            url_df = pd.DataFrame({"URL": iocs["urls"][:30]})
                            st.dataframe(url_df, use_container_width=True, hide_index=True, height=300)

                    # Export IOCs
                    if any(len(v) > 0 for v in iocs.values()):
                        ioc_export = json.dumps(iocs, indent=2)
                        st.download_button(
                            "⬇️ Export IOCs as JSON",
                            ioc_export,
                            file_name=f"iocs_{uploaded_file.name}_{datetime.now().strftime('%Y%m%d')}.json",
                            mime="application/json",
                        )

                # ════════════════════════════════════════════════════
                # MITRE ATT&CK MAPPING TAB
                # ════════════════════════════════════════════════════
                with atab4:
                    st.markdown("### MITRE ATT&CK Technique Detection")
                    st.markdown("Rule-based pattern matching against known adversary behaviors in log data.")

                    with st.spinner("Scanning logs for MITRE ATT&CK patterns..."):
                        mitre_matches = map_logs_to_mitre(parsed_df)

                    if mitre_matches:
                        st.success(f"**{len(mitre_matches)} technique(s) detected** across {len(set(m['tactic'] for m in mitre_matches))} tactics")

                        # Confidence breakdown
                        conf_counts = {}
                        for m in mitre_matches:
                            conf_counts[m["confidence"]] = conf_counts.get(m["confidence"], 0) + 1

                        conf_cols = st.columns(4)
                        conf_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
                        for i, conf in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
                            with conf_cols[i]:
                                st.metric(f"{conf_icons.get(conf, '')} {conf}",
                                          conf_counts.get(conf, 0))

                        # Tactic heatmap
                        tactic_data = {}
                        for m in mitre_matches:
                            tactic_data[m["tactic"]] = tactic_data.get(m["tactic"], 0) + m["match_count"]

                        if tactic_data:
                            tac_df = pd.DataFrame([
                                {"Tactic": k, "Matches": v}
                                for k, v in sorted(tactic_data.items(), key=lambda x: -x[1])
                            ])
                            fig = px.bar(
                                tac_df, x="Matches", y="Tactic", orientation="h",
                                color="Matches", color_continuous_scale="YlOrRd",
                                title="Technique Detections by Tactic",
                            )
                            fig.update_layout(template="plotly_dark",
                                              plot_bgcolor="rgba(10,14,23,0.8)",
                                              paper_bgcolor="rgba(10,14,23,0.8)",
                                              height=400, yaxis=dict(autorange="reversed"))
                            st.plotly_chart(fig, use_container_width=True)

                        # Detailed findings
                        st.markdown("### Detailed Findings")
                        for match in mitre_matches:
                            conf_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
                            icon = conf_color.get(match["confidence"], "⚪")
                            with st.expander(
                                f"{icon} {match['technique_id']}: {match['technique_name']} "
                                f"— {match['tactic']} ({match['match_count']} matches)",
                                expanded=(match["confidence"] in ("CRITICAL", "HIGH")),
                            ):
                                st.markdown(f"**Confidence:** {match['confidence']}")
                                st.markdown(f"**Description:** {match['description']}")
                                st.markdown(f"**Tactic:** {match['tactic']}")
                                st.markdown(f"**Matches Found:** {match['match_count']}")
                                if match["sample_evidence"]:
                                    st.markdown("**Sample Evidence:**")
                                    for evidence in match["sample_evidence"]:
                                        st.code(evidence[:500], language="text")
                    else:
                        st.info("No MITRE ATT&CK patterns detected in this log file.")

                # ════════════════════════════════════════════════════
                # ANOMALY DETECTION TAB
                # ════════════════════════════════════════════════════
                with atab5:
                    st.markdown("### ML Anomaly Detection on Log Data")

                    # Build IOC-like records from extracted IPs for clustering
                    iocs_for_ml = extract_iocs_from_df(parsed_df)
                    all_ips = iocs_for_ml["public_ips"] + iocs_for_ml["private_ips"]

                    if len(all_ips) >= 5:
                        st.markdown("#### IP Address Anomaly Analysis (Isolation Forest)")
                        # Build IOC records with frequency as risk proxy
                        ip_text = " ".join(parsed_df.astype(str).values.flatten())
                        ioc_records = []
                        for ip in all_ips[:200]:
                            freq = ip_text.count(ip)
                            ioc_records.append({"ioc": ip, "risk_score": min(freq, 100)})

                        detector = AnomalyDetector(contamination=0.1)
                        anomaly_df = detector.train_and_detect(ioc_records)

                        anomaly_count = anomaly_df["is_anomaly"].sum()
                        a_cols = st.columns(3)
                        with a_cols[0]:
                            st.metric("IPs Analyzed", len(anomaly_df))
                        with a_cols[1]:
                            st.metric("Anomalies Detected", int(anomaly_count))
                        with a_cols[2]:
                            st.metric("Anomaly Rate", f"{(anomaly_count/len(anomaly_df)*100):.1f}%")

                        fig = px.scatter(
                            anomaly_df, x="entropy", y="risk_score",
                            color=anomaly_df["is_anomaly"].map({True: "Anomaly", False: "Normal"}),
                            size="anomaly_score",
                            hover_data=["ioc", "anomaly_score"],
                            title="IP Anomaly Detection — Isolation Forest",
                            color_discrete_map={"Anomaly": "#ef4444", "Normal": "#22c55e"},
                        )
                        fig.update_layout(template="plotly_dark",
                                          plot_bgcolor="rgba(10,14,23,0.8)",
                                          paper_bgcolor="rgba(10,14,23,0.8)", height=450)
                        st.plotly_chart(fig, use_container_width=True)

                        # Show anomalous IPs
                        anomalous = anomaly_df[anomaly_df["is_anomaly"]].sort_values("anomaly_score", ascending=False)
                        if len(anomalous) > 0:
                            st.markdown("#### Flagged Anomalous IPs")
                            st.dataframe(
                                anomalous[["ioc", "entropy", "risk_score", "anomaly_score"]],
                                use_container_width=True, hide_index=True,
                            )
                    else:
                        st.info("Need at least 5 unique IPs in logs for anomaly detection.")

                    # Domain clustering
                    domains = iocs_for_ml.get("domains", [])
                    if len(domains) >= 5:
                        st.markdown("---")
                        st.markdown("#### Domain DGA/Clustering Analysis")
                        domain_records = [{"ioc": d, "risk_score": 50} for d in domains[:100]]
                        clusterer = ThreatClusterer(n_clusters=min(4, len(domain_records)), method="kmeans")
                        cluster_df = clusterer.train_and_cluster(domain_records)

                        fig = px.scatter(
                            cluster_df, x="entropy", y="digit_ratio",
                            color="cluster_label", size="string_length",
                            hover_data=["ioc"],
                            title="Domain Clustering — Entropy vs Digit Ratio",
                            color_discrete_sequence=px.colors.qualitative.Set1,
                        )
                        fig.update_layout(template="plotly_dark",
                                          plot_bgcolor="rgba(10,14,23,0.8)",
                                          paper_bgcolor="rgba(10,14,23,0.8)", height=450)
                        st.plotly_chart(fig, use_container_width=True)

                        st.dataframe(
                            cluster_df[["ioc", "entropy", "digit_ratio", "cluster_label"]],
                            use_container_width=True, hide_index=True,
                        )

                # ════════════════════════════════════════════════════
                # RAW DATA TAB
                # ════════════════════════════════════════════════════
                with atab6:
                    st.markdown("### Parsed Log Data")
                    st.markdown(f"Showing first 500 rows of {len(parsed_df):,} total")
                    st.dataframe(parsed_df.head(500), use_container_width=True, height=600)

                    st.markdown("### Column Summary")
                    col_info = []
                    for col in parsed_df.columns:
                        col_info.append({
                            "Column": col,
                            "Type": str(parsed_df[col].dtype),
                            "Non-Null": int(parsed_df[col].notna().sum()),
                            "Unique": int(parsed_df[col].nunique()),
                            "Sample": str(parsed_df[col].dropna().iloc[0])[:100] if parsed_df[col].notna().any() else "N/A",
                        })
                    st.dataframe(pd.DataFrame(col_info), use_container_width=True, hide_index=True)

    else:
        st.info("Upload one or more log files above to start analysis. Supported formats: CSV, CSV.GZ, JSON, JSONL, TXT.")
        st.markdown("**Example log sources:** FortiGate UTM, Splunk stream exports, Windows Registry, Sysmon, network flow data, firewall logs.")


# ════════════════════════════════════════════════════════════════════
# TAB 2: Chat History & Investigation Export
# ════════════════════════════════════════════════════════════════════
with tab_chat:
    st.markdown("### Chat Investigation History")
    st.markdown("Review, search, and export your threat hunting session history.")

    if "investigation_log" not in st.session_state or not st.session_state.investigation_log:
        st.info("No investigation activity yet. Start chatting on the main page!")
    else:
        logs = st.session_state.investigation_log

        search = st.text_input("🔍 Filter logs", placeholder="Search by query or response...", key="log_search")

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

        # Export
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

    # Full chat history
    st.markdown("---")
    st.markdown("### 💬 Full Chat History")
    if "messages" not in st.session_state or not st.session_state.messages:
        st.info("No chat messages yet.")
    else:
        for msg in st.session_state.messages:
            role = "🕵️ Assistant" if msg["role"] == "assistant" else "👤 You"
            with st.expander(f"{role}: {msg['content'][:100]}..."):
                st.markdown(msg["content"])
