"""
📊 ML Analysis Page
Visualizes K-Means/DBSCAN clustering, Isolation Forest anomaly detection,
and DGA domain scanning.
"""

import streamlit as st
import plotly.express as px
import pandas as pd
from utils.ml_engine import ThreatClusterer, AnomalyDetector, DGADetector
from utils.ai_chat import render_ai_analysis

st.set_page_config(page_title="ML Analysis", page_icon="📊", layout="wide")
st.title("📊 ML Threat Analysis")

tab1, tab2, tab3 = st.tabs(["🔬 Cluster Analysis", "⚠️ Anomaly Detection", "🧬 DGA Scanner"])

# ════════════════════════════════════════════════════════════════════
# TAB 1: Cluster Analysis
# ════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### IOC Campaign Clustering")
    st.markdown("Identify threat campaigns using unsupervised ML on IOC feature space.")

    sample_data = """ax7qz9.com,85
microsoft.com,5
evil-c2-server.xyz,92
google.com,2
q8x2k1m.net,78
phishing-login.com,70
github.com,3
r4nd0m-dga.biz,88
amazon.com,4
cobalt-strike-c2.io,95
sub.sub.deep.evil.com,80
a1b2c3d4e5.net,75
login-paypal-secure.com,65
x9z8y7.ru,90"""

    ioc_text = st.text_area("IOC List (one per line: `ioc,risk_score`)", value=sample_data, height=200)

    col1, col2 = st.columns(2)
    with col1:
        method = st.selectbox("Algorithm", ["K-Means", "DBSCAN"])
    with col2:
        n_clusters = st.slider("Clusters (K-Means only)", 2, 8, 4) if method == "K-Means" else 4

    if st.button("🔬 Run Cluster Analysis", use_container_width=True):
        iocs = []
        for line in ioc_text.strip().split("\n"):
            parts = line.strip().split(",")
            ioc = parts[0].strip()
            score = float(parts[1].strip()) if len(parts) > 1 else 50.0
            if ioc:
                iocs.append({"ioc": ioc, "risk_score": score})

        if len(iocs) < 4:
            st.warning("Need at least 4 IOCs.")
        else:
            algo = "dbscan" if method == "DBSCAN" else "kmeans"
            clusterer = ThreatClusterer(n_clusters=n_clusters, method=algo)
            df = clusterer.train_and_cluster(iocs)

            fig = px.scatter(
                df, x="entropy", y="risk_score", color="cluster_label",
                size="string_length",
                hover_data=["ioc", "entropy", "digit_ratio", "vowel_consonant_ratio", "risk_score"],
                title=f"IOC Feature Space — {method} Clustering",
                labels={"entropy": "Shannon Entropy", "risk_score": "Consensus Risk Score"},
                color_discrete_sequence=px.colors.qualitative.Set1,
            )
            fig.update_layout(template="plotly_dark",
                              plot_bgcolor="rgba(10,14,23,0.8)",
                              paper_bgcolor="rgba(10,14,23,0.8)", height=550)
            st.plotly_chart(fig, use_container_width=True)

            # Feature comparison chart
            fig2 = px.scatter(
                df, x="vowel_consonant_ratio", y="digit_ratio",
                color="cluster_label", size="entropy",
                hover_data=["ioc"],
                title="Vowel/Consonant Ratio vs Digit Ratio",
                color_discrete_sequence=px.colors.qualitative.Set1,
            )
            fig2.update_layout(template="plotly_dark",
                               plot_bgcolor="rgba(10,14,23,0.8)",
                               paper_bgcolor="rgba(10,14,23,0.8)", height=450)
            st.plotly_chart(fig2, use_container_width=True)

            st.markdown("### Cluster Assignments")
            st.dataframe(df[["ioc", "entropy", "string_length", "risk_score",
                             "vowel_consonant_ratio", "digit_ratio",
                             "subdomain_depth", "cluster", "cluster_label"]],
                         use_container_width=True, hide_index=True)

            # AI Analysis
            render_ai_analysis(
                df[["ioc", "entropy", "risk_score", "cluster_label"]].to_dict(),
                context_label="cluster analysis results",
                page_key="cluster",
                system_context="Focus on identifying potential threat campaigns, DGA patterns, and C2 infrastructure based on the cluster groupings.",
            )

# ════════════════════════════════════════════════════════════════════
# TAB 2: Anomaly Detection
# ════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### Isolation Forest Anomaly Detection")
    st.markdown("Identify statistically unusual IOCs that may indicate novel or zero-day threats.")

    anomaly_text = st.text_area(
        "IOC List for Anomaly Detection",
        value=sample_data,
        height=200,
        key="anomaly_input",
    )

    contamination = st.slider("Contamination (expected % anomalies)", 0.05, 0.30, 0.10, 0.05)

    if st.button("⚠️ Run Anomaly Detection", use_container_width=True):
        iocs = []
        for line in anomaly_text.strip().split("\n"):
            parts = line.strip().split(",")
            ioc = parts[0].strip()
            score = float(parts[1].strip()) if len(parts) > 1 else 50.0
            if ioc:
                iocs.append({"ioc": ioc, "risk_score": score})

        if len(iocs) < 5:
            st.warning("Need at least 5 IOCs for anomaly detection.")
        else:
            detector = AnomalyDetector(contamination=contamination)
            df = detector.train_and_detect(iocs)

            anomaly_count = df["is_anomaly"].sum()
            st.metric("Anomalies Detected", f"{anomaly_count} / {len(df)}")

            fig = px.scatter(
                df, x="entropy", y="risk_score",
                color=df["is_anomaly"].map({True: "🔴 Anomaly", False: "🟢 Normal"}),
                size="anomaly_score",
                hover_data=["ioc", "anomaly_score", "digit_ratio"],
                title="Anomaly Detection — Isolation Forest",
                labels={"entropy": "Shannon Entropy", "risk_score": "Risk Score",
                        "color": "Status"},
            )
            fig.update_layout(template="plotly_dark",
                              plot_bgcolor="rgba(10,14,23,0.8)",
                              paper_bgcolor="rgba(10,14,23,0.8)", height=550)
            st.plotly_chart(fig, use_container_width=True)

            st.markdown("### Results")
            display_df = df[["ioc", "entropy", "risk_score", "anomaly_score", "is_anomaly"]].sort_values(
                "anomaly_score", ascending=False
            )
            st.dataframe(display_df, use_container_width=True, hide_index=True)

            # AI Analysis
            render_ai_analysis(
                display_df.to_dict(),
                context_label="anomaly detection results",
                page_key="anomaly",
                system_context="Focus on which anomalous IOCs are most likely to be genuine threats vs false positives, and recommend investigation priorities.",
            )

# ════════════════════════════════════════════════════════════════════
# TAB 3: DGA Scanner
# ════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### DGA Domain Scanner")
    st.markdown("Analyze domains for Domain Generation Algorithm characteristics using entropy, n-gram analysis, and linguistic features.")

    dga_input = st.text_area(
        "Domains to Scan (one per line)",
        value="microsoft.com\ngoogle.com\nax7qz9k2m.com\nq8x2k1m.net\nlogin-paypal-secure.com\nr4nd0m-dga.biz\na1b2c3d4e5f6g7h8.ru\namazon.com\nxyz123abc456.cn\ngithub.com",
        height=200,
        key="dga_input",
    )

    if st.button("🧬 Scan for DGA Patterns", use_container_width=True):
        detector = DGADetector()
        results = []
        for line in dga_input.strip().split("\n"):
            domain = line.strip()
            if domain:
                result = detector.detect(domain)
                results.append({
                    "domain": result["domain"],
                    "dga_score": result["dga_score"],
                    "verdict": result["verdict"],
                    "entropy": result["features"]["entropy"],
                    "bigram_score": result["features"]["bigram_score"],
                    "vowel_ratio": result["features"]["vowel_consonant_ratio"],
                    "digit_ratio": result["features"]["digit_ratio"],
                })

        df = pd.DataFrame(results)

        # Summary metrics
        cols = st.columns(3)
        with cols[0]:
            st.metric("Likely DGA", len(df[df["verdict"] == "LIKELY DGA"]))
        with cols[1]:
            st.metric("Suspicious", len(df[df["verdict"] == "SUSPICIOUS"]))
        with cols[2]:
            st.metric("Likely Legitimate", len(df[df["verdict"] == "LIKELY LEGITIMATE"]))

        fig = px.bar(
            df.sort_values("dga_score", ascending=True),
            x="dga_score", y="domain", orientation="h",
            color="verdict",
            color_discrete_map={
                "LIKELY DGA": "#ef4444",
                "SUSPICIOUS": "#eab308",
                "LIKELY LEGITIMATE": "#22c55e",
            },
            title="DGA Probability Scores",
        )
        fig.update_layout(template="plotly_dark",
                          plot_bgcolor="rgba(10,14,23,0.8)",
                          paper_bgcolor="rgba(10,14,23,0.8)",
                          height=max(400, len(df) * 40))
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Detailed Results")
        st.dataframe(df, use_container_width=True, hide_index=True)

        # AI Analysis
        render_ai_analysis(
            df.to_dict(),
            context_label="DGA domain scan results",
            page_key="dga",
            system_context="Focus on which domains are most likely DGA-generated, potential malware families, and recommended blocking actions.",
        )
