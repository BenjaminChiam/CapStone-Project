"""
📊 IOC Cluster Analysis Page
Visualizes K-Means clustering of IOCs using Plotly scatter charts.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from utils.ml_engine import ThreatClusterer

st.set_page_config(page_title="IOC Cluster Analysis", page_icon="📊", layout="wide")
st.title("📊 IOC Cluster Analysis")
st.markdown("Visualize threat campaigns using unsupervised ML clustering on IOC feature space.")

# ── Sample IOC Data Input ───────────────────────────────────────────
st.markdown("### Input IOCs")
st.markdown("Paste IOCs (one per line) with optional risk scores (`ioc,score`):")

sample_data = """ax7qz9.com,85
microsoft.com,5
evil-c2-server.xyz,92
google.com,2
q8x2k1m.net,78
phishing-login.com,70
github.com,3
r4nd0m-dga.biz,88
amazon.com,4
cobalt-strike-c2.io,95"""

ioc_text = st.text_area("IOC List", value=sample_data, height=250)

n_clusters = st.slider("Number of Clusters (K)", 2, 8, 4)

if st.button("🔬 Run Cluster Analysis", use_container_width=True):
    # Parse input
    iocs = []
    for line in ioc_text.strip().split("\n"):
        parts = line.strip().split(",")
        ioc = parts[0].strip()
        score = float(parts[1].strip()) if len(parts) > 1 else 50.0
        if ioc:
            iocs.append({"ioc": ioc, "risk_score": score})

    if len(iocs) < 4:
        st.warning("Need at least 4 IOCs for clustering.")
    else:
        # Run clustering
        clusterer = ThreatClusterer(n_clusters=n_clusters)
        df = clusterer.train_and_cluster(iocs)

        # ── Scatter Plot ────────────────────────────────────────────
        st.markdown("### Cluster Visualization")

        fig = px.scatter(
            df,
            x="entropy",
            y="risk_score",
            color="cluster_label",
            size="string_length",
            hover_data=["ioc", "entropy", "string_length", "risk_score"],
            title="IOC Feature Space — Shannon Entropy vs Risk Score",
            labels={
                "entropy": "Shannon Entropy (Randomness)",
                "risk_score": "Consensus Risk Score",
                "string_length": "String Length",
            },
            color_discrete_sequence=px.colors.qualitative.Set1,
        )
        fig.update_layout(
            template="plotly_dark",
            plot_bgcolor="rgba(10, 14, 23, 0.8)",
            paper_bgcolor="rgba(10, 14, 23, 0.8)",
            height=600,
        )
        st.plotly_chart(fig, use_container_width=True)

        # ── Data Table ──────────────────────────────────────────────
        st.markdown("### Cluster Assignments")
        st.dataframe(
            df[["ioc", "entropy", "string_length", "risk_score", "cluster", "cluster_label"]],
            use_container_width=True,
            hide_index=True,
        )

        # ── Cluster Stats ───────────────────────────────────────────
        st.markdown("### Cluster Statistics")
        stats = df.groupby("cluster_label").agg(
            count=("ioc", "count"),
            avg_entropy=("entropy", "mean"),
            avg_risk=("risk_score", "mean"),
            avg_length=("string_length", "mean"),
        ).round(2)
        st.dataframe(stats, use_container_width=True)
