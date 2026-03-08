"""
🎯 MITRE ATT&CK Navigator & Visualization Page
================================================
Features:
1. ATT&CK Matrix Heatmap (Navigator-style)
2. Technique Deep Dive Explorer
3. Threat Actor Group Mapping
4. Detection Coverage Tracker
5. Kill Chain Relationship Graph
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from utils.mitre_attack_data import (
    TACTICS, TECHNIQUES, GROUPS, SOFTWARE, MITIGATIONS,
    get_techniques_by_tactic, get_parent_techniques_by_tactic,
    get_subtechniques, get_groups_using_technique,
    get_software_using_technique, get_mitigations_for_technique,
    get_technique_by_id, get_group_by_name, search_techniques,
    get_tactic_technique_matrix,
)

st.set_page_config(page_title="MITRE ATT&CK Navigator", page_icon="🎯", layout="wide")
st.title("🎯 MITRE ATT&CK Navigator & Visualization")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🗺️ ATT&CK Matrix", "🔎 Technique Explorer",
    "👥 Group Analysis", "📊 Coverage Tracker", "🕸️ Relationship Graph"
])

# ════════════════════════════════════════════════════════════════════
# TAB 1: ATT&CK Matrix Heatmap
# ════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### ATT&CK Enterprise Matrix — Technique Heatmap")
    st.markdown("Visualizes technique density and threat actor coverage per tactic.")

    heat_mode = st.radio(
        "Heatmap Mode",
        ["Technique Count per Tactic", "Threat Group Coverage", "Select a Group"],
        horizontal=True,
    )

    selected_group = None
    if heat_mode == "Select a Group":
        group_names = [f"{g.name} ({', '.join(g.aliases[:2])})" if g.aliases else g.name for g in GROUPS]
        selected_name = st.selectbox("Choose Threat Group", group_names)
        # Extract actual group name
        actual_name = selected_name.split(" (")[0]
        selected_group = get_group_by_name(actual_name)

    # Build matrix data
    matrix_data = []
    for tactic in TACTICS:
        parent_techs = get_parent_techniques_by_tactic(tactic.id)

        if heat_mode == "Technique Count per Tactic":
            value = len(parent_techs)
            hover_text = f"{tactic.name}<br>{value} techniques"
        elif heat_mode == "Threat Group Coverage":
            # Count how many groups use techniques in this tactic
            group_count = 0
            for tech in parent_techs:
                group_count += len(get_groups_using_technique(tech.id))
            value = group_count
            hover_text = f"{tactic.name}<br>{group_count} group-technique mappings"
        else:
            # Specific group coverage
            if selected_group:
                covered = sum(1 for t in parent_techs if t.id in selected_group.technique_ids)
                value = covered
                hover_text = f"{tactic.name}<br>{covered}/{len(parent_techs)} techniques used by {selected_group.name}"
            else:
                value = 0
                hover_text = ""

        matrix_data.append({
            "tactic": tactic.name,
            "tactic_id": tactic.id,
            "order": tactic.order,
            "value": value,
            "hover": hover_text,
            "technique_count": len(parent_techs),
        })

    df_matrix = pd.DataFrame(matrix_data).sort_values("order")

    # Heatmap bar chart
    fig = go.Figure(data=[
        go.Bar(
            x=df_matrix["tactic"],
            y=df_matrix["value"],
            marker=dict(
                color=df_matrix["value"],
                colorscale="YlOrRd",
                showscale=True,
                colorbar=dict(title="Count"),
            ),
            text=df_matrix["value"],
            textposition="outside",
            hovertext=df_matrix["hover"],
            hoverinfo="text",
        )
    ])
    fig.update_layout(
        template="plotly_dark",
        plot_bgcolor="rgba(10,14,23,0.8)",
        paper_bgcolor="rgba(10,14,23,0.8)",
        height=450,
        xaxis_tickangle=-45,
        yaxis_title="Count",
        title=heat_mode,
        margin=dict(b=120),
    )
    st.plotly_chart(fig, use_container_width=True)

    # Matrix grid view
    st.markdown("### Matrix Grid View")
    cols = st.columns(len(TACTICS))
    for i, tactic in enumerate(sorted(TACTICS, key=lambda t: t.order)):
        with cols[i]:
            st.markdown(f"**{tactic.name}**")
            techs = get_parent_techniques_by_tactic(tactic.id)
            for tech in techs[:8]:
                if selected_group and tech.id in selected_group.technique_ids:
                    st.markdown(f"🔴 `{tech.id}`")
                else:
                    st.caption(f"`{tech.id}` {tech.name[:18]}")
            if len(techs) > 8:
                st.caption(f"... +{len(techs)-8} more")


# ════════════════════════════════════════════════════════════════════
# TAB 2: Technique Explorer
# ════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### Technique Deep Dive")

    search_query = st.text_input("Search Techniques", placeholder="e.g., T1566, Phishing, PowerShell...")

    if search_query:
        results = search_techniques(search_query)
        if results:
            tech_options = [f"{t.id} — {t.name}" for t in results]
            selected_tech_str = st.selectbox("Select Technique", tech_options)
            selected_tech_id = selected_tech_str.split(" — ")[0]
        else:
            st.warning("No techniques found.")
            selected_tech_id = None
    else:
        # Default: browse by tactic
        tactic_names = [f"{t.name} ({t.id})" for t in sorted(TACTICS, key=lambda t: t.order)]
        selected_tactic_str = st.selectbox("Browse by Tactic", tactic_names)
        selected_tactic_id = selected_tactic_str.split("(")[-1].rstrip(")")
        techs = get_techniques_by_tactic(selected_tactic_id)
        parent_techs = [t for t in techs if not t.is_subtechnique]
        tech_options = [f"{t.id} — {t.name}" for t in parent_techs]
        if tech_options:
            selected_tech_str = st.selectbox("Select Technique", tech_options)
            selected_tech_id = selected_tech_str.split(" — ")[0]
        else:
            selected_tech_id = None

    if selected_tech_id:
        tech = get_technique_by_id(selected_tech_id)
        if tech:
            st.markdown(f"## {tech.id}: {tech.name}")
            st.markdown(f"**Description:** {tech.description}")

            if tech.platforms:
                st.markdown(f"**Platforms:** {', '.join(tech.platforms)}")

            # Tactics
            tactic_names = []
            for tid in tech.tactic_ids:
                for t in TACTICS:
                    if t.id == tid:
                        tactic_names.append(f"{t.name} ({t.id})")
            st.markdown(f"**Tactics:** {', '.join(tactic_names)}")

            col1, col2 = st.columns(2)

            # Sub-techniques
            with col1:
                subtechs = get_subtechniques(tech.id)
                if subtechs:
                    st.markdown("### Sub-Techniques")
                    for st_ in subtechs:
                        st.markdown(f"- **{st_.id}**: {st_.name} — {st_.description[:80]}...")

            # Groups using this technique
            with col2:
                groups = get_groups_using_technique(tech.id)
                if groups:
                    st.markdown("### Threat Groups Using This")
                    for g in groups:
                        st.markdown(f"- **{g.name}** ({g.id}) — {g.country}")
                        if g.aliases:
                            st.caption(f"  Aliases: {', '.join(g.aliases[:3])}")

            col3, col4 = st.columns(2)

            # Software
            with col3:
                sw = get_software_using_technique(tech.id)
                if sw:
                    st.markdown("### Software / Tools")
                    for s in sw:
                        st.markdown(f"- **{s.name}** ({s.id}) [{s.sw_type}]")
                        st.caption(f"  {s.description[:100]}...")

            # Mitigations
            with col4:
                mits = get_mitigations_for_technique(tech.id)
                if mits:
                    st.markdown("### Mitigations")
                    for m in mits:
                        st.markdown(f"- **{m.id}: {m.name}**")
                        st.caption(f"  {m.description[:100]}...")

            # Data sources
            if tech.data_sources:
                st.markdown(f"### Detection Data Sources")
                st.markdown(", ".join(tech.data_sources))


# ════════════════════════════════════════════════════════════════════
# TAB 3: Group Analysis
# ════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### Threat Actor Group Analysis")

    group_names = [f"{g.name} — {g.country}" for g in GROUPS]
    selected_group_str = st.selectbox("Select Threat Group", group_names, key="group_tab")
    selected_group_name = selected_group_str.split(" — ")[0]
    group = get_group_by_name(selected_group_name)

    if group:
        st.markdown(f"## {group.name} ({group.id})")
        if group.aliases:
            st.markdown(f"**Aliases:** {', '.join(group.aliases)}")
        st.markdown(f"**Country:** {group.country}")
        st.markdown(f"**Description:** {group.description}")
        st.markdown(f"**Techniques Used:** {len(group.technique_ids)}")

        # Tactic coverage chart
        tactic_counts = {}
        for tid in group.technique_ids:
            tech = get_technique_by_id(tid)
            if tech:
                for tac_id in tech.tactic_ids:
                    for tac in TACTICS:
                        if tac.id == tac_id:
                            tactic_counts[tac.name] = tactic_counts.get(tac.name, 0) + 1

        if tactic_counts:
            df_tactic = pd.DataFrame([
                {"Tactic": k, "Techniques": v}
                for k, v in sorted(tactic_counts.items(),
                                   key=lambda x: next((t.order for t in TACTICS if t.name == x[0]), 99))
            ])

            fig_radar = go.Figure()
            fig_radar.add_trace(go.Scatterpolar(
                r=df_tactic["Techniques"].tolist() + [df_tactic["Techniques"].iloc[0]],
                theta=df_tactic["Tactic"].tolist() + [df_tactic["Tactic"].iloc[0]],
                fill="toself",
                name=group.name,
                line=dict(color="#ef4444"),
                fillcolor="rgba(239, 68, 68, 0.2)",
            ))
            fig_radar.update_layout(
                polar=dict(
                    bgcolor="rgba(10,14,23,0.8)",
                    radialaxis=dict(visible=True, gridcolor="rgba(56,189,248,0.1)"),
                    angularaxis=dict(gridcolor="rgba(56,189,248,0.1)"),
                ),
                template="plotly_dark",
                paper_bgcolor="rgba(10,14,23,0.8)",
                title=f"{group.name} — Kill Chain Coverage (Radar)",
                height=550,
                showlegend=False,
            )
            st.plotly_chart(fig_radar, use_container_width=True)

        # Techniques table
        st.markdown("### Techniques Used")
        tech_rows = []
        for tid in group.technique_ids:
            tech = get_technique_by_id(tid)
            if tech:
                tactics = ", ".join(
                    [t.name for t in TACTICS if t.id in tech.tactic_ids]
                )
                tech_rows.append({
                    "ID": tech.id,
                    "Name": tech.name,
                    "Tactics": tactics,
                    "Sub-technique": "Yes" if tech.is_subtechnique else "No",
                })
        if tech_rows:
            st.dataframe(pd.DataFrame(tech_rows), use_container_width=True, hide_index=True)

        # Group comparison
        st.markdown("### Compare with Another Group")
        other_names = [f"{g.name}" for g in GROUPS if g.name != group.name]
        compare_name = st.selectbox("Compare with", other_names)
        compare_group = get_group_by_name(compare_name)

        if compare_group:
            shared = set(group.technique_ids) & set(compare_group.technique_ids)
            only_a = set(group.technique_ids) - set(compare_group.technique_ids)
            only_b = set(compare_group.technique_ids) - set(group.technique_ids)

            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("Shared Techniques", len(shared))
            with c2:
                st.metric(f"Only {group.name}", len(only_a))
            with c3:
                st.metric(f"Only {compare_group.name}", len(only_b))

            if shared:
                st.markdown("**Shared Techniques:**")
                shared_names = [f"`{tid}` {get_technique_by_id(tid).name}" for tid in shared if get_technique_by_id(tid)]
                st.markdown(" | ".join(shared_names[:15]))


# ════════════════════════════════════════════════════════════════════
# TAB 4: Detection Coverage Tracker
# ════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### Detection Coverage Tracker")
    st.markdown(
        "Select techniques your SOC currently detects to visualize coverage gaps."
    )

    # Build technique checklist by tactic
    all_parent_techs = [t for t in TECHNIQUES if not t.is_subtechnique]

    if "covered_techniques" not in st.session_state:
        st.session_state.covered_techniques = set()

    # Quick select
    col_q1, col_q2 = st.columns(2)
    with col_q1:
        if st.button("Select All", use_container_width=True):
            st.session_state.covered_techniques = {t.id for t in all_parent_techs}
            st.rerun()
    with col_q2:
        if st.button("Clear All", use_container_width=True):
            st.session_state.covered_techniques = set()
            st.rerun()

    # Tactic-by-tactic selection
    for tactic in sorted(TACTICS, key=lambda t: t.order):
        techs = get_parent_techniques_by_tactic(tactic.id)
        if not techs:
            continue
        with st.expander(f"{tactic.name} ({len(techs)} techniques)", expanded=False):
            for tech in techs:
                checked = tech.id in st.session_state.covered_techniques
                if st.checkbox(f"{tech.id}: {tech.name}", value=checked, key=f"cov_{tech.id}"):
                    st.session_state.covered_techniques.add(tech.id)
                else:
                    st.session_state.covered_techniques.discard(tech.id)

    # Coverage visualization
    st.markdown("---")
    total = len(all_parent_techs)
    covered = len(st.session_state.covered_techniques)
    pct = (covered / total * 100) if total > 0 else 0

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Total Techniques", total)
    with c2:
        st.metric("Covered", covered)
    with c3:
        st.metric("Coverage %", f"{pct:.1f}%")

    # Coverage by tactic
    cov_data = []
    for tactic in sorted(TACTICS, key=lambda t: t.order):
        techs = get_parent_techniques_by_tactic(tactic.id)
        covered_in_tactic = sum(1 for t in techs if t.id in st.session_state.covered_techniques)
        total_in_tactic = len(techs)
        pct_tac = (covered_in_tactic / total_in_tactic * 100) if total_in_tactic > 0 else 0
        cov_data.append({
            "Tactic": tactic.name,
            "Covered": covered_in_tactic,
            "Total": total_in_tactic,
            "Gap": total_in_tactic - covered_in_tactic,
            "Coverage %": round(pct_tac, 1),
        })

    df_cov = pd.DataFrame(cov_data)

    fig_cov = go.Figure(data=[
        go.Bar(name="Covered", x=df_cov["Tactic"], y=df_cov["Covered"],
               marker_color="#22c55e"),
        go.Bar(name="Gap", x=df_cov["Tactic"], y=df_cov["Gap"],
               marker_color="#ef4444"),
    ])
    fig_cov.update_layout(
        barmode="stack", template="plotly_dark",
        plot_bgcolor="rgba(10,14,23,0.8)",
        paper_bgcolor="rgba(10,14,23,0.8)",
        title="Detection Coverage by Tactic",
        height=450, xaxis_tickangle=-45,
        margin=dict(b=120),
    )
    st.plotly_chart(fig_cov, use_container_width=True)


# ════════════════════════════════════════════════════════════════════
# TAB 5: Relationship Graph
# ════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown("### Technique ↔ Group ↔ Software Relationship Graph")

    focus_options = ["By Technique", "By Group", "By Software"]
    focus = st.radio("Focus on", focus_options, horizontal=True)

    if focus == "By Technique":
        tech_opts = [f"{t.id} — {t.name}" for t in TECHNIQUES if not t.is_subtechnique]
        sel = st.selectbox("Select Technique", tech_opts, key="rel_tech")
        focus_id = sel.split(" — ")[0]

        tech = get_technique_by_id(focus_id)
        groups = get_groups_using_technique(focus_id)
        sw = get_software_using_technique(focus_id)
        mits = get_mitigations_for_technique(focus_id)

        # Build nodes and edges
        nodes = [{"id": focus_id, "label": f"{focus_id}\n{tech.name}", "color": "#0ea5e9", "size": 30}]
        edges = []

        for g in groups:
            nodes.append({"id": g.id, "label": g.name, "color": "#ef4444", "size": 20})
            edges.append({"from": g.id, "to": focus_id, "label": "uses"})
        for s in sw:
            nodes.append({"id": s.id, "label": s.name, "color": "#eab308", "size": 18})
            edges.append({"from": s.id, "to": focus_id, "label": "uses"})
        for m in mits:
            nodes.append({"id": m.id, "label": m.name, "color": "#22c55e", "size": 16})
            edges.append({"from": m.id, "to": focus_id, "label": "mitigates"})

    elif focus == "By Group":
        g_opts = [f"{g.name} ({g.id})" for g in GROUPS]
        sel = st.selectbox("Select Group", g_opts, key="rel_group")
        group_name = sel.split(" (")[0]
        group = get_group_by_name(group_name)

        nodes = [{"id": group.id, "label": group.name, "color": "#ef4444", "size": 30}]
        edges = []

        for tid in group.technique_ids[:20]:
            tech = get_technique_by_id(tid)
            if tech:
                nodes.append({"id": tid, "label": f"{tid}\n{tech.name[:20]}", "color": "#0ea5e9", "size": 15})
                edges.append({"from": group.id, "to": tid, "label": "uses"})

    else:
        sw_opts = [f"{s.name} ({s.id})" for s in SOFTWARE]
        sel = st.selectbox("Select Software", sw_opts, key="rel_sw")
        sw_name = sel.split(" (")[0]
        sw_obj = next((s for s in SOFTWARE if s.name == sw_name), None)

        nodes = [{"id": sw_obj.id, "label": sw_obj.name, "color": "#eab308", "size": 30}]
        edges = []

        for tid in sw_obj.technique_ids[:20]:
            tech = get_technique_by_id(tid)
            if tech:
                nodes.append({"id": tid, "label": f"{tid}\n{tech.name[:20]}", "color": "#0ea5e9", "size": 15})
                edges.append({"from": sw_obj.id, "to": tid, "label": "uses"})

    # Render as Plotly network graph
    import math
    n = len(nodes)
    if n > 0:
        # Position nodes in a radial layout
        center = nodes[0]
        positions = {center["id"]: (0, 0)}
        for i, node in enumerate(nodes[1:]):
            angle = 2 * math.pi * i / max(n - 1, 1)
            radius = 2
            positions[node["id"]] = (radius * math.cos(angle), radius * math.sin(angle))

        # Edge traces
        edge_x, edge_y = [], []
        for edge in edges:
            x0, y0 = positions.get(edge["from"], (0, 0))
            x1, y1 = positions.get(edge["to"], (0, 0))
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y, mode="lines",
            line=dict(width=1, color="rgba(150,150,150,0.5)"),
            hoverinfo="none",
        )

        # Node traces
        node_x = [positions[n["id"]][0] for n in nodes]
        node_y = [positions[n["id"]][1] for n in nodes]
        node_colors = [n["color"] for n in nodes]
        node_sizes = [n["size"] for n in nodes]
        node_labels = [n["label"] for n in nodes]

        node_trace = go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            marker=dict(size=node_sizes, color=node_colors, line=dict(width=1, color="#1e293b")),
            text=node_labels,
            textposition="top center",
            textfont=dict(size=9, color="#e2e8f0"),
            hoverinfo="text",
        )

        fig_graph = go.Figure(data=[edge_trace, node_trace])
        fig_graph.update_layout(
            template="plotly_dark",
            plot_bgcolor="rgba(10,14,23,0.8)",
            paper_bgcolor="rgba(10,14,23,0.8)",
            height=600,
            showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            title="Relationship Graph",
            margin=dict(l=20, r=20, t=50, b=20),
        )
        st.plotly_chart(fig_graph, use_container_width=True)

    # Legend
    st.markdown(
        "**Legend:** "
        "🔵 Technique &nbsp; 🔴 Threat Group &nbsp; 🟡 Software/Tool &nbsp; 🟢 Mitigation"
    )
