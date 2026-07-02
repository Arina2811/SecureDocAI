"""
SecureDoc AI — DLP & Compliance Analysis Platform

Main Streamlit application providing:
  • Drag-and-drop document upload (PDF, TXT, CSV)
  • Sensitive data detection dashboard
  • Risk assessment with security scoring
  • AI-generated compliance reports
  • RAG-powered interactive Q&A
  • Report export (JSON)
"""

from __future__ import annotations

import json
import time
import logging
from collections import Counter
from datetime import datetime

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
try:
    import google.api_core.exceptions as google_exceptions
except ImportError:
    google_exceptions = None

import config
from models.schemas import (
    ComplianceReport,
    DetectedEntity,
    DocumentAnalysis,
    RiskAssessment,
)
from services.parser import parse_document
from services.detector import detect_sensitive_data, get_entities_summary
from services.classifier import assess_risk
from services.summarizer import generate_report
from services.rag import DocumentVectorStore, answer_question
from utils.helpers import (
    audit_log,
    format_file_size,
    mask_value,
    risk_color,
    severity_emoji,
)

logger = logging.getLogger("securedoc.app")

# ─── Page Configuration ───────────────────────────────────────────────────────

st.set_page_config(
    page_title=config.APP_TITLE,
    page_icon=config.APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ────────────────────────────────────────────────────────────────

st.markdown(
    """
    <style>
    /* ── Import Google Font ─────────────────────────────────────── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    /* ── Global ─────────────────────────────────────────────────── */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .main .block-container {
        padding-top: 1.5rem;
        max-width: 1400px;
    }

    /* ── Header ─────────────────────────────────────────────────── */
    .app-header {
        background: var(--secondary-background-color);
        padding: 2rem 2.5rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        box-shadow: 0 8px 32px rgba(0,0,0,.08);
        border: 1px solid rgba(128,128,128,0.2);
    }
    .app-header h1 {
        color: var(--text-color);
        font-weight: 800;
        font-size: 2rem;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .app-header p {
        color: var(--text-color);
        opacity: 0.7;
        font-size: 1rem;
        margin: .5rem 0 0;
    }

    /* ── Metric Cards ───────────────────────────────────────────── */
    .metric-card {
        background: var(--secondary-background-color);
        border: 1px solid rgba(128,128,128,0.2);
        border-radius: 14px;
        padding: 1.4rem 1.6rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0,0,0,.05);
        transition: transform .2s ease, box-shadow .2s ease;
    }
    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 30px rgba(79,70,229,.15);
    }
    .metric-card .value {
        font-size: 2.2rem;
        font-weight: 800;
        color: var(--primary-color);
    }
    .metric-card .label {
        color: var(--text-color);
        opacity: 0.7;
        font-size: .85rem;
        margin-top: .3rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* ── Risk Badge ─────────────────────────────────────────────── */
    .risk-badge {
        display: inline-block;
        padding: .35rem 1.2rem;
        border-radius: 999px;
        font-weight: 700;
        font-size: .95rem;
        letter-spacing: .5px;
        text-transform: uppercase;
    }
    .risk-low     { background: #27ae6022; color: #27ae60; border: 1px solid #27ae6044; }
    .risk-medium  { background: #f39c1222; color: #f39c12; border: 1px solid #f39c1244; }
    .risk-high    { background: #e67e2222; color: #e67e22; border: 1px solid #e67e2244; }
    .risk-critical{ background: #e74c3c22; color: #e74c3c; border: 1px solid #e74c3c44; }

    /* ── Sidebar ────────────────────────────────────────────────── */
    [data-testid="stSidebar"] {
        background: var(--secondary-background-color);
    }

    /* ── Chat bubbles ───────────────────────────────────────────── */
    .chat-user {
        background: var(--primary-color);
        color: white;
        padding: .8rem 1.2rem;
        border-radius: 14px 14px 4px 14px;
        margin: .5rem 0;
        max-width: 80%;
        margin-left: auto;
    }
    .chat-assistant {
        background: var(--secondary-background-color);
        color: var(--text-color);
        padding: .8rem 1.2rem;
        border-radius: 14px 14px 14px 4px;
        margin: .5rem 0;
        max-width: 80%;
        border: 1px solid rgba(128,128,128,0.2);
    }

    /* ── Tabs ───────────────────────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 20px;
        font-weight: 600;
    }

    /* ── Expander ───────────────────────────────────────────────── */
    .streamlit-expanderHeader {
        font-weight: 600;
        font-size: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ─── Session State Initialisation ──────────────────────────────────────────────

def _init_session():
    defaults = {
        "analyses": {},
        "selected_file": None,
        "vector_store": None,
        "chat_history": [],
        "processing": False,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


_init_session()


# ─── Header ───────────────────────────────────────────────────────────────────

st.markdown(
    """
    <div class="app-header">
        <h1>🛡️ SecureDoc AI</h1>
        <p>Enterprise-grade Data Loss Prevention &amp; Compliance Analysis Platform</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 📤 Upload Documents")
    uploaded_files = st.file_uploader(
        "Drag & drop or browse",
        type=["pdf", "txt", "csv"],
        accept_multiple_files=True,
        help="Supported formats: PDF, TXT, CSV (max 50 MB per file)",
    )

    st.divider()

    st.markdown("### ⚙️ Analysis Settings")
    use_ner = st.toggle("Enable NER Detection", value=True, help="Use spaCy for named entity recognition")
    use_llm = st.toggle("Enable LLM Detection", value=True, help="Use Gemini for contextual detection")
    use_rag = st.toggle("Enable RAG for Q&A", value=True, help="Build vector index for better Q&A")

    st.divider()

    if st.session_state.analyses:
        st.markdown("### 📈 Aggregate Stats")
        total_files = len(st.session_state.analyses)
        total_entities = sum(a.risk_assessment.total_entities for a in st.session_state.analyses.values() if a.risk_assessment)
        avg_score = sum(a.risk_assessment.security_score for a in st.session_state.analyses.values() if a.risk_assessment) / max(total_files, 1)
        
        st.metric("Total Files Processed", total_files)
        st.metric("Total Sensitive Items", total_entities)
        st.metric("Avg Security Score", f"{avg_score:.0f}/100")
        
    st.divider()

    if st.session_state.analyses and st.session_state.selected_file:
        st.markdown("### 📊 Document Stats")
        a: DocumentAnalysis = st.session_state.analyses[st.session_state.selected_file]
        st.metric("Entities Found", a.risk_assessment.total_entities if a.risk_assessment else 0)
        st.metric("Security Score", f"{a.risk_assessment.security_score}/100" if a.risk_assessment else "N/A")
        st.metric("File Size", format_file_size(a.file_size_bytes))

    st.divider()
    st.caption(f"SecureDoc AI v{config.APP_VERSION}")
    


# ─── File Processing ──────────────────────────────────────────────────────────

def _process_file(uploaded_file) -> None:
    """Run the full analysis pipeline on the uploaded file."""
    st.session_state.processing = True
    st.session_state.chat_history = []

    file_bytes = uploaded_file.getvalue()
    filename = uploaded_file.name

    audit_log("file_uploaded", {"filename": filename, "size": len(file_bytes)})

    progress = st.progress(0, text="🔄 Initialising analysis…")
    status = st.status("Analysing document…", expanded=True)

    try:
        # Step 1: Parse document
        status.write("📄 Extracting text from document…")
        progress.progress(10, text="📄 Parsing document…")
        text, file_type = parse_document(file_bytes, filename)
        status.write(f"✅ Extracted {len(text):,} characters from {file_type.upper()} file")

        # Step 2: Detect sensitive data
        status.write("🔍 Running sensitive data detection…")
        progress.progress(30, text="🔍 Detecting sensitive data…")
        entities = detect_sensitive_data(text, use_ner=use_ner, use_llm=use_llm)
        status.write(f"✅ Found {len(entities)} sensitive entities")

        # Step 3: Risk assessment
        status.write("📊 Computing risk assessment…")
        progress.progress(55, text="📊 Assessing risk…")
        risk = assess_risk(entities)
        status.write(f"✅ Risk level: {risk.risk_level} | Score: {risk.security_score}/100")

        # Step 4: Compliance report
        status.write("📝 Generating compliance report…")
        progress.progress(70, text="📝 Generating report…")
        report = generate_report(text, entities, risk)
        status.write("✅ Compliance report generated")

        # Step 5: Build RAG index
        if use_rag:
            status.write("🧠 Building knowledge index for Q&A…")
            progress.progress(85, text="🧠 Building RAG index…")
            vs = DocumentVectorStore()
            vs.build_index(text)
            st.session_state.vector_store = vs
            status.write("✅ RAG index ready")

        progress.progress(100, text="✅ Analysis complete!")

        # Store results
        analysis = DocumentAnalysis(
            filename=filename,
            file_type=file_type,
            file_size_bytes=len(file_bytes),
            text_length=len(text),
            extracted_text=text,
            entities=entities,
            risk_assessment=risk,
            compliance_report=report,
            analysed_at=datetime.utcnow(),
        )
        st.session_state.analyses[filename] = analysis
        st.session_state.selected_file = filename

        status.update(label=f"✅ Analysis complete for {filename}!", state="complete")
        audit_log("analysis_complete", {
            "filename": filename,
            "entities": len(entities),
            "risk_level": risk.risk_level,
            "security_score": risk.security_score,
        })

    except ValueError as exc:
        progress.empty()
        status.update(label=f"❌ Error in {filename}", state="error")
        st.error(f"❌ {exc}")
    except Exception as exc:
        progress.empty()
        status.update(label=f"❌ Error in {filename}", state="error")
        
        # Friendly error messages for common API failures
        if google_exceptions and isinstance(exc, google_exceptions.ResourceExhausted):
            st.error("❌ Google Gemini API rate limit exceeded. Please wait a moment and try again.")
        elif google_exceptions and isinstance(exc, google_exceptions.ServiceUnavailable):
            st.error("❌ Google Gemini API is currently unavailable. Please check your network connection.")
        elif "pdfplumber" in str(exc) or "fitz" in str(exc):
            st.error("❌ Failed to parse document. The file may be corrupt or encrypted.")
        else:
            st.error(f"❌ An unexpected error occurred: {exc}")
        
        logger.exception("Analysis pipeline failed")
    finally:
        st.session_state.processing = False


# ── Trigger analysis on upload ────────────────────────────────────────────────
if uploaded_files:
    for file in uploaded_files:
        if file.name not in st.session_state.analyses:
            _process_file(file)
            
# Clean up removed files
if uploaded_files:
    uploaded_names = {f.name for f in uploaded_files}
    for name in list(st.session_state.analyses.keys()):
        if name not in uploaded_names:
            del st.session_state.analyses[name]
    if st.session_state.selected_file not in uploaded_names and st.session_state.analyses:
        st.session_state.selected_file = next(iter(st.session_state.analyses.keys()))
else:
    st.session_state.analyses.clear()
    st.session_state.selected_file = None


# ─── Main Content ─────────────────────────────────────────────────────────────

if not st.session_state.analyses:
    # Empty state
    st.markdown(
        """
        <div style="text-align:center; padding:4rem 2rem; opacity:.7;">
            <h2 style="font-size:2.5rem;">📄 Upload a Document to Begin</h2>
            <p style="font-size:1.1rem; max-width:600px; margin:auto;">
                SecureDoc AI will automatically detect sensitive information,
                assess compliance risks, generate security reports, and let you
                ask questions about your documents.
            </p>
            <p style="margin-top:1rem; font-size:.9rem; color:#888;">
                Supported formats: <strong>PDF</strong>, <strong>TXT</strong>, <strong>CSV</strong>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()


# ── Loaded analysis ───────────────────────────────────────────────────────────
st.session_state.selected_file = st.selectbox(
    "Select Document to View", 
    options=list(st.session_state.analyses.keys()), 
    index=list(st.session_state.analyses.keys()).index(st.session_state.selected_file) if st.session_state.selected_file in st.session_state.analyses else 0
)

analysis: DocumentAnalysis = st.session_state.analyses[st.session_state.selected_file]
risk: RiskAssessment = analysis.risk_assessment  # type: ignore[assignment]
report: ComplianceReport = analysis.compliance_report  # type: ignore[assignment]

# ─── Tabs ─────────────────────────────────────────────────────────────────────

tab_dashboard, tab_entities, tab_redacted, tab_compliance, tab_qa, tab_export = st.tabs([
    "📊 Dashboard",
    "🔍 Detected Entities",
    "📄 Redacted Document",
    "📋 Compliance Report",
    "💬 Ask Questions",
    "📥 Export",
])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1: Dashboard
# ═══════════════════════════════════════════════════════════════════════════════

with tab_dashboard:
    # ── Top Metrics Row ───────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)

    risk_cls = risk.risk_level.lower() if isinstance(risk.risk_level, str) else risk.risk_level.value.lower()
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="value">{risk.security_score}</div>
                <div class="label">Security Score</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <span class="risk-badge risk-{risk_cls}">{risk.risk_level}</span>
                <div class="label" style="margin-top:.8rem;">Risk Level</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="value">{risk.total_entities}</div>
                <div class="label">Entities Detected</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="value">{len({e.entity_type for e in analysis.entities})}</div>
                <div class="label">Entity Types</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("")  # spacer

    # ── Charts Row ────────────────────────────────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### 🎯 Security Score Gauge")
        fig_gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=risk.security_score,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": "Security Score", "font": {"size": 18, "color": "#ccc"}},
                number={"suffix": "/100", "font": {"size": 36, "color": "#fff"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#555"},
                    "bar": {"color": risk_color(risk.risk_level)},
                    "bgcolor": "#1a1a2e",
                    "steps": [
                        {"range": [0, 40], "color": "rgba(231,76,60,.2)"},
                        {"range": [40, 60], "color": "rgba(230,126,34,.2)"},
                        {"range": [60, 80], "color": "rgba(243,156,18,.2)"},
                        {"range": [80, 100], "color": "rgba(39,174,96,.2)"},
                    ],
                    "threshold": {
                        "line": {"color": "#fff", "width": 3},
                        "thickness": 0.8,
                        "value": risk.security_score,
                    },
                },
            )
        )
        fig_gauge.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=300,
            margin=dict(t=60, b=20, l=30, r=30),
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col_right:
        st.markdown("#### 📊 Severity Distribution")
        sev_data = {
            "Severity": ["Critical", "High", "Medium", "Low", "Info"],
            "Count": [risk.critical_count, risk.high_count, risk.medium_count, risk.low_count, risk.info_count],
        }
        sev_df = pd.DataFrame(sev_data)
        sev_df = sev_df[sev_df["Count"] > 0]

        if not sev_df.empty:
            colors = {"Critical": "#e74c3c", "High": "#e67e22", "Medium": "#f39c12", "Low": "#27ae60", "Info": "#3498db"}
            fig_bar = px.bar(
                sev_df,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map=colors,
            )
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                height=300,
                margin=dict(t=20, b=40, l=40, r=20),
                xaxis=dict(color="#ccc"),
                yaxis=dict(color="#ccc", gridcolor="rgba(255,255,255,.05)"),
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No entities to visualise.")

    # ── Category Breakdown ────────────────────────────────────────────────
    st.markdown("#### 🗂️ Entities by Category")
    cat_counter = Counter(e.category for e in analysis.entities)
    if cat_counter:
        cat_df = pd.DataFrame(
            [{"Category": k, "Count": v} for k, v in cat_counter.most_common()]
        )
        fig_pie = px.pie(
            cat_df,
            values="Count",
            names="Category",
            hole=0.45,
            color_discrete_sequence=px.colors.sequential.Purp,
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=350,
            margin=dict(t=20, b=20, l=20, r=20),
            legend=dict(font=dict(color="#ccc")),
        )
        fig_pie.update_traces(textinfo="percent+value", textfont_color="#fff")
        st.plotly_chart(fig_pie, use_container_width=True)

    # ── Risk Factors ──────────────────────────────────────────────────────
    if risk.risk_factors:
        st.markdown("#### ⚠️ Risk Factors")
        for factor in risk.risk_factors:
            st.markdown(f"- {severity_emoji('High')} {factor}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: Detected Entities
# ═══════════════════════════════════════════════════════════════════════════════

with tab_entities:
    st.markdown("### 🔍 Detected Sensitive Entities")

    if not analysis.entities:
        st.success("✅ No sensitive entities detected in this document.")
    else:
        # Filters
        fcol1, fcol2, fcol3 = st.columns(3)
        all_types = sorted({e.entity_type for e in analysis.entities})
        all_categories = sorted({e.category for e in analysis.entities})
        all_severities = sorted({e.severity for e in analysis.entities})

        with fcol1:
            filter_type = st.multiselect("Filter by Type", all_types, default=all_types)
        with fcol2:
            filter_cat = st.multiselect("Filter by Category", all_categories, default=all_categories)
        with fcol3:
            filter_sev = st.multiselect("Filter by Severity", all_severities, default=all_severities)

        st.divider()
        mask_data = st.toggle("Show Masked Values", value=True, help="Toggle to show original or masked data")

        filtered = [
            e for e in analysis.entities
            if e.entity_type in filter_type
            and e.category in filter_cat
            and e.severity in filter_sev
        ]

        st.caption(f"Showing {len(filtered)} of {len(analysis.entities)} entities")

        # Table
        table_data = []
        for e in filtered:
            table_data.append({
                "Severity": f"{severity_emoji(e.severity)} {e.severity}",
                "Type": e.entity_type,
                "Category": e.category,
                "Value": mask_value(e.value) if mask_data else e.value,
                "Confidence": f"{e.confidence:.0%}",
                "Method": e.detection_method,
                "Position": e.position or "—",
            })

        if table_data:
            st.dataframe(
                pd.DataFrame(table_data),
                use_container_width=True,
                hide_index=True,
                height=min(len(table_data) * 40 + 40, 600),
            )

        # Type breakdown
        st.markdown("#### Entity Type Breakdown")
        type_counter = Counter(e.entity_type for e in filtered)
        type_df = pd.DataFrame(
            [{"Entity Type": k, "Count": v} for k, v in type_counter.most_common()]
        )
        if not type_df.empty:
            fig_types = px.bar(
                type_df,
                x="Count",
                y="Entity Type",
                orientation="h",
                color="Count",
                color_continuous_scale="Purp",
            )
            fig_types.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=max(len(type_df) * 35, 200),
                margin=dict(t=10, b=20, l=10, r=10),
                yaxis=dict(color="#ccc"),
                xaxis=dict(color="#ccc", gridcolor="rgba(255,255,255,.05)"),
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig_types, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3: Redacted Document
# ═══════════════════════════════════════════════════════════════════════════════

with tab_redacted:
    st.markdown("### 📄 Redacted Document")
    st.caption("All detected sensitive entities have been masked to protect privacy.")
    
    redacted_text = analysis.extracted_text
    # Sort by length descending so we replace longer strings first (e.g. "Full Name" before "Name")
    sorted_entities = sorted(analysis.entities, key=lambda x: len(x.value), reverse=True)
    
    for e in sorted_entities:
        redacted_text = redacted_text.replace(e.value, mask_value(e.value))
        
    st.text_area("Redacted Text", value=redacted_text, height=400, disabled=True)
    
    st.download_button(
        label="⬇️ Download Redacted Text",
        data=redacted_text,
        file_name=f"redacted_{analysis.filename}.txt",
        mime="text/plain",
        use_container_width=True,
    )

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4: Compliance Report
# ═══════════════════════════════════════════════════════════════════════════════

with tab_compliance:
    st.markdown("### 📋 AI Compliance & Security Report")

    # Executive Summary
    with st.expander("📌 Executive Summary", expanded=True):
        st.markdown(report.executive_summary)

    # Compliance Violations
    with st.expander(f"⚖️ Compliance Violations ({len(report.compliance_violations)})", expanded=True):
        if report.compliance_violations:
            for v in report.compliance_violations:
                sev_em = severity_emoji(v.severity)
                st.markdown(f"**{sev_em} {v.framework}** — {v.violation}")
                st.markdown(f"> {v.description}")
                if v.affected_entities:
                    st.markdown(f"*Affected entities:* {', '.join(v.affected_entities)}")
                if v.recommendation:
                    st.info(f"💡 **Recommendation:** {v.recommendation}")
                st.divider()
        else:
            st.success("No compliance violations detected.")

    # Security Risks
    with st.expander(f"🔐 Security Risks ({len(report.security_risks)})", expanded=False):
        if report.security_risks:
            for r_item in report.security_risks:
                st.markdown(f"- {r_item}")
        else:
            st.success("No significant security risks identified.")

    # Business Impact
    with st.expander(f"💼 Business Impact ({len(report.business_impact)})", expanded=False):
        if report.business_impact:
            for b_item in report.business_impact:
                st.markdown(f"- {b_item}")
        else:
            st.info("No specific business impact noted.")

    # Recommendations
    with st.expander(f"✅ Recommended Remediation ({len(report.recommendations)})", expanded=True):
        if report.recommendations:
            for idx, rec in enumerate(report.recommendations, 1):
                st.markdown(f"**{idx}.** {rec}")
        else:
            st.info("No specific recommendations at this time.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5: Q&A
# ═══════════════════════════════════════════════════════════════════════════════

with tab_qa:
    st.markdown("### 💬 Ask Questions About Your Document")
    st.caption(
        "Ask anything about the document's content, detected entities, "
        "compliance status, or security risks."
    )

    # Quick-question chips
    st.markdown("**Quick questions:**")
    qcols = st.columns(3)
    quick_questions = [
        "What sensitive information exists?",
        "How many Aadhaar numbers are present?",
        "Which API keys are exposed?",
        "Summarize this document.",
        "Does this document violate GDPR?",
        "What should be redacted?",
        "Show all financial information.",
        "List all employee IDs.",
        "What security risks are identified?",
    ]

    for i, q in enumerate(quick_questions):
        col = qcols[i % 3]
        if col.button(q, key=f"quick_{i}", use_container_width=True):
            st.session_state.chat_history.append({"role": "user", "content": q})

            with st.spinner("🤔 Thinking…"):
                try:
                    answer = answer_question(
                        question=q,
                        text=analysis.extracted_text,
                        entities=analysis.entities,
                        risk=risk,
                        vector_store=st.session_state.vector_store,
                    )
                except Exception as exc:
                    logger.error("Q&A failed for quick question: %s", exc)
                    err_str = str(exc).lower()
                    if "429" in err_str or "quota" in err_str or "exhausted" in err_str or "rate" in err_str:
                        answer = "⚠️ The Gemini API rate limit has been exceeded. Please wait a minute and try again."
                    else:
                        answer = "⚠️ Could not generate an answer due to a temporary error. Please try again."
            st.session_state.chat_history.append({"role": "assistant", "content": answer})

    st.divider()

    # Chat history
    for msg in st.session_state.chat_history:
        if msg["role"] == "user":
            st.markdown(
                f'<div class="chat-user">{msg["content"]}</div>',
                unsafe_allow_html=True,
            )
        else:
            with st.chat_message("assistant"):
                st.markdown(msg["content"])

    # Chat input
    user_q = st.chat_input("Ask a question about the document…")
    if user_q:
        st.session_state.chat_history.append({"role": "user", "content": user_q})

        with st.spinner("🤔 Thinking…"):
            try:
                answer = answer_question(
                    question=user_q,
                    text=analysis.extracted_text,
                    entities=analysis.entities,
                    risk=risk,
                    vector_store=st.session_state.vector_store,
                )
            except Exception as exc:
                logger.error("Q&A failed for user question: %s", exc)
                err_str = str(exc).lower()
                if "429" in err_str or "quota" in err_str or "exhausted" in err_str or "rate" in err_str:
                    answer = "⚠️ The Gemini API rate limit has been exceeded. Please wait a minute and try again."
                else:
                    answer = "⚠️ Could not generate an answer due to a temporary error. Please try again."
        st.session_state.chat_history.append({"role": "assistant", "content": answer})
        st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 6: Export
# ═══════════════════════════════════════════════════════════════════════════════

with tab_export:
    st.markdown("### 📥 Export Analysis Report")

    # JSON export
    st.markdown("#### 📄 JSON Report")
    report_dict = {
        "filename": analysis.filename,
        "file_type": analysis.file_type,
        "file_size_bytes": analysis.file_size_bytes,
        "analysed_at": analysis.analysed_at.isoformat(),
        "risk_assessment": {
            "risk_level": risk.risk_level,
            "security_score": risk.security_score,
            "total_entities": risk.total_entities,
            "critical_count": risk.critical_count,
            "high_count": risk.high_count,
            "medium_count": risk.medium_count,
            "low_count": risk.low_count,
            "info_count": risk.info_count,
            "risk_factors": risk.risk_factors,
        },
        "entities": [
            {
                "entity_type": e.entity_type,
                "category": e.category,
                "value": mask_value(e.value),
                "confidence": e.confidence,
                "detection_method": e.detection_method,
                "severity": e.severity,
                "position": e.position,
            }
            for e in analysis.entities
        ],
        "compliance_report": {
            "executive_summary": report.executive_summary,
            "violations": [
                {
                    "framework": v.framework,
                    "violation": v.violation,
                    "severity": v.severity,
                    "affected_entities": v.affected_entities,
                }
                for v in report.compliance_violations
            ],
            "security_risks": report.security_risks,
            "business_impact": report.business_impact,
            "recommendations": report.recommendations,
        },
    }

    json_str = json.dumps(report_dict, indent=2, default=str)

    st.download_button(
        label="⬇️ Download JSON Report",
        data=json_str,
        file_name=f"securedoc_report_{analysis.filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        use_container_width=True,
    )

    with st.expander("Preview JSON", expanded=False):
        st.code(json_str, language="json")

    # CSV export of entities
    st.markdown("#### 📊 Entities CSV")
    if analysis.entities:
        entities_df = pd.DataFrame([
            {
                "Type": e.entity_type,
                "Category": e.category,
                "Value (masked)": mask_value(e.value),
                "Confidence": f"{e.confidence:.0%}",
                "Method": e.detection_method,
                "Severity": e.severity,
                "Position": e.position or "",
            }
            for e in analysis.entities
        ])
        csv_data = entities_df.to_csv(index=False)
        st.download_button(
            label="⬇️ Download Entities CSV",
            data=csv_data,
            file_name=f"securedoc_entities_{analysis.filename}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    else:
        st.info("No entities to export.")
