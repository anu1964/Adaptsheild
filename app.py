"""
app.py
AdaptShield — Professional Security Dashboard
Deploy to: https://share.streamlit.io
"""

import streamlit as st
import plotly.graph_objects as go
import numpy as np
from pathlib import Path
import json

# ==================== PAGE CONFIG ====================
st.set_page_config(
    page_title="AdaptShield | LLM Defense Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CUSTOM CSS ====================
st.markdown("""
<style>
    .main-header {
        font-size: 42px;
        font-weight: 800;
        color: #e74c3c;
        text-align: center;
        margin-bottom: 10px;
    }
    .sub-header {
        font-size: 16px;
        color: #7f8c8d;
        text-align: center;
        margin-bottom: 30px;
    }
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 15px;
        padding: 20px;
        border: 1px solid #2a2a4a;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    .safe-banner {
        background: linear-gradient(90deg, #27ae60, #2ecc71);
        color: white;
        padding: 20px;
        border-radius: 12px;
        text-align: center;
        font-size: 28px;
        font-weight: bold;
        box-shadow: 0 4px 15px rgba(46, 204, 113, 0.3);
    }
    .warn-banner {
        background: linear-gradient(90deg, #f39c12, #f1c40f);
        color: white;
        padding: 20px;
        border-radius: 12px;
        text-align: center;
        font-size: 28px;
        font-weight: bold;
        box-shadow: 0 4px 15px rgba(241, 196, 15, 0.3);
    }
    .block-banner {
        background: linear-gradient(90deg, #c0392b, #e74c3c);
        color: white;
        padding: 20px;
        border-radius: 12px;
        text-align: center;
        font-size: 28px;
        font-weight: bold;
        box-shadow: 0 4px 15px rgba(231, 76, 60, 0.3);
    }
    .score-label {
        font-size: 12px;
        color: #95a5a6;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .score-value {
        font-size: 32px;
        font-weight: 800;
        color: #ecf0f1;
    }
    .flag-pill {
        display: inline-block;
        background: #e74c3c;
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        margin: 2px;
        font-weight: 600;
    }
    .info-pill {
        display: inline-block;
        background: #3498db;
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        margin: 2px;
        font-weight: 600;
    }
    .stProgress > div > div {
        background-color: #e74c3c;
    }
</style>
""", unsafe_allow_html=True)

# ==================== IMPORT MODULES ====================
@st.cache_resource
def load_modules():
    modules = {}
    try:
        from input_guard import scan_prompt
        modules["scan_prompt"] = scan_prompt
        modules["layer1_ok"] = True
    except Exception as e:
        modules["layer1_ok"] = False
        modules["layer1_err"] = str(e)
    
    try:
        from document_engine.document_engine import parse_document
        modules["parse_document"] = parse_document
        modules["engine_ok"] = True
    except Exception as e:
        modules["engine_ok"] = False
        modules["engine_err"] = str(e)
    
    try:
        from document_analyzer import analyze_document
        modules["analyze_document"] = analyze_document
        modules["analyzer_ok"] = True
    except Exception as e:
        modules["analyzer_ok"] = False
        modules["analyzer_err"] = str(e)
    
    try:
        from unified_scorer import calculate_final_decision
        modules["calculate_final_decision"] = calculate_final_decision
        modules["scorer_ok"] = True
    except Exception as e:
        modules["scorer_ok"] = False
        modules["scorer_err"] = str(e)
    
    return modules

modules = load_modules()

# ==================== HEADER ====================
st.markdown('<div class="main-header">🛡️ ADAPTSHIELD</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Dual-Layer Defense Against LLM Prompt Injection Attacks</div>', unsafe_allow_html=True)

# ==================== SIDEBAR ====================
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=80)
    st.title("System Status")
    
    st.markdown("---")
    st.markdown("**Layer 1: Input Guard**")
    if modules["layer1_ok"]:
        st.success("✅ Online")
    else:
        st.error(f"❌ Offline: {modules.get('layer1_err', 'Unknown')}")
    
    st.markdown("**Layer 2A: Document Engine**")
    if modules["engine_ok"]:
        st.success("✅ Online")
    else:
        st.error(f"❌ Offline: {modules.get('engine_err', 'Unknown')}")
    
    st.markdown("**Layer 2B: Document Analyzer**")
    if modules["analyzer_ok"]:
        st.success("✅ Online")
    else:
        st.error(f"❌ Offline: {modules.get('analyzer_err', 'Unknown')}")
    
    st.markdown("**Layer 3: Unified Scorer**")
    if modules["scorer_ok"]:
        st.success("✅ Online")
    else:
        st.error(f"❌ Offline: {modules.get('scorer_err', 'Unknown')}")
    
    st.markdown("---")
    st.info("💡 **Tip:** Enter a prompt and upload a file to see the full pipeline in action.")
    
    st.markdown("---")
    st.caption("© 2026 AdaptShield Team | KSIT")

# ==================== INPUT SECTION ====================
st.markdown("---")
col_input1, col_input2 = st.columns([2, 1])

with col_input1:
    st.subheader("📝 User Prompt")
    user_prompt = st.text_area(
        "Enter a prompt to analyze:",
        value="Summarize the meeting notes",
        height=100,
        placeholder="Type a prompt here..."
    )

with col_input2:
    st.subheader("📎 Document Upload")
    uploaded_file = st.file_uploader(
        "Upload PDF, HTML, or Email",
        type=["pdf", "html", "htm", "eml", "txt", "docx"],
        help="Upload a document to scan for hidden malicious instructions"
    )

analyze_btn = st.button("🔍 RUN SECURITY SCAN", type="primary", use_container_width=True)

# ==================== ANALYSIS ====================
if analyze_btn:
    if not modules["layer1_ok"]:
        st.error("Layer 1 (Input Guard) is not available. Check dependencies.")
        st.stop()
    
    # --- Layer 1 Analysis ---
    with st.spinner("🔍 Scanning prompt for injection attacks..."):
        l1_result = modules["scan_prompt"](user_prompt)
    
    r1 = l1_result.get("r1", 0.0)
    l1_flags = l1_result.get("flags", [])
    l1_keywords = l1_result.get("matched_keywords", [])
    l1_detectors = l1_result.get("detectors", {})
    
    # --- Layer 2 Analysis ---
    r2 = 0.0
    divergence = 0.0
    l2_flags = []
    l2_keywords = []
    
    if uploaded_file and modules["engine_ok"] and modules["analyzer_ok"]:
        with st.spinner("📄 Parsing document and analyzing intent divergence..."):
            # Save uploaded file temporarily
            file_ext = uploaded_file.name.split(".")[-1].lower()
            temp_path = f"temp_upload.{file_ext}"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getvalue())
            
            try:
                doc_data = modules["parse_document"](temp_path, file_ext)
                l2_result = modules["analyze_document"](doc_data, user_prompt)
                r2 = l2_result.get("r2", 0.0)
                divergence = l2_result.get("divergence", 0.0)
                l2_flags = l2_result.get("flags", [])
                l2_keywords = l2_result.get("matched_keywords", [])
            except Exception as e:
                st.warning(f"Document analysis warning: {e}")
            
            Path(temp_path).unlink(missing_ok=True)
    
    # --- Layer 3: Final Decision ---
    if modules["scorer_ok"]:
        final = modules["calculate_final_decision"](r1, r2, divergence)
        final_score = final.get("final_score", 0.0)
        decision = final.get("decision", "UNKNOWN")
    else:
        final_score = (r1 * 0.35) + (r2 * 0.40) + (divergence * 0.25)
        if final_score < 0.35:
            decision = "SAFE"
        elif final_score < 0.65:
            decision = "WARN"
        else:
            decision = "BLOCK"
    
    # ==================== RESULTS DISPLAY ====================
    st.markdown("---")
    st.subheader("📊 Threat Analysis Results")
    
    # --- Final Decision Banner ---
    if decision == "SAFE":
        st.markdown(f'<div class="safe-banner">✅ SAFE — No Threats Detected<br><span style="font-size:16px">Final Score: {final_score:.3f}</span></div>', unsafe_allow_html=True)
    elif decision == "WARN":
        st.markdown(f'<div class="warn-banner">⚠️ WARNING — Suspicious Activity Detected<br><span style="font-size:16px">Final Score: {final_score:.3f}</span></div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="block-banner">🚨 BLOCKED — Malicious Content Detected<br><span style="font-size:16px">Final Score: {final_score:.3f}</span></div>', unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # --- Score Cards ---
    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown(f'<div class="score-label">Layer 1 Score</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="score-value" style="color:{"#e74c3c" if r1 > 0.5 else "#2ecc71"}">{r1:.3f}</div>', unsafe_allow_html=True)
        st.progress(min(r1, 1.0), text="Prompt Risk")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with c2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown(f'<div class="score-label">Layer 2 Score</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="score-value" style="color:{"#e74c3c" if r2 > 0.5 else "#2ecc71"}">{r2:.3f}</div>', unsafe_allow_html=True)
        st.progress(min(r2, 1.0), text="Document Risk")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with c3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown(f'<div class="score-label">Intent Divergence</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="score-value" style="color:{"#e74c3c" if divergence > 0.5 else "#2ecc71"}">{divergence:.3f}</div>', unsafe_allow_html=True)
        st.progress(min(divergence, 1.0), text="Semantic Mismatch")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with c4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown(f'<div class="score-label">Final Score</div>', unsafe_allow_html=True)
        color = "#2ecc71" if final_score < 0.35 else "#f1c40f" if final_score < 0.65 else "#e74c3c"
        st.markdown(f'<div class="score-value" style="color:{color}">{final_score:.3f}</div>', unsafe_allow_html=True)
        st.progress(min(final_score, 1.0), text="Overall Risk")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # --- Gauge Charts ---
    st.markdown("<br>", unsafe_allow_html=True)
    g1, g2 = st.columns(2)
    
    with g1:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=r1,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Layer 1: Prompt Risk", 'font': {'size': 18, 'color': 'white'}},
            number={'font': {'size': 36, 'color': 'white'}},
            gauge={
                'axis': {'range': [0, 1], 'tickcolor': 'white'},
                'bar': {'color': '#e74c3c' if r1 > 0.5 else '#2ecc71'},
                'bgcolor': '#1a1a2e',
                'borderwidth': 2,
                'bordercolor': '#2a2a4a',
                'steps': [
                    {'range': [0, 0.35], 'color': '#1e3a2f'},
                    {'range': [0.35, 0.65], 'color': '#3d3a1e'},
                    {'range': [0.65, 1], 'color': '#3a1e1e'}
                ],
                'threshold': {
                    'line': {'color': 'white', 'width': 3},
                    'thickness': 0.75,
                    'value': 0.5
                }
            }
        ))
        fig.update_layout(
            paper_bgcolor='#0e0e1a',
            plot_bgcolor='#0e0e1a',
            font={'color': 'white'},
            height=300,
            margin=dict(l=20, r=20, t=50, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with g2:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=r2,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Layer 2: Document Risk", 'font': {'size': 18, 'color': 'white'}},
            number={'font': {'size': 36, 'color': 'white'}},
            gauge={
                'axis': {'range': [0, 1], 'tickcolor': 'white'},
                'bar': {'color': '#e74c3c' if r2 > 0.5 else '#2ecc71'},
                'bgcolor': '#1a1a2e',
                'borderwidth': 2,
                'bordercolor': '#2a2a4a',
                'steps': [
                    {'range': [0, 0.35], 'color': '#1e3a2f'},
                    {'range': [0.35, 0.65], 'color': '#3d3a1e'},
                    {'range': [0.65, 1], 'color': '#3a1e1e'}
                ],
                'threshold': {
                    'line': {'color': 'white', 'width': 3},
                    'thickness': 0.75,
                    'value': 0.5
                }
            }
        ))
        fig.update_layout(
            paper_bgcolor='#0e0e1a',
            plot_bgcolor='#0e0e1a',
            font={'color': 'white'},
            height=300,
            margin=dict(l=20, r=20, t=50, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # --- Flags & Details ---
    st.markdown("---")
    det_col1, det_col2 = st.columns(2)
    
    with det_col1:
        st.subheader("🚩 Layer 1 Flags")
        if l1_flags:
            for flag in l1_flags:
                st.markdown(f'<span class="flag-pill">{flag}</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="info-pill">No flags detected</span>', unsafe_allow_html=True)
        
        if l1_keywords:
            st.markdown("**Matched Keywords:** " + ", ".join(l1_keywords))
        
        with st.expander("Layer 1 Detector Details"):
            st.json(l1_detectors)
    
    with det_col2:
        st.subheader("🚩 Layer 2 Flags")
        if l2_flags:
            for flag in l2_flags:
                st.markdown(f'<span class="flag-pill">{flag}</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="info-pill">No flags detected</span>', unsafe_allow_html=True)
        
        if l2_keywords:
            st.markdown("**Matched Keywords:** " + ", ".join(l2_keywords))
        
        if uploaded_file:
            st.info(f"📄 Analyzed: **{uploaded_file.name}**")
        else:
            st.info("📄 No document uploaded")

# ==================== FOOTER ====================
st.markdown("---")
st.caption("🔒 AdaptShield v1.0 | Built with Streamlit + Sentence Transformers | KSIT CSE 2026")