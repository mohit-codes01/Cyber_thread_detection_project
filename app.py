"""
Cyber Threat Detection System - SOC Dashboard
Production-ready Streamlit Application
Powered by Scikit-learn Random Forest Model on UNSW-NB15 Dataset
"""

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from datetime import datetime

# ==============================================================================
# 1. PAGE CONFIGURATION
# ==============================================================================
st.set_page_config(
    page_title="Cyber Threat Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Constants
MODEL_PATH = Path("models/threat_model.pkl")
MAX_FILE_SIZE_MB = 1024
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# Non-input columns dropped during inference if present
DROP_COLUMNS = ["id", "attack_cat", "label"]

# ==============================================================================
# 2. CACHED MODEL LOADER
# ==============================================================================
@st.cache_resource(show_spinner=False)
def load_threat_model():
    """
    Loads the serialized Scikit-learn Pipeline from models/threat_model.pkl.
    Utilizes Streamlit caching to prevent reloading on subsequent interactions.
    """
    if not MODEL_PATH.exists():
        return None, f"Model file not found at '{MODEL_PATH}'. Please verify the models directory."
    try:
        model = joblib.load(MODEL_PATH)
        return model, None
    except Exception as exc:
        return None, f"Error loading model: {str(exc)}"

pipeline, model_load_error = load_threat_model()

# ==============================================================================
# 3. DYNAMIC DATE & TIME
# ==============================================================================
now = datetime.now()
current_date = now.strftime("%d %B %Y")
current_time = now.strftime("%I:%M:%S %p")

# ==============================================================================
# 4. CUSTOM SOC DARK THEME CSS
# ==============================================================================
st.markdown(
    """
    <style>
    /* Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Main Container Background */
    .stApp {
        background-color: #020B18;
        background-image: 
            radial-gradient(circle at 90% 10%, rgba(0, 168, 255, 0.08) 0%, transparent 40%),
            radial-gradient(circle at 10% 90%, rgba(0, 230, 160, 0.04) 0%, transparent 40%),
            linear-gradient(180deg, #020B18 0%, #031124 100%);
        color: #EAF4FF;
    }

    /* Hide Default Header/Footer elements if needed */
    header[data-testid="stHeader"] {
        background: transparent;
    }
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #030F20 0%, #020B18 100%);
        border-right: 1px solid rgba(8, 120, 209, 0.25);
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.4);
    }
    section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] > div {
        padding-left: 0.5rem;
        padding-right: 0.5rem;
    }

    /* Sidebar Brand */
    .soc-brand {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 6px 18px 6px;
        border-bottom: 1px solid rgba(8, 120, 209, 0.25);
        margin-bottom: 18px;
    }
    .soc-brand-icon {
        font-size: 32px;
        filter: drop-shadow(0 0 10px rgba(0, 168, 255, 0.6));
    }
    .soc-brand-title {
        font-size: 15px;
        font-weight: 800;
        letter-spacing: 1.5px;
        color: #FFFFFF;
        line-height: 1.2;
    }
    .soc-brand-sub {
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 1.2px;
        color: #00D9FF;
    }

    /* Section Headers */
    .section-header {
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        color: #8FA8C0;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* System Online Badge */
    .online-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(0, 230, 160, 0.1);
        border: 1px solid rgba(0, 230, 160, 0.3);
        border-radius: 20px;
        padding: 5px 12px;
        font-size: 12px;
        font-weight: 600;
        color: #00E6A0;
    }
    .pulse-dot {
        width: 8px;
        height: 8px;
        background: #00E6A0;
        border-radius: 50%;
        box-shadow: 0 0 8px #00E6A0;
        animation: pulseAnimation 2s infinite;
    }
    @keyframes pulseAnimation {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 230, 160, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(0, 230, 160, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 230, 160, 0); }
    }

    /* Top Hero Header Card */
    .soc-hero {
        background: linear-gradient(135deg, rgba(7, 26, 43, 0.95) 0%, rgba(3, 17, 34, 0.95) 100%);
        border: 1px solid #0878D1;
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 20px;
        box-shadow: 0 0 30px rgba(0, 168, 255, 0.1);
        position: relative;
        overflow: hidden;
    }
    .soc-hero::after {
        content: '';
        position: absolute;
        top: 0;
        right: 0;
        width: 250px;
        height: 100%;
        background: radial-gradient(circle at 100% 50%, rgba(0, 168, 255, 0.12), transparent 70%);
        pointer-events: none;
    }
    .soc-hero-title {
        font-size: 28px;
        font-weight: 800;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 6px;
        letter-spacing: -0.5px;
    }
    .soc-hero-subtitle {
        font-size: 14px;
        color: #8FA8C0;
        font-weight: 400;
        line-height: 1.5;
    }

    /* Date & Time Header Cards */
    .time-card {
        background: rgba(7, 26, 43, 0.85);
        border: 1px solid rgba(8, 120, 209, 0.4);
        border-radius: 12px;
        padding: 12px 16px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        height: 100%;
    }
    .time-card-lbl {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 1.2px;
        color: #00D9FF;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .time-card-val {
        font-size: 14px;
        font-weight: 700;
        color: #EAF4FF;
        font-family: 'JetBrains Mono', monospace;
        margin-top: 4px;
    }

    /* Refresh Button Styling */
    div.stButton > button {
        background: linear-gradient(135deg, #0077CC 0%, #005599 100%);
        color: #FFFFFF;
        border: 1px solid #00A8FF;
        border-radius: 10px;
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.3px;
        padding: 8px 18px;
        transition: all 0.25s ease;
        box-shadow: 0 4px 14px rgba(0, 120, 209, 0.25);
    }
    div.stButton > button:hover {
        background: linear-gradient(135deg, #00A8FF 0%, #0077CC 100%);
        border-color: #00D9FF;
        box-shadow: 0 6px 20px rgba(0, 168, 255, 0.4);
        transform: translateY(-1px);
        color: #FFFFFF;
    }

    /* Download Results Button Styling - Dark Rich Navy */
    div.stDownloadButton > button,
    div[data-testid="stDownloadButton"] > button,
    div[data-testid="stDownloadButton"] button,
    .stDownloadButton button {
        background: #15233A !important;
        background-color: #15233A !important;
        color: #FFFFFF !important;
        border: 1px solid rgba(8, 120, 209, 0.5) !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        font-size: 13px !important;
        letter-spacing: 0.3px !important;
        padding: 8px 18px !important;
        transition: all 0.25s ease !important;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4) !important;
    }
    div.stDownloadButton > button:hover,
    div[data-testid="stDownloadButton"] > button:hover,
    .stDownloadButton button:hover {
        background: #1C2E4C !important;
        background-color: #1C2E4C !important;
        border-color: #00D9FF !important;
        box-shadow: 0 6px 20px rgba(0, 168, 255, 0.35) !important;
        transform: translateY(-1px);
        color: #FFFFFF !important;
    }
    div.stDownloadButton > button:active,
    div[data-testid="stDownloadButton"] > button:active,
    div.stDownloadButton > button:focus,
    div[data-testid="stDownloadButton"] > button:focus,
    .stDownloadButton button:active,
    .stDownloadButton button:focus {
        background: #101B2E !important;
        background-color: #101B2E !important;
        border-color: #00A8FF !important;
        box-shadow: 0 0 14px rgba(0, 168, 255, 0.5) !important;
        color: #FFFFFF !important;
    }
    div.stDownloadButton > button p,
    div.stDownloadButton > button span,
    div[data-testid="stDownloadButton"] > button p,
    div[data-testid="stDownloadButton"] > button span,
    .stDownloadButton button p,
    .stDownloadButton button span {
        color: #FFFFFF !important;
        font-weight: 600 !important;
    }

    /* Metric Values - Enhanced Visibility for Overview Metrics & Benchmarks */
    [data-testid="stMetricValue"],
    [data-testid="stMetricValue"] > div {
        color: #FFFFFF !important;
        font-weight: 700 !important;
    }

    /* Zero height for background iframe component */
    div:has(> iframe[title="st.iframe"]) {
        margin: 0 !important;
        padding: 0 !important;
        height: 0 !important;
        min-height: 0 !important;
    }

    /* General SOC Card */
    .soc-card {
        background: #071A2B;
        border: 1px solid rgba(8, 120, 209, 0.4);
        border-radius: 14px;
        padding: 20px 22px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        margin-bottom: 20px;
        transition: border-color 0.2s ease;
    }
    .soc-card:hover {
        border-color: rgba(0, 168, 255, 0.6);
    }
    .soc-card-title {
        font-size: 16px;
        font-weight: 700;
        color: #FFFFFF;
        margin-bottom: 14px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* Metric Cards */
    .metric-card {
        background: #071A2B;
        border: 1px solid rgba(8, 120, 209, 0.35);
        border-radius: 14px;
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #0878D1;
    }
    .metric-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 10px;
    }
    .metric-label {
        font-size: 13px;
        font-weight: 600;
        color: #8FA8C0;
        letter-spacing: 0.3px;
    }
    .metric-icon-wrap {
        width: 36px;
        height: 36px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 18px;
    }
    .icon-cyan { background: rgba(0, 217, 255, 0.12); color: #00D9FF; }
    .icon-red { background: rgba(255, 59, 107, 0.12); color: #FF3B6B; }
    .icon-green { background: rgba(0, 230, 160, 0.12); color: #00E6A0; }
    .icon-orange { background: rgba(255, 159, 67, 0.12); color: #FF9F43; }
    .icon-purple { background: rgba(139, 92, 246, 0.12); color: #8B5CF6; }

    .metric-value {
        font-size: 28px;
        font-weight: 800;
        color: #FFFFFF;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: -0.5px;
    }
    .metric-value.red { color: #FF3B6B; text-shadow: 0 0 12px rgba(255, 59, 107, 0.3); }
    .metric-value.green { color: #00E6A0; text-shadow: 0 0 12px rgba(0, 230, 160, 0.3); }
    .metric-value.orange { color: #FF9F43; }
    .metric-value.cyan { color: #00D9FF; }

    /* Donut Chart Component */
    .donut-card {
        background: #071A2B;
        border: 1px solid rgba(8, 120, 209, 0.4);
        border-radius: 14px;
        padding: 20px;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .donut-card-title {
        font-size: 15px;
        font-weight: 700;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 15px;
    }
    .donut-wrapper {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 10px 0;
    }
    .donut-graphic {
        width: 160px;
        height: 160px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
        box-shadow: 0 0 25px rgba(0, 0, 0, 0.5);
    }
    .donut-hole {
        width: 112px;
        height: 112px;
        border-radius: 50%;
        background: #071A2B;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        box-shadow: inset 0 0 12px rgba(0, 0, 0, 0.6);
    }
    .donut-center-val {
        font-size: 20px;
        font-weight: 800;
        color: #FFFFFF;
        font-family: 'JetBrains Mono', monospace;
    }
    .donut-center-lbl {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.5px;
        color: #8FA8C0;
        margin-top: 2px;
    }
    .donut-legend {
        margin-top: 15px;
        border-top: 1px solid rgba(8, 120, 209, 0.2);
        padding-top: 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .legend-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 12px;
        color: #EAF4FF;
    }
    .legend-dot-label {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .dot-threat { width: 10px; height: 10px; border-radius: 50%; background: #FF3B6B; box-shadow: 0 0 6px #FF3B6B; }
    .dot-normal { width: 10px; height: 10px; border-radius: 50%; background: #00E6A0; box-shadow: 0 0 6px #00E6A0; }
    .dot-correct { width: 10px; height: 10px; border-radius: 50%; background: #00A8FF; box-shadow: 0 0 6px #00A8FF; }
    .dot-error { width: 10px; height: 10px; border-radius: 50%; background: #FF9F43; box-shadow: 0 0 6px #FF9F43; }

    /* Alert Banners */
    .alert-banner-danger {
        background: linear-gradient(90deg, rgba(255, 59, 107, 0.15) 0%, rgba(7, 26, 43, 0.4) 100%);
        border-left: 4px solid #FF3B6B;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .alert-banner-safe {
        background: linear-gradient(90deg, rgba(0, 230, 160, 0.15) 0%, rgba(7, 26, 43, 0.4) 100%);
        border-left: 4px solid #00E6A0;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .alert-banner-info {
        background: linear-gradient(90deg, rgba(0, 168, 255, 0.12) 0%, rgba(7, 26, 43, 0.4) 100%);
        border-left: 4px solid #00A8FF;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        gap: 12px;
    }

    /* Radio Navigation Styling */
    div[data-testid="stRadio"] > div {
        background: rgba(7, 26, 43, 0.6);
        border: 1px solid rgba(8, 120, 209, 0.3);
        border-radius: 12px;
        padding: 6px;
        gap: 4px;
    }
    div[data-testid="stRadio"] label {
        padding: 8px 12px;
        border-radius: 8px;
        transition: all 0.2s ease;
        font-weight: 700 !important;
        color: #EAF4FF !important;
    }
    div[data-testid="stRadio"] label p,
    div[data-testid="stRadio"] label span {
        font-weight: 700 !important;
        color: #EAF4FF !important;
        font-size: 14px;
    }
    div[data-testid="stRadio"] label:hover {
        background: rgba(0, 168, 255, 0.1);
    }

    /* Badges */
    .badge-threat-table {
        background: rgba(255, 59, 107, 0.15);
        color: #FF3B6B;
        border: 1px solid #FF3B6B;
        border-radius: 6px;
        padding: 2px 8px;
        font-weight: 700;
        font-size: 11px;
    }
    .badge-normal-table {
        background: rgba(0, 230, 160, 0.15);
        color: #00E6A0;
        border: 1px solid #00E6A0;
        border-radius: 6px;
        padding: 2px 8px;
        font-weight: 700;
        font-size: 11px;
    }

    /* Footer */
    .soc-footer {
        text-align: center;
        padding: 24px 0 10px 0;
        border-top: 1px solid rgba(8, 120, 209, 0.2);
        color: #8FA8C0;
        font-size: 12px;
        margin-top: 40px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Live Continuous Clock Engine (updates seconds in real-time)
LIVE_CLOCK_JS = """
<script>
(function() {
    function formatTime(d) {
        var hours = d.getHours();
        var minutes = String(d.getMinutes()).padStart(2, '0');
        var seconds = String(d.getSeconds()).padStart(2, '0');
        var ampm = hours >= 12 ? 'PM' : 'AM';
        hours = hours % 12;
        hours = hours ? hours : 12;
        var hoursStr = String(hours).padStart(2, '0');
        return hoursStr + ':' + minutes + ':' + seconds + ' ' + ampm;
    }

    function updateClocks() {
        var timeStr = formatTime(new Date());

        var docList = [document];
        try {
            if (window.parent && window.parent.document && window.parent.document !== document) {
                docList.push(window.parent.document);
            }
        } catch(e) {}
        try {
            if (window.top && window.top.document && !docList.includes(window.top.document)) {
                docList.push(window.top.document);
            }
        } catch(e) {}

        for (var i = 0; i < docList.length; i++) {
            var doc = docList[i];
            try {
                // 1. Header live clock element
                var hEl = doc.getElementById('soc-live-time');
                if (hEl && hEl.textContent !== timeStr) {
                    hEl.textContent = timeStr;
                }

                // 2. Sidebar live clock element
                var sEl = doc.getElementById('soc-sidebar-time');
                if (sEl) {
                    var fullSidebarText = '🕐 ' + timeStr;
                    if (sEl.textContent !== fullSidebarText) {
                        sEl.textContent = fullSidebarText;
                    }
                }

                // 3. Fallback: Any .time-card element with CURRENT TIME
                var cards = doc.querySelectorAll('.time-card');
                for (var j = 0; j < cards.length; j++) {
                    var card = cards[j];
                    var lbl = card.querySelector('.time-card-lbl');
                    var val = card.querySelector('.time-card-val');
                    if (lbl && val && lbl.textContent.indexOf('CURRENT TIME') !== -1) {
                        if (val.textContent !== timeStr) {
                            val.textContent = timeStr;
                        }
                    }
                }
            } catch(err) {}
        }
    }

    var rootWin = window;
    try {
        if (window.parent && window.parent !== window) {
            rootWin = window.parent;
        }
    } catch(e) {}

    if (rootWin._socClockInterval) {
        clearInterval(rootWin._socClockInterval);
    }
    updateClocks();
    rootWin._socClockInterval = setInterval(updateClocks, 250);

    try {
        var rootDoc = rootWin.document || document;
        if (!rootDoc._socClockObserver && rootDoc.body) {
            rootDoc._socClockObserver = new MutationObserver(function() {
                updateClocks();
            });
            rootDoc._socClockObserver.observe(rootDoc.body, { childList: true, subtree: true });
        }
    } catch(e) {}
})();
</script>
"""

try:
    st.html(LIVE_CLOCK_JS, unsafe_allow_javascript=True)
except Exception:
    pass

try:
    components.html(LIVE_CLOCK_JS, height=0, width=0)
except Exception:
    pass

# ==============================================================================
# 5. CORE INFERENCE & DATA PROCESSING FUNCTIONS
# ==============================================================================
def run_model_inference(df_raw: pd.DataFrame, ml_pipeline):
    """
    Executes real inference using the trained Scikit-learn Pipeline.
    Handles schema validation, non-input column dropping, confidence extraction,
    and ground-truth accuracy calculations when 'label' is available.
    """
    if ml_pipeline is None:
        return None, "Model pipeline is not loaded."

    # Copy input dataframe
    df_clean = df_raw.copy()

    # Determine input features by dropping metadata/target columns
    input_features_df = df_clean.copy()
    for col in DROP_COLUMNS:
        if col in input_features_df.columns:
            input_features_df = input_features_df.drop(columns=[col])

    # Feature validation against pipeline's expected features
    expected_features = getattr(ml_pipeline, "feature_names_in_", None)
    if expected_features is not None:
        missing_cols = [col for col in expected_features if col not in input_features_df.columns]
        if missing_cols:
            return None, {
                "error_type": "missing_features",
                "missing_columns": missing_cols,
                "message": "Prediction cannot be performed because required model features are missing."
            }

    # Execute Pipeline Predict
    try:
        raw_preds = ml_pipeline.predict(input_features_df)
    except Exception as e:
        return None, f"ML prediction failed during inference: {str(e)}"

    # Convert predictions to binary ints (0 or 1)
    binary_preds = [int(p) for p in raw_preds]
    status_labels = ["Threat" if p == 1 else "Normal" for p in binary_preds]

    # Calculate Confidences if predict_proba is supported
    confidences = None
    if hasattr(ml_pipeline, "predict_proba"):
        try:
            proba_matrix = ml_pipeline.predict_proba(input_features_df)
            classes_list = list(ml_pipeline.classes_)
            confidences = []
            for i, p in enumerate(binary_preds):
                c_idx = classes_list.index(p)
                confidences.append(round(proba_matrix[i][c_idx] * 100, 2))
        except Exception:
            confidences = None

    # Construct result DataFrame
    res_df = df_raw.copy()
    res_df.insert(0, "#", range(1, len(res_df) + 1))
    res_df.insert(1, "Prediction", binary_preds)
    res_df.insert(2, "Status", status_labels)
    if confidences is not None:
        res_df.insert(3, "Confidence (%)", confidences)

    # Core Counts & Rates
    total_records = len(binary_preds)
    threat_count = int(sum(1 for p in binary_preds if p == 1))
    normal_count = int(total_records - threat_count)
    threat_rate = (threat_count / total_records * 100) if total_records > 0 else 0.0
    normal_rate = (normal_count / total_records * 100) if total_records > 0 else 0.0

    # Ground-truth Label Evaluation (Strictly only when 'label' exists)
    has_ground_truth = "label" in df_raw.columns
    accuracy_data = None

    if has_ground_truth:
        try:
            raw_labels = df_raw["label"].tolist()
            # Normalize ground truth labels
            true_labels = []
            for val in raw_labels:
                v_str = str(val).strip().lower()
                if v_str in ["1", "1.0", "threat", "attack", "true"]:
                    true_labels.append(1)
                else:
                    true_labels.append(0)

            correct_count = sum(1 for yt, yp in zip(true_labels, binary_preds) if yt == yp)
            error_count = total_records - correct_count
            acc_pct = (correct_count / total_records * 100) if total_records > 0 else 0.0
            err_pct = (error_count / total_records * 100) if total_records > 0 else 0.0

            # Confusion Matrix components
            tp = sum(1 for yt, yp in zip(true_labels, binary_preds) if yt == 1 and yp == 1)
            fp = sum(1 for yt, yp in zip(true_labels, binary_preds) if yt == 0 and yp == 1)
            tn = sum(1 for yt, yp in zip(true_labels, binary_preds) if yt == 0 and yp == 0)
            fn = sum(1 for yt, yp in zip(true_labels, binary_preds) if yt == 1 and yp == 0)

            accuracy_data = {
                "has_label": True,
                "correct_count": correct_count,
                "error_count": error_count,
                "accuracy_percentage": acc_pct,
                "error_percentage": err_pct,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn
            }
        except Exception:
            accuracy_data = {"has_label": False}
    else:
        accuracy_data = {"has_label": False}

    return {
        "result_df": res_df,
        "total_records": total_records,
        "threat_count": threat_count,
        "normal_count": normal_count,
        "threat_rate": threat_rate,
        "normal_rate": normal_rate,
        "accuracy_data": accuracy_data,
        "has_confidences": confidences is not None
    }, None

# ==============================================================================
# 6. SESSION STATE MANAGEMENT
# ==============================================================================
if "active_file_name" not in st.session_state:
    st.session_state.active_file_name = None

if "active_analysis" not in st.session_state:
    st.session_state.active_analysis = None

if "last_refresh_time" not in st.session_state:
    st.session_state.last_refresh_time = current_time

if "processing_error" not in st.session_state:
    st.session_state.processing_error = None

# ==============================================================================
# 7. SIDEBAR SETUP
# ==============================================================================
with st.sidebar:
    # Branding
    st.markdown(
        """
        <div class="soc-brand">
            <div class="soc-brand-icon">🛡️</div>
            <div>
                <div class="soc-brand-title">CYBER THREAT</div>
                <div class="soc-brand-sub">DETECTION SYSTEM</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Control Panel Header
    st.markdown(
        '<div class="section-header">⚙️ CONTROL PANEL</div>',
        unsafe_allow_html=True
    )

    # CSV Upload Section
    st.markdown(
        '<div style="font-size:13px; font-weight:600; color:#EAF4FF; margin-bottom:6px;">Upload Network Traffic CSV</div>',
        unsafe_allow_html=True
    )

    uploaded_file = st.file_uploader(
        "Drag and drop file here",
        type=["csv"],
        help="Upload UNSW-NB15 network traffic CSV dataset (up to 1GB).",
        label_visibility="collapsed"
    )

    st.markdown(
        '<div style="font-size:11px; color:#8FA8C0; margin-top:2px; margin-bottom:18px;">Limit 1GB per file • CSV</div>',
        unsafe_allow_html=True
    )

    # Navigation Radio
    st.markdown(
        '<div class="section-header">🧭 NAVIGATION</div>',
        unsafe_allow_html=True
    )

    navigation = st.radio(
        "Navigation",
        [
            "🏠 Dashboard",
            "🔍 Threat Detection",
            "📊 Analytics",
            "ℹ️ About"
        ],
        label_visibility="collapsed"
    )

    # System Status & Model Info
    st.markdown("<div style='margin-top:25px;'></div>", unsafe_allow_html=True)
    st.markdown(
        '<div class="section-header">📡 SYSTEM STATUS</div>',
        unsafe_allow_html=True
    )

    if pipeline is not None:
        st.markdown(
            """
            <div style="background:rgba(7,26,43,0.7); border:1px solid rgba(8,120,209,0.3); border-radius:10px; padding:12px 14px;">
                <div class="online-badge">
                    <div class="pulse-dot"></div>
                    <span>System Online</span>
                </div>
                <div style="font-size:11px; color:#8FA8C0; margin-top:8px;">
                    Model: <b style="color:#00D9FF;">threat_model.pkl</b>
                </div>
                <div style="font-size:11px; color:#8FA8C0;">
                    Pipeline: <span style="color:#00E6A0;">Active & Loaded</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            """
            <div style="background:rgba(255,59,107,0.1); border:1px solid #FF3B6B; border-radius:10px; padding:12px 14px;">
                <div style="color:#FF3B6B; font-weight:700; font-size:13px;">🔴 Model Offline</div>
                <div style="font-size:11px; color:#8FA8C0; margin-top:4px;">threat_model.pkl could not be loaded</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Date & Time in Sidebar
    st.markdown(
        f"""
        <div style="margin-top:18px; padding-top:14px; border-top:1px solid rgba(8,120,209,0.2); font-size:11px; color:#8FA8C0;">
            <div>📅 <b>{current_date}</b></div>
            <div id="soc-sidebar-time" style="font-family:'JetBrains Mono', monospace; margin-top:2px;">🕐 {current_time}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

# ==============================================================================
# 8. GLOBAL FILE PROCESSING (SYNC ACROSS ALL TABS)
# ==============================================================================
if uploaded_file is not None:
    # Check if a new file was uploaded or re-uploaded
    if st.session_state.active_file_name != uploaded_file.name:
        if uploaded_file.size > MAX_FILE_SIZE_BYTES:
            st.session_state.processing_error = f"File size ({uploaded_file.size / 1024 / 1024:.1f}MB) exceeds the 1GB limit."
            st.session_state.active_analysis = None
            st.session_state.active_file_name = uploaded_file.name
        else:
            try:
                df_uploaded = pd.read_csv(uploaded_file)
                if df_uploaded.empty:
                    st.session_state.processing_error = "The uploaded CSV file contains no data rows."
                    st.session_state.active_analysis = None
                    st.session_state.active_file_name = uploaded_file.name
                else:
                    analysis_result, err = run_model_inference(df_uploaded, pipeline)
                    if err:
                        st.session_state.processing_error = err
                        st.session_state.active_analysis = None
                    else:
                        st.session_state.processing_error = None
                        st.session_state.active_analysis = analysis_result
                        st.session_state.active_analysis["raw_df"] = df_uploaded
                        st.session_state.active_analysis["file_name"] = uploaded_file.name
                        st.session_state.active_analysis["file_size_kb"] = uploaded_file.size / 1024
                        st.session_state.active_analysis["analyzed_time"] = current_time
                    st.session_state.active_file_name = uploaded_file.name
            except Exception as read_exc:
                st.session_state.processing_error = f"Unable to read CSV file: {str(read_exc)}"
                st.session_state.active_analysis = None
                st.session_state.active_file_name = uploaded_file.name
else:
    # File was removed / cleared
    st.session_state.active_file_name = None
    st.session_state.active_analysis = None
    st.session_state.processing_error = None

analysis = st.session_state.active_analysis
proc_error = st.session_state.processing_error

# ==============================================================================
# 9. MAIN SOC HEADER & REFRESH DASHBOARD BAR
# ==============================================================================
header_col1, header_col2, header_col3 = st.columns([5, 2, 2])

with header_col1:
    st.markdown(
        """
        <div class="soc-hero">
            <div class="soc-hero-title">
                <span>🛡️</span> Cyber Threat Detection System
            </div>
            <div class="soc-hero-subtitle">
                Machine Learning based network traffic classification using the UNSW-NB15 dataset.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with header_col2:
    st.markdown(
        f"""
        <div class="time-card">
            <div class="time-card-lbl">📅 CURRENT DATE</div>
            <div class="time-card-val">{current_date}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with header_col3:
    st.markdown(
        f"""
        <div class="time-card">
            <div class="time-card-lbl">🕐 CURRENT TIME</div>
            <div class="time-card-val" id="soc-live-time">{current_time}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

# Refresh Button Bar
ref_col1, ref_col2 = st.columns([2, 8])
with ref_col1:
    if st.button("🔄 Refresh Dashboard", use_container_width=True):
        st.session_state.last_refresh_time = datetime.now().strftime("%I:%M:%S %p")
        st.rerun()

with ref_col2:
    if analysis is not None:
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:10px; padding:8px 0; font-size:13px; color:#8FA8C0;">
                <span>📁 Active File: <b style="color:#00D9FF;">{analysis['file_name']}</b></span>
                <span>•</span>
                <span>📊 Rows: <b style="color:#EAF4FF;">{analysis['total_records']:,}</b></span>
                <span>•</span>
                <span>⏱️ Inferred at: <span style="color:#EAF4FF;">{analysis['analyzed_time']}</span></span>
            </div>
            """,
            unsafe_allow_html=True
        )

# Critical Model Check Guard
if pipeline is None:
    st.markdown(
        """
        <div class="soc-card" style="border-color:#FF3B6B;">
            <div style="color:#FF3B6B; font-size:20px; font-weight:800; display:flex; align-items:center; gap:8px;">
                🔴 Model Unavailable
            </div>
            <div style="color:#EAF4FF; font-size:14px; margin-top:8px;">
                The Cyber Threat Detection Machine Learning model could not be loaded into memory.
            </div>
            <div style="background:rgba(0,0,0,0.4); border-radius:8px; padding:12px; margin-top:12px; font-family:'JetBrains Mono', monospace; font-size:12px; color:#FF9F43;">
                Expected location: models/threat_model.pkl
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    if model_load_error:
        st.error(model_load_error)
    st.stop()

# Processing Error Display Guard (e.g. Missing columns, bad CSV)
if proc_error is not None:
    if isinstance(proc_error, dict) and proc_error.get("error_type") == "missing_features":
        st.markdown(
            """
            <div class="alert-banner-danger">
                <span style="font-size:22px;">⚠️</span>
                <div>
                    <b style="color:#FF3B6B; font-size:15px;">Prediction cannot be performed because required model features are missing.</b>
                    <div style="font-size:13px; color:#EAF4FF; margin-top:4px;">
                        The uploaded CSV lacks one or more critical columns trained into the Random Forest pipeline.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.write("Missing columns:")
        st.code("\n".join(proc_error["missing_columns"]))
    else:
        st.markdown(
            f"""
            <div class="alert-banner-danger">
                <span style="font-size:22px;">⚠️</span>
                <div>
                    <b style="color:#FF3B6B; font-size:15px;">Data Processing Failed</b>
                    <div style="font-size:13px; color:#EAF4FF; margin-top:4px;">
                        {str(proc_error)}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

# ==============================================================================
# 10. NAVIGATION PAGE 1: 🏠 DASHBOARD
# ==============================================================================
if navigation == "🏠 Dashboard":
    if analysis is None:
        # State: NO CSV UPLOADED
        st.markdown(
            """
            <div class="alert-banner-info">
                <span style="font-size:24px;">📤</span>
                <div>
                    <b style="color:#00D9FF; font-size:15px;">Upload a CSV file from the sidebar to start cyber threat detection.</b>
                    <div style="font-size:13px; color:#8FA8C0; margin-top:2px;">
                        Select or drag and drop a UNSW-NB15 formatted network traffic CSV into the Control Panel.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Placeholders Metric Cards
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        with m_col1:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Total Records</span>
                        <div class="metric-icon-wrap icon-cyan">📄</div>
                    </div>
                    <div class="metric-value">--</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m_col2:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Threats Detected</span>
                        <div class="metric-icon-wrap icon-red">🚨</div>
                    </div>
                    <div class="metric-value">--</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m_col3:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Normal Traffic</span>
                        <div class="metric-icon-wrap icon-green">🛡️</div>
                    </div>
                    <div class="metric-value">--</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m_col4:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Threat Rate</span>
                        <div class="metric-icon-wrap icon-orange">🎯</div>
                    </div>
                    <div class="metric-value">--</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)

        # Standby Charts Row
        c_col1, c_col2, c_col3 = st.columns([1.3, 1.3, 1])
        with c_col1:
            st.markdown(
                """
                <div class="donut-card">
                    <div class="donut-card-title">🚨 Threat Ratio</div>
                    <div class="donut-wrapper">
                        <div class="donut-graphic" style="background: conic-gradient(#00E6A0 0deg, #00E6A0 360deg);">
                            <div class="donut-hole">
                                <div class="donut-center-val" style="color:#8FA8C0;">0.00%</div>
                                <div class="donut-lbl">THREAT</div>
                            </div>
                        </div>
                    </div>
                    <div class="donut-legend">
                        <div class="legend-item">
                            <span class="legend-dot-label"><span class="dot-threat"></span> Threat</span>
                            <span>0 (0.00%)</span>
                        </div>
                        <div class="legend-item">
                            <span class="legend-dot-label"><span class="dot-normal"></span> Normal</span>
                            <span>0 (0.00%)</span>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with c_col2:
            st.markdown(
                """
                <div class="donut-card">
                    <div class="donut-card-title">🎯 Detection Accuracy</div>
                    <div class="donut-wrapper">
                        <div class="donut-graphic" style="background: conic-gradient(#1B3654 0deg, #1B3654 360deg);">
                            <div class="donut-hole">
                                <div class="donut-center-val" style="color:#8FA8C0;">N/A</div>
                                <div class="donut-lbl">NO DATA</div>
                            </div>
                        </div>
                    </div>
                    <div style="text-align:center; color:#8FA8C0; font-size:12px; padding:10px 0;">
                        Upload a CSV containing network traffic to compute model detection accuracy.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with c_col3:
            st.markdown(
                """
                <div class="donut-card">
                    <div class="donut-card-title">🟢 Model Status</div>
                    <div style="margin-top:15px;">
                        <div style="color:#00E6A0; font-size:17px; font-weight:800;">🟢 Ready to Detect</div>
                        <div style="font-size:12px; color:#8FA8C0; line-height:1.6; margin-top:8px;">
                            The Random Forest ML Pipeline is loaded in memory and waiting for network traffic input.
                        </div>
                        <div style="margin-top:16px; font-size:12px; color:#00D9FF; font-weight:600;">Engine:</div>
                        <div style="font-size:12px; color:#FFFFFF; font-family:'JetBrains Mono', monospace;">UNSW-NB15 Pipeline</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)

        # About the Project Card
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">📖 ABOUT THE PROJECT</div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:24px;">
                    <div style="background:rgba(0,168,255,0.04); border:1px solid rgba(0,168,255,0.2); border-radius:10px; padding:18px;">
                        <div style="color:#00D9FF; font-weight:700; font-size:15px; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                            🤖 Machine Learning
                        </div>
                        <ul style="color:#EAF4FF; font-size:13px; line-height:1.9; margin:0; padding-left:18px;">
                            <li>Random Forest Classifier (100 Estimators, Balanced Weights)</li>
                            <li>Scikit-learn Pipeline Architecture</li>
                            <li>One-Hot Encoding for Protocol & Service Features</li>
                            <li>Median & Most-Frequent Missing Value Imputation</li>
                        </ul>
                    </div>
                    <div style="background:rgba(139,92,246,0.04); border:1px solid rgba(139,92,246,0.2); border-radius:10px; padding:18px;">
                        <div style="color:#8B5CF6; font-weight:700; font-size:15px; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                            🛡️ Cyber Security
                        </div>
                        <ul style="color:#EAF4FF; font-size:13px; line-height:1.9; margin:0; padding-left:18px;">
                            <li>Network Traffic Flow Analysis</li>
                            <li>High-Precision Cyber Threat & Anomaly Detection</li>
                            <li>Binary Classification (0 = Normal, 1 = Threat)</li>
                            <li>Trained on comprehensive UNSW-NB15 Security Benchmark</li>
                        </ul>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    else:
        # State: CSV UPLOADED & LIVE ANALYSIS AVAILABLE
        tot = analysis["total_records"]
        tc = analysis["threat_count"]
        nc = analysis["normal_count"]
        tr = analysis["threat_rate"]
        nr = analysis["normal_rate"]
        acc_info = analysis["accuracy_data"]

        # Alert Banner based on threat findings
        if tc > 0:
            st.markdown(
                f"""
                <div class="alert-banner-danger">
                    <span style="font-size:24px;">🚨</span>
                    <div>
                        <b style="color:#FF3B6B; font-size:15px;">THREATS DETECTED IN TRAFFIC</b>
                        <div style="font-size:13px; color:#EAF4FF; margin-top:2px;">
                            The machine learning pipeline flagged <b>{tc:,}</b> out of <b>{tot:,}</b> records ({tr:.2f}%) as potential cyber threats.
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div class="alert-banner-safe">
                    <span style="font-size:24px;">✅</span>
                    <div>
                        <b style="color:#00E6A0; font-size:15px;">NETWORK TRAFFIC NORMAL</b>
                        <div style="font-size:13px; color:#EAF4FF; margin-top:2px;">
                            All <b>{tot:,}</b> evaluated records were classified as safe, benign network traffic.
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # 4 Real Statistics Cards
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        with m_col1:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Total Records</span>
                        <div class="metric-icon-wrap icon-cyan">📄</div>
                    </div>
                    <div class="metric-value">{tot:,}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m_col2:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Threats Detected</span>
                        <div class="metric-icon-wrap icon-red">🚨</div>
                    </div>
                    <div class="metric-value red">{tc:,}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m_col3:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Normal Traffic</span>
                        <div class="metric-icon-wrap icon-green">🛡️</div>
                    </div>
                    <div class="metric-value green">{nc:,}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with m_col4:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Threat Rate</span>
                        <div class="metric-icon-wrap icon-orange">🎯</div>
                    </div>
                    <div class="metric-value orange">{tr:.2f}%</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)

        # Charts Row: Threat Ratio Donut, Detection Accuracy Donut, Model Status Card
        c_col1, c_col2, c_col3 = st.columns([1.3, 1.3, 1])

        threat_deg = tr * 3.6
        with c_col1:
            st.markdown(
                f"""
                <div class="donut-card">
                    <div class="donut-card-title">🚨 Threat Ratio</div>
                    <div class="donut-wrapper">
                        <div class="donut-graphic" style="background: conic-gradient(#FF3B6B 0deg {threat_deg}deg, #00E6A0 {threat_deg}deg 360deg);">
                            <div class="donut-hole">
                                <div class="donut-center-val" style="color:{'#FF3B6B' if tr > 0 else '#00E6A0'};">{tr:.2f}%</div>
                                <div class="donut-lbl">THREAT</div>
                            </div>
                        </div>
                    </div>
                    <div class="donut-legend">
                        <div class="legend-item">
                            <span class="legend-dot-label"><span class="dot-threat"></span> Threat</span>
                            <span style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#FF3B6B;">{tc:,} ({tr:.2f}%)</span>
                        </div>
                        <div class="legend-item">
                            <span class="legend-dot-label"><span class="dot-normal"></span> Normal</span>
                            <span style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#00E6A0;">{nc:,} ({nr:.2f}%)</span>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with c_col2:
            if acc_info["has_label"]:
                acc_val = acc_info["accuracy_percentage"]
                err_val = acc_info["error_percentage"]
                corr_c = acc_info["correct_count"]
                err_c = acc_info["error_count"]
                acc_deg = acc_val * 3.6

                st.markdown(
                    f"""
                    <div class="donut-card">
                        <div class="donut-card-title">🎯 Detection Accuracy</div>
                        <div class="donut-wrapper">
                            <div class="donut-graphic" style="background: conic-gradient(#00A8FF 0deg {acc_deg}deg, #FF9F43 {acc_deg}deg 360deg);">
                                <div class="donut-hole">
                                    <div class="donut-center-val" style="color:#00A8FF;">{acc_val:.2f}%</div>
                                    <div class="donut-lbl">ACCURACY</div>
                                </div>
                            </div>
                        </div>
                        <div class="donut-legend">
                            <div class="legend-item">
                                <span class="legend-dot-label"><span class="dot-correct"></span> Correct</span>
                                <span style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#00A8FF;">{corr_c:,} ({acc_val:.2f}%)</span>
                            </div>
                            <div class="legend-item">
                                <span class="legend-dot-label"><span class="dot-error"></span> Error</span>
                                <span style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#FF9F43;">{err_c:,} ({err_val:.2f}%)</span>
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    """
                    <div class="donut-card">
                        <div class="donut-card-title">🎯 Detection Accuracy</div>
                        <div class="donut-wrapper">
                            <div class="donut-graphic" style="background: conic-gradient(#1B3654 0deg, #1B3654 360deg);">
                                <div class="donut-hole">
                                    <div class="donut-center-val" style="color:#8FA8C0;">N/A</div>
                                    <div class="donut-lbl">NO LABEL</div>
                                </div>
                            </div>
                        </div>
                        <div style="text-align:center; color:#8FA8C0; font-size:12px; padding:12px 6px; line-height:1.5;">
                            Ground-truth <b>label</b> column not available in uploaded CSV.<br>
                            Accuracy cannot be calculated for this file.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        with c_col3:
            st.markdown(
                f"""
                <div class="donut-card">
                    <div class="donut-card-title">🟢 Model Status</div>
                    <div style="margin-top:10px;">
                        <div style="color:#00E6A0; font-size:17px; font-weight:800;">✓ Analysis Complete</div>
                        <div style="font-size:12px; color:#8FA8C0; line-height:1.5; margin-top:6px;">
                            Random Forest ML pipeline successfully processed network traffic.
                        </div>
                        <div style="margin-top:14px; font-size:11px; color:#00D9FF; font-weight:700;">PROCESSED FILE:</div>
                        <div style="font-size:12px; color:#FFFFFF; word-break:break-all; font-family:'JetBrains Mono', monospace;">
                            {analysis['file_name']}
                        </div>
                        <div style="margin-top:10px; font-size:11px; color:#00D9FF; font-weight:700;">EVALUATED ROWS:</div>
                        <div style="font-size:14px; color:#FFFFFF; font-weight:700;">
                            {tot:,} records
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)

        # Quick Results Preview Card
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">🔎 Detection Results Preview</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        preview_cols = ["#", "Prediction", "Status"]
        if analysis["has_confidences"]:
            preview_cols.append("Confidence (%)")
        for col in ["proto", "service", "state", "sbytes", "dbytes", "sttl", "dur"]:
            if col in analysis["result_df"].columns and col not in preview_cols:
                preview_cols.append(col)

        st.dataframe(
            analysis["result_df"][preview_cols].head(10),
            use_container_width=True,
            hide_index=True
        )

        btn_col1, btn_col2 = st.columns([2, 8])
        with btn_col1:
            csv_data = analysis["result_df"].to_csv(index=False)
            st.download_button(
                label="⬇ Download Results",
                data=csv_data,
                file_name="cyber_threat_detection_results.csv",
                mime="text/csv",
                use_container_width=True
            )
        with btn_col2:
            st.caption("Download the complete prediction results table as a standard CSV file.")

        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)

        # About the Project Card at Bottom
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">📖 ABOUT THE PROJECT</div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:24px;">
                    <div style="background:rgba(0,168,255,0.04); border:1px solid rgba(0,168,255,0.2); border-radius:10px; padding:18px;">
                        <div style="color:#00D9FF; font-weight:700; font-size:15px; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                            🤖 Machine Learning
                        </div>
                        <ul style="color:#EAF4FF; font-size:13px; line-height:1.9; margin:0; padding-left:18px;">
                            <li>Random Forest Classifier (100 Estimators, Balanced Weights)</li>
                            <li>Scikit-learn Pipeline Architecture</li>
                            <li>One-Hot Encoding for Protocol & Service Features</li>
                            <li>Median & Most-Frequent Missing Value Imputation</li>
                        </ul>
                    </div>
                    <div style="background:rgba(139,92,246,0.04); border:1px solid rgba(139,92,246,0.2); border-radius:10px; padding:18px;">
                        <div style="color:#8B5CF6; font-weight:700; font-size:15px; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                            🛡️ Cyber Security
                        </div>
                        <ul style="color:#EAF4FF; font-size:13px; line-height:1.9; margin:0; padding-left:18px;">
                            <li>Network Traffic Flow Analysis</li>
                            <li>High-Precision Cyber Threat & Anomaly Detection</li>
                            <li>Binary Classification (0 = Normal, 1 = Threat)</li>
                            <li>Trained on comprehensive UNSW-NB15 Security Benchmark</li>
                        </ul>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

# ==============================================================================
# 11. NAVIGATION PAGE 2: 🔍 THREAT DETECTION
# ==============================================================================
elif navigation == "🔍 Threat Detection":
    st.markdown(
        """
        <div class="soc-card">
            <div class="soc-card-title">🔍 Threat Detection</div>
            <div style="font-size:13px; color:#8FA8C0;">
                Network traffic classification using the Scikit-learn Random Forest Pipeline. Inspect prediction status, model confidence, and download prediction results.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if analysis is None:
        st.markdown(
            """
            <div class="alert-banner-info">
                <span style="font-size:24px;">👈</span>
                <div>
                    <b style="color:#00D9FF; font-size:15px;">No Data Available</b>
                    <div style="font-size:13px; color:#8FA8C0; margin-top:2px;">
                        Upload a network traffic CSV file from the left sidebar to execute cyber threat detection.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        tot = analysis["total_records"]
        tc = analysis["threat_count"]
        nc = analysis["normal_count"]
        tr = analysis["threat_rate"]

        # Status Summary Header
        if tc > 0:
            st.markdown(
                f"""
                <div class="alert-banner-danger">
                    <span style="font-size:24px;">🚨</span>
                    <div>
                        <b style="color:#FF3B6B; font-size:16px;">{tc:,} POTENTIAL THREATS IDENTIFIED</b>
                        <div style="font-size:13px; color:#EAF4FF; margin-top:2px;">
                            Analyzed {tot:,} records • Normal: {nc:,} • Threat Rate: {tr:.2f}%
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div class="alert-banner-safe">
                    <span style="font-size:24px;">✅</span>
                    <div>
                        <b style="color:#00E6A0; font-size:16px;">ALL {tot:,} RECORDS CLASSIFIED NORMAL</b>
                        <div style="font-size:13px; color:#EAF4FF; margin-top:2px;">
                            No anomalous or malicious traffic patterns detected by the Random Forest model.
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Large Detection Results Card
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">🔎 Detection Results</div>
                <div style="font-size:13px; color:#8FA8C0; margin-bottom:12px;">
                    Full prediction results table. Use the filter controls below to view specific traffic classes.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        filter_col1, filter_col2, filter_col3 = st.columns([2, 2, 4])
        with filter_col1:
            status_filter = st.selectbox(
                "Filter by Classification Status",
                ["All Records", "Threats Only (1)", "Normal Only (0)"]
            )
        with filter_col2:
            row_limit = st.selectbox(
                "Records to Display",
                [100, 250, 500, 1000, "All Records"]
            )

        # Apply Filtering
        filtered_df = analysis["result_df"].copy()
        if status_filter == "Threats Only (1)":
            filtered_df = filtered_df[filtered_df["Prediction"] == 1]
        elif status_filter == "Normal Only (0)":
            filtered_df = filtered_df[filtered_df["Prediction"] == 0]

        if row_limit != "All Records":
            filtered_df = filtered_df.head(int(row_limit))

        st.caption(f"Displaying {len(filtered_df):,} of {len(analysis['result_df']):,} records")

        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
            height=480
        )

        # Download Section
        st.markdown("<div style='margin-top:15px;'></div>", unsafe_allow_html=True)
        d_col1, d_col2 = st.columns([2, 8])
        with d_col1:
            csv_export = analysis["result_df"].to_csv(index=False)
            st.download_button(
                label="⬇ Download Results",
                data=csv_export,
                file_name="cyber_threat_detection_results.csv",
                mime="text/csv",
                use_container_width=True
            )
        with d_col2:
            st.markdown(
                """
                <div style="font-size:12px; color:#8FA8C0; padding-top:8px;">
                    Exports the full dataset with original network traffic columns plus <b>Prediction (0/1)</b>, <b>Status (Normal/Threat)</b>, and <b>Confidence (%)</b>.
                </div>
                """,
                unsafe_allow_html=True
            )

# ==============================================================================
# 12. NAVIGATION PAGE 3: 📊 ANALYTICS
# ==============================================================================
elif navigation == "📊 Analytics":
    st.markdown(
        """
        <div class="soc-card">
            <div class="soc-card-title">📊 Security Analytics</div>
            <div style="font-size:13px; color:#8FA8C0;">
                Comprehensive analytics, protocol distributions, and dataset statistics derived directly from the uploaded dataset and predictions.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if analysis is None:
        st.markdown(
            """
            <div class="alert-banner-info">
                <span style="font-size:24px;">👈</span>
                <div>
                    <b style="color:#00D9FF; font-size:15px;">No Analytics Available</b>
                    <div style="font-size:13px; color:#8FA8C0; margin-top:2px;">
                        Upload a network traffic CSV in the sidebar to generate live analytics.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        tot = analysis["total_records"]
        tc = analysis["threat_count"]
        nc = analysis["normal_count"]
        tr = analysis["threat_rate"]
        nr = analysis["normal_rate"]
        raw_df = analysis["raw_df"]
        acc_info = analysis["accuracy_data"]

        # Dataset Shape & Missing Values
        missing_count = int(raw_df.isna().sum().sum())
        num_cols = len(raw_df.columns)
        num_rows = len(raw_df)

        st.markdown('<div class="section-header">📈 OVERVIEW METRICS</div>', unsafe_allow_html=True)
        r1_col1, r1_col2, r1_col3, r1_col4 = st.columns(4)
        with r1_col1:
            st.metric("Total Records", f"{tot:,}")
        with r1_col2:
            st.metric("Normal Records", f"{nc:,}", delta=f"{nr:.1f}%")
        with r1_col3:
            st.metric("Threat Records", f"{tc:,}", delta=f"-{tr:.1f}%" if tr > 0 else "0.0%", delta_color="inverse")
        with r1_col4:
            st.metric("Threat Percentage", f"{tr:.2f}%")

        r2_col1, r2_col2, r2_col3, r2_col4 = st.columns(4)
        with r2_col1:
            st.metric("Normal Percentage", f"{nr:.2f}%")
        with r2_col2:
            st.metric("Missing Values", f"{missing_count:,}")
        with r2_col3:
            st.metric("Number of Columns", f"{num_cols:,}")
        with r2_col4:
            st.metric("Number of Rows", f"{num_rows:,}")

        # Ground-Truth Accuracy Section if 'label' is available
        if acc_info["has_label"]:
            st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
            st.markdown('<div class="section-header">🎯 GROUND-TRUTH ACCURACY BENCHMARK</div>', unsafe_allow_html=True)

            acc_col1, acc_col2, acc_col3, acc_col4 = st.columns(4)
            with acc_col1:
                st.metric("Model Accuracy", f"{acc_info['accuracy_percentage']:.2f}%")
            with acc_col2:
                st.metric("Error Rate", f"{acc_info['error_percentage']:.2f}%")
            with acc_col3:
                st.metric("Correct Predictions", f"{acc_info['correct_count']:,}")
            with acc_col4:
                st.metric("Incorrect Predictions", f"{acc_info['error_count']:,}")

            # Confusion Matrix Table
            st.markdown(
                f"""
                <div class="soc-card" style="margin-top:15px;">
                    <div class="soc-card-title">🔬 Confusion Matrix Breakdown</div>
                    <div style="display:grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap:12px; margin-top:10px;">
                        <div style="background:rgba(0,230,160,0.08); border:1px solid rgba(0,230,160,0.3); border-radius:8px; padding:12px; text-align:center;">
                            <div style="font-size:11px; color:#8FA8C0;">TRUE POSITIVE (TP)</div>
                            <div style="font-size:22px; font-weight:800; color:#00E6A0; font-family:'JetBrains Mono', monospace;">{acc_info['tp']:,}</div>
                            <div style="font-size:10px; color:#8FA8C0;">Actual Threat detected as Threat</div>
                        </div>
                        <div style="background:rgba(255,159,67,0.08); border:1px solid rgba(255,159,67,0.3); border-radius:8px; padding:12px; text-align:center;">
                            <div style="font-size:11px; color:#8FA8C0;">FALSE POSITIVE (FP)</div>
                            <div style="font-size:22px; font-weight:800; color:#FF9F43; font-family:'JetBrains Mono', monospace;">{acc_info['fp']:,}</div>
                            <div style="font-size:10px; color:#8FA8C0;">Normal traffic flagged as Threat</div>
                        </div>
                        <div style="background:rgba(0,168,255,0.08); border:1px solid rgba(0,168,255,0.3); border-radius:8px; padding:12px; text-align:center;">
                            <div style="font-size:11px; color:#8FA8C0;">TRUE NEGATIVE (TN)</div>
                            <div style="font-size:22px; font-weight:800; color:#00A8FF; font-family:'JetBrains Mono', monospace;">{acc_info['tn']:,}</div>
                            <div style="font-size:10px; color:#8FA8C0;">Normal traffic correctly passed</div>
                        </div>
                        <div style="background:rgba(255,59,107,0.08); border:1px solid rgba(255,59,107,0.3); border-radius:8px; padding:12px; text-align:center;">
                            <div style="font-size:11px; color:#8FA8C0;">FALSE NEGATIVE (FN)</div>
                            <div style="font-size:22px; font-weight:800; color:#FF3B6B; font-family:'JetBrains Mono', monospace;">{acc_info['fn']:,}</div>
                            <div style="font-size:10px; color:#8FA8C0;">Threat missed by classifier</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Visual Charts Section
        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
        st.markdown('<div class="section-header">📊 VISUAL CLASSIFICATION CHARTS</div>', unsafe_allow_html=True)

        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.markdown(
                """
                <div class="soc-card">
                    <div class="soc-card-title">Traffic Distribution: Threat vs Normal</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            dist_data = pd.DataFrame(
                {"Count": [nc, tc]},
                index=["Normal", "Threat"]
            )
            st.bar_chart(dist_data)

        with chart_col2:
            st.markdown(
                """
                <div class="soc-card">
                    <div class="soc-card-title">Top Network Protocols (proto)</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if "proto" in analysis["result_df"].columns:
                proto_counts = analysis["result_df"]["proto"].value_counts().head(8)
                st.bar_chart(proto_counts)
            else:
                st.info("Protocol ('proto') column not found in dataset.")

        # Dataset Overview Section
        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
        st.markdown('<div class="section-header">📋 DATASET OVERVIEW & PREVIEW</div>', unsafe_allow_html=True)
        st.caption(f"First 100 rows of uploaded dataset: {analysis['file_name']}")
        st.dataframe(
            raw_df.head(100),
            use_container_width=True
        )

# ==============================================================================
# 13. NAVIGATION PAGE 4: ℹ️ ABOUT
# ==============================================================================
elif navigation == "ℹ️ About":
    st.markdown(
        """
        <div class="soc-card">
            <div class="soc-card-title">ℹ️ About the Project</div>
            <div style="font-size:14px; color:#EAF4FF; line-height:1.7;">
                This project uses Machine Learning to classify network traffic and identify potentially malicious traffic using the UNSW-NB15 dataset.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    ab_col1, ab_col2 = st.columns(2)

    with ab_col1:
        st.markdown(
            """
            <div class="soc-card" style="height:100%;">
                <div class="soc-card-title" style="color:#00D9FF;">🤖 Machine Learning</div>
                <div style="font-size:13px; color:#8FA8C0; line-height:1.8;">
                    • Random Forest Classifier<br>
                    • Scikit-learn Pipeline<br>
                    • ColumnTransformer<br>
                    • One-Hot Encoding<br>
                    • Missing Value Handling (SimpleImputer)<br>
                    • Binary Classification
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with ab_col2:
        st.markdown(
            """
            <div class="soc-card" style="height:100%;">
                <div class="soc-card-title" style="color:#8B5CF6;">🛡️ Cyber Security</div>
                <div style="font-size:13px; color:#8FA8C0; line-height:1.8;">
                    • Network Traffic Analysis<br>
                    • Threat Detection<br>
                    • Binary Classification (0 = Normal, 1 = Threat)<br>
                    • UNSW-NB15 Dataset<br>
                    • CSV Based Analysis
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)

    # Technology Stack
    st.markdown(
        """
        <div class="soc-card">
            <div class="soc-card-title">⚙️ Technology Stack</div>
            <div style="display:grid; grid-template-columns: repeat(6, 1fr); gap:12px; text-align:center; margin-top:12px;">
                <div style="background:rgba(0,168,255,0.06); border:1px solid rgba(0,168,255,0.2); border-radius:8px; padding:12px 6px;">
                    <div style="font-size:24px;">🐍</div>
                    <div style="font-size:12px; font-weight:700; color:#FFFFFF; margin-top:4px;">Python</div>
                    <div style="font-size:10px; color:#8FA8C0;">Core Runtime</div>
                </div>
                <div style="background:rgba(255,75,75,0.06); border:1px solid rgba(255,75,75,0.2); border-radius:8px; padding:12px 6px;">
                    <div style="font-size:24px;">🎈</div>
                    <div style="font-size:12px; font-weight:700; color:#FFFFFF; margin-top:4px;">Streamlit</div>
                    <div style="font-size:10px; color:#8FA8C0;">Interactive SOC UI</div>
                </div>
                <div style="background:rgba(0,230,160,0.06); border:1px solid rgba(0,230,160,0.2); border-radius:8px; padding:12px 6px;">
                    <div style="font-size:24px;">🤖</div>
                    <div style="font-size:12px; font-weight:700; color:#FFFFFF; margin-top:4px;">Scikit-learn</div>
                    <div style="font-size:10px; color:#8FA8C0;">ML Random Forest</div>
                </div>
                <div style="background:rgba(255,159,67,0.06); border:1px solid rgba(255,159,67,0.2); border-radius:8px; padding:12px 6px;">
                    <div style="font-size:24px;">🐼</div>
                    <div style="font-size:12px; font-weight:700; color:#FFFFFF; margin-top:4px;">Pandas</div>
                    <div style="font-size:10px; color:#8FA8C0;">Data Processing</div>
                </div>
                <div style="background:rgba(139,92,246,0.06); border:1px solid rgba(139,92,246,0.2); border-radius:8px; padding:12px 6px;">
                    <div style="font-size:24px;">💾</div>
                    <div style="font-size:12px; font-weight:700; color:#FFFFFF; margin-top:4px;">Joblib</div>
                    <div style="font-size:10px; color:#8FA8C0;">Model Serialization</div>
                </div>
                <div style="background:rgba(0,217,255,0.06); border:1px solid rgba(0,217,255,0.2); border-radius:8px; padding:12px 6px;">
                    <div style="font-size:24px;">🌐</div>
                    <div style="font-size:12px; font-weight:700; color:#FFFFFF; margin-top:4px;">UNSW-NB15</div>
                    <div style="font-size:10px; color:#8FA8C0;">Security Dataset</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

# ==============================================================================
# 14. FOOTER
# ==============================================================================
st.markdown(
    """
    <div class="soc-footer">
        🛡️ <b>Cyber Threat Detection System</b> &nbsp;•&nbsp; Machine Learning Security Dashboard &nbsp;•&nbsp; Python + Streamlit
    </div>
    """,
    unsafe_allow_html=True
)