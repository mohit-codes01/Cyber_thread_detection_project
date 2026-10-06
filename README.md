# 🛡️ Cyber Threat Detection System

A Streamlit-based Cyber Threat Detection dashboard using Machine Learning to classify network traffic records from the **UNSW-NB15** dataset into Normal or Threat.

The system uses a Scikit-learn Pipeline with a **Random Forest Classifier** to perform real-time binary classification (`0 = Normal`, `1 = Threat`) on network traffic CSV files.

---

## 📌 Project Overview

- **Project Name**: Cyber Threat Detection System
- **Dataset**: UNSW-NB15 Network Traffic Dataset
- **Machine Learning Model**: Random Forest Classifier (`RandomForestClassifier(n_estimators=100)`)
- **Pipeline Components**:
  - `ColumnTransformer` for feature preprocessing
  - `SimpleImputer` (median for numerical features, most frequent for categorical features)
  - `OneHotEncoder` (`handle_unknown='ignore'`) for categorical variables
  - `RandomForestClassifier` with balanced class weights
- **Target**: Binary Classification
  - `0` = Normal
  - `1` = Threat
- **Input Data**: Network traffic CSV files with UNSW-NB15 flow features (non-input columns `id`, `attack_cat`, and `label` are automatically dropped before inference if present)
- **Model Output**: Predicted class (`0` or `1`), status label (`Normal` or `Threat`), and model prediction confidence (`%`) from `predict_proba()`

---

## 🌟 Application Features

### 1. Cyber Security SOC Dashboard Theme
- Professional dark cybersecurity theme inspired by Security Operations Center (SOC) dashboards.
- Colors: Dark navy background (`#020B18`), card background (`#071A2B`), blue borders (`#0878D1`), cyan accents (`#00D9FF`), threat alerts (`#FF3B6B`), and normal traffic green (`#00E6A0`).
- Dynamic real-time date and time display on the header and sidebar.
- `● System Online` status indicator.
- Clearly visible `🔄 Refresh Dashboard` button that reloads application state and refreshes calculations using `st.rerun()`.

### 2. Real Machine Learning Predictions & Statistics
- **Zero fake predictions or hardcoded percentages**: Every metric is calculated dynamically from the loaded model (`models/threat_model.pkl`) and the uploaded dataset.
- **Statistics Cards**:
  - **Total Records**: Actual count of uploaded rows.
  - **Threats Detected**: Actual count of predictions equal to 1.
  - **Normal Traffic**: Actual count of predictions equal to 0.
  - **Threat Rate**: Actual percentage `(threats / total_records) * 100`.
  - Shows `--` before any CSV is uploaded.
- **Threat Ratio Donut**:
  - Visualizes the proportion of Threat vs Normal traffic using actual model predictions.
  - Center displays the exact `XX.XX% THREAT` rate.
  - Legend displays counts and percentages for both Threat and Normal traffic.
- **Detection Accuracy Donut**:
  - Automatically checks if the uploaded CSV contains the ground-truth `label` column.
  - If `label` exists: Calculates real correct predictions, incorrect predictions, accuracy percentage, and error percentage.
  - If `label` does NOT exist: Displays `N/A` with the message: *"Ground-truth label column not available. Accuracy cannot be calculated for this file."*
- **Model Status Card**:
  - Displays `🟢 Ready to Detect` when the model is loaded in memory.
  - Displays `🟢 Analysis Complete` with file details after processing.
  - Displays `🔴 Model Unavailable` with clear guidance if the model file is missing.

### 3. Functional Sidebar Navigation
- **🏠 Dashboard**: Metric cards, Threat Ratio donut, Detection Accuracy donut, Model Status, and preview table.
- **🔍 Threat Detection**: Full results table with status filtering (`All`, `Threats Only`, `Normal Only`), row limit selection, model confidence, and `⬇ Download Results` button.
- **📊 Analytics**: Dataset summary (total rows, columns, missing values), traffic distribution chart, top network protocols (`proto`) chart, and confusion matrix breakdown (TP, FP, TN, FN) when ground truth `label` is available.
- **ℹ️ About**: Project architecture, Machine Learning details, and Cyber Security context.

### 4. Results Export
- **⬇ Download Results Button**: Exports `cyber_threat_detection_results.csv` containing the original dataset columns plus `Prediction` (0/1), `Status` (Normal/Threat), and `Confidence (%)`.

### 5. Robust File & Feature Validation
- Checks uploaded file format and size (up to 1GB limit).
- Validates required features against the trained model (`pipeline.feature_names_in_`).
- If required columns are missing, displays a clear message listing the missing columns without crashing.

---

## 🏗️ Project Structure

```
Cyber-Threat-Detection/
│
├── app.py                             # Main Streamlit SOC Dashboard Application
├── train_model.py                     # ML Model Training Script (Random Forest Pipeline)
├── test_system.py                     # Automated 10-Point Verification Test Suite
├── requirements.txt                   # Project Dependencies
├── README.md                          # Project Documentation
│
├── models/
│   └── threat_model.pkl               # Trained Scikit-learn Pipeline Model
│
└── data/
    ├── sample/
    │   └── sample_network_traffic.csv # 500-record test dataset with ground truth
    ├── UNSW_NB15_training-set.csv     # UNSW-NB15 Training Dataset
    └── UNSW_NB15_testing-set.csv      # UNSW-NB15 Testing Dataset
```

---

## ⚙️ Installation & Setup

### 1. Prerequisites
- Python 3.10 to 3.13 installed on your system.

### 2. Clone or Download the Repository
```bash
git clone https://github.com/YOUR_USERNAME/Cyber-Threat-Detection.git
cd Cyber-Threat-Detection
```

### 3. Set Up a Virtual Environment (Recommended)
**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Application

To start the Cyber Threat Detection System:

```bash
python -m streamlit run app.py
```

The application will launch in your browser at:
👉 **`http://localhost:8501`**

---

## 🧪 Testing & Verification

An automated 10-point test suite is included to verify all functionality:

```bash
python test_system.py
```

### Verified Test Scenarios:
1. **TEST 1**: Application starts with no CSV (metrics display `--`, model loads cleanly).
2. **TEST 2**: Upload valid UNSW-NB15 CSV (`sample_network_traffic.csv` produces real predictions).
3. **TEST 3**: Upload a different valid CSV (dashboard dynamically recalculates to the new data).
4. **TEST 4**: Refresh Dashboard button (`st.rerun()` refreshes timestamps and state).
5. **TEST 5**: Download Results (verifies `cyber_threat_detection_results.csv` export).
6. **TEST 6**: Upload CSV with `label` column (calculates accuracy, error rate, and confusion matrix).
7. **TEST 7**: Upload CSV without `label` column (predictions work; accuracy displays `N/A`).
8. **TEST 8**: Upload CSV missing required features (displays clean error listing missing columns).
9. **TEST 9**: Missing model file (displays `🔴 Model Unavailable` message gracefully).
10. **TEST 10**: Sidebar navigation (all 4 views: Dashboard, Threat Detection, Analytics, About verified).

---

## 🧠 Machine Learning Pipeline

```
Uploaded CSV
    │
    ▼
[Separate non-input columns: 'id', 'attack_cat', 'label']
    │
    ▼
[Validate 42 input features against trained pipeline]
    │
    ▼
[ColumnTransformer Preprocessing]
    ├── Numerical Features   ──► SimpleImputer(strategy='median')
    └── Categorical Features ──► SimpleImputer(strategy='most_frequent') + OneHotEncoder
    │
    ▼
[RandomForestClassifier(n_estimators=100, class_weight='balanced')]
    │
    ├── pipeline.predict(X) ────────► Prediction: 0 (Normal) or 1 (Threat)
    └── pipeline.predict_proba(X) ──► Prediction Confidence (%)
```

---

## 📤 GitHub Upload Commands

To upload your project to GitHub:

```bash
# 1. Initialize git (if not already done)
git init

# 2. Stage files
git add app.py train_model.py test_system.py requirements.txt README.md data/ models/

# 3. Commit
git commit -m "Cyber Threat Detection System: Streamlit SOC Dashboard with Random Forest ML"

# 4. Set main branch
git branch -M main

# 5. Add remote repository
git remote add origin https://github.com/YOUR_USERNAME/Cyber-Threat-Detection.git

# 6. Push to GitHub
git push -u origin main
```

*(Note: If `models/threat_model.pkl` exceeds 100MB, configure Git LFS with `git lfs track "*.pkl"` or attach the model file in GitHub Releases).*

---

## 🌐 Deployment Instructions

### Streamlit Community Cloud
1. Push the repository to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io) and log in with GitHub.
3. Click **"New App"**:
   - Repository: `YOUR_USERNAME/Cyber-Threat-Detection`
   - Branch: `main`
   - Main file path: `app.py`
4. Click **Deploy**.
