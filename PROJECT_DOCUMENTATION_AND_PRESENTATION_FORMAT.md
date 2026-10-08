# 🛡️ PROJECT REPORT & PRESENTATION FORMAT

---

## 1. TITLE
**AI-Powered Cyber Threat Detection System Using Machine Learning on UNSW-NB15 Network Traffic**

---

## 2. INTRODUCTION
In today's digital era, computer networks and enterprise cloud infrastructures are continuously exposed to sophisticated cyber threats, ranging from Distributed Denial of Service (DDoS) and unauthorized privilege escalations to automated reconnaissance and zero-day exploits. As network bandwidth and packet velocity grow exponentially, manual inspection of log files by Security Operations Center (SOC) analysts is no longer viable. 

Intrusion Detection Systems (IDS) serve as the first line of defense in identifying suspicious activities. However, conventional signature-based detection systems rely on static rule databases and fail when confronted with modified or previously unseen attack patterns. This project presents an intelligent, automated **Cyber Threat Detection System** powered by Machine Learning. Using the modern benchmark **UNSW-NB15** network flow dataset, the system automatically analyzes statistical and transactional flow features to classify incoming traffic into **Normal** or **Threat** in real-time, delivering actionable intelligence through an interactive SOC Dashboard.

---

## 3. PROBLEM STATEMENT
Traditional Network Intrusion Detection Systems (NIDS) and perimeter firewalls face critical limitations:
1. **Inability to Detect Zero-Day & Polymorphic Attacks:** Signature-based tools only identify known attack signatures. When attackers modify payload signatures or exploit zero-day vulnerabilities, the systems fail.
2. **Alert Fatigue and High False Positive Rates:** Heuristic and static rules frequently generate false alarms, overwhelming security analysts and causing critical incidents to be overlooked.
3. **High Volume and Dimensionality of Network Data:** Modern network traffic generates millions of records containing mixed data types (numerical packet counters, categorical network protocols, and connection states) that cannot be parsed manually.
4. **Data Imbalance:** In real-world networks, benign traffic dominates malicious traffic, leading standard predictive models to exhibit strong bias toward predicting normal traffic.

---

## 4. OBJECTIVES
The primary objectives of this project are:
1. **Develop an Accurate ML-Based Threat Classifier:** Train and evaluate an ensemble Machine Learning model (Random Forest) capable of binary classification (`0 = Normal`, `1 = Threat`) on network traffic flows.
2. **Build an End-to-End Automated Preprocessing Pipeline:** Construct a robust pipeline that cleans data, handles missing values via median imputation, and dynamically encodes categorical network protocols without data leakage.
3. **Design a Real-Time SOC Dashboard:** Develop an interactive, dark-themed Security Operations Center (SOC) dashboard that allows security analysts to upload network CSV logs, view real-time threat rates, examine prediction confidence, and review confusion matrices.
4. **Implement Resilient Error Handling & Unknown Feature Management:** Ensure the system handles edge cases gracefully, such as unlabelled production datasets, missing required columns, or unseen network protocols (`handle_unknown='ignore'`).
5. **Provide Verifiable Audit & Reporting Capabilities:** Enable one-click export of audited detection logs with confidence scores and maintain a comprehensive 10-point automated test suite to ensure system reliability.

---

## 5. PROPOSED SOLUTION
The proposed solution replaces rigid static signatures with a behavioral, machine learning-driven detection platform:
* **Benchmark Dataset Ingestion:** Utilizes the peer-reviewed **UNSW-NB15** dataset, which reflects modern network traffic and contemporary attack behaviors.
* **Unified Scikit-Learn Pipeline:** Integrates data preprocessing and classification into a single serialized pipeline object (`threat_model.pkl`), ensuring 100% consistency between training and real-time inference.
* **Balanced Ensemble Classification:** Implements `RandomForestClassifier` with balanced class weights to give equal importance to minority attack records and reduce false negatives.
* **Interactive Analyst Interface:** Provides a high-contrast SOC dashboard built with Streamlit featuring real-time gauges, threat-ratio donut charts, protocol distribution graphs, and dynamic data filtering.
* **Dual Enterprise Architecture:** Complemented by a scalable FastAPI REST backend and SQLite database for production-grade security event logging and API integration.

---

## 6. TECHNOLOGIES USED

### A. Programming Languages & Core Tools
* **Python (v3.10 - 3.13):** Core development language for data processing, machine learning, and application logic.
* **HTML5, CSS3, JavaScript (ES6):** Used for front-end interface components, styling, and SOC dashboard visualization.

### B. Machine Learning & Data Science Libraries
* **Scikit-Learn:** Feature preprocessing (`ColumnTransformer`, `OneHotEncoder`, `SimpleImputer`), model training (`RandomForestClassifier`), and evaluation metrics.
* **Pandas:** High-performance tabular data manipulation, feature extraction, and CSV parsing.
* **NumPy:** Multi-dimensional numerical operations and array computations.
* **Joblib:** Model serialization and compression (`compress=7`), keeping the model artifact lightweight (~18.5 MB).

### C. Frameworks, APIs & Database
* **Streamlit:** Framework for building the interactive SOC analyst dashboard (`app.py`).
* **FastAPI:** High-performance asynchronous web framework for enterprise REST APIs (`main.py`).
* **Uvicorn:** ASGI web server implementation for hosting the FastAPI application.
* **SQLite3:** Embedded relational database for storing audit logs, security events, and detection rules (`cyber_threat_detector.db`).

---

## 7. SYSTEM ARCHITECTURE

```
+-----------------------------------------------------------------------------------+
|                        CYBER THREAT DETECTION PLATFORM                            |
+-----------------------------------------------------------------------------------+
                                          |
                +-------------------------+-------------------------+
                |                                                   |
      [Streamlit SOC UI (app.py)]                        [FastAPI Backend (main.py)]
      - Port: 8501                                       - Port: 8000
      - CSV Ingestion (up to 1GB)                        - REST Endpoints (/docs)
      - Real-Time Visual Gauges                          - SQLite Database Logging
                |                                                   |
                +-------------------------+-------------------------+
                                          |
                        +-----------------------------------+
                        |      DATA VALIDATION MODULE       |
                        | - File format & integrity check   |
                        | - Feature alignment verification  |
                        +-----------------------------------+
                                          |
                        +-----------------------------------+
                        |     SCIKIT-LEARN ML PIPELINE      |
                        | 1. Numerical: SimpleImputer       |
                        |    (Median strategy)              |
                        | 2. Categorical: OneHotEncoder     |
                        |    (handle_unknown='ignore')      |
                        | 3. Model: RandomForestClassifier  |
                        |    (100 Trees, Balanced Weights)  |
                        +-----------------------------------+
                                          |
                        +-----------------------------------+
                        |    PREDICTION & INFERENCE ENGINE  |
                        | - Class: 0 (Normal) / 1 (Threat)  |
                        | - Confidence Score (predict_proba)|
                        +-----------------------------------+
                                          |
                +-------------------------+-------------------------+
                |                                                   |
    [SOC Analytics & Metrics]                             [Audit Export]
    - Threat vs Normal Donut                              - Download Results CSV
    - Ground-Truth Accuracy Donut                         - Security Audit Logs
    - Confusion Matrix Breakdown
```

---

## 8. METHODOLOGY
The system operates through five methodical stages:

1. **Data Acquisition:** Network flow records are collected from the UNSW-NB15 benchmark dataset, containing 45 flow features capturing duration, packet volume, protocol types, time-to-live, and arrival rates.
2. **Data Cleaning & Target Isolation:** Non-predictive identifiers (`id`) and multi-class categories (`attack_cat`) are dropped to eliminate bias. The binary target column (`label`: `0` for normal, `1` for threat) is isolated.
3. **Feature Preprocessing Pipeline:**
   * Numerical attributes are imputed with median values to remain robust against traffic spikes.
   * Categorical attributes (`proto`, `service`, `state`) are encoded into sparse binary matrices using `OneHotEncoder(handle_unknown='ignore')`.
4. **Model Training & Hyperparameter Setup:** The `RandomForestClassifier` is trained using 100 decision trees, balanced class weighting, and multi-core parallelization (`n_jobs=-1`).
5. **Real-Time Inference & Verification:** The trained pipeline evaluates incoming network CSV streams, outputs predicted classes along with confidence percentages, and is verified against a 10-point test suite.

---

## 9. IMPLEMENTATION
The project is implemented through modular, production-ready code components:

1. **Model Training Pipeline (`train_model.py`):**
   * Reads UNSW-NB15 training and testing CSVs.
   * Constructs the `ColumnTransformer` preprocessing and model pipeline.
   * Fits the model, evaluates performance, and serializes the compressed artifact to `models/threat_model.pkl`.
2. **Interactive Streamlit Dashboard (`app.py`):**
   * Features a custom CSS SOC dark theme (`#020B18` background, `#0878D1` borders, `#00D9FF` cyber accents).
   * Ingests CSV files, verifies required columns against `pipeline.feature_names_in_`, and executes batch predictions.
   * Renders dynamic metric cards, Threat Ratio Donut, Detection Accuracy Donut, and filterable data tables.
   * Generates a downloadable `cyber_threat_detection_results.csv` with predictions and confidence scores.
3. **Enterprise REST API & Server (`main.py` & `backend/`):**
   * Starts a Uvicorn-powered FastAPI server at `http://localhost:8000` with interactive Swagger API documentation at `/docs`.
   * Integrates heuristic detectors (Brute Force, Network Rules, Privilege Escalation) with SQLite audit logging.
4. **Automated Verification Test Suite (`test_system.py`):**
   * Executes 10 automated test scenarios verifying empty state handling, inference accuracy, state refresh, CSV export, ground-truth confusion matrix, missing columns, and missing model recovery.

---

## 10. RESULTS
* **Model Accuracy:** Achieved **~88.0%** classification accuracy on the UNSW-NB15 test dataset.
* **Confusion Matrix Performance:** Tested on representative network flow samples, achieving high sensitivity for threats:
  * **True Positives (Threats Correctly Flagged):** 239
  * **True Negatives (Normal Traffic Cleared):** 201
  * **False Positives (Benign Flagged as Threat):** 49
  * **False Negatives (Threats Missed):** 11
* **Low Latency Inference:** Generates predictions and probability confidence for 500 records in less than **0.05 seconds**.
* **Test Verification:** **10 out of 10 automated test cases passed successfully**, proving resilience against real-world data issues.

---

## 11. FUTURE SCOPE
1. **Multi-Class Threat Classification:** Extend the model from binary classification to granular multi-class categorization (specifically identifying DoS, Reconnaissance, Backdoor, Worms, Exploits).
2. **Live Packet Sniffing Integration:** Integrate low-level packet capture tools (e.g., Scapy, PyShark, Libpcap) to capture live network interface card (NIC) traffic in real time.
3. **Deep Learning & Temporal Sequence Models:** Implement Bidirectional LSTM (Bi-LSTM) or Transformer architectures to analyze sequential time-series packet patterns.
4. **Automated Incident Response & Webhooks:** Integrate automated firewall rule generation and real-time webhook notifications (Slack, Discord, Email alerts) when threat thresholds are breached.

---

## 12. CONCLUSION
The **Cyber Threat Detection System** successfully bridges the gap between machine learning research and practical cybersecurity operations. By combining the benchmark **UNSW-NB15** dataset with an automated Scikit-Learn preprocessing pipeline and an ensemble Random Forest classifier, the system achieves reliable ~88% detection accuracy while maintaining low inference latency. The intuitive SOC Dashboard, complete with real-time analytics, confidence scores, and exportable audit logs, equips security analysts with an effective tool to detect, visualize, and mitigate modern cyber attacks.
