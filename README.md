# CyberShield AI: Intelligent Cyber Threat Prediction System for Digital Banking Security

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4+-orange.svg)](https://scikit-learn.org/)
[![SHAP](https://img.shields.io/badge/XAI-SHAP-red.svg)](https://shap.readthedocs.io/)
[![Tests](https://img.shields.io/badge/tests-36%20passed-brightgreen.svg)]()

Academic major project prototype implementing an AI-driven cyber threat prediction and prevention system for digital banking users, featuring specialized machine-learning detectors, a unified Risk Analysis Engine, and Explainable AI (SHAP) feature attribution.

---

## 1. System Architecture

```
                                USER / CLIENT
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
             URL Threat Scanner               Static PE File Scanner
                     │                                 │
                     ▼                                 ▼
           URL Feature Extraction             Static PE Header Parsing
         (20 Deterministic Lexical)             (53 Header Fields via pefile)
                     │                                 │
                     ▼                                 ▼
          Phishing ML Classifier             Malware ML Classifier
         (Random Forest Ensemble)           (Random Forest Ensemble)
                     │                                 │
                     └────────────────┬────────────────┘
                                      │
                                      ▼
                            RISK ANALYSIS ENGINE
             Unified Risk Score = 100 × [0.85·P(threat) + 0.15·C(context)]
                                      │
                                      ▼
                           SEVERITY CLASSIFICATION
               [0-29 Low] | [30-59 Med] | [60-79 High] | [80-100 Crit]
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
              SECURITY DECISION              EXPLAINABLE AI (XAI)
          (ALLOW / CAUTION / WARN / BLOCK)    (SHAP Feature Attributions)
                     │                                 │
                     └────────────────┬────────────────┘
                                      │
                                      ▼
                        EXPLANATION & RECOMMENDATION
                      (Plain-English Banking Guidance)
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
               WEB DASHBOARD                   AUDIT HISTORY DB
          (Interactive Visualizer)           (SQLite & SQLAlchemy)
                     ▲
                     │
          CHROME BROWSER EXTENSION
         (Pre-Navigation Alert MV3)
```

---

## 2. Core Features & Scientific Rigor

- **Real Trained ML Estimators:** Random Forest models trained on genuine benchmarks (PhiUSIIL Phishing Dataset & ClaMP Static PE Malware Dataset). Zero fabricated results.
- **Formal Feature Contracts:** Enforces 100% schema alignment (`Training Schema == Inference Schema`).
- **Static URL Analysis Only:** Analyses URLs without navigating to or fetching the untrusted destination.
- **Static PE Binary Inspection:** Parses Windows PE headers using `pefile` without ever executing untrusted files.
- **Unified Risk Score (0–100):** Fuses machine learning evidence with contextual threat indicators into an intuitive common scale.
- **Explainable AI (SHAP):** TreeExplainer calculates exact feature contributions, translated by an Explanation Formatter into human-readable banking security guidance.
- **Chrome Browser Extension (MV3):** Connects to the centralized backend API for pre-navigation inspection and on-page warning banners.

---

## 3. Quick Start Guide

### Prerequisites
- Python 3.12+ installed
- Virtual environment (`venv`)

### Installation
```bash
# Clone or navigate into project directory
cd CyberSheild-AI

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
# Launch FastAPI server and Web Dashboard
python run.py
```
- **Web Dashboard:** [http://localhost:8000](http://localhost:8000)
- **Interactive API Docs (Swagger):** [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health Check:** [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

## 4. Running the Chrome Extension (Manifest V3)

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in upper right).
3. Click **Load unpacked**.
4. Select the `browser_extension/` directory inside `CyberSheild-AI`.
5. Ensure the backend server is running on `http://localhost:8000`.
6. Click the CyberShield AI extension icon in your browser toolbar to scan active tabs!

---

## 5. Automated Verification & Testing Suite

Execute the comprehensive 36-test automated suite:
```bash
PYTHONPATH=. ./.venv/bin/pytest tests/ -v
```

### Test Coverage Summary:
- `tests/test_features/`: URL & PE feature contract validation and extraction speed.
- `tests/test_models/`: Phishing and Malware model serialization, recall, and false negative bounds.
- `tests/test_risk_engine/`: Boundary threshold tests and decision policy mapping.
- `tests/test_explainable_ai/`: SHAP TreeExplainer attribution and plain-language formatting.
- `tests/test_api/`: Health, URL analysis, file upload validation, and history persistence.
- `tests/test_integration.py`: End-to-end execution of all 4 core demonstration scenarios.

---

## 6. Empirical Evaluation Results

All performance values reflect evaluation on unseen stratified test sets:

| Component | Dataset | Test Size | Accuracy | Threat Recall | Precision | F1-Score | ROC-AUC | False Negatives |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phishing Model** | PhiUSIIL + Deep-Path URLs | 8,453 | **93.81%** | **95.64%** | **92.13%** | **0.9385** | **0.9857** | **182 / 8,453** |
| **Malware Model** | ClaMP Static PE Headers | 684 | **99.27%** | **99.68%** | **98.73%** | **0.9920** | **0.9998** | **1 / 684** |

---

## 7. Project Directory Structure

```
CyberSheild-AI/
├── backend/
│   ├── api/             # FastAPI routes (health, url, file, history)
│   ├── schemas/         # Pydantic data contracts
│   ├── services/        # Pipeline orchestration & secure file handler
│   ├── config.py        # System configuration & weights
│   └── main.py          # FastAPI application & static mount
├── browser_extension/   # Chrome Manifest V3 extension
├── data/
│   ├── raw/             # Benchmark datasets (PhiUSIIL, ClaMP)
│   └── processed/       # Stratified Train/Val/Test splits
├── database/            # SQLite models, engine & repository
├── docs/                # Architecture, verification report, extension spec
├── explainable_ai/      # SHAP explainers & plain-language formatter
├── feature_extraction/  # URL & PE feature extractors & contracts
├── frontend/            # Web Dashboard (HTML, CSS, JS)
├── models/              # Champion models, scalers & metadata
├── scripts/             # Training, evaluation & dataset verification
├── tests/               # 36 unit, model, API & integration tests
├── requirements.txt     # Locked dependencies
├── run.py               # Master startup script
└── README.md            # Comprehensive documentation
```
