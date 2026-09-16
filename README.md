# CyberShield AI: Intelligent Cyber Threat Prediction System for Digital Banking Security

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4+-orange.svg)](https://scikit-learn.org/)
[![SHAP](https://img.shields.io/badge/XAI-SHAP-red.svg)](https://shap.readthedocs.io/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

Academic major project prototype implementing an AI-driven cyber threat prediction and prevention system for digital banking users, featuring specialized machine-learning detectors (URL Phishing, Static PE Malware, and GenAI Message Content), a learned Risk Fusion Engine, and Explainable AI (SHAP & token highlight attributions).

---

## 1. System Architecture

```
                                      USER / CLIENT
                                            │
                      ┌─────────────────────┼─────────────────────┐
                      ▼                     ▼                     ▼
              URL Threat Scanner   Static PE File Scanner   Message Threat Scanner
                      │                     │                     │
                      ▼                     ▼                     ▼
            URL Feature Extraction    PE Header Parsing    Message Stylometrics & NLP
          (20 Lexical Features)     (53 Header Fields)     (24 Features + DistilBERT)
                      │                     │                     │
                      ▼                     ▼                     ▼
           Phishing Classifier      Malware Classifier     GenAI Message Detector
          (Random Forest Model)    (Random Forest Model)   (Stylometric + Transformer)
                      │                     │                     │
                      └─────────────────────┼─────────────────────┘
                                            │
                                            ▼
                                  LEARNED RISK FUSION
                    Unified Risk Score = 100 × [Logistic Meta-Classifier]
                               (Fallback to Weighted Baseline)
                                            │
                                            ▼
                                 SEVERITY CLASSIFICATION
                     [0-29 Low] | [30-59 Med] | [60-79 High] | [80-100 Crit]
                                            │
                      ┌─────────────────────┴─────────────────────┐
                      ▼                                           ▼
               SECURITY DECISION                        EXPLAINABLE AI (XAI)
           (ALLOW / CAUTION / WARN / BLOCK)          (SHAP & Span Attributions)
                      │                                           │
                      └─────────────────────┬─────────────────────┘
                                            │
                                            ▼
                               EXPLANATION & RECOMMENDATION
                             (Plain-English Banking Guidance)
                                            │
                      ┌─────────────────────┴─────────────────────┐
                      ▼                                           ▼
                WEB DASHBOARD                             AUDIT HISTORY DB
           (Interactive Visualizer)                     (SQLite & SQLAlchemy)
                      ▲
                      │
           CHROME BROWSER EXTENSION
          (Pre-Navigation Alert MV3)
```

---

## 2. Core Features & Scientific Rigor

- **Multi-Modal Detection Pipeline:** Three dedicated inspection pipelines covering URLs, executable binaries (PE files), and communication/email messages.
- **GenAI & Human Phishing Message Detector:** Identifies AI-synthesized lures (GPT-4o style) and human social engineering using 24 stylometric features and transformer token attributions.
- **Learned Risk Fusion:** Interpretable Logistic Regression meta-classifier handling partial evidence and multi-modal risk aggregation, with automatic fallback to weighted baselines.
- **Formal Feature Contracts:** Enforces 100% schema alignment (`Training Schema == Inference Schema`) across URL (`v1.0.0`), PE (`v1.0.0`), and Message (`v1.0.0`) inputs.
- **Zero In-Execution Risks:** Analyses URLs statically without navigation; parses Windows PE headers statically with `pefile`; inspects messages without executing active scripts.
- **Explainable AI (SHAP & Span Highlights):** Computes exact feature attributions and visual token highlights, translated into human-readable banking security guidance.
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
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy English model for stylometric extraction
python -m spacy download en_core_web_sm
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

## 4. API Endpoints

- `POST /api/v1/analyze/url` — Analyzes a target URL for lexical/structural phishing indicators.
- `POST /api/v1/analyze/file` — Statically inspects a PE binary (.exe, .dll, .sys) for malicious anomalies.
- `POST /api/v1/analyze/message` — Analyzes message/email text for GenAI-synthesized and social engineering phishing.
- `GET /api/v1/health` — System status, schema versions, and model loading indicators.
- `GET /api/v1/history` — Audit trail of past threat predictions and risk assessments.

---

## 5. Machine Learning & Evaluation Scripts

- `scripts/prepare_message_data.py` — Ingests raw corpora (`data/raw/messages/`), strips email headers/HTML, deduplicates, and produces stratified 70/15/15 splits.
- `scripts/train_phishing.py` — Trains and selects champion URL phishing model on PhiUSIIL benchmark.
- `scripts/train_malware.py` — Trains and selects champion static PE malware model on ClaMP benchmark.
- `scripts/train_message_stylometric.py` — Trains stylometric tree classifier on 24 message features.
- `scripts/train_message_transformer.py` — Fine-tunes `distilbert-base-uncased` sequence classifier.
- `scripts/train_fusion.py` — Trains the learned risk fusion meta-classifier against fixed-weight baseline.
- `scripts/adversarial_report.py` — Evaluates evasion robustness (homographs, subdomain injection, synonym replacement) and writes `docs/adversarial_robustness_report.json`.
- `scripts/cross_generator_eval.py` — Evaluates cross-LLM generalization on held-out generator corpora and writes `docs/cross_generator_report.json`.

---

## 6. Automated Testing Suite

Execute the complete automated test suite:
```bash
python -m pytest tests/ -v
```

### Test Coverage:
- `tests/test_features/`: URL, PE, and Message feature contract definitions, NaN/Inf rejection, and extraction tests.
- `tests/test_models/`: Model serialization integrity and recall bounds.
- `tests/test_risk_engine/`: Boundary threshold clamping, context heuristics, and learned fusion logic.
- `tests/test_explainable_ai/`: SHAP tree explainer attributions and token/span highlights.
- `tests/test_api/`: URL, file upload, message scanner, health, and history endpoints.
- `tests/test_adversarial/`: Homograph, subdomain injection, path padding, and message synonym perturbation tests.
- `tests/test_integration.py`: End-to-end multi-modal demonstration scenarios.

---

## 7. Empirical Evaluation Results

All performance values reflect evaluation on unseen stratified test sets (zero fabricated numbers):

| Component | Architecture | Dataset | Test Size | Accuracy | Threat Recall | Precision | F1-Score | ROC-AUC | False Negatives |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phishing Model** | Random Forest Ensemble | PhiUSIIL + Deep-Path URLs | 8,453 | **93.81%** | **95.64%** | **92.13%** | **0.9385** | **0.9857** | **182 / 8,453** |
| **Malware Model** | Random Forest PE Detector | ClaMP Static PE Headers | 684 | **99.27%** | **99.68%** | **98.73%** | **0.9920** | **0.9998** | **1 / 684** |
| **GenAI Message Model** | Stylometric + DistilBERT | Opara GPT-4o + Nazario + Enron | TBD | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** |
| **Learned Risk Fusion** | Logistic Meta-Classifier | Multi-modal Held-out Splits | TBD | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** |

---

## 8. Project Directory Structure

```
CyberSheild-AI/
├── backend/
│   ├── api/             # FastAPI routes (health, url, file, message, history)
│   ├── schemas/         # Pydantic data contracts
│   ├── services/        # Pipeline orchestration & threat service
│   ├── config.py        # System configuration & risk weights
│   └── main.py          # FastAPI application & static mount
├── browser_extension/   # Chrome Manifest V3 extension
├── data/
│   ├── raw/             # Benchmark datasets (PhiUSIIL, ClaMP, raw messages)
│   └── processed/       # Stratified Train/Val/Test splits
├── database/            # SQLite models, engine & repository
├── docs/                # Architecture, verification report, adversarial reports
├── explainable_ai/      # SHAP explainers, span highlights & formatter
├── feature_extraction/  # URL, PE, & Message feature extractors & contracts
├── frontend/            # Web Dashboard (HTML, CSS, JS)
├── models/              # Champion models, scalers, checkpoints & metadata
├── risk_engine/         # Thresholds, context heuristics, decision policy & fusion
├── scripts/             # Training, evaluation, adversarial & cross-gen scripts
├── tests/               # Unit, model, API, adversarial & integration tests
├── requirements.txt     # Locked dependencies
├── run.py               # Master startup script
└── README.md            # Comprehensive documentation
```
