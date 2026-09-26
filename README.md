# CyberShield AI: Intelligent Cyber Threat Prediction System for Digital Banking Security

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4+-orange.svg)](https://scikit-learn.org/)
[![SHAP](https://img.shields.io/badge/XAI-SHAP-red.svg)](https://shap.readthedocs.io/)

Academic major-project prototype for cyber-threat analysis in a digital-banking context. The current web dashboard provides URL threat analysis, static PE-file analysis, analysis history, and model/XAI metrics. The backend also retains message-content and download-metadata analysis APIs; message scanning is not currently exposed as a dashboard tab. URL scoring combines model output with URL and domain evidence, and results include explainable score breakdowns.

---

## 1. System Architecture

```
                                      USER / CLIENT
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
              Web Dashboard                                 Browser Extension
        URL + Static PE Scanners                         (URL inspection client)
                     │                                             │
                     └──────────────────────┬──────────────────────┘
                                            ▼
                                      FastAPI Backend
                 ┌──────────────────────────┼─────────────────────────┐
                 ▼                          ▼                         ▼
          URL Analysis API           Static PE API             Other APIs
          URL features + ML          PE header parser       Message + download
          RDAP / DNS / TLS            Malware model          metadata analysis
                 └──────────────────────────┼─────────────────────────┘
                                            ▼
                             Scoring, Decisions & Explanations
                        Unified risk + likelihood + context scores
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
             Web Dashboard                              SQLite Audit History
        Results, score breakdowns,                   Past analysis records
          metrics and recommendations
```

---

## 2. Core Features & Scientific Rigor

- **Dashboard scanners:** URL threat analysis and static Windows PE executable analysis. The manual Message Threat Scanner tab was removed from the dashboard.
- **Additional backend analysis APIs:** Message/email content analysis and download-metadata analysis remain available as API capabilities; they are not currently presented as dashboard scanning tabs.
- **Message analysis pipeline:** The retained backend pipeline supports stylometric and transformer-based message analysis and span attributions when its models and dependencies are installed.
- **Risk scoring:** URL scoring uses its evidence-based policy described below. File, message, and download analyses use their modality-specific model and contextual signals.
- **URL Domain Verification:** Checks registration metadata through RDAP, DNS resolution, and HTTPS certificate validity/expiry. It does not load the submitted webpage, and these checks do not certify that its content is safe.
- **Evidence-Based URL Risk:** Unified URL Risk combines the phishing model, URL signals, and supporting domain evidence. A confirmed threat-intelligence match sets a minimum score of 90.
- **Formal Feature Contracts:** Enforces 100% schema alignment (`Training Schema == Inference Schema`) across URL (`v1.0.0`), PE (`v1.0.0`), and Message (`v1.0.0`) inputs.
- **Zero In-Execution Risks:** Analyses URLs statically without navigation; parses Windows PE headers statically with `pefile`; inspects messages without executing active scripts.
- **Explainable AI (SHAP & score breakdowns):** URL result score cards reveal their calculation details on hover or keyboard focus. Model explanations and message span highlights are supported by applicable analysis pipelines.
- **Chrome Browser Extension (MV3):** A separate browser client connects to the backend for URL inspection and warnings. Extension packaging and browser permissions are configured in `browser_extension/manifest.json`.

---

## 2.1 Security Indicators & Mathematical Methodology

The dashboard separates model likelihood, combined risk, and contextual risk. URL-specific scoring is described below; other scanners retain their own risk policies.

### 1. Unified Risk Score (0–100)
- **URL definition:** A combined risk index, not a model probability. URL scoring currently weights the configured model/context score at 65%, a mapped URL-feature risk signal at 25%, and domain verification/reputation evidence at 10%.
- **URL signals:** The contextual URL indicators include numeric-IP hosts, suspicious terms, subdomain depth, missing HTTPS, and an unranked domain. The phishing model also evaluates the URL feature vector.
- **Domain evidence:** RDAP registration status/age, DNS resolution, TLS validity, and domain reputation are supporting signals. An established domain with successful registration, DNS, and TLS checks receives only a small score reduction; these checks cannot cancel strong phishing evidence. Unranked domains have a minimum risk score of 15 and remain caution/unknown rather than being treated as confirmed phishing.
- **Confirmed threat:** A positive match from configured threat-intelligence feeds sets a minimum Unified Risk of 90.
- **URL risk bands:** 0–29: LOW | 30–49: MEDIUM | 50–89: HIGH | 90–100: CRITICAL. URL bands differ from thresholds used by other scanners.

### 2. Model Phishing Likelihood (%)
- **Definition:** The phishing classifier's output probability for the URL feature input. It is a model score, not a guarantee of correctness or a calibrated 85–90% certainty claim:
  - Threat Predictions: $\text{Prediction Likelihood} = P(\text{threat}) \times 100\%$ (labeled `Phishing Likelihood` or `Malware Likelihood`).
  - Legitimate Predictions: $\text{Prediction Likelihood} = [1.0 - P(\text{threat})] \times 100\%$ (labeled `Legitimate Likelihood`).
- **Distinction from Unified Risk:** Model Phishing Likelihood comes from the URL model; Unified Risk combines model, URL-feature, and domain evidence. A low model likelihood can still accompany a Suspicious / Unknown result when there is insufficient evidence to call a domain legitimate.

### 3. Contextual Risk Score (0–100)
- **Definition:** An independent, deterministic risk score evaluating static environmental and structural threat indicators ($100 \times C_{\text{context}}$):
  - **URL Context:** Numeric IP host (+0.40), banking keyword (+0.30), subdomain depth $\ge 2$ (+0.20), missing HTTPS (+0.10).
  - **PE Malware Context:** Single binary section (+0.40), compilation year anomaly (+0.30), missing code section (+0.30).
  - **Message Context:** Urgency lexicon (+0.35), credential solicitation (+0.35), generic greeting (+0.20), embedded link (+0.10).
  - **Download Context:** Executable extension tier (+0.40), cross-domain redirect (+0.30), keyword match (+0.20), high entropy (+0.10).

### URL registration, DNS, and certificate checks

- The scanner uses IANA's RDAP bootstrap and the applicable registry for registration metadata, resolves the hostname, and performs a certificate-validating TLS handshake for HTTPS URLs when possible.
- It does not request page content, follow redirects, or navigate to the destination website.
- Registration status/domain age, DNS status, and TLS status/issuer/expiry are shown separately. Failed lookups are reported as unavailable or unknown, not as a clean result.
- Registration and a valid TLS certificate establish infrastructure facts only. An old registered domain with valid TLS can still host phishing content; none of these checks certifies a site as safe.

---

## 2.2 Explainable AI (SHAP TreeExplainer) Methodology

- **TreeExplainer Attribution:** Computes exact Shapley attributions in polynomial time $\mathcal{O}(T L D^2)$ for tree ensembles.
- **Efficiency Axiom:** The attributions sum to the model's output deviation from the training background expectation:
  $$f(\mathbf{x}) = \phi_0 + \sum_{i=1}^{M} \phi_i(\mathbf{x})$$
- **Positive SHAP Values ($\phi_i > 0$):** Features that push the prediction towards the threat class (Elevated Risk Factor, red bar, $+|\phi_i|$).
- **Negative SHAP Values ($\phi_i < 0$):** Features that pull the prediction away from the threat class (Mitigating/Benign Factor, green bar, $-|\phi_i|$).
- **Feature Ranking:** Features are ranked by absolute SHAP impact: $\text{Rank}(i) \propto |\phi_i|$.
- **Relative Bar Width Derivation:**
  $$\text{Bar Width } (\%) = \min\left(100.0, \max\left(10.0, \frac{|\phi_i|}{\max_{j} |\phi_j|} \times 100.0\right)\right)$$

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

The dashboard's current navigation includes URL Threat Scanner, Static PE Malware Scanner, Analysis History, and AI Models & XAI Metrics. There is no manual message-scanning tab. Message analyses may still appear in existing history records and can be inspected from History.

---

## 4. API Endpoints

- `POST /api/v1/analyze/url` — Analyzes URL features and returns model likelihood, combined risk, threat-intelligence result, domain reputation, and registration/DNS/TLS evidence when available.
- `POST /api/v1/analyze/file` — Statically inspects a PE binary (.exe, .dll, .sys) for malicious anomalies.
- `POST /api/v1/analyze/download` — Evaluates download metadata such as filename, extension, source URL, and direct download URL. It does not accept raw file bytes.
- `POST /api/v1/analyze/message` — Backend/API capability for message/email text analysis. The dashboard's manual Message Threat Scanner has been removed.
- `GET /api/v1/health` — System status, schema versions, and model loading indicators.
- `GET /api/v1/history` — Audit trail of past threat predictions and risk assessments.
- `GET /api/v1/history/{record_id}` — Retrieves a saved analysis result.
- `DELETE /api/v1/history` — Clears saved analysis history.

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

Run the automated test suite:
```bash
python -m pytest tests/ -v
```

### Test Coverage:
- `tests/test_features/`: URL, PE, and Message feature contract definitions, NaN/Inf rejection, and extraction tests.
- `tests/test_models/`: Model serialization integrity and recall bounds.
- `tests/test_risk_engine/`: Boundary threshold clamping, context heuristics, and learned fusion logic.
- `tests/test_explainable_ai/`: SHAP tree explainer attributions and token/span highlights.
- `tests/test_api/`: URL, file upload, message API, health, and history endpoints.
- `tests/test_adversarial/`: Homograph, subdomain injection, path padding, and message synonym perturbation tests.
- `tests/test_integration.py`: End-to-end multi-modal demonstration scenarios.

---

## 7. Empirical Evaluation Results

All performance values reflect evaluation on unseen stratified test sets (zero fabricated numbers):

| Component | Architecture | Dataset | Test Size | Accuracy | Threat Recall | Precision | F1-Score | ROC-AUC | False Negatives |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phishing Model** | Random Forest | PhiUSIIL Phishing URL Dataset (UCI) | 8,512 | **93.02%** | **94.30%** | **91.71%** | **0.9298** | **0.9811** | **238 / 8,512** |
| **Malware Model** | Random Forest PE Detector | ClaMP Static PE Headers | 684 | **99.27%** | **99.68%** | **98.73%** | **0.9920** | **0.9998** | **1 / 684** |
| **Message Analysis Pipeline** | Stylometric + DistilBERT (backend/API capability) | Opara GPT-4o + Nazario + Enron | TBD | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** |
| **Learned Risk Fusion** | Logistic Meta-Classifier (where configured) | Multi-modal Held-out Splits | TBD | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** | **TBD** |

---

## 8. Project Directory Structure

```
CyberSheild-AI/
├── backend/
│   ├── api/             # FastAPI routes (health, URL, file, message, download, history)
│   ├── schemas/         # Pydantic request and response contracts
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
