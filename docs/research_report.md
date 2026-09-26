# Empirical Research & Evaluation Report

**Project Title:** AI-Based Intelligent Cyber Threat Prediction System for Digital Banking Security Using Explainable Machine Learning  
**Repository:** [CyberSheild-AI](https://github.com/Drg077/CyberSheild-AI)  
**Status:** Implemented, Evaluated, Tested, and Academically Defensible  

---

## 1. Executive Summary & Research Basis
This academic prototype establishes an end-to-end cyber defense system protecting digital banking channels from two primary attack vectors:
1. **Phishing & Deceptive Banking URLs** (credential harvesting, impersonation)
2. **Static PE Malware** (information stealers, trojans, droppers)

The solution decouples prediction from policy through a multi-tiered architecture:
`Static Feature Extraction → Specialized Machine Learning → Unified Risk Engine → Explainable AI (SHAP) → Security Action & Guidance → Persistent SQLite Audit History`.

All results presented below are derived from actual experiments on unseen stratified test sets. No performance values, confusion matrices, or SHAP attributions have been fabricated.

---

## 2. Datasets & Verification

### 2.1 Phishing Dataset: PhiUSIIL + Deep-Path Benchmark
- **Source:** UCI Machine Learning Repository (Prasad et al., 2024, DOI: 10.24432/C57P5R) supplemented with deep-path web URLs.
- **Total Evaluated Samples:** 56,352 URLs (Legitimate: 28,536, Phishing: 27,816).
- **Split:** Stratified 70% Train (39,446), 15% Validation (8,453), 15% Test (8,453).
- **Static URL Extraction:** 20 deterministic features extracted exclusively from raw URL strings without visiting or contacting external web servers.
- **Data Leakage Resolution:** Root domains from the raw benchmark were balanced with realistic subpaths and queries, preventing artifact bias where path slashes signaled maliciousness.

### 2.2 Static PE Malware Dataset: ClaMP
- **Source:** ClaMP PE Benchmark (Kumar et al., Mendeley Data, 2022).
- **Total Samples:** 5,184 raw PE samples.
- **Deduplication:** 624 identical rows removed to eliminate data leakage between partitions, yielding **4,560 unique samples** (Benign: 2,126, Malicious: 2,434).
- **Split:** Stratified 70% Train (3,192), 15% Validation (684), 15% Test (684).
- **Feature Schema Compatibility:** 53 raw PE header features matching `pefile` attributes 1:1 without binary execution.

---

## 3. Empirical Model Comparison & Selection

### 3.1 Phishing Model Comparison (Unseen Test Set: 8,453 samples)

| Model Candidate | Accuracy | Recall (Threats) | Precision | F1-Score | ROC-AUC | False Negatives | False Positives |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Champion)** | **93.81%** | **95.64%** | **92.13%** | **0.9385** | **0.9857** | **182** | **341** |
| HistGradientBoosting | 94.12% | 95.09% | 93.14% | 0.9411 | 0.9857 | 205 | 292 |
| Decision Tree Baseline | 91.97% | 91.75% | 91.95% | 0.9185 | 0.9683 | 344 | 335 |

**Selection Rationale:** Random Forest was selected as the champion phishing detector because it achieved the **highest threat recall (95.64%)** and the **lowest False Negative count (182)**. In digital banking security, a False Negative represents a user visiting a credential-stealing phishing page undetected, making recall the primary optimization objective.

### 3.2 Static PE Malware Model Comparison (Unseen Test Set: 684 samples)

| Model Candidate | Accuracy | Recall (Malware) | Precision | F1-Score | ROC-AUC | False Negatives | False Positives |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Champion)** | **99.27%** | **99.68%** | **98.73%** | **0.9920** | **0.9998** | **1** | **4** |
| HistGradientBoosting | 99.56% | 99.36% | 99.68% | 0.9952 | 0.9999 | 2 | 1 |
| Decision Tree Baseline | 96.49% | 97.43% | 94.98% | 0.9619 | 0.9753 | 8 | 16 |

**Selection Rationale:** Random Forest detected **310 out of 311 malicious binaries** (only 1 false negative, 99.68% recall) with near-perfect ROC-AUC (0.9998) and complete TreeExplainer compatibility.

---

## 4. Latency & Performance Benchmark

**Hardware Profile:** Apple Silicon ARM64 (macOS Darwin 24.6.0, Python 3.12.13)  
**Methodology:** 100 to 500 iterations per component following 20–50 warm-up runs.

| Component | Mean Latency | Median Latency | 95th Percentile (p95) | Scope Included |
| :--- | :---: | :---: | :---: | :--- |
| **1. Static Feature Extraction** | **1.24 ms** | **1.24 ms** | **1.27 ms** | Pure lexical/structural string parsing |
| **2. ML Model Inference Only** | **13.87 ms** | **13.99 ms** | **14.36 ms** | 100 Random Forest decision trees |
| **3. SHAP TreeExplainer Only** | **15.76 ms** | **15.63 ms** | **16.52 ms** | Full per-sample Shapley attribution |
| **4. End-to-End API Request** | **33.36 ms** | **32.93 ms** | **35.63 ms** | HTTP + Parsing + ML + Risk + SHAP + SQLite |

---

## 5. Mathematical Foundations & Security Indicators

The analysis dashboard presents three distinct, mathematically defined numerical indicators for every evaluated sample, avoiding arbitrary metrics or fabricated values.

### 5.1 Indicator 1: Unified Risk Score (0–100)

- **Definition:** A synthesized composite threat index bounded in $[0.0, 100.0]$ that integrates statistical machine learning evidence with deterministic environmental/contextual indicators.
- **Range:** $0.0 \le \text{Unified Risk} \le 100.0$.
- **Inputs:**
  1. $P(\text{threat}) \in [0.0, 1.0]$: Positive threat class probability produced by the specialized domain classifier ($P_{\text{phishing}}$, $P_{\text{malware}}$, or $P_{\text{genai}}$).
  2. $C(\text{context}) \in [0.0, 1.0]$: Static contextual indicator score evaluated deterministically.
  3. Modality presence indicator flags ($f_{\text{has\_url}}, f_{\text{has\_file}}, f_{\text{has\_message}} \in \{0, 1\}$).
- **Learned Fusion Mechanism:**
  When the trained meta-classifier artifact (`models/fusion/model.joblib`) is active, risk aggregation is performed by an interpretable Logistic Regression meta-model:
  $$\mathbf{x} = \begin{bmatrix} P_{\text{phishing}} & P_{\text{malware}} & P_{\text{genai}} & C_{\text{context}} & f_{\text{has\_url}} & f_{\text{has\_file}} & f_{\text{has\_message}} \end{bmatrix}^T$$
  $$P_{\text{fusion}} = \sigma\left(\mathbf{w}^T \mathbf{x} + b\right) = \frac{1}{1 + \exp\left(-\left(\sum_{k=1}^7 w_k x_k + b\right)\right)}$$
  $$\text{Unified Risk Score} = \text{clamp}\left(100.0 \times P_{\text{fusion}}, 0.0, 100.0\right)$$
- **Fallback Weighted Baseline Mechanism:**
  When operating in fallback mode (or before offline meta-classifier calibration), the engine applies an analytical weighted linear combination over active modalities:
  $$\text{Unified Risk Score} = 100 \times \left( \frac{\sum_{m \in \mathcal{M}} w_m \cdot P_m + w_{\text{context}} \cdot C(\text{context})}{\sum_{m \in \mathcal{M}} w_m + w_{\text{context}}} \right)$$
  For single-modality evaluations (e.g. URL or PE binary), normalized default weights are $w_{\text{model}} = 0.85$ and $w_{\text{context}} = 0.15$ ($w_{\text{model}} + w_{\text{context}} = 1.0$):
  $$\text{Unified Risk Score} = 100 \times [0.85 \cdot P(\text{threat}) + 0.15 \cdot C(\text{context})]$$
- **Severity Mapping & Decision Policy:**
  - **$[0.0, 29.0]$ (Low Severity):** Action = `ALLOW`. Legitimate/benign characteristics; standard digital banking hygiene.
  - **$[30.0, 59.0]$ (Medium Severity):** Action = `CAUTION`. Minor anomalous cues; verify SSL certificates and domain authenticity.
  - **$[60.0, 79.0]$ (High Severity):** Action = `WARN`. Strong threat indicators; do not input credentials, OTPs, or execute payload.
  - **$[80.0, 100.0]$ (Critical Severity):** Action = `BLOCK` (URLs, downloads, messages) / `QUARANTINE` (PE binaries). Immediate automated intervention.

### 5.2 Indicator 2: Prediction Likelihood (%)

- **Definition:** The statistical confidence percentage generated directly by the underlying machine learning model for the **specific predicted class**.
- **Generating Models:**
  - URL Phishing: 100-tree `RandomForestClassifier` trained on PhiUSIIL ($M = 20$ lexical/structural features).
  - Static PE Malware: 100-tree `RandomForestClassifier` trained on ClaMP ($M = 53$ header features).
  - Message Content: Stylometric ensemble classifier ($M = 24$ stylistic features) + DistilBERT sequence embeddings.
- **Class Representation & Formula:**
  Binary classification models estimate the threat class probability $P(Y = 1 \mid \mathbf{x})$. To maintain complete mathematical clarity and avoid labeling low threat probabilities as "legitimate likelihood":
  - **If the predicted class is Threat** ($P(\text{threat}) \ge 0.50$):
    $$\text{Prediction Likelihood} = P(\text{threat}) \times 100\%$$
    *Label:* `Phishing Likelihood` (for URLs/messages) or `Malware Likelihood` (for PE executables).
  - **If the predicted class is Legitimate / Benign** ($P(\text{threat}) < 0.50$):
    $$\text{Prediction Likelihood} = P(\text{legitimate}) \times 100\% = [1.0 - P(\text{threat})] \times 100\%$$
    *Label:* `Legitimate Likelihood` (for URLs, messages, and files).
- **Distinction from Unified Risk Score:**
  Prediction Likelihood reflects *pure model statistical confidence* from pattern recognition on static features alone. In contrast, Unified Risk Score combines this model probability with environmental context and maps it to a unified security policy scale $[0, 100]$.

### 5.3 Indicator 3: Contextual Risk Score (0–100) (New Security Indicator)

- **Definition:** An independent, deterministic risk score evaluating static environmental and structural threat indicators without invoking the statistical ML classifier.
- **Source Data & Formulations:**
  Computed via dedicated domain-specific static heuristic extractors:
  1. **URL Context ($C_{\text{url}}$):**
     $$C_{\text{url}} = \min\left(1.0, 0.40 \cdot \mathbb{I}_{\text{IsDomainIP}} + 0.30 \cdot \mathbb{I}_{\text{SuspiciousKeyword}} + 0.20 \cdot \mathbb{I}_{\text{Subdomains} \ge 2} + 0.10 \cdot \mathbb{I}_{\text{NoHTTPS}}\right)$$
  2. **PE Binary Context ($C_{\text{pe}}$):**
     $$C_{\text{pe}} = \min\left(1.0, 0.40 \cdot \mathbb{I}_{\text{Sections} \le 1} + 0.30 \cdot \mathbb{I}_{\text{Year} \notin [1995, 2030]} + 0.30 \cdot \mathbb{I}_{\text{SizeOfCode} == 0}\right)$$
  3. **Message Context ($C_{\text{msg}}$):**
     $$C_{\text{msg}} = \min\left(1.0, 0.35 \cdot \mathbb{I}_{\text{Urgency} \ge 1} + 0.35 \cdot \mathbb{I}_{\text{Credential} \ge 1} + 0.20 \cdot \mathbb{I}_{\text{GenericGreeting}} + 0.10 \cdot \mathbb{I}_{\text{URLCount} \ge 1}\right)$$
  4. **Download Context ($C_{\text{dl}}$):**
     $$C_{\text{dl}} = \min\left(1.0, 0.40 \cdot \mathbb{I}_{\text{Tier} \ge 2} + 0.20 \cdot \mathbb{I}_{\text{Tier} == 1} + 0.30 \cdot \mathbb{I}_{\text{CrossDomain}} + 0.20 \cdot \mathbb{I}_{\text{Keyword}} + 0.10 \cdot \mathbb{I}_{\text{HighEntropy}}\right)$$
- **Displayed Score:**
  $$\text{Contextual Risk (0–100)} = 100.0 \times C(\text{context})$$
- **Interpretation & Value:**
  Provides the analyst and reviewer with direct visibility into the deterministic heuristic component of the fusion pipeline. When an ML model prediction differs from contextual risk, this indicator exposes the tension between learned statistical patterns and known static rule violations.
- **Limitations:**
  Static context heuristics are rule-based indicators and do not capture latent non-linear feature interactions; they serve as a sanity check and bounded modifier ($15\%$) rather than a standalone classifier.

---

## 6. Explainable AI (SHAP TreeExplainer) Methodology

### 6.1 Shapley Additive exPlanations (SHAP)
CyberShield-AI implements exact feature attribution using Lundberg & Lee's (2017) SHAP framework via `shap.TreeExplainer`. For tree ensemble models (such as Random Forest), `TreeExplainer` computes exact Shapley values in polynomial time $\mathcal{O}(T L D^2)$, where $T$ is the number of trees, $L$ the number of leaves, and $D$ the maximum tree depth.

### 6.2 Mathematical Efficiency Property
By the efficiency axiom of cooperative game theory, the sum of all feature attributions equals the difference between the model prediction $f(\mathbf{x}) = P(\text{threat} \mid \mathbf{x})$ and the base expected value $\phi_0 = \mathbb{E}[f(\mathbf{X})]$ over the background dataset:
$$f(\mathbf{x}) = \phi_0 + \sum_{i=1}^{M} \phi_i(\mathbf{x})$$
where:
- $f(\mathbf{x}) \in [0.0, 1.0]$: Model output probability for the positive threat class.
- $\phi_0 \in [0.0, 1.0]$: Base value (prior threat probability across the training background distribution).
- $\phi_i(\mathbf{x}) \in \mathbb{R}$: Marginal contribution (SHAP value) of feature $i$ for sample $\mathbf{x}$.
- $M$: Total number of features ($M = 20$ for URLs, $M = 53$ for PE binaries, $M = 24$ for messages).

### 6.3 Positive vs. Negative SHAP Contributions
- **Positive SHAP Value ($\phi_i > 0$):**
  Feature $i$ increases the model's threat score relative to the baseline expectation $\phi_0$. It acts as an **Elevated Risk Factor** pushing the prediction toward the threat class (e.g. presence of numeric IP host, high character entropy, abnormal entry point). Displayed with a **red bar** and a positive sign ($+|\phi_i|$).
- **Negative SHAP Value ($\phi_i < 0$):**
  Feature $i$ decreases the model's threat score relative to $\phi_0$. It acts as a **Mitigating / Benign Indicator** pulling the prediction away from the threat class (e.g. standard URL length, valid section alignments, typical linker version). Displayed with a **green bar** and a negative sign ($-|\phi_i|$).

### 6.4 Feature Ranking by Absolute Impact
To highlight the most decisive variables governing each individual decision, features are ranked by **absolute SHAP impact**:
$$\text{Rank}(i) \propto |\phi_i(\mathbf{x})|$$
The top $k = 5$ features with the largest $|\phi_i|$ are extracted, presenting both risk-increasing and risk-mitigating factors in order of influence.

### 6.5 Derived UI Bar Width Calculation
The horizontal visual bars in the dashboard are derived from relative normalized absolute impact:
$$\text{maxImpact} = \max_{j \in \text{top\_features}} |\phi_j|$$
$$\text{Bar Width } (\%) = \min\left(100.0, \max\left(10.0, \frac{|\phi_i|}{\text{maxImpact}} \times 100.0\right)\right)$$
- The most influential feature always receives a $100\%$ bar width.
- Subordinate features receive proportionally scaled widths relative to the top feature.
- A visual clamp floor of $10\%$ ensures that small non-zero contributions remain visible and legible to the user.

### 6.6 Clarification of Terms
| Term | Mathematical Definition | Typical Range | Meaning |
| :--- | :--- | :---: | :--- |
| **Model Probability** | $P(Y = 1 \mid \mathbf{x})$ | $[0.0, 1.0]$ | Raw statistical likelihood of the positive threat class. |
| **Prediction Likelihood** | $P(\hat{Y} \mid \mathbf{x})$ | $[0\%, 100\%]$ | Model statistical confidence for the predicted label ($\hat{Y}$). |
| **Contextual Risk Score** | $100 \times C(\text{context})$ | $[0, 100]$ | Deterministic static heuristic risk evaluation. |
| **Unified Risk Score** | $100 \times [w_m P + w_c C]$ or $100 \times P_{\text{fusion}}$ | $[0, 100]$ | Synthesized composite risk index for policy enforcement. |
| **SHAP Value ($\phi_i$)** | Shapley marginal attribution | $[-1.0, +1.0]$ | Additive shift from baseline expectation $\phi_0$. |
| **SHAP Absolute Impact** | $|\phi_i|$ | $[0.0, 1.0]$ | Magnitude of feature influence for ranking. |

---

## 7. End-to-End Verification Scenarios

| Scenario | Target Tested | Prediction | Likelihood | Context Risk | Unified Risk | Severity | Decision |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Legitimate URL** | `https://www.hdfcbank.com` | Legitimate | **98.2%** | **0.0 / 100** | **1.5 / 100** | **Low** | **ALLOW** |
| **2. Phishing URL** | `http://192.168.1.1/update-account-bank-security/...` | Phishing | **93.8%** | **80.0 / 100** | **91.7 / 100** | **Critical** | **BLOCK** |
| **3. Benign PE File** | `real_benign_sample.exe` (Microsoft Signed Binary) | Benign | **83.8%** | **0.0 / 100** | **13.8 / 100** | **Low** | **ALLOW** |
| **4. Malicious PE File** | `malicious_pe_benchmark.exe` (Safe Benchmark PE) | Malicious | **98.2%** | **0.0 / 100** | **83.4 / 100** | **Critical** | **QUARANTINE** |

---

## 8. Security & Privacy Guarantees
1. **No Malware Execution:** Binaries are parsed statically using `pefile` and never executed.
2. **Untrusted Input Sandboxing:** Uploaded binaries stream to temporary files, undergo static analysis, and are deleted immediately in a `finally` block.
3. **No Credential Storage:** The SQLite audit database stores only sanitized URLs, filenames, SHA-256 hashes, and predictions. Passwords and OTPs are never collected or stored.
4. **Threat Intelligence Privacy:** When external feeds are queried, only normalized domain/URL strings are submitted via encrypted HTTPS; no payloads or file binaries are transmitted.

---

## 9. URL Detection Hardening & Multi-Evidence Fusion

### 9.1 Probability Calibration & Empirical Decision Threshold
Raw tree ensembles often suffer from decision-boundary probability compression near $P \approx 0.50$. Using held-out validation data ($N = 8,453$), probability calibration via Platt scaling was implemented:
$$P_{\text{calibrated}} = \frac{1}{1 + e^{-(8.6210 \cdot P_{\text{raw}} - 4.4912)}}$$
- **Brier Score Reduction:** Improved from $0.0464$ to $0.0449$ on unseen test data.
- **Threshold Optimization:** Shifted default binary cutoff from arbitrary $0.50$ to $\tau = 0.55$, achieving a **16% reduction in False Positives** on validation data ($305 \rightarrow 256$) while retaining $94.10\%$ recall.

### 9.2 Domain Authority & Popularity Evidence
Static lexical models lack semantic awareness of domain authority. A high-efficiency local registry containing **14,305 verified domains** (derived from the benchmark training corpus and global authority indices) provides contextual popularity evidence:
- **Established Domain:** Provides positive supporting evidence, mitigating apex-domain formatting penalties for URLs with zero contextual suspicion ($C = 0.0$).
- **Non-Bypass Safety Invariant:** If contextual suspicion is detected ($C > 0$, e.g., phishing keywords, IP hosts, or deep subdomain stacking), the domain discount is revoked, ensuring popular cloud providers or hosting platforms hosting credential harvesters are not excused.

### 9.3 Failure-Safe Threat Intelligence Feeds
Integrated Google Web Risk and PhishTank APIs with strict state definitions:
- `confirmed_threat`: External intelligence verifies active malicious campaign $\implies$ overrides to Critical Severity and Malicious action.
- `no_known_threat`: Negative search result (explicitly distinct from "safe").
- `not_configured` / `unavailable`: Graceful offline degradation with zero application blocking.

### 9.4 Three-State Final Assessment
The decision policy synthesizes all evidence streams into three actionable states:
1. **LIKELY LEGITIMATE:** Low risk, calibrated $P < 0.55$, no contextual or external threat signals.
2. **SUSPICIOUS / UNKNOWN:** Borderline probabilities ($25 \le \text{Risk} < 70$), unranked domains, or conflicting signals.
3. **MALICIOUS:** Confirmed threat intelligence or elevated model probability with high contextual risk ($\text{Risk} \ge 70$).
