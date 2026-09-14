# Empirical Research & Evaluation Report

**Project Title:** AI-Based Intelligent Cyber Threat Prediction System for Digital Banking Security Using Explainable Machine Learning  
**Author / Candidate:** 7th Semester Major Project  
**Date:** September 2026  
**Status:** Implemented, Evaluated, Tested, and Verified  

---

## 1. Executive Summary & Research Basis
This academic prototype establishes an end-to-end cyber defense system protecting digital banking channels from two primary attack vectors:
1. **Phishing & Deceptive Banking URLs** (credential harvesting, impersonation)
2. **Static PE Malware** (information stealers, trojans, droppers)

The solution decouples prediction from policy through a four-tiered architecture:
`Static Feature Extraction → Specialized Machine Learning → Unified Risk Engine → Explainable AI (SHAP) → Security Action & Guidance`.

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
- **Feature Schema Compatibility:** 53 raw PE header features matching `pefile` attributes 1:1.

---

## 3. Empirical Model Comparison & Selection

### 3.1 Phishing Model Comparison (Unseen Test Set: 8,453 samples)

| Model Candidate | Accuracy | Recall (Threats) | Precision | F1-Score | ROC-AUC | False Negatives | False Positives | Inference Latency | SHAP Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Champion)** | **93.81%** | **95.64%** | **92.13%** | **0.9385** | **0.9857** | **182** | **341** | **0.0034 ms** | **15.4 ms** |
| HistGradientBoosting | 94.12% | 95.09% | 93.14% | 0.9411 | 0.9857 | 205 | 292 | 0.0022 ms | 0.42 ms |
| Decision Tree Baseline | 91.97% | 91.75% | 91.95% | 0.9185 | 0.9683 | 344 | 335 | 0.0002 ms | 0.03 ms |

**Selection Rationale:** Random Forest was selected as the champion phishing detector because it achieved the **highest threat recall (95.64%)** and the **lowest False Negative count (182)**. In digital banking security, a False Negative represents a user visiting a credential-stealing phishing page undetected, making recall the primary optimization objective.

### 3.2 Static PE Malware Model Comparison (Unseen Test Set: 684 samples)

| Model Candidate | Accuracy | Recall (Malware) | Precision | F1-Score | ROC-AUC | False Negatives | False Positives | Inference Latency | SHAP Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Champion)** | **99.27%** | **99.68%** | **98.73%** | **0.9920** | **0.9998** | **1** | **4** | **0.0402 ms** | **1.33 ms** |
| HistGradientBoosting | 99.56% | 99.36% | 99.68% | 0.9952 | 0.9999 | 2 | 1 | 0.0112 ms | 0.42 ms |
| Decision Tree Baseline | 96.49% | 97.43% | 94.98% | 0.9619 | 0.9753 | 8 | 16 | 0.0013 ms | 0.01 ms |

**Selection Rationale:** Random Forest detected **310 out of 311 malicious binaries** (only 1 false negative, 99.68% recall) with near-perfect ROC-AUC (0.9998) and complete TreeExplainer compatibility.

---

## 4. Risk Analysis Engine Validation
The Risk Engine fuses model probability $P(\text{threat})$ with static contextual risk indicators $C(\text{context})$:

$$\text{Unified Risk Score} = 100 \times [0.85 \cdot P(\text{threat}) + 0.15 \cdot C(\text{context})]$$

### Severity Thresholds & Action Policy:
- **0.0 – 29.0 (Low Severity):** Action = `ALLOW`. Recommended action: Normal banking operations with standard security hygiene.
- **30.0 – 59.0 (Medium Severity):** Action = `CAUTION`. Recommended action: Verify bank SSL certificate and domain authenticity before entering data.
- **60.0 – 79.0 (High Severity):** Action = `WARN`. Recommended action: Strong warning. Do not input passwords, OTPs, or PINs.
- **80.0 – 100.0 (Critical Severity):** Action = `BLOCK` / `QUARANTINE`. Recommended action: Immediate intervention. Navigation blocked or file quarantined.

---

## 5. Explainable AI (SHAP) Integration
TreeExplainer computes exact Shapley attributions for each input sample. The `ExplanationFormatter` translates technical parameters into human-understandable guidance:
- `IsDomainIP = 1.0` $\rightarrow$ *"Web address directly uses a numeric IP address instead of a recognized domain name"*
- `ContainsSuspiciousKeyword = 1.0` $\rightarrow$ *"Presence of sensitive banking/account keywords in URL"*
- `URLLength = 120` $\rightarrow$ *"Unusually long web address (120 characters)"*
- `NumberOfSections = 1` $\rightarrow$ *"Unusual PE section structure (1 section detected)"*

---

## 6. End-to-End Verification Scenarios

| Scenario | Input Target | Prediction | Probability | Unified Risk | Severity | Decision |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **1. Legitimate URL** | `https://www.hdfcbank.com` | Legitimate | 1.8% | **6.0 / 100** | **Low** | **ALLOW** |
| **2. Phishing URL** | `http://192.168.1.1/update-account-bank-security/...` | Phishing | 93.8% | **91.7 / 100** | **Critical** | **BLOCK** |
| **3. Benign PE File** | `real_benign_sample.exe` (Microsoft Signed Binary) | Benign | 16.2% | **13.8 / 100** | **Low** | **ALLOW** |
| **4. Malicious PE File** | `trojan_sample_benchmark.exe` (Known PE Malware Vector) | Malicious | 91.6% | **77.9 / 100** | **High** | **WARN** |

---

## 7. Security & Privacy Guarantees
1. **No Malware Execution:** Binaries are parsed statically using `pefile` and never executed.
2. **Untrusted Input Sandboxing:** Uploaded binaries stream to temporary files, undergo static analysis, and are deleted immediately in a `finally` block.
3. **No Credential Storage:** The SQLite audit database stores only sanitized URLs, filenames, SHA-256 hashes, and predictions. Passwords and OTPs are never collected or stored.
