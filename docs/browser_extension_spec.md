# Browser Extension Specification & Capabilities (Chrome Manifest V3)

## 1. Overview & Architectural Role
The CyberShield AI Browser Extension provides client-side protection for digital banking users before and while interacting with web pages. Rather than maintaining an incomplete heuristic engine on the client, the extension connects directly to the centralized CyberShield AI FastAPI backend (`POST /api/v1/analyze/url`).

This ensures 100% predictive consistency between the Web Dashboard and the Browser Extension.

```
USER ATTEMPTS NAVIGATION / OPENS TAB
                ↓
    CHROME EXTENSION (MV3)
    ├── onBeforeNavigate (pre-navigation hook)
    ├── onUpdated (tab loading fallback)
    └── Manual Popup Scanner (on-demand)
                ↓
    API REQUEST (POST /api/v1/analyze/url)
                ↓
    CENTRALIZED BACKEND PIPELINE:
    Feature Extractor (Static) → Phishing Model → Risk Engine → SHAP → Decision Policy
                ↓
    STRUCTURED API RESPONSE
                ↓
    EXTENSION BANNER / POPUP WARNING
    ├── Risk Score (0-100) & Severity Badge
    ├── Plain-English Explanations
    ├── "Leave Site Safely" (redirect to about:blank)
    └── "Proceed Anyway" (explicit user override)
```

## 2. Trigger Points & Analysis Timing
The extension operates across three distinct triggers:
1. **Pre-Navigation Detection (`chrome.webNavigation.onBeforeNavigate`)**: Intercepts the destination URL as soon as top-level frame navigation is initiated by the browser.
2. **Tab-Load Interception (`chrome.tabs.onUpdated`)**: Acts as a resilient fallback during the page `loading` lifecycle.
3. **Manual On-Demand Scan (`popup.html`)**: Allows the user to inspect any current page or pasted URL at any time via the extension icon.

## 3. Intervention Mechanism
When a target URL is analyzed:
- **Low / Medium Risk:** Browsing continues unimpeded. The popup badge reflects safe status.
- **High / Critical Risk:** `background.js` dispatches an immediate notification to `content.js`, which injects a prominent, styled security intervention banner (`#cybershield-warning-banner`) at the top of the webpage before login forms can be interacted with.
- The banner provides:
  - Severity level and Unified Risk Score (0–100)
  - Plain-English threat reasons derived from SHAP
  - Banking recommendations (e.g., *"Do NOT enter passwords, OTPs, or PINs"*)
  - **"Leave Site Safely"** button (immediately redirects active tab to `about:blank`)
  - **"Dismiss Warning (Unsafe)"** button (allows user override with explicit acknowledgment)

## 4. Realistic Capabilities vs. Platform Limitations
In accordance with academic defensibility and project non-negotiable rules:
- **Manifest V3 Interception Model:** Under Chrome Manifest V3, `chrome.declarativeNetRequest` is restricted to pre-compiled static rule lists and cannot evaluate dynamic, remote AI/SHAP endpoints synchronously before socket connection. Therefore, CyberShield AI implements real-time asynchronous API queries coupled with immediate DOM intervention (`run_at: document_start`). It does not claim low-level synchronous network socket drops.
- **Browser Scope:** Specifically developed and verified for Chromium-based browsers (Google Chrome, Microsoft Edge, Brave) supporting Manifest V3.
