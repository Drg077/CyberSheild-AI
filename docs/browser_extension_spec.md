# Browser Extension Specification & Capabilities (Manifest V3)

## 1. Overview & Architectural Role
The CyberShield AI Browser Extension provides proactive client-side protection for digital banking users before or while navigating to web pages. Rather than maintaining an independent or simplified detection model on the client, the extension acts as a lightweight security agent that transmits candidate URLs to the centralized CyberShield AI FastAPI backend (`POST /api/v1/analyze/url`).

This ensures 100% predictive consistency between the Web Dashboard and the Browser Extension.

```
USER NAVIGATES TO URL
         ↓
BROWSER EXTENSION (Chrome MV3)
         ↓
API REQUEST (POST /api/v1/analyze/url)
         ↓
CENTRALIZED PIPELINE:
Feature Extractor (Static) → Phishing Model → Risk Engine → SHAP → Decision Policy
         ↓
STRUCTURED API RESPONSE
         ↓
EXTENSION BANNER / POPUP WARNING
         ↓
USER DECISION (Leave Site / Dismiss)
```

## 2. Tested & Verified Capabilities
- **URL Detection**: Reads the active tab URL via `chrome.tabs.onUpdated` and `chrome.tabs.query`.
- **On-Demand Popup Scanner**: Allows manual scanning of current or arbitrary links directly from the extension action icon.
- **Backend API Integration**: Connects to `http://localhost:8000/api/v1/analyze/url` and receives the unified risk score, severity, plain-English reasons, and banking recommendations.
- **On-Page Warning Intervention**: For `High` and `Critical` severity threats, `background.js` notifies `content.js`, which injects a high-visibility, dismissible overlay security banner (`#cybershield-warning-banner`) at the top of the webpage.
- **Safe Exit Navigation**: The "Leave Site Safely" button immediately redirects the browser to `about:blank`, preventing credential entry.

## 3. Realistic Capabilities vs. Platform Limitations
In accordance with academic integrity and project guidelines, the following distinctions are explicitly documented:
- **Pre-Navigation Intervention**: In Chrome Manifest V3, arbitrary asynchronous API queries during pre-navigation (`declarativeNetRequest`) are restricted to static rule definitions. Therefore, CyberShield AI implements real-time DOM interception via content script injection on page load (`run_at: document_start`), displaying a prominent intervention banner before the user interacts with login forms.
- **Cross-Browser Support**: Tested specifically for Chromium-based browsers (Google Chrome, Microsoft Edge, Brave) running Manifest V3. Firefox/Safari support represents a future enhancement.
- **Offline Mode**: If the local CyberShield AI backend server is offline, the extension fails safely and alerts the user rather than claiming false safety.
