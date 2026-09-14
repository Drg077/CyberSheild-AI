/**
 * CyberShield AI - Background Service Worker (Manifest V3)
 * Monitors tab navigation and queries the centralized threat prediction backend.
 */

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only check once page begins loading with a valid HTTP/HTTPS URL
  if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
    // Ignore localhost/internal
    if (tab.url.includes("localhost:8000") || tab.url.includes("127.0.0.1:8000")) {
      return;
    }

    checkUrlThreat(tabId, tab.url);
  }
});

async function checkUrlThreat(tabId, url) {
  try {
    const response = await fetch("http://localhost:8000/api/v1/analyze/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) return;

    const data = await response.json();

    // If High or Critical risk, send message to content script to display warning
    if (data.severity === "High" || data.severity === "Critical") {
      chrome.tabs.sendMessage(tabId, {
        action: "CYBERSHIELD_THREAT_DETECTED",
        threat: data
      }, (resp) => {
        // Suppress errors if content script not yet ready
        if (chrome.runtime.lastError) {}
      });
    }
  } catch (err) {
    // Backend offline or unreachable
    console.debug("CyberShield backend offline:", err);
  }
}
