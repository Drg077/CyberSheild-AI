/**
 * CyberShield AI - Background Service Worker (Manifest V3)
 * Monitors tab navigation events and queries the centralized threat prediction backend.
 */

// 1. Listen for pre-navigation events where available
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only intercept top-level frame navigations
    if (details.frameId === 0 && details.url && details.url.startsWith("http")) {
      if (!details.url.includes("localhost:8000") && !details.url.includes("127.0.0.1:8000")) {
        checkUrlThreat(details.tabId, details.url);
      }
    }
  });
}

// 2. Also listen for tab updates during loading state as fallback
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
    if (!tab.url.includes("localhost:8000") && !tab.url.includes("127.0.0.1:8000")) {
      checkUrlThreat(tabId, tab.url);
    }
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

    // Cache latest result in storage for popup
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ [url]: data });
    }

    // If High or Critical risk, send message to content script to display warning banner
    if (data.severity === "High" || data.severity === "Critical") {
      chrome.tabs.sendMessage(tabId, {
        action: "CYBERSHIELD_THREAT_DETECTED",
        threat: data
      }, (resp) => {
        if (chrome.runtime.lastError) {
          // Suppress error if content script is still initializing
        }
      });
    }
  } catch (err) {
    console.debug("CyberShield backend offline:", err);
  }
}
