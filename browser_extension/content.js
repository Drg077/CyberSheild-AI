/**
 * CyberShield AI - Content Script
 * Displays an on-page security warning banner for high-risk URLs.
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "CYBERSHIELD_THREAT_DETECTED") {
    showThreatBanner(message.threat);
    sendResponse({ status: "banner_displayed" });
  }
});

function showThreatBanner(threat) {
  // Check if banner already exists
  if (document.getElementById("cybershield-warning-banner")) return;

  const banner = document.createElement("div");
  banner.id = "cybershield-warning-banner";
  banner.className = `cybershield-banner sev-${threat.severity.toLowerCase()}`;

  banner.innerHTML = `
    <div class="cybershield-content">
      <div class="cybershield-header">
        <span class="cybershield-icon">⚠️</span>
        <div>
          <strong class="cybershield-title">CYBERSHIELD AI WARNING: ${threat.severity.toUpperCase()} RISK DETECTED (${threat.risk_score}/100)</strong>
          <p class="cybershield-rec">${threat.recommendation}</p>
        </div>
      </div>
      <div class="cybershield-buttons">
        <button id="cybershield-leave-btn" class="cybershield-btn-leave">Leave Site Safely</button>
        <button id="cybershield-dismiss-btn" class="cybershield-btn-dismiss">Dismiss Warning (Unsafe)</button>
      </div>
    </div>
  `;

  document.body.prepend(banner);

  document.getElementById("cybershield-leave-btn").addEventListener("click", () => {
    window.location.href = "about:blank";
  });

  document.getElementById("cybershield-dismiss-btn").addEventListener("click", () => {
    banner.remove();
  });
}
