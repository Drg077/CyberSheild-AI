/**
 * CyberShield AI - Content Script
 * Displays secure, sanitized on-page security warning banners for URL threats and dangerous downloads.
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "CYBERSHIELD_THREAT_DETECTED") {
    showThreatBanner(message.threat);
    sendResponse({ status: "banner_displayed" });
  } else if (message.action === "CYBERSHIELD_DOWNLOAD_WARNING") {
    showDownloadWarningBanner(message.threat, message.downloadInfo);
    sendResponse({ status: "download_banner_displayed" });
  }
});

function escapeHtml(str) {
  if (!str) return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function showThreatBanner(threat) {
  if (!threat) return;
  if (document.getElementById("cybershield-warning-banner")) return;

  const severityClass = (threat.severity || "high").toLowerCase();
  const decisionClass = (threat.decision || "").toLowerCase();

  const banner = document.createElement("div");
  banner.id = "cybershield-warning-banner";
  banner.className = `cybershield-banner sev-${severityClass} sev-${decisionClass}`;

  const content = document.createElement("div");
  content.className = "cybershield-content";

  const header = document.createElement("div");
  header.className = "cybershield-header";

  const icon = document.createElement("span");
  icon.className = "cybershield-icon";
  icon.textContent = "⚠️";

  const textWrap = document.createElement("div");
  
  const title = document.createElement("strong");
  title.className = "cybershield-title";
  title.textContent = `CYBERSHIELD AI WARNING: ${(threat.severity || "HIGH").toUpperCase()} RISK DETECTED (${threat.risk_score || 0}/100)`;

  const rec = document.createElement("p");
  rec.className = "cybershield-rec";
  rec.textContent = threat.recommendation || "Do not proceed on this destination.";

  textWrap.appendChild(title);
  textWrap.appendChild(rec);
  header.appendChild(icon);
  header.appendChild(textWrap);

  const buttons = document.createElement("div");
  buttons.className = "cybershield-buttons";

  const leaveBtn = document.createElement("button");
  leaveBtn.id = "cybershield-leave-btn";
  leaveBtn.className = "cybershield-btn-leave";
  leaveBtn.textContent = "Leave Site Safely";
  leaveBtn.addEventListener("click", () => {
    window.location.href = "about:blank";
  });

  const scannerBtn = document.createElement("button");
  scannerBtn.id = "cybershield-scanner-btn";
  scannerBtn.className = "cybershield-btn-scanner";
  scannerBtn.textContent = "Open Scanner";
  scannerBtn.addEventListener("click", () => {
    window.open("http://localhost:8000", "_blank");
  });

  const dismissBtn = document.createElement("button");
  dismissBtn.id = "cybershield-dismiss-btn";
  dismissBtn.className = "cybershield-btn-dismiss";
  dismissBtn.textContent = "Dismiss";
  dismissBtn.addEventListener("click", () => {
    banner.remove();
  });

  buttons.appendChild(leaveBtn);
  buttons.appendChild(scannerBtn);
  buttons.appendChild(dismissBtn);

  content.appendChild(header);
  content.appendChild(buttons);
  banner.appendChild(content);

  document.body.prepend(banner);
}

function showDownloadWarningBanner(threat, downloadInfo) {
  if (document.getElementById("cybershield-download-warning-banner")) return;

  const severity = (threat && threat.severity) ? threat.severity.toLowerCase() : "medium";
  const decision = (threat && threat.decision) ? threat.decision.toLowerCase() : "caution";
  const filename = (downloadInfo && downloadInfo.filename) ? downloadInfo.filename : "Downloaded File";
  const recText = (threat && threat.recommendation) ? threat.recommendation : "Exercise caution with this downloaded file.";

  const banner = document.createElement("div");
  banner.id = "cybershield-download-warning-banner";
  banner.className = `cybershield-banner sev-${severity} sev-${decision}`;

  const content = document.createElement("div");
  content.className = "cybershield-content";

  const header = document.createElement("div");
  header.className = "cybershield-header";

  const icon = document.createElement("span");
  icon.className = "cybershield-icon";
  icon.textContent = "🛡️";

  const textWrap = document.createElement("div");
  
  const title = document.createElement("strong");
  title.className = "cybershield-title";
  title.textContent = `CYBERSHIELD AI: ${severity.toUpperCase()} RISK DOWNLOAD DETECTED (${filename})`;

  const rec = document.createElement("p");
  rec.className = "cybershield-rec";
  rec.textContent = recText;

  textWrap.appendChild(title);
  textWrap.appendChild(rec);
  header.appendChild(icon);
  header.appendChild(textWrap);

  const buttons = document.createElement("div");
  buttons.className = "cybershield-buttons";

  const scannerBtn = document.createElement("button");
  scannerBtn.className = "cybershield-btn-scanner";
  scannerBtn.textContent = "Open Scanner";
  scannerBtn.addEventListener("click", () => {
    window.open("http://localhost:8000", "_blank");
  });

  const dismissBtn = document.createElement("button");
  dismissBtn.className = "cybershield-btn-dismiss";
  dismissBtn.textContent = "Dismiss";
  dismissBtn.addEventListener("click", () => {
    banner.remove();
  });

  buttons.appendChild(scannerBtn);
  buttons.appendChild(dismissBtn);

  content.appendChild(header);
  content.appendChild(buttons);
  banner.appendChild(content);

  document.body.prepend(banner);

  if (severity === "low" || decision === "allow") {
    setTimeout(() => {
      if (banner && banner.parentNode) {
        banner.remove();
      }
    }, 6000);
  }
}
