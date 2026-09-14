document.addEventListener("DOMContentLoaded", async () => {
  const activeUrlDiv = document.getElementById("activeUrl");
  const scanBtn = document.getElementById("scanBtn");
  const resultBox = document.getElementById("resultBox");
  const riskScore = document.getElementById("riskScore");
  const severityPill = document.getElementById("severityPill");
  const threatTitle = document.getElementById("threatTitle");
  const reasonsList = document.getElementById("reasonsList");
  const recommendation = document.getElementById("recommendation");
  const actionButtonGroup = document.getElementById("actionButtonGroup");
  const leavePageBtn = document.getElementById("leavePageBtn");
  const dismissBtn = document.getElementById("dismissBtn");

  let currentTabUrl = "";
  let activeTabId = null;

  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        currentTabUrl = tabs[0].url;
        activeTabId = tabs[0].id;
        activeUrlDiv.textContent = currentTabUrl;
      } else {
        activeUrlDiv.textContent = "Unable to read active tab URL.";
      }
    });
  } else {
    currentTabUrl = "https://www.hdfcbank.com";
    activeUrlDiv.textContent = currentTabUrl;
  }

  scanBtn.addEventListener("click", async () => {
    if (!currentTabUrl || currentTabUrl.startsWith("chrome://")) {
      alert("Cannot scan internal browser pages.");
      return;
    }

    scanBtn.textContent = "Analyzing...";
    scanBtn.disabled = true;

    try {
      const res = await fetch("http://localhost:8000/api/v1/analyze/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentTabUrl })
      });

      if (!res.ok) throw new Error("Backend offline or error");

      const data = await res.json();
      resultBox.style.display = "block";
      riskScore.textContent = data.risk_score;

      const sev = data.severity.toLowerCase();
      severityPill.textContent = data.severity;
      severityPill.className = `pill ${sev}`;

      threatTitle.textContent = data.title;
      reasonsList.innerHTML = data.reasons.slice(0, 3).map(r => `<li>${r}</li>`).join("");
      recommendation.innerHTML = `<strong>Action:</strong> ${data.recommendation}`;

      if (data.severity === "High" || data.severity === "Critical") {
        actionButtonGroup.style.display = "flex";
      } else {
        actionButtonGroup.style.display = "none";
      }
    } catch (err) {
      alert("Failed to connect to CyberShield AI API at http://localhost:8000. Ensure the backend is running.");
    } finally {
      scanBtn.textContent = "Scan URL with AI";
      scanBtn.disabled = false;
    }
  });

  leavePageBtn.addEventListener("click", () => {
    if (typeof chrome !== "undefined" && chrome.tabs && activeTabId) {
      chrome.tabs.update(activeTabId, { url: "about:blank" });
    } else {
      window.location.href = "about:blank";
    }
  });

  dismissBtn.addEventListener("click", () => {
    resultBox.style.display = "none";
  });
});
