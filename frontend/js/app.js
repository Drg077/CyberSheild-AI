/**
 * CyberShield AI - Frontend Application Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initUrlScanner();
  initFileScanner();
  initHistory();
  checkSystemHealth();
});

// 1. Tab Switching
function initTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  const contents = document.querySelectorAll(".tab-content");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      contents.forEach(c => c.classList.remove("active"));

      tab.classList.add("active");
      const target = document.getElementById(tab.dataset.tab);
      if (target) target.classList.add("active");

      if (tab.dataset.tab === "history-tab") {
        loadHistory();
      }
    });
  });
}

// 2. Health Status
async function checkSystemHealth() {
  try {
    const res = await fetch("/api/v1/health");
    if (res.ok) {
      const data = await res.json();
      document.getElementById("systemStatusText").textContent = "AI Online (v1.0.0)";
    }
  } catch (err) {
    document.getElementById("systemStatusText").textContent = "API Offline";
    document.getElementById("systemStatusBadge").style.color = "#ef4444";
  }
}

// 3. URL Scanner
function initUrlScanner() {
  const form = document.getElementById("urlForm");
  const input = document.getElementById("urlInput");
  const btn = document.getElementById("urlSubmitBtn");
  const resultContainer = document.getElementById("urlResultContainer");

  // Sample Buttons
  document.querySelectorAll(".sample-btn").forEach(btnSample => {
    btnSample.addEventListener("click", () => {
      input.value = btnSample.dataset.url;
      form.dispatchEvent(new Event("submit"));
    });
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) return;

    setLoading(btn, true);
    resultContainer.style.display = "none";

    try {
      const response = await fetch("/api/v1/analyze/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || "Analysis failed");
      }

      const result = await response.json();
      renderResult(resultContainer, result);
      updateHistoryBadge();
    } catch (error) {
      alert("Analysis error: " + error.message);
    } finally {
      setLoading(btn, false);
    }
  });
}

// 4. File Scanner
function initFileScanner() {
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");
  const selectedInfo = document.getElementById("selectedFileInfo");
  const selectedName = document.getElementById("selectedFileName");
  const submitBtn = document.getElementById("fileSubmitBtn");
  const resultContainer = document.getElementById("fileResultContainer");

  let activeFile = null;

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "var(--primary)";
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.style.borderColor = "var(--border-color)";
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "var(--border-color)";
    if (e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  function handleFileSelected(file) {
    activeFile = file;
    selectedName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    selectedInfo.style.display = "flex";
  }

  submitBtn.addEventListener("click", async () => {
    if (!activeFile) return;

    setLoading(submitBtn, true);
    resultContainer.style.display = "none";

    const formData = new FormData();
    formData.append("file", activeFile);

    try {
      const response = await fetch("/api/v1/analyze/file", {
        method: "POST",
        body: formData
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || "File analysis failed");
      }

      const result = await response.json();
      renderResult(resultContainer, result);
      updateHistoryBadge();
    } catch (error) {
      alert("File analysis error: " + error.message);
    } finally {
      setLoading(submitBtn, false);
    }
  });
}

// 5. Render Threat Assessment Result
function renderResult(container, data) {
  const sevLower = data.severity.toLowerCase();
  
  // Calculate max SHAP impact for relative bar widths
  const maxImpact = Math.max(...data.top_features.map(f => f.absolute_impact || Math.abs(f.shap_value) || 0.01), 0.01);

  const barsHtml = data.top_features.map(feat => {
    const impact = feat.absolute_impact || Math.abs(feat.shap_value);
    const pct = Math.min(100, Math.max(10, (impact / maxImpact) * 100));
    const isRisk = feat.direction === "increases_risk";
    return `
      <div class="shap-bar-item">
        <div class="bar-labels">
          <span>${feat.feature} = ${feat.value}</span>
          <span style="color: ${isRisk ? '#f87171' : '#34d399'}">${isRisk ? '+' : '-'}${impact.toFixed(3)}</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill ${isRisk ? 'risk' : 'safe'}" style="width: ${pct}%"></div>
        </div>
      </div>
    `;
  }).join("");

  const reasonsHtml = data.reasons.map(r => `<li>${r}</li>`).join("");

  container.innerHTML = `
    <!-- Top Threat Banner -->
    <div class="threat-banner severity-${sevLower}">
      <div class="banner-content">
        <div class="severity-tag ${sevLower}">${data.severity} Severity</div>
        <h3 style="margin-top: 8px;">${data.title}</h3>
        <p class="target-url">${data.target}</p>
      </div>
      <div class="banner-scores">
        <div class="score-box">
          <div class="score-value">${data.risk_score}</div>
          <div class="score-label">Unified Risk (0-100)</div>
        </div>
        <div class="score-box">
          <div class="score-value">${(data.probability * 100).toFixed(1)}%</div>
          <div class="score-label">${data.prediction} Likelihood</div>
        </div>
      </div>
    </div>

    <!-- Detailed Split Grid -->
    <div class="result-grid">
      <!-- Action & Banking Guidance -->
      <div class="action-card">
        <h4>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Security Decision: <span style="color: var(--primary);">${data.decision}</span>
        </h4>
        <p class="action-recommendation"><strong>Recommendation:</strong> ${data.recommendation}</p>
        <div class="action-disclaimer">
          <strong>Notice:</strong> ${data.disclaimer}
        </div>
      </div>

      <!-- Explainable AI (SHAP) -->
      <div class="shap-card">
        <h4>Explainable AI (SHAP Feature Attribution)</h4>
        <p class="shap-summary">${data.summary}</p>
        <ul class="shap-reasons-list">
          ${reasonsHtml}
        </ul>
        <h5 style="font-size: 0.85rem; margin-bottom: 8px; color: var(--text-muted);">Key Feature Influence:</h5>
        <div class="shap-bars">
          ${barsHtml}
        </div>
      </div>
    </div>
  `;

  container.style.display = "flex";
  container.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// 6. History Management
function initHistory() {
  const filter = document.getElementById("historyFilter");
  const clearBtn = document.getElementById("clearHistoryBtn");

  filter.addEventListener("change", () => loadHistory());
  clearBtn.addEventListener("click", async () => {
    if (confirm("Are you sure you want to clear all analysis history?")) {
      await fetch("/api/v1/history", { method: "DELETE" });
      loadHistory();
      updateHistoryBadge();
    }
  });

  updateHistoryBadge();
}

async function loadHistory() {
  const tbody = document.getElementById("historyTableBody");
  const filter = document.getElementById("historyFilter").value;
  const url = filter ? `/api/v1/history?input_type=${filter}` : "/api/v1/history";

  try {
    const res = await fetch(url);
    const records = await res.json();

    if (records.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="padding: 24px; color: var(--text-muted);">No analysis records found.</td></tr>`;
      return;
    }

    tbody.innerHTML = records.map(r => {
      const sev = r.severity.toLowerCase();
      const date = new Date(r.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      return `
        <tr>
          <td>${date}</td>
          <td><span class="badge-version">${r.input_type}</span></td>
          <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${r.target}</td>
          <td><strong>${r.prediction}</strong> (${(r.probability * 100).toFixed(1)}%)</td>
          <td>${r.risk_score} / 100</td>
          <td><span class="severity-tag ${sev}" style="padding: 2px 8px; font-size: 0.75rem;">${r.severity}</span></td>
          <td><strong>${r.decision}</strong></td>
          <td><button class="secondary-btn" style="padding: 4px 10px; font-size: 0.75rem;" onclick="viewHistoryDetail('${r.id}')">Inspect</button></td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: #ef4444;">Failed to load history: ${err.message}</td></tr>`;
  }
}

async function viewHistoryDetail(recordId) {
  try {
    const res = await fetch(`/api/v1/history/${recordId}`);
    if (res.ok) {
      const data = await res.json();
      // Switch to URL or file tab and render
      if (data.input_type === "URL") {
        document.querySelector('[data-tab="url-tab"]').click();
        renderResult(document.getElementById("urlResultContainer"), data);
      } else {
        document.querySelector('[data-tab="file-tab"]').click();
        renderResult(document.getElementById("fileResultContainer"), data);
      }
    }
  } catch (err) {
    alert("Error fetching record detail: " + err.message);
  }
}

async function updateHistoryBadge() {
  try {
    const res = await fetch("/api/v1/history?limit=100");
    if (res.ok) {
      const records = await res.json();
      document.getElementById("historyCounter").textContent = records.length;
    }
  } catch (e) {}
}

function setLoading(btn, isLoading) {
  const text = btn.querySelector(".btn-text");
  const spinner = btn.querySelector(".btn-spinner");
  if (isLoading) {
    btn.disabled = true;
    if (text) text.style.opacity = "0.5";
    if (spinner) spinner.style.display = "inline-block";
  } else {
    btn.disabled = false;
    if (text) text.style.opacity = "1";
    if (spinner) spinner.style.display = "none";
  }
}
