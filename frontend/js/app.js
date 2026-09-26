/**
 * CyberShield AI - Frontend Application Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initUrlScanner();
  initFileScanner();
  initMessageScanner();
  initHistory();
  checkSystemHealth();
});

// Helper: Escape HTML to avoid XSS vulnerabilities
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Helper: Render text with weighted inline <mark> highlights
function renderHighlightedText(rawText, spans) {
  if (!rawText) return "";
  if (!spans || spans.length === 0) {
    return `<p class="highlighted-text-box">${escapeHtml(rawText)}</p>`;
  }

  // Sort spans by start index
  const sortedSpans = [...spans].sort((a, b) => a.start - b.start);
  let html = "";
  let cursor = 0;

  for (const span of sortedSpans) {
    const s = Math.max(cursor, span.start);
    const e = Math.min(rawText.length, span.end);
    if (s < e) {
      // Append preceding unhighlighted text
      if (s > cursor) {
        html += escapeHtml(rawText.slice(cursor, s));
      }
      const weight = Math.max(0.2, Math.min(1.0, span.weight || 0.8));
      const opacity = (weight * 0.45).toFixed(2);
      const spanText = escapeHtml(rawText.slice(s, e));
      html += `<mark class="threat-span" style="background-color: rgba(239, 68, 68, ${opacity}); border-bottom: 2px solid rgba(239, 68, 68, 0.8); padding: 2px 4px; border-radius: 4px;" title="Threat weight: ${(weight*100).toFixed(0)}%">${spanText}</mark>`;
      cursor = e;
    }
  }

  if (cursor < rawText.length) {
    html += escapeHtml(rawText.slice(cursor));
  }

  return `<div class="highlighted-text-box" style="line-height: 1.6; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 6px; font-family: inherit; margin-top: 8px;">${html}</div>`;
}

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

// 5. Message Scanner (GenAI Phishing)
function initMessageScanner() {
  const form = document.getElementById("messageForm");
  const input = document.getElementById("messageInput");
  const btn = document.getElementById("messageSubmitBtn");
  const resultContainer = document.getElementById("messageResultContainer");

  document.querySelectorAll(".sample-msg-btn").forEach(btnSample => {
    btnSample.addEventListener("click", () => {
      input.value = btnSample.dataset.msg;
      form.dispatchEvent(new Event("submit"));
    });
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || text.length < 10) {
      alert("Message text must be at least 10 characters long.");
      return;
    }

    setLoading(btn, true);
    resultContainer.style.display = "none";

    try {
      const response = await fetch("/api/v1/analyze/message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || "Message analysis failed");
      }

      const result = await response.json();
      result.rawInputText = text;
      renderResult(resultContainer, result);
      updateHistoryBadge();
    } catch (error) {
      alert("Message analysis error: " + error.message);
    } finally {
      setLoading(btn, false);
    }
  });
}

// 6. Render Threat Assessment Result
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
          <span>${escapeHtml(feat.feature)} = ${typeof feat.value === 'number' ? feat.value : escapeHtml(feat.value)}</span>
          <span style="color: ${isRisk ? '#f87171' : '#34d399'}">${isRisk ? '+' : '-'}${impact.toFixed(3)}</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill ${isRisk ? 'risk' : 'safe'}" style="width: ${pct}%"></div>
        </div>
      </div>
    `;
  }).join("");

  const reasonsHtml = data.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("");

  // Optional highlighted span block for message analyses
  let spansBlock = "";
  if (data.input_type === "MESSAGE" && (data.rawInputText || data.target)) {
    const content = data.rawInputText || data.target;
    spansBlock = `
      <div class="card" style="margin-top: 16px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
        <h4 style="margin-bottom: 8px;">Suspicious Phrase Highlights</h4>
        <p style="font-size: 0.85rem; color: var(--text-muted);">Inline cues identified by the sequence model as contributing to the threat assessment:</p>
        ${renderHighlightedText(content, data.highlighted_spans)}
      </div>
    `;
  }

  const isLegit = ["legitimate", "benign", "legitimate / safe"].includes((data.prediction || "").toLowerCase());
  const predictionLikelihoodVal = data.prediction_likelihood != null
    ? (data.prediction_likelihood * 100).toFixed(1)
    : (isLegit ? ((1.0 - data.probability) * 100).toFixed(1) : (data.probability * 100).toFixed(1));
  const predictionLikelihoodLabel = data.prediction_likelihood_label || 
    (isLegit ? "Legitimate Likelihood" : (data.prediction.toLowerCase().includes("suspicious") ? "Model Phishing Likelihood" : (data.prediction.toLowerCase().includes("mal") ? "Malware Likelihood" : "Phishing Likelihood")));
  const contextScoreVal = ((data.context_score != null ? data.context_score : 0.0) * 100).toFixed(1);

  container.innerHTML = `
    <!-- Top Threat Banner -->
    <div class="threat-banner severity-${sevLower}">
      <div class="banner-content">
        <div class="severity-tag ${sevLower}">${escapeHtml(data.severity)} Severity</div>
        <h3 style="margin-top: 8px;">${escapeHtml(data.title)}</h3>
        <p class="target-url">${escapeHtml(data.target)}</p>
      </div>
      <div class="banner-scores">
        <div class="score-box" title="Unified Risk Score (0-100): Multi-modal synthesis of ML statistical probability and static contextual indicators">
          <div class="score-value">${data.risk_score}</div>
          <div class="score-label">Unified Risk (0-100)</div>
        </div>
        <div class="score-box" title="Prediction Likelihood (%): Machine learning model class probability for the predicted classification (${escapeHtml(predictionLikelihoodLabel)})">
          <div class="score-value">${predictionLikelihoodVal}%</div>
          <div class="score-label">${escapeHtml(predictionLikelihoodLabel)}</div>
        </div>
        <div class="score-box" title="Static URL signals (0-100): IP host, suspicious terms, deep subdomains, missing HTTPS, and unranked domain reputation.">
          <div class="score-value">${contextScoreVal}</div>
          <div class="score-label">Contextual Risk (0-100)</div>
        </div>
      </div>
    </div>

    <!-- Multi-Source Evidence Breakdown (for URLs) -->
    ${data.input_type === 'URL' ? `
    <div class="evidence-strip" style="display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; margin-bottom: 16px; padding: 10px 16px; background: rgba(30, 41, 59, 0.7); border: 1px solid var(--border-color); border-radius: 8px; align-items: center; justify-content: space-between;">
      <div style="display: flex; gap: 16px; flex-wrap: wrap; align-items: center;">
        <div style="font-size: 0.85rem;">
          <span style="color: var(--text-muted);">Threat Intel:</span>
          <span class="badge" style="margin-left: 6px; font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; font-weight: 500; ${data.threat_intel?.is_threat ? 'background: #dc2626; color: #fff;' : (data.threat_intel?.status === 'no_known_threat' ? 'background: rgba(16, 185, 129, 0.2); color: #34d399;' : 'background: rgba(100, 116, 139, 0.2); color: #94a3b8;')}">
            ${escapeHtml(data.threat_intel?.status === 'confirmed_threat' ? 'Confirmed Threat' : (data.threat_intel?.status === 'no_known_threat' ? 'No Known Threat Found' : (data.threat_intel?.status === 'unavailable' ? 'Unavailable' : 'Not Configured')))}
          </span>
        </div>
        <div style="font-size: 0.85rem;">
          <span style="color: var(--text-muted);">Domain Authority:</span>
          <span class="badge" style="margin-left: 6px; font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; font-weight: 500; ${data.domain_reputation?.is_established ? 'background: rgba(16, 185, 129, 0.2); color: #34d399;' : 'background: rgba(100, 116, 139, 0.2); color: #94a3b8;'}">
            ${escapeHtml(data.domain_reputation?.is_established ? `Established (${data.domain_reputation?.domain})` : 'Standard / Unranked')}
          </span>
        </div>
        <div style="font-size: 0.85rem;">
          <span style="color: var(--text-muted);">Registration / DNS / TLS:</span>
          <span class="badge" style="margin-left: 6px; font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; font-weight: 500; background: rgba(100, 116, 139, 0.2); color: #cbd5e1;">
            ${escapeHtml(`${data.domain_verification?.registration_status || 'unknown'} / ${data.domain_verification?.dns_status || 'unknown'} / ${data.domain_verification?.tls_status || 'unknown'}`)}
          </span>
          ${data.domain_verification?.domain_age_days != null ? `<span style="color: var(--text-muted); margin-left: 6px;">Registered ${Number(data.domain_verification.domain_age_days)} days ago</span>` : ''}
        </div>
      </div>
      <div style="font-size: 0.85rem;">
        <span style="color: var(--text-muted);">Final Assessment:</span>
        <strong style="margin-left: 6px; letter-spacing: 0.5px; color: ${data.final_assessment === 'MALICIOUS' ? '#f87171' : (data.final_assessment === 'LIKELY LEGITIMATE' ? '#34d399' : '#fbbf24')};">
          ${escapeHtml(data.final_assessment || (data.severity === 'Low' ? 'LIKELY LEGITIMATE' : (data.severity === 'Critical' ? 'MALICIOUS' : 'SUSPICIOUS / UNKNOWN')))}
        </strong>
      </div>
    </div>
    ` : ''}

    <!-- Highlighted spans (for messages) -->
    ${spansBlock}

    <!-- Detailed Split Grid -->
    <div class="result-grid">
      <!-- Action & Banking Guidance -->
      <div class="action-card">
        <h4>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Security Decision: <span style="color: var(--primary);">${escapeHtml(data.decision)}</span>
        </h4>
        <p class="action-recommendation"><strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}</p>
        <div class="action-disclaimer">
          <strong>Notice:</strong> ${escapeHtml(data.disclaimer)}
        </div>
      </div>

      <!-- Explainable AI (SHAP) -->
      <div class="shap-card">
        <h4>Explainable AI (SHAP Feature Attribution)</h4>
        <p class="shap-summary">${escapeHtml(data.summary)}</p>
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

// 7. History Management
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
      const typeIcon = r.input_type === "DOWNLOAD" ? "📥 " : (r.input_type === "FILE" ? "📄 " : (r.input_type === "MESSAGE" ? "✉️ " : "🔗 "));
      const targetContent = r.input_type === "DOWNLOAD" && r.download_source_url
        ? `<strong>${escapeHtml(r.target)}</strong><div style="font-size: 0.72rem; color: var(--text-muted); text-overflow: ellipsis; overflow: hidden;" title="${escapeHtml(r.download_source_url)}">from: ${escapeHtml(r.download_source_url)}</div>`
        : escapeHtml(r.target);

      const isLegit = ["legitimate", "benign", "legitimate / safe"].includes((r.prediction || "").toLowerCase());
      const displayLikelihood = r.prediction_likelihood != null
        ? (r.prediction_likelihood * 100).toFixed(1)
        : (isLegit ? ((1.0 - r.probability) * 100).toFixed(1) : (r.probability * 100).toFixed(1));

      return `
        <tr>
          <td>${date}</td>
          <td><span class="badge-version">${typeIcon}${escapeHtml(r.input_type)}</span></td>
          <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${targetContent}</td>
          <td><strong>${escapeHtml(r.prediction)}</strong> (${displayLikelihood}%)</td>
          <td>${r.risk_score} / 100</td>
          <td><span class="severity-tag ${sev}" style="padding: 2px 8px; font-size: 0.75rem;">${escapeHtml(r.severity)}</span></td>
          <td><strong>${escapeHtml(r.decision)}</strong></td>
          <td><button class="secondary-btn" style="padding: 4px 10px; font-size: 0.75rem;" onclick="viewHistoryDetail('${escapeHtml(r.id)}')">Inspect</button></td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color: #ef4444;">Failed to load history: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function viewHistoryDetail(recordId) {
  try {
    const res = await fetch(`/api/v1/history/${recordId}`);
    if (res.ok) {
      const data = await res.json();
      if (data.input_type === "URL") {
        document.querySelector('[data-tab="url-tab"]').click();
        renderResult(document.getElementById("urlResultContainer"), data);
      } else if (data.input_type === "FILE" || data.input_type === "DOWNLOAD") {
        document.querySelector('[data-tab="file-tab"]').click();
        renderResult(document.getElementById("fileResultContainer"), data);
      } else {
        document.querySelector('[data-tab="message-tab"]').click();
        renderResult(document.getElementById("messageResultContainer"), data);
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
