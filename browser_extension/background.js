/**
 * CyberShield AI - Background Service Worker (Manifest V3)
 * Monitors tab navigation events and automatically intercepts file downloads,
 * routing them through the centralized AI threat prediction backend.
 */

const HIGH_RISK_EXTENSIONS = new Set([
  ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd",
  ".ps1", ".vbs", ".js", ".jar", ".msi", ".bin"
]);

// Keep track of analyzed downloads to prevent duplicate processing
const processedDownloads = new Set();

// 1. Listen for pre-navigation events
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
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

// 3. Listen for Chrome file download creation
if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    processDownloadItem(downloadItem);
  });
}

// 4. Also listen for download changes (when filename or state resolves)
if (chrome.downloads && chrome.downloads.onChanged) {
  chrome.downloads.onChanged.addListener((delta) => {
    if (delta.filename && !processedDownloads.has(delta.id)) {
      chrome.downloads.search({ id: delta.id }, (items) => {
        if (items && items.length > 0) {
          processDownloadItem(items[0]);
        }
      });
    }
  });
}

/**
 * Automatically inspects file download metadata and reports AI risk results.
 */
async function processDownloadItem(downloadItem) {
  const downloadId = downloadItem.id;
  if (processedDownloads.has(downloadId)) return;
  processedDownloads.add(downloadId);

  const rawUrl = downloadItem.url || "";
  const referrerUrl = downloadItem.referrer || "";
  
  // Extract filename & extension
  let filename = downloadItem.filename ? downloadItem.filename.replace(/^.*[\\\/]/, '') : "";
  if (!filename && rawUrl) {
    try {
      const parsed = new URL(rawUrl);
      const parts = parsed.pathname.split("/").filter(Boolean);
      filename = parts.length > 0 ? parts[parts.length - 1] : "unknown_file";
    } catch (e) {
      filename = "downloaded_file";
    }
  }
  if (!filename) filename = "downloaded_file";

  let fileExt = "";
  if (filename.includes(".")) {
    fileExt = "." + filename.split(".").pop().toLowerCase();
  }
  
  const isHighRiskExt = HIGH_RISK_EXTENSIONS.has(fileExt);

  // Attempt immediate cancel for high-risk extensions
  if (isHighRiskExt) {
    try {
      chrome.downloads.cancel(downloadId, () => {
        if (chrome.runtime.lastError) {
          // May fail if download is already finished
        }
      });
    } catch (err) {
      console.warn("Proactive cancel attempt error:", err);
    }
  }

  // Send download metadata to CyberShield AI Backend
  let analysisResult = null;
  try {
    const response = await fetch("http://localhost:8000/api/v1/analyze/download", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: filename,
        file_extension: fileExt || ".bin",
        source_url: referrerUrl || rawUrl,
        download_url: rawUrl
      })
    });

    if (response.ok) {
      analysisResult = await response.json();
      
      // Store latest download analysis in local storage for popup inspection
      if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          latestDownload: {
            filename: filename,
            file_extension: fileExt,
            timestamp: new Date().toISOString(),
            analysis: analysisResult
          }
        });
      }
    }
  } catch (err) {
    console.debug("CyberShield download analysis API error:", err);
  }

  // Reconcile download state after delay
  setTimeout(() => {
    chrome.downloads.search({ id: downloadId }, (items) => {
      const currentItem = (items && items.length > 0) ? items[0] : downloadItem;
      const isComplete = currentItem.state === "complete";
      const isInterrupted = currentItem.state === "interrupted";

      if (isHighRiskExt) {
        if (isComplete) {
          // File wrote to disk -> delete it
          try {
            chrome.downloads.removeFile(downloadId, () => {
              showDownloadNotification({
                type: "removed",
                filename: filename,
                extension: fileExt,
                analysis: analysisResult
              });
            });
          } catch (e) {
            showDownloadNotification({
              type: "removed",
              filename: filename,
              extension: fileExt,
              analysis: analysisResult
            });
          }
        } else {
          // Blocked before writing
          showDownloadNotification({
            type: "blocked",
            filename: filename,
            extension: fileExt,
            analysis: analysisResult
          });
        }
      } else if (analysisResult) {
        // Notification for standard / safe downloads
        showDownloadNotification({
          type: "result",
          filename: filename,
          extension: fileExt,
          analysis: analysisResult
        });
      }

      // Display on-page result banner in active tab
      if (analysisResult) {
        notifyActiveTabOfDownloadRisk(analysisResult, filename, fileExt, rawUrl);
      }
    });
  }, 400);
}

/**
 * Displays native notification with CyberShield AI threat prediction.
 */
function showDownloadNotification({ type, filename, extension, analysis }) {
  if (!chrome.notifications) return;

  let title = "CyberShield AI: Download Scanned";
  let message = `${filename}: Analysis complete.`;

  if (type === "blocked") {
    title = "CyberShield AI: High-Risk Download Blocked";
    message = `Blocked dangerous ${extension} file (${filename}) before saving to disk. Action: ${analysis ? analysis.decision : 'BLOCK'}.`;
  } else if (type === "removed") {
    title = "CyberShield AI: Dangerous File Removed From Disk";
    message = `High-risk ${extension} file (${filename}) was downloaded and automatically deleted from disk for protection.`;
  } else if (analysis) {
    const sev = (analysis.severity || "Low").toUpperCase();
    const score = analysis.risk_score || 0;
    const dec = analysis.decision || "ALLOW";
    
    if (analysis.severity === "Low") {
      title = "CyberShield AI: Download Verified Safe (ALLOW)";
      message = `${filename} (${extension}) verified safe. Risk Score: ${score}/100. No threats detected.`;
    } else {
      title = `CyberShield AI: Download ${sev} Risk Alert (${dec})`;
      message = `${filename}: Risk Score ${score}/100 (${dec}). ${analysis.recommendation || ''}`;
    }
  }

  chrome.notifications.create({
    type: "basic",
    iconUrl: "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='48' height='48' fill='%2338bdf8'><circle cx='24' cy='24' r='20'/></svg>",
    title: title,
    message: message,
    priority: 2
  });
}

/**
 * Sends a message to the active tab to display an inline security banner.
 */
function notifyActiveTabOfDownloadRisk(analysis, filename, fileExt, downloadUrl) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs.length > 0) {
      chrome.tabs.sendMessage(tabs[0].id, {
        action: "CYBERSHIELD_DOWNLOAD_WARNING",
        threat: analysis,
        downloadInfo: {
          filename: filename,
          fileExtension: fileExt,
          downloadUrl: downloadUrl
        }
      }, () => {
        if (chrome.runtime.lastError) {
          // Suppress error if content script is not loaded
        }
      });
    }
  });
}

async function checkUrlThreat(tabId, url) {
  try {
    const response = await fetch("http://localhost:8000/api/v1/analyze/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) return;

    const data = await response.json();

    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ [url]: data, latestUrlScan: data });
    }

    if (data.severity === "High" || data.severity === "Critical") {
      chrome.tabs.sendMessage(tabId, {
        action: "CYBERSHIELD_THREAT_DETECTED",
        threat: data
      }, () => {
        if (chrome.runtime.lastError) {}
      });
    }
  } catch (err) {
    console.debug("CyberShield backend offline:", err);
  }
}
