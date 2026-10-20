"use strict";

const elements = {
  runButton: document.getElementById("runCheckBtn"),
  buttonLabel: document.getElementById("buttonLabel"),
  search: document.getElementById("searchInput"),
  tableBody: document.getElementById("certificateTableBody"),
  tableFooter: document.getElementById("tableFooter"),
  total: document.getElementById("totalCount"),
  healthy: document.getElementById("healthyCount"),
  warning: document.getElementById("warningCount"),
  critical: document.getElementById("criticalCount"),
  overallTitle: document.getElementById("overallTitle"),
  overallMessage: document.getElementById("overallMessage"),
  generatedAt: document.getElementById("generatedAt"),
  latestResult: document.getElementById("latestResult"),
  checkOutput: document.getElementById("checkOutput"),
  toast: document.getElementById("toast")
};

let currentResults = [];
let latestReport = null;
let toastTimeout = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function formatDate(value) {
  if (!value) return "Not available";

  // The checker reports timestamps with UTC explicitly.
  const normalized = String(value).replace(/ UTC$/, "Z").replace(" ", "T");
  const date = new Date(normalized);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short"
  }).format(date);
}

function statusDetails(result) {
  const status = String(result?.status ?? "unknown").toLowerCase();

  const labels = {
    ok: { label: "Healthy", className: "healthy" },
    warning: { label: "Warning", className: "warning" },
    critical: { label: "Critical", className: "critical" },
    failed: { label: "Failed", className: "failed" },
    error: { label: "Failed", className: "failed" }
  };

  return labels[status] || {
    label: status.charAt(0).toUpperCase() + status.slice(1),
    className: "unknown"
  };
}

function getCounts(report) {
  const counts = report?.counts || {};

  return {
    total: currentResults.length,
    healthy: Number(counts.ok ?? currentResults.filter(
      item => String(item.status).toLowerCase() === "ok"
    ).length),
    warning: Number(counts.warning ?? currentResults.filter(
      item => String(item.status).toLowerCase() === "warning"
    ).length),
    critical: Number(counts.critical ?? currentResults.filter(
      item => String(item.status).toLowerCase() === "critical"
    ).length),
    failed: Number(counts.failed ?? currentResults.filter(
      item => ["failed", "error"].includes(String(item.status).toLowerCase())
    ).length)
  };
}

function renderSummary(report) {
  const counts = getCounts(report);

  elements.total.textContent = counts.total;
  elements.healthy.textContent = counts.healthy;
  elements.warning.textContent = counts.warning;
  elements.critical.textContent = counts.critical + counts.failed;

  const overall = String(report?.overall ?? "unknown").toLowerCase();

  if (counts.failed > 0 || overall === "failed" || overall === "error") {
    elements.overallTitle.textContent = "Certificate check needs attention";
    elements.overallMessage.textContent =
      `${counts.failed} failed, ${counts.critical} critical, ` +
      `${counts.warning} warning, ${counts.healthy} healthy.`;
  } else if (counts.critical > 0 || counts.warning > 0) {
    elements.overallTitle.textContent = "Certificates need attention";
    elements.overallMessage.textContent =
      `${counts.critical} critical, ${counts.warning} warning, ` +
      `${counts.healthy} healthy.`;
  } else {
    elements.overallTitle.textContent = "All monitored certificates are healthy";
    elements.overallMessage.textContent =
      `${counts.healthy} healthy, 0 warnings, 0 critical, 0 failed.`;
  }

  elements.generatedAt.textContent = report?.generated_at
    ? formatDate(report.generated_at)
    : "Not available";

  elements.latestResult.textContent = overall.toUpperCase();
}

function renderTable() {
  const query = elements.search.value.trim().toLowerCase();

  const filtered = currentResults.filter(result => {
    const searchable = [
      result.host,
      result.port,
      result.issuer,
      result.not_after,
      result.days_left,
      result.status,
      result.error
    ].join(" ").toLowerCase();

    return searchable.includes(query);
  });

  if (filtered.length === 0) {
    elements.tableBody.innerHTML = `
      <tr>
        <td colspan="5" class="empty-state">
          ${currentResults.length === 0
            ? "No certificate results are available."
            : "No certificates match your search."}
        </td>
      </tr>
    `;
    elements.tableFooter.textContent = "0 certificates shown";
    return;
  }

  elements.tableBody.innerHTML = filtered.map(result => {
    const status = statusDetails(result);
    const host = result.host || "Unknown host";
    const port = result.port ?? 443;
    const issuer = result.issuer || result.error || "Not available";
    const expiry = formatDate(result.not_after);
    const days = Number.isFinite(Number(result.days_left))
      ? `${Number(result.days_left)} days`
      : "Not available";

    return `
      <tr>
        <td>
          <div class="host-name">${escapeHtml(host)}</div>
          <div class="host-port">Port ${escapeHtml(port)}</div>
        </td>
        <td class="issuer-cell">${escapeHtml(issuer)}</td>
        <td>${escapeHtml(expiry)}</td>
        <td class="days-cell">${escapeHtml(days)}</td>
        <td>
          <span class="status-badge ${escapeHtml(status.className)}">
            ${escapeHtml(status.label)}
          </span>
        </td>
      </tr>
    `;
  }).join("");

  elements.tableFooter.textContent =
    `Showing ${filtered.length} of ${currentResults.length} certificates`;
}

function showToast(message, isError = false) {
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", isError);
  elements.toast.classList.add("visible");

  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    elements.toast.classList.remove("visible");
  }, 3500);
}

async function loadReport() {
  const response = await fetch("/api/report", {
    cache: "no-store",
    headers: { "Accept": "application/json" }
  });

  if (!response.ok) {
    throw new Error(`Could not load report (HTTP ${response.status})`);
  }

  const report = await response.json();

  if (!Array.isArray(report.results)) {
    throw new Error("The report does not contain a valid results array.");
  }

  latestReport = report;
  currentResults = report.results;

  renderSummary(report);
  renderTable();
}

async function runCheck() {
  elements.runButton.disabled = true;
  elements.buttonLabel.textContent = "Checking...";
  elements.checkOutput.hidden = true;
  elements.checkOutput.textContent = "";

  try {
    const response = await fetch("/api/check", {
      method: "POST",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const data = await response.json();

    if (data.output) {
      elements.checkOutput.textContent = data.output;
      elements.checkOutput.hidden = false;
    }

    if (!response.ok) {
      throw new Error(data.error || `Check failed (HTTP ${response.status})`);
    }

    // Use the report returned by the check endpoint when available.
    if (data.results && Array.isArray(data.results)) {
      latestReport = data;
      currentResults = data.results;
      renderSummary(data);
      renderTable();
    } else {
      await loadReport();
    }

    showToast("Certificate check completed.");
  } catch (error) {
    showToast(error.message || "Unable to run certificate check.", true);

    try {
      await loadReport();
    } catch (loadError) {
      console.error("Could not refresh report:", loadError);
    }

    console.error("Certificate check error:", error);
  } finally {
    elements.runButton.disabled = false;
    elements.buttonLabel.textContent = "Run Check";
  }
}

elements.search.addEventListener("input", renderTable);
elements.runButton.addEventListener("click", runCheck);

loadReport().catch(error => {
  console.error("Report loading error:", error);
  elements.tableBody.innerHTML = `
    <tr>
      <td colspan="5" class="empty-state">
        Unable to load certificate report. Check the Flask terminal.
      </td>
    </tr>
  `;
  elements.tableFooter.textContent = "Report unavailable";
  elements.overallTitle.textContent = "Unable to load report";
  elements.overallMessage.textContent = error.message;
});
