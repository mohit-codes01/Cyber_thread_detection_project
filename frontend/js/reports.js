/**
 * Cyber Threat Detector - Reports Controller
 * Executive report generation (PDF, CSV, JSON) and download management.
 */

import { API } from "./api.js";
import { showToast } from "./app.js";

export async function loadReportsView() {
  try {
    const stats = await API.getStats();
    renderSecurityScore(stats);

    const reports = await API.getReports();
    renderReportsList(reports);

    setupReportButtons();
  } catch (err) {
    console.error("Failed to load reports view:", err);
  }
}

function renderSecurityScore(stats) {
  const scoreVal = document.getElementById("reportsScoreVal");
  if (scoreVal) scoreVal.textContent = `${Number(stats.security_score || 95).toFixed(1)}/100`;

  const gradeVal = document.getElementById("reportsGradeVal");
  if (gradeVal) gradeVal.textContent = stats.security_grade || "A (Optimal)";

  const breakdown = stats.risk_breakdown || {};
  const setBar = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.style.width = `${Math.min(100, Math.max(5, val || 5))}%`;
    const textEl = document.getElementById(id + "Text");
    if (textEl) textEl.textContent = `${(val || 0).toFixed(1)}%`;
  };

  setBar("authRiskBar", breakdown.authentication_risk);
  setBar("netRiskBar", breakdown.network_risk);
  setBar("indRiskBar", breakdown.indicator_risk);
  setBar("behRiskBar", breakdown.behavioral_risk);
  setBar("dataRiskBar", breakdown.data_risk);
}

function setupReportButtons() {
  const pdfBtn = document.getElementById("generatePdfReportBtn");
  const csvBtn = document.getElementById("generateCsvReportBtn");
  const jsonBtn = document.getElementById("generateJsonReportBtn");

  const handleGenerate = async (format, btn) => {
    try {
      const origText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = `<span>⏳ Compiling ${format}...</span>`;
      showToast(`Generating executive ${format} report...`, "info");

      const res = await API.generateReport(format, `Cyber Threat Detector Security Report (${format})`);
      showToast(`${format} Report compiled successfully!`, "success");

      // Trigger instant download
      const downloadUrl = API.getReportDownloadUrl(res.id);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `Security_Report_${res.id}.${format.toLowerCase()}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      // Refresh list
      const updatedReports = await API.getReports();
      renderReportsList(updatedReports);

      btn.disabled = false;
      btn.innerHTML = origText;
    } catch (err) {
      showToast(`Failed to generate ${format} report: ${err.message}`, "error");
      btn.disabled = false;
    }
  };

  if (pdfBtn) pdfBtn.onclick = () => handleGenerate("PDF", pdfBtn);
  if (csvBtn) csvBtn.onclick = () => handleGenerate("CSV", csvBtn);
  if (jsonBtn) jsonBtn.onclick = () => handleGenerate("JSON", jsonBtn);
}

function renderReportsList(reports = []) {
  const tbody = document.getElementById("reportsTableBody");
  if (!tbody) return;

  if (!reports.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; padding: 24px; color: var(--text-muted);">
          No saved reports in the local archive. Generate a report above to download.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = reports.map(r => {
    const time = r.created_at ? new Date(r.created_at).toLocaleString() : "Recent";
    const size = r.file_size ? `${(r.file_size / 1024).toFixed(1)} KB` : "-";
    const downloadUrl = API.getReportDownloadUrl(r.id);

    return `
      <tr>
        <td style="font-weight: 600; color: #fff;">${r.title}</td>
        <td><span class="sev-pill" style="background: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.3);">${r.report_format}</span></td>
        <td style="font-family: var(--font-mono); color: var(--text-muted);">${time}</td>
        <td style="font-family: var(--font-mono); color: var(--text-secondary);">${size}</td>
        <td style="font-weight: 600; color: var(--color-critical);">${r.threats_count || 0}</td>
        <td>
          <a href="${downloadUrl}" class="header-btn" style="padding: 4px 12px; font-size: 0.76rem; text-decoration: none;" download>
            ⬇ Download
          </a>
        </td>
      </tr>
    `;
  }).join("");
}
