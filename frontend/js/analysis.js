/**
 * Cyber Threat Detector - Threat Analysis Controller
 * Forensic filtering, drill-down investigation modal, and status updates.
 */

import { API } from "./api.js";
import { showToast } from "./app.js";

let allThreats = [];

export async function loadThreatAnalysisView() {
  try {
    allThreats = await API.getThreats({ limit: 200 });
    populateTypeFilter(allThreats);
    renderThreatTable(allThreats);
    renderSummaryPills(allThreats);
  } catch (err) {
    console.error("Failed to load threat analysis:", err);
  }
}

export function initAnalysisFilters() {
  const searchInput = document.getElementById("threatSearchInput");
  const sevFilter = document.getElementById("threatSeverityFilter");
  const typeFilter = document.getElementById("threatTypeFilter");
  const statusFilter = document.getElementById("threatStatusFilter");

  const applyFilters = () => {
    const q = (searchInput?.value || "").toLowerCase().trim();
    const sev = sevFilter?.value || "";
    const typ = typeFilter?.value || "";
    const stat = statusFilter?.value || "";

    const filtered = allThreats.filter(t => {
      if (sev && (t.severity || "").toUpperCase() !== sev.toUpperCase()) return false;
      if (typ && (t.threat_type || "") !== typ) return false;
      if (stat && (t.status || "").toUpperCase() !== stat.toUpperCase()) return false;

      if (q) {
        const match = [
          t.threat_type,
          t.source_ip,
          t.destination_ip,
          t.username,
          t.rule_triggered,
          t.explanation
        ].some(val => val && String(val).toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });

    renderThreatTable(filtered);
    renderSummaryPills(filtered);
  };

  if (searchInput) searchInput.addEventListener("input", applyFilters);
  if (sevFilter) sevFilter.addEventListener("change", applyFilters);
  if (typeFilter) typeFilter.addEventListener("change", applyFilters);
  if (statusFilter) statusFilter.addEventListener("change", applyFilters);

  // Close modal handler
  const closeBtn = document.getElementById("closeForensicModalBtn");
  const backdrop = document.getElementById("forensicModalBackdrop");
  if (closeBtn) closeBtn.addEventListener("click", () => backdrop.classList.remove("active"));
  if (backdrop) {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) backdrop.classList.remove("active");
    });
  }
}

function populateTypeFilter(threats) {
  const select = document.getElementById("threatTypeFilter");
  if (!select) return;

  const types = Array.from(new Set(threats.map(t => t.threat_type).filter(Boolean))).sort();
  const currentVal = select.value;
  select.innerHTML = `<option value="">All Threat Types</option>` + types.map(t => `<option value="${t}">${t}</option>`).join("");
  if (currentVal && types.includes(currentVal)) select.value = currentVal;
}

function renderSummaryPills(threats) {
  const crit = threats.filter(t => (t.severity || "").toUpperCase() === "CRITICAL").length;
  const high = threats.filter(t => (t.severity || "").toUpperCase() === "HIGH").length;
  const med = threats.filter(t => (t.severity || "").toUpperCase() === "MEDIUM").length;
  const low = threats.filter(t => (t.severity || "").toUpperCase() === "LOW").length;

  const countEl = document.getElementById("filteredThreatCount");
  if (countEl) countEl.textContent = `${threats.length} Threats Match`;

  const critEl = document.getElementById("analysisCritCount");
  if (critEl) critEl.textContent = crit;
  const highEl = document.getElementById("analysisHighCount");
  if (highEl) highEl.textContent = high;
  const medEl = document.getElementById("analysisMedCount");
  if (medEl) medEl.textContent = med;
}

function renderThreatTable(threats) {
  const tbody = document.getElementById("threatsTableBody");
  if (!tbody) return;

  if (!threats.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; padding: 36px; color: var(--text-muted);">
          No threats found matching the current search & filter criteria.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = threats.map(t => {
    const sev = (t.severity || "LOW").toUpperCase();
    const sevClass = sev.toLowerCase();
    const score = Number(t.risk_score || 0).toFixed(1);
    const timeStr = t.timestamp ? new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : "-";
    const srcIp = t.source_ip || "192.168.1.10";
    const method = t.detection_method || "HYBRID";

    return `
      <tr style="cursor: pointer;" onclick="window.openThreatForensics(${t.id})">
        <td style="font-family: var(--font-mono); color: var(--text-muted);">#${t.id}</td>
        <td style="font-family: var(--font-mono); color: var(--text-muted);">${timeStr}</td>
        <td style="font-weight: 700; color: #fff;">${t.threat_type || "Anomaly"}</td>
        <td><span class="sev-pill ${sevClass}">● ${sev}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: ${score >= 75 ? 'var(--color-critical)' : 'var(--cyan-primary)'};">${score}</td>
        <td><span class="ip-badge">${srcIp}</span></td>
        <td><span style="font-size: 0.72rem; padding: 2px 6px; background: rgba(255, 255, 255, 0.05); border-radius: 4px; color: var(--text-secondary);">${method}</span></td>
        <td>
          <button class="header-btn" style="padding: 4px 10px; font-size: 0.74rem;" onclick="event.stopPropagation(); window.openThreatForensics(${t.id})">
            Investigate →
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

// Global modal trigger
window.openThreatForensics = async function(threatId) {
  try {
    const threat = await API.getThreatDetail(threatId);
    renderModalContent(threat);
    document.getElementById("forensicModalBackdrop").classList.add("active");
  } catch (err) {
    showToast("Failed to fetch threat forensics", "error");
  }
};

function renderModalContent(t) {
  const sev = (t.severity || "LOW").toUpperCase();
  const sevClass = sev.toLowerCase();

  document.getElementById("modalThreatType").textContent = t.threat_type;
  document.getElementById("modalThreatSev").innerHTML = `<span class="sev-pill ${sevClass}">● ${sev}</span>`;
  document.getElementById("modalThreatId").textContent = `#${t.id}`;
  document.getElementById("modalRiskScore").textContent = Number(t.risk_score || 0).toFixed(1);
  document.getElementById("modalRuleScore").textContent = Number(t.rule_score || 0).toFixed(1);
  document.getElementById("modalAnomalyScore").textContent = Number(t.anomaly_score || 0).toFixed(1);
  document.getElementById("modalMlScore").textContent = Number(t.ml_score || 0).toFixed(1);

  document.getElementById("modalSourceIp").textContent = t.source_ip || "Unknown";
  document.getElementById("modalDestIp").textContent = t.destination_ip || "Internal Gateway";
  document.getElementById("modalRuleTriggered").textContent = t.rule_triggered || "ML Isolation Forest";
  document.getElementById("modalExplanation").textContent = t.explanation || "Behavioral deviation detected.";
  document.getElementById("modalRecommendations").textContent = t.recommended_actions || "Inspect source IP and maintain monitoring.";

  // Evidence JSON formatting
  const evidenceBox = document.getElementById("modalEvidenceJson");
  if (evidenceBox) {
    let evObj = t.evidence;
    try {
      if (typeof evObj === "string") evObj = JSON.parse(evObj);
    } catch {
      // keep as string
    }
    evidenceBox.textContent = typeof evObj === "object" ? JSON.stringify(evObj, null, 2) : (evObj || "{}");
  }

  // Hook up status change buttons
  const resolveBtn = document.getElementById("modalResolveBtn");
  if (resolveBtn) {
    resolveBtn.onclick = async () => {
      try {
        await API.updateThreatStatus(t.id, "RESOLVED");
        showToast(`Threat #${t.id} marked as RESOLVED`, "success");
        document.getElementById("forensicModalBackdrop").classList.remove("active");
        await loadThreatAnalysisView();
      } catch (e) {
        showToast("Failed to update status", "error");
      }
    };
  }
}
