/**
 * Cyber Threat Detector - Live Monitoring Controller
 * Dataset monitoring, system resource telemetry, and terminal stream.
 */

import { API } from "./api.js";

let telemetryTimer = null;
let terminalLogs = [];

export async function loadMonitoringView() {
  await fetchSystemTelemetry();

  if (!telemetryTimer) {
    telemetryTimer = setInterval(fetchSystemTelemetry, 4000);
  }

  // Populate terminal stream from actual threats
  try {
    const threats = await API.getThreats({ limit: 20 });
    const terminalBox = document.getElementById("monitoringTerminalBox");
    if (!terminalBox) return;

    terminalBox.innerHTML = "";
    addTerminalLog("[SYS_INIT] SOC SIEM telemetry streaming active. Monitoring packet ingest pipeline...");

    if (threats.length) {
      threats.forEach(t => {
        const time = t.timestamp ? new Date(t.timestamp).toISOString() : new Date().toISOString();
        const sev = (t.severity || "LOW").toUpperCase();
        addTerminalLog(`[${time}] [${sev}] Entity: ${t.source_ip || 'Internal Host'} | Alert: ${t.threat_type} | Trigger: ${t.rule_triggered || 'ML_CLASSIFIER'} | Risk: ${t.risk_score}`);
      });
    } else {
      addTerminalLog(`[${new Date().toISOString()}] [INFO] Network baseline operational. Zero malicious indicators detected.`);
    }
  } catch (err) {
    console.error("Failed to populate monitoring terminal:", err);
  }
}

async function fetchSystemTelemetry() {
  try {
    const status = await API.getSystemStatus();
    
    const cpuEl = document.getElementById("gaugeCpuVal");
    if (cpuEl) cpuEl.textContent = `${status.cpu_usage_percent || 12}%`;

    const ramEl = document.getElementById("gaugeRamVal");
    if (ramEl) ramEl.textContent = `${status.ram_usage_percent || 45}%`;

    const ramMbEl = document.getElementById("gaugeRamMb");
    if (ramMbEl) ramMbEl.textContent = `${status.ram_used_mb || 4200} MB`;

    const engineEl = document.getElementById("gaugeEngineVal");
    if (engineEl) engineEl.textContent = status.detection_engine || "ONLINE";

    const dbEl = document.getElementById("gaugeDbVal");
    if (dbEl) dbEl.textContent = status.database || "CONNECTED";

  } catch (err) {
    console.warn("Telemetry fetch error:", err);
  }
}

function addTerminalLog(msg) {
  const terminalBox = document.getElementById("monitoringTerminalBox");
  if (!terminalBox) return;

  const line = document.createElement("div");
  line.style.marginBottom = "4px";

  if (msg.includes("[CRITICAL]")) {
    line.style.color = "#ef4444";
  } else if (msg.includes("[HIGH]")) {
    line.style.color = "#f97316";
  } else if (msg.includes("[MEDIUM]")) {
    line.style.color = "#f59e0b";
  } else {
    line.style.color = "#38bdf8";
  }

  line.textContent = msg;
  terminalBox.appendChild(line);
  terminalBox.scrollTop = terminalBox.scrollHeight;
}
