/**
 * Cyber Threat Detector - API Service Layer
 * Interfaces directly with FastAPI backend endpoints.
 */

const API_BASE = ""; // Relative URL matches FastAPI host

export const API = {
  // 1. Dashboard Endpoints
  async getStats() {
    const res = await fetch(`${API_BASE}/api/dashboard/stats`);
    if (!res.ok) throw new Error(`Failed to load stats: ${res.statusText}`);
    return await res.json();
  },

  async getCharts() {
    const res = await fetch(`${API_BASE}/api/dashboard/charts`);
    if (!res.ok) throw new Error(`Failed to load charts: ${res.statusText}`);
    return await res.json();
  },

  async getSystemStatus() {
    const res = await fetch(`${API_BASE}/api/dashboard/system-status`);
    if (!res.ok) throw new Error(`Failed to load system status: ${res.statusText}`);
    return await res.json();
  },

  async loadDemoData() {
    const res = await fetch(`${API_BASE}/api/dashboard/load-demo-data`, {
      method: "POST"
    });
    if (!res.ok) throw new Error(`Failed to load demo data: ${res.statusText}`);
    return await res.json();
  },

  // 2. Data Upload & Ingestion
  async uploadFile(file) {
    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch(`${API_BASE}/api/analyze/upload`, {
      method: "POST",
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "File upload failed");
    }
    return await res.json();
  },

  async startAnalysis(jobId) {
    const res = await fetch(`${API_BASE}/api/analyze/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ job_id: jobId })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Analysis execution failed");
    }
    return await res.json();
  },

  async loadSampleDataset() {
    const res = await fetch(`${API_BASE}/api/analyze/load-sample`, {
      method: "POST"
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Failed to load sample dataset");
    }
    return await res.json();
  },

  // 3. Threat Forensics & Investigation
  async getThreats(params = {}) {
    const query = new URLSearchParams();
    if (params.severity) query.append("severity", params.severity);
    if (params.threat_type) query.append("threat_type", params.threat_type);
    if (params.status) query.append("status", params.status);
    if (params.search) query.append("search", params.search);
    if (params.min_risk !== undefined) query.append("min_risk", params.min_risk);
    if (params.limit) query.append("limit", params.limit);

    const res = await fetch(`${API_BASE}/api/threats?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to fetch threats: ${res.statusText}`);
    return await res.json();
  },

  async getThreatDetail(threatId) {
    const res = await fetch(`${API_BASE}/api/threats/${threatId}`);
    if (!res.ok) throw new Error(`Failed to fetch threat details: ${res.statusText}`);
    return await res.json();
  },

  async updateThreatStatus(threatId, status) {
    const res = await fetch(`${API_BASE}/api/threats/${threatId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status })
    });
    if (!res.ok) throw new Error(`Failed to update status: ${res.statusText}`);
    return await res.json();
  },

  // 4. Reports Generation & Download
  async generateReport(format = "PDF", title = "Cyber Threat Analysis Report") {
    const res = await fetch(`${API_BASE}/api/reports/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: title,
        report_format: format
      })
    });
    if (!res.ok) throw new Error(`Report generation failed: ${res.statusText}`);
    return await res.json();
  },

  async getReports() {
    const res = await fetch(`${API_BASE}/api/reports`);
    if (!res.ok) throw new Error(`Failed to list reports: ${res.statusText}`);
    return await res.json();
  },

  getReportDownloadUrl(reportId) {
    return `${API_BASE}/api/reports/download/${reportId}`;
  }
};
