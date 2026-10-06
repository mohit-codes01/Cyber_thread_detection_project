/**
 * Cyber Threat Detector - Main Application Router & Controller
 * Manages SPA view state transitions, notifications, and navigation.
 */

import { initCharts } from "./charts.js";
import { loadDashboardData } from "./dashboard.js";
import { initUploadView } from "./upload.js";
import { loadThreatAnalysisView, initAnalysisFilters } from "./analysis.js";
import { loadMonitoringView } from "./monitoring.js";
import { loadReportsView } from "./reports.js";
import { loadSettingsView } from "./settings.js";
import { API } from "./api.js";

// Global navigation router
window.navigateToTab = function(tabName) {
  // Update sidebar active class
  document.querySelectorAll(".nav-item").forEach(item => {
    item.classList.remove("active");
    if (item.dataset.tab === tabName) {
      item.classList.add("active");
    }
  });

  // Switch view sections
  document.querySelectorAll(".view-section").forEach(sec => {
    sec.classList.remove("active");
  });

  const targetView = document.getElementById(`view-${tabName}`);
  if (targetView) {
    targetView.classList.add("active");
  }

  // Close mobile sidebar if open
  const sidebar = document.getElementById("appSidebar");
  const backdrop = document.getElementById("sidebarBackdrop");
  if (sidebar) sidebar.classList.remove("mobile-open");
  if (backdrop) backdrop.classList.remove("active");

  // Load view-specific data
  if (tabName === "dashboard") loadDashboardData();
  else if (tabName === "analysis") loadThreatAnalysisView();
  else if (tabName === "monitoring") loadMonitoringView();
  else if (tabName === "reports") loadReportsView();
  else if (tabName === "settings") loadSettingsView();
};

// Global Toast Notification System
export function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;

  const icon = type === "success" ? "✓" : (type === "error" ? "✕" : "ℹ");
  toast.innerHTML = `<span style="font-weight: bold;">${icon}</span> <span>${message}</span>`;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

document.addEventListener("DOMContentLoaded", () => {
  // Initialize Chart.js
  initCharts();

  // Initialize upload handlers
  initUploadView();

  // Initialize analysis table filters
  initAnalysisFilters();

  // Sidebar navigation click handlers
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const tab = item.dataset.tab;
      if (tab) window.navigateToTab(tab);
    });
  });

  // Mobile sidebar toggle
  const toggleBtn = document.getElementById("mobileNavToggle");
  const sidebar = document.getElementById("appSidebar");
  const backdrop = document.getElementById("sidebarBackdrop");

  if (toggleBtn && sidebar && backdrop) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("mobile-open");
      backdrop.classList.toggle("active");
    });

    backdrop.addEventListener("click", () => {
      sidebar.classList.remove("mobile-open");
      backdrop.classList.remove("active");
    });
  }

  // Notification Center Toggle
  const notifBtn = document.getElementById("headerNotificationBtn");
  const notifDropdown = document.getElementById("notifDropdown");
  if (notifBtn && notifDropdown) {
    notifBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      notifDropdown.style.display = notifDropdown.style.display === "block" ? "none" : "block";
    });
    document.addEventListener("click", (e) => {
      if (!notifDropdown.contains(e.target)) {
        notifDropdown.style.display = "none";
      }
    });
  }

  // Header "Load Demo Data" Button
  const demoBtn = document.getElementById("headerDemoBtn");
  if (demoBtn) {
    demoBtn.addEventListener("click", async () => {
      try {
        demoBtn.disabled = true;
        demoBtn.innerHTML = `<span>⏳ Injecting Telemetry...</span>`;
        showToast("Injecting synthetic cybersecurity event baseline...", "info");

        const res = await API.loadDemoData();
        showToast(`Demo Mode Active: Injected ${res.records_inserted} events and flagged ${res.threats_identified} threats!`, "success");

        await loadDashboardData();
        window.navigateToTab("dashboard");
      } catch (err) {
        showToast(err.message || "Failed to inject demo telemetry", "error");
      } finally {
        demoBtn.disabled = false;
        demoBtn.innerHTML = `<span class="btn-icon">🧪</span> Load Demo Data`;
      }
    });
  }

  // Dashboard Quick Action Buttons
  const qaUpload = document.getElementById("qaUploadBtn");
  if (qaUpload) qaUpload.onclick = () => window.navigateToTab("upload");

  const qaAnalysis = document.getElementById("qaRunAnalysisBtn");
  if (qaAnalysis) {
    qaAnalysis.onclick = async () => {
      showToast("Triggering instant sample dataset analysis...", "info");
      try {
        await API.loadSampleDataset();
        showToast("Sample analysis completed!", "success");
        await loadDashboardData();
        window.navigateToTab("dashboard");
      } catch (err) {
        window.navigateToTab("upload");
      }
    };
  }

  const qaReports = document.getElementById("qaViewReportsBtn");
  if (qaReports) qaReports.onclick = () => window.navigateToTab("reports");

  const qaDownloadPdf = document.getElementById("qaDownloadPdfBtn");
  if (qaDownloadPdf) {
    qaDownloadPdf.onclick = async () => {
      try {
        showToast("Generating Executive PDF Report...", "info");
        const res = await API.generateReport("PDF", "Executive Cyber Threat Security Report");
        const a = document.createElement("a");
        a.href = API.getReportDownloadUrl(res.id);
        a.download = `Security_Report_${res.id}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        showToast("PDF Report downloaded successfully!", "success");
      } catch (e) {
        showToast("Please load data or run analysis before downloading report.", "error");
      }
    };
  }

  // Load initial Dashboard data
  loadDashboardData();

  // Initialize Lucide Icons if available
  if (window.lucide) {
    window.lucide.createIcons();
  }
});
