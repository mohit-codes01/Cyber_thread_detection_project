/**
 * Cyber Threat Detector - Upload Controller
 * Drag & Drop, schema validation, data quality assessment, and execution trigger.
 */

import { API } from "./api.js";
import { showToast } from "./app.js";
import { loadDashboardData } from "./dashboard.js";

let currentJobId = null;

export function initUploadView() {
  const dropzone = document.getElementById("dropzoneArea");
  const fileInput = document.getElementById("csvFileInput");
  const browseBtn = document.getElementById("browseFilesBtn");
  const analyzeBtn = document.getElementById("startAnalysisBtn");
  const clearBtn = document.getElementById("clearUploadBtn");
  const sampleBtn = document.getElementById("loadSampleDatasetBtn");

  if (browseBtn && fileInput) {
    browseBtn.addEventListener("click", () => fileInput.click());
  }

  if (fileInput) {
    fileInput.addEventListener("change", (e) => {
      if (e.target.files.length) {
        handleFileSelection(e.target.files[0]);
      }
    });
  }

  if (dropzone) {
    ["dragenter", "dragover"].forEach(evt => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach(evt => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
      });
    });

    dropzone.addEventListener("drop", (e) => {
      if (e.dataTransfer.files.length) {
        handleFileSelection(e.dataTransfer.files[0]);
      }
    });
  }

  if (analyzeBtn) {
    analyzeBtn.addEventListener("click", async () => {
      if (!currentJobId) {
        showToast("Please select and upload a valid dataset file first.", "error");
        return;
      }
      await runAnalysisJob(currentJobId);
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", () => resetUploadForm());
  }

  if (sampleBtn) {
    sampleBtn.addEventListener("click", async () => {
      try {
        sampleBtn.disabled = true;
        sampleBtn.innerHTML = `<span>⏳ Ingesting & Analyzing Sample...</span>`;
        showToast("Loading 500-record UNSW-NB15 sample dataset...", "info");

        const result = await API.loadSampleDataset();
        showToast(`Analysis Complete: Flagged ${result.summary.threats_detected} threats!`, "success");

        await loadDashboardData();
        // Switch to dashboard
        window.navigateToTab("dashboard");
      } catch (err) {
        showToast(err.message || "Failed to load sample dataset", "error");
      } finally {
        sampleBtn.disabled = false;
        sampleBtn.innerHTML = `<span class="btn-icon">⚡</span> Load Sample UNSW-NB15 Dataset (500 records)`;
      }
    });
  }
}

async function handleFileSelection(file) {
  // Validate extension
  const validExts = [".csv", ".json", ".log", ".txt"];
  const ext = "." + file.name.split(".").pop().toLowerCase();
  if (!validExts.includes(ext)) {
    showToast(`Invalid file type (${ext}). Please select a CSV, JSON, or text log.`, "error");
    return;
  }

  // Validate size (1GB)
  if (file.size > 1024 * 1024 * 1024) {
    showToast("File exceeds maximum allowed size of 1 GB.", "error");
    return;
  }

  const progressBar = document.getElementById("uploadProgressBar");
  const progressContainer = document.getElementById("uploadProgressContainer");
  const fileDetailsCard = document.getElementById("fileDetailsCard");
  const fileNameDisplay = document.getElementById("uploadedFileName");
  const fileSizeDisplay = document.getElementById("uploadedFileSize");

  if (progressContainer) progressContainer.style.display = "block";
  if (progressBar) progressBar.style.width = "40%";

  try {
    const uploadRes = await API.uploadFile(file);
    currentJobId = uploadRes.job_id;

    if (progressBar) progressBar.style.width = "100%";
    setTimeout(() => {
      if (progressContainer) progressContainer.style.display = "none";
    }, 600);

    // Display File Details & Quality Assessment
    if (fileDetailsCard) fileDetailsCard.style.display = "block";
    if (fileNameDisplay) fileNameDisplay.textContent = file.name;
    if (fileSizeDisplay) fileSizeDisplay.textContent = `${(file.size / 1024).toFixed(1)} KB`;

    renderQualityReport(uploadRes.data_quality);
    showToast("Dataset uploaded and inspected. Click 'Analyze Dataset' to execute detection.", "success");

    const analyzeBtn = document.getElementById("startAnalysisBtn");
    if (analyzeBtn) analyzeBtn.disabled = false;

  } catch (err) {
    if (progressContainer) progressContainer.style.display = "none";
    showToast(err.message || "File upload failed", "error");
  }
}

async function runAnalysisJob(jobId) {
  const analyzeBtn = document.getElementById("startAnalysisBtn");
  if (analyzeBtn) {
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = `<span>⏳ ML Models Executing...</span>`;
  }

  try {
    showToast("Running hybrid detection engine (Rules + Isolation Forest + Random Forest)...", "info");
    const result = await API.startAnalysis(jobId);

    showToast(`Analysis Complete! Detected ${result.summary.threats_detected} threats out of ${result.summary.total_records} records.`, "success");

    // Refresh Dashboard
    await loadDashboardData();

    // Navigate to Dashboard
    window.navigateToTab("dashboard");

  } catch (err) {
    showToast(err.message || "Threat analysis failed", "error");
  } finally {
    if (analyzeBtn) {
      analyzeBtn.disabled = false;
      analyzeBtn.innerHTML = `<span>⚡ Analyze Dataset</span>`;
    }
  }
}

function renderQualityReport(quality) {
  const panel = document.getElementById("qualityAssessmentPanel");
  if (!panel || !quality) return;

  panel.style.display = "block";

  const recCount = document.getElementById("qualityRecordCount");
  const colCount = document.getElementById("qualityColumnCount");
  const qualScore = document.getElementById("qualityScoreVal");
  const detectedCols = document.getElementById("qualityDetectedCols");

  if (recCount) recCount.textContent = Number(quality.record_count || 0).toLocaleString();
  if (colCount) colCount.textContent = quality.column_count || 0;
  if (qualScore) qualScore.textContent = `${quality.quality_score || 95}%`;
  
  if (detectedCols) {
    const fields = Object.keys(quality.detected_fields || {});
    detectedCols.textContent = fields.length ? fields.join(", ") : "Generic telemetry";
  }
}

function resetUploadForm() {
  currentJobId = null;
  const fileInput = document.getElementById("csvFileInput");
  if (fileInput) fileInput.value = "";

  const fileDetailsCard = document.getElementById("fileDetailsCard");
  if (fileDetailsCard) fileDetailsCard.style.display = "none";

  const panel = document.getElementById("qualityAssessmentPanel");
  if (panel) panel.style.display = "none";

  const analyzeBtn = document.getElementById("startAnalysisBtn");
  if (analyzeBtn) analyzeBtn.disabled = true;
}
