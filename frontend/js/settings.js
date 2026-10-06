/**
 * Cyber Threat Detector - Settings Controller
 * System diagnostics, ML model parameters, and dataset specifications.
 */

import { API } from "./api.js";
import { showToast } from "./app.js";

export function loadSettingsView() {
  const seedBtn = document.getElementById("seedDefaultUsersBtn");
  if (seedBtn) {
    seedBtn.onclick = async () => {
      try {
        const res = await fetch("/api/auth/seed-defaults", { method: "POST" });
        const data = await res.json();
        showToast(data.message || "Default accounts verified.", "success");
      } catch (err) {
        showToast("Account initialization error.", "error");
      }
    };
  }
}
