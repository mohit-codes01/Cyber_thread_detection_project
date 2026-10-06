/**
 * Cyber Threat Detector - Chart.js Visualizations
 * High-performance interactive charts for SOC SIEM telemetry.
 */

let trafficChartInstance = null;
let donutChartInstance = null;

const CYBER_PALETTE = [
  "#ef4444", // Critical Red
  "#f97316", // High Orange
  "#f59e0b", // Amber Yellow
  "#00f0ff", // Neon Cyan
  "#0ea5e9", // Electric Blue
  "#a855f7", // Purple
  "#ec4899", // Pink
  "#10b981", // Emerald Green
  "#6366f1"  // Indigo
];

export function initCharts() {
  const trafficCtx = document.getElementById("trafficOverviewChart");
  const donutCtx = document.getElementById("threatTypesChart");

  if (trafficCtx) {
    const ctx = trafficCtx.getContext("2d");
    
    // Create subtle gradients
    const normalGradient = ctx.createLinearGradient(0, 0, 0, 300);
    normalGradient.addColorStop(0, "rgba(0, 240, 255, 0.35)");
    normalGradient.addColorStop(1, "rgba(0, 240, 255, 0.0)");

    const threatGradient = ctx.createLinearGradient(0, 0, 0, 300);
    threatGradient.addColorStop(0, "rgba(239, 68, 68, 0.35)");
    threatGradient.addColorStop(1, "rgba(239, 68, 68, 0.0)");

    trafficChartInstance = new Chart(trafficCtx, {
      type: "line",
      data: {
        labels: ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "23:59"],
        datasets: [
          {
            label: "Normal Traffic",
            data: [0, 0, 0, 0, 0, 0, 0],
            borderColor: "#00f0ff",
            backgroundColor: normalGradient,
            borderWidth: 2,
            fill: true,
            tension: 0.38,
            pointRadius: 4,
            pointHoverRadius: 6,
            pointBackgroundColor: "#00f0ff"
          },
          {
            label: "Threats Detected",
            data: [0, 0, 0, 0, 0, 0, 0],
            borderColor: "#ef4444",
            backgroundColor: threatGradient,
            borderWidth: 2,
            fill: true,
            tension: 0.38,
            pointRadius: 4,
            pointHoverRadius: 6,
            pointBackgroundColor: "#ef4444"
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: "index",
          intersect: false
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(10, 15, 29, 0.95)",
            borderColor: "rgba(0, 240, 255, 0.3)",
            borderWidth: 1,
            titleColor: "#00f0ff",
            bodyColor: "#e2e8f0",
            padding: 12,
            cornerRadius: 6,
            displayColors: true
          }
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: { color: "#64748b", font: { size: 11 } }
          },
          y: {
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: { color: "#64748b", font: { size: 11 } },
            beginAtZero: true
          }
        }
      }
    });
  }

  if (donutCtx) {
    donutChartInstance = new Chart(donutCtx, {
      type: "doughnut",
      data: {
        labels: ["Baseline"],
        datasets: [
          {
            data: [100],
            backgroundColor: ["rgba(56, 189, 248, 0.15)"],
            borderColor: "#0c1427",
            borderWidth: 3,
            hoverOffset: 4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "72%",
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(10, 15, 29, 0.95)",
            borderColor: "rgba(0, 240, 255, 0.3)",
            borderWidth: 1,
            titleColor: "#00f0ff",
            bodyColor: "#e2e8f0",
            padding: 10,
            cornerRadius: 6
          }
        }
      }
    });
  }
}

export function updateTrafficChart(timeline = []) {
  if (!trafficChartInstance || !timeline.length) return;

  const labels = timeline.map(t => t.label);
  const normalData = timeline.map(t => t.normal !== undefined ? t.normal : (t.total ? t.total - (t.threats || 0) : 0));
  const threatData = timeline.map(t => t.threats || 0);

  trafficChartInstance.data.labels = labels;
  trafficChartInstance.data.datasets[0].data = normalData;
  trafficChartInstance.data.datasets[1].data = threatData;
  trafficChartInstance.update();
}

export function updateThreatDonutChart(categories = []) {
  if (!donutChartInstance) return;

  const legendList = document.getElementById("donutLegendBreakdown");

  if (!categories || categories.length === 0) {
    donutChartInstance.data.labels = ["Normal Traffic"];
    donutChartInstance.data.datasets[0].data = [100];
    donutChartInstance.data.datasets[0].backgroundColor = ["#10b981"];
    donutChartInstance.update();

    if (legendList) {
      legendList.innerHTML = `
        <div class="donut-legend-row">
          <span class="donut-legend-cat">
            <span class="legend-color" style="background:#10b981"></span>
            Normal Traffic
          </span>
          <span class="donut-legend-count">100%</span>
        </div>
      `;
    }
    return;
  }

  const labels = categories.map(c => c.category);
  const counts = categories.map(c => c.count);
  const colors = categories.map((_, i) => CYBER_PALETTE[i % CYBER_PALETTE.length]);
  const total = counts.reduce((a, b) => a + b, 0);

  donutChartInstance.data.labels = labels;
  donutChartInstance.data.datasets[0].data = counts;
  donutChartInstance.data.datasets[0].backgroundColor = colors;
  donutChartInstance.update();

  if (legendList) {
    legendList.innerHTML = categories.map((c, i) => {
      const pct = total > 0 ? Math.round((c.count / total) * 100) : 0;
      const col = colors[i];
      return `
        <div class="donut-legend-row">
          <span class="donut-legend-cat">
            <span class="legend-color" style="background:${col}"></span>
            ${c.category}
          </span>
          <span class="donut-legend-count">${c.count} (${pct}%)</span>
        </div>
      `;
    }).join("");
  }
}
