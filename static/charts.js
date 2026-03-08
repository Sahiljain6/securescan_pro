(() => {
    const palette = ["#ef4444", "#f97316", "#facc15", "#22c55e", "#38bdf8", "#a855f7", "#14b8a6"];

    const createChart = (canvasId, config) => {
        const canvas = document.getElementById(canvasId);
        if (!canvas) {
            return;
        }
        new Chart(canvas, config);
    };

    const entries = (obj) => Object.entries(obj || {});

    const domainCanvas = document.getElementById("owaspChart");
    if (domainCanvas) {
        const domains = JSON.parse(domainCanvas.dataset.domains || "[]");
        const labels = domains.map((item) => item.domain);
        const riskValues = domains.map((item) => Number(item.risk) * 100);
        createChart("owaspChart", {
            type: "bar",
            data: {
                labels,
                datasets: [
                    { label: "Weighted Risk (%)", data: riskValues, backgroundColor: "rgba(255,99,132,0.55)" },
                    { label: "Confidence (%)", data: domains.map((item) => Number(item.confidence)), backgroundColor: "rgba(54,162,235,0.55)" },
                ],
            },
            options: { responsive: true, scales: { y: { beginAtZero: true, max: 100 } } },
        });

        createChart("radarChart", {
            type: "radar",
            data: {
                labels,
                datasets: [{ label: "Control Domain Risk Radar", data: riskValues, borderColor: "rgba(255,206,86,1)", backgroundColor: "rgba(255,206,86,0.2)" }],
            },
            options: { responsive: true, scales: { r: { beginAtZero: true, max: 100 } } },
        });
    }

    createChart("scannerChart", {
        type: "bar",
        data: {
            labels: Object.keys(JSON.parse(document.getElementById("scannerChart")?.dataset.scanners || "{}")),
            datasets: [{
                label: "Vulnerabilities",
                data: Object.values(JSON.parse(document.getElementById("scannerChart")?.dataset.scanners || "{}")),
                backgroundColor: "rgba(75, 192, 192, 0.55)",
            }],
        },
        options: { responsive: true, scales: { y: { beginAtZero: true } } },
    });

    const owaspData = JSON.parse(document.getElementById("owaspHybridChart")?.dataset.owasp || "{}");
    createChart("owaspHybridChart", {
        type: "doughnut",
        data: { labels: Object.keys(owaspData), datasets: [{ data: Object.values(owaspData), backgroundColor: palette }] },
        options: { responsive: true },
    });

    const severityData = JSON.parse(document.getElementById("severityChart")?.dataset.severity || "{}");
    createChart("severityChart", {
        type: "pie",
        data: { labels: Object.keys(severityData), datasets: [{ data: Object.values(severityData), backgroundColor: palette }] },
        options: { responsive: true },
    });

    const confidenceData = JSON.parse(document.getElementById("confidenceChart")?.dataset.confidence || "{}");
    createChart("confidenceChart", {
        type: "line",
        data: {
            labels: Object.keys(confidenceData),
            datasets: [{ label: "Average Confidence", data: Object.values(confidenceData), borderColor: "#60a5fa", fill: false }],
        },
        options: { responsive: true, scales: { y: { beginAtZero: true, max: 1 } } },
    });

    const heatmapData = JSON.parse(document.getElementById("heatmapChart")?.dataset.heatmap || "{}");
    createChart("heatmapChart", {
        type: "bar",
        data: { labels: Object.keys(heatmapData), datasets: [{ label: "Findings", data: Object.values(heatmapData), backgroundColor: "rgba(147, 51, 234, 0.6)" }] },
        options: { responsive: true, indexAxis: "y", scales: { x: { beginAtZero: true } } },
    });

    const dashboardSeverityCanvas = document.getElementById("dashboardSeverityChart");
    if (dashboardSeverityCanvas) {
        fetch("/api/dashboard-data")
            .then((response) => response.json())
            .then((payload) => {
                const severity = payload.severity_distribution || {};
                const scannerComparison = payload.scanner_comparison || {};
                const owaspCategories = payload.owasp_categories || {};
                const heatmap = payload.heatmap || {};

                createChart("dashboardSeverityChart", {
                    type: "pie",
                    data: { labels: Object.keys(severity), datasets: [{ data: Object.values(severity), backgroundColor: palette }] },
                    options: { responsive: true },
                });

                createChart("dashboardScannerChart", {
                    type: "bar",
                    data: { labels: Object.keys(scannerComparison), datasets: [{ label: "Findings", data: Object.values(scannerComparison), backgroundColor: "rgba(59,130,246,0.55)" }] },
                    options: { responsive: true, scales: { y: { beginAtZero: true } } },
                });

                createChart("dashboardOwaspChart", {
                    type: "doughnut",
                    data: { labels: Object.keys(owaspCategories), datasets: [{ data: Object.values(owaspCategories), backgroundColor: palette }] },
                    options: { responsive: true },
                });

                createChart("dashboardHeatmapChart", {
                    type: "bar",
                    data: { labels: entries(heatmap).map(([key]) => key), datasets: [{ label: "Findings", data: entries(heatmap).map(([, count]) => count), backgroundColor: "rgba(168,85,247,0.6)" }] },
                    options: { responsive: true, indexAxis: "y", scales: { x: { beginAtZero: true } } },
                });
            })
            .catch((error) => {
                console.error("Failed to load dashboard data", error);
            });
    }
})();
