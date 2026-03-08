(() => {
    const barCanvas = document.getElementById("owaspChart");
    if (barCanvas) {
        const domains = JSON.parse(barCanvas.dataset.domains || "[]");
        const labels = domains.map((d) => d.domain);
        const riskValues = domains.map((d) => Number(d.risk) * 100);
        const confidenceValues = domains.map((d) => Number(d.confidence));

        new Chart(barCanvas, {
            type: "bar",
            data: {
                labels,
                datasets: [
                    { label: "Weighted Risk (%)", data: riskValues, backgroundColor: "rgba(255, 99, 132, 0.55)" },
                    { label: "Confidence (%)", data: confidenceValues, backgroundColor: "rgba(54, 162, 235, 0.55)" },
                ],
            },
            options: { responsive: true, scales: { y: { beginAtZero: true, max: 100 } } },
        });

        const radarCanvas = document.getElementById("radarChart");
        if (radarCanvas) {
            new Chart(radarCanvas, {
                type: "radar",
                data: {
                    labels,
                    datasets: [
                        {
                            label: "Control Domain Risk Radar",
                            data: riskValues,
                            borderColor: "rgba(255, 206, 86, 1)",
                            backgroundColor: "rgba(255, 206, 86, 0.2)",
                        },
                    ],
                },
                options: { responsive: true, scales: { r: { beginAtZero: true, max: 100 } } },
            });
        }
    }

    const scannerCanvas = document.getElementById("scannerChart");
    if (scannerCanvas) {
        const scannerData = JSON.parse(scannerCanvas.dataset.scanners || "{}");
        new Chart(scannerCanvas, {
            type: "bar",
            data: {
                labels: Object.keys(scannerData),
                datasets: [{ label: "Vulnerabilities", data: Object.values(scannerData), backgroundColor: "rgba(75, 192, 192, 0.55)" }],
            },
            options: { responsive: true, scales: { y: { beginAtZero: true } } },
        });
    }

    const owaspHybridCanvas = document.getElementById("owaspHybridChart");
    if (owaspHybridCanvas) {
        const owaspData = JSON.parse(owaspHybridCanvas.dataset.owasp || "{}");
        new Chart(owaspHybridCanvas, {
            type: "doughnut",
            data: {
                labels: Object.keys(owaspData),
                datasets: [{ data: Object.values(owaspData), backgroundColor: ["#ff6384", "#36a2eb", "#ffce56", "#8dd17e", "#c38dff"] }],
            },
            options: { responsive: true },
        });
    }

    const severityCanvas = document.getElementById("severityChart");
    if (severityCanvas) {
        const severityData = JSON.parse(severityCanvas.dataset.severity || "{}");
        new Chart(severityCanvas, {
            type: "pie",
            data: {
                labels: Object.keys(severityData),
                datasets: [{ data: Object.values(severityData), backgroundColor: ["#ef4444", "#f97316", "#facc15", "#22c55e", "#38bdf8"] }],
            },
            options: { responsive: true },
        });
    }

    const confidenceCanvas = document.getElementById("confidenceChart");
    if (confidenceCanvas) {
        const confidenceData = JSON.parse(confidenceCanvas.dataset.confidence || "{}");
        new Chart(confidenceCanvas, {
            type: "line",
            data: {
                labels: Object.keys(confidenceData),
                datasets: [{ label: "Average Confidence", data: Object.values(confidenceData), borderColor: "#60a5fa", fill: false }],
            },
            options: { responsive: true, scales: { y: { beginAtZero: true, max: 1 } } },
        });
    }

    const heatmapCanvas = document.getElementById("heatmapChart");
    if (heatmapCanvas) {
        const heatmapData = JSON.parse(heatmapCanvas.dataset.heatmap || "{}");
        const labels = Object.keys(heatmapData);
        new Chart(heatmapCanvas, {
            type: "bar",
            data: {
                labels,
                datasets: [{ label: "Findings", data: Object.values(heatmapData), backgroundColor: "rgba(147, 51, 234, 0.6)" }],
            },
            options: { responsive: true, indexAxis: "y", scales: { x: { beginAtZero: true } } },
        });
    }
})();
