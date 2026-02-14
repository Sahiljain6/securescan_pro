(() => {
    const barCanvas = document.getElementById("owaspChart");
    if (!barCanvas) return;

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
    if (!radarCanvas) return;

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
})();
