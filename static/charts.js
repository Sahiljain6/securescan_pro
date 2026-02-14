(function () {
  const canvas = document.getElementById('owaspChart');
  if (!canvas || typeof Chart === 'undefined') return;

  const findings = JSON.parse(canvas.dataset.findings || '[]');
  const issueCount = findings.filter((f) => f.vulnerable).length;
  const safeCount = findings.length - issueCount;

  const confidenceMap = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  findings.forEach((f) => {
    confidenceMap[f.confidence] = (confidenceMap[f.confidence] || 0) + 1;
  });

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Issue Detected', 'No Issue'],
      datasets: [{
        data: [issueCount, safeCount],
        backgroundColor: ['#ef4444', '#16a34a'],
        borderColor: '#0f172a',
        borderWidth: 2,
      }],
    },
    options: {
      plugins: {
        legend: { labels: { color: '#e2e8f0' } },
        tooltip: { enabled: true },
      },
    },
  });

  const breakdown = document.createElement('p');
  breakdown.className = 'muted';
  breakdown.textContent = `Confidence mix — High: ${confidenceMap.High}, Medium: ${confidenceMap.Medium}, Low: ${confidenceMap.Low}, Informational: ${confidenceMap.Informational}`;

  canvas.parentElement.appendChild(breakdown);
})();
