(function () {
  const canvas = document.getElementById('owaspChart');
  if (!canvas || typeof Chart === 'undefined') return;

  const findings = JSON.parse(canvas.dataset.findings || '[]');
  const issueCount = findings.filter((f) => (f.exploitability_score || 0) >= 1.5).length;
  const infoCount = findings.length - issueCount;

  const avgConfidence = findings.length
    ? (findings.reduce((acc, f) => acc + (Number(f.confidence) || 0), 0) / findings.length).toFixed(1)
    : '0.0';

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Issue Detected', 'Informational'],
      datasets: [{
        data: [issueCount, infoCount],
        backgroundColor: ['#ef4444', '#64748b'],
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
  breakdown.textContent = `Average confidence: ${avgConfidence}% across ${findings.length} finding(s).`;
  canvas.parentElement.appendChild(breakdown);
})();
