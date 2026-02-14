(function () {
  const canvas = document.getElementById('owaspChart');
  if (!canvas || typeof Chart === 'undefined') return;

  const domains = JSON.parse(canvas.dataset.domains || '[]');
  const labels = domains.map((d) => d.domain);
  const risks = domains.map((d) => Number(d.risk || 0) * 10);
  const confidence = domains.map((d) => Number(d.confidence || 0));

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Risk (0-10)',
          data: risks,
          backgroundColor: '#ef4444',
          borderColor: '#7f1d1d',
          borderWidth: 1,
        },
        {
          label: 'Confidence (%)',
          data: confidence,
          backgroundColor: '#3b82f6',
          borderColor: '#1e3a8a',
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      scales: {
        y: { beginAtZero: true, max: 100, ticks: { color: '#e2e8f0' } },
        x: { ticks: { color: '#e2e8f0' } },
      },
      plugins: {
        legend: { labels: { color: '#e2e8f0' } },
      },
    },
  });
})();
