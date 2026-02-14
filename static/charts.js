(function () {
  // Minimal helper for future chart wiring (client-only, no framework dependency)
  const findings = document.querySelectorAll('.finding-item');
  if (!findings.length) return;

  const total = findings.length;
  let issues = 0;
  findings.forEach((el) => {
    if (el.textContent.includes('Issue Detected')) issues += 1;
  });

  const panel = document.createElement('p');
  panel.className = 'muted';
  panel.textContent = `Vulnerability breakdown: ${issues} / ${total} controls flagged.`;

  const target = document.querySelector('.finding-list');
  if (target) target.prepend(panel);
})();
