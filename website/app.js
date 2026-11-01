(() => {
  const normaliseTarget = (value) => value.trim().replace(/^https?:\/\//i, '').replace(/\/$/, '');

  const homeForm = document.querySelector('#home-scan-form');
  if (homeForm) {
    homeForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const input = document.querySelector('#home-target');
      const target = normaliseTarget(input.value);
      if (!target) return;
      window.location.href = `tools.html?target=${encodeURIComponent(target)}#website-scan`;
    });
  }

  const toolForm = document.querySelector('#tool-scan-form');
  if (!toolForm) return;

  const input = document.querySelector('#tool-target');
  const button = document.querySelector('#scan-button');
  const empty = document.querySelector('#results-empty');
  const results = document.querySelector('#scan-results');
  const targetLabel = document.querySelector('#result-target');
  const score = document.querySelector('#result-score');
  const list = document.querySelector('#result-list');
  const status = document.querySelector('#scan-status');

  const queryTarget = new URLSearchParams(window.location.search).get('target');
  if (queryTarget) input.value = normaliseTarget(queryTarget);

  const demoChecks = [
    ['HTTPS enabled', 'PASS', 'pass', 'Traffic can be encrypted between the browser and server.'],
    ['Certificate validity', 'PASS', 'pass', 'The demo certificate is shown as valid.'],
    ['HTTP → HTTPS redirect', 'PASS', 'pass', 'Plain HTTP is redirected to the encrypted version.'],
    ['Strict-Transport-Security', 'MISSING', 'warn', 'HSTS can tell supported browsers to use HTTPS only.'],
    ['Content-Security-Policy', 'REVIEW', 'warn', 'A strong CSP can reduce the impact of some script injection issues.'],
    ['X-Content-Type-Options', 'PASS', 'pass', 'The browser is instructed not to MIME-sniff content types.'],
    ['Referrer-Policy', 'REVIEW', 'warn', 'A deliberate referrer policy can reduce unnecessary information leakage.']
  ];

  function renderChecks() {
    list.innerHTML = demoChecks.map(([name, result, type, description]) => `
      <div class="result-row">
        <span><i class="result-icon ${type}">${type === 'pass' ? '✓' : '!'}</i><span><strong>${name}</strong><small style="display:block;color:var(--dim);font-weight:500;margin-top:2px">${description}</small></span></span>
        <b class="${type === 'pass' ? 'pass-text' : 'warn-text'}">${result}</b>
      </div>
    `).join('');
  }

  toolForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const target = normaliseTarget(input.value);
    if (!target) return;

    button.disabled = true;
    button.textContent = 'Running demo…';
    status.innerHTML = '<div class="loading-line"></div><p>Preparing a local demo report. No request is being sent to the target yet.</p>';
    empty.classList.add('hidden');
    results.classList.remove('visible');

    window.setTimeout(() => {
      targetLabel.textContent = target;
      score.textContent = '82';
      renderChecks();
      status.innerHTML = '<p class="demo-warning">Demo only: these are sample results used to preview ForgeSec. The live FastAPI scanning backend has not been connected yet.</p>';
      results.classList.add('visible');
      button.disabled = false;
      button.textContent = 'Run demo scan';
    }, 900);
  });

  if (queryTarget) {
    window.setTimeout(() => toolForm.requestSubmit(), 150);
  }
})();
