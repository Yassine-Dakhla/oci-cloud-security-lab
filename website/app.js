(() => {
  const normalizeTarget = (value) => {
    let target = (value || '').trim();
    if (!target) return '';
    target = target.replace(/^https?:\/\//i, '').split('/')[0].trim().replace(/\.$/, '');
    return target.toLowerCase();
  };

  const isReasonableHost = (value) => {
    if (!value || value.length > 253 || value.includes(' ')) return false;
    return /^([a-z0-9-]+\.)+[a-z0-9-]{2,}$/i.test(value);
  };

  const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

  const formatDate = (iso) => {
    if (!iso) return 'Unavailable';
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  };

  document.querySelectorAll('[data-scan-form]').forEach((form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const input = form.querySelector('input[name="target"]');
      const target = normalizeTarget(input?.value);

      if (!isReasonableHost(target)) {
        input?.focus();
        input?.setAttribute('aria-invalid', 'true');
        showMessage(form, 'Enter a public domain such as example.com.', 'error');
        return;
      }

      input?.removeAttribute('aria-invalid');
      if (form.hasAttribute('data-live-scan')) {
        await runLiveScan(form, target);
      } else {
        window.location.href = `tools.html?target=${encodeURIComponent(target)}#scanner`;
      }
    });
  });

  function showMessage(form, text, type = 'info') {
    const shell = form.closest('.demo-shell');
    const message = shell?.querySelector('[data-scan-message]');
    if (!message) return;
    message.textContent = text;
    message.className = `scan-message ${type}`;
    message.hidden = false;
  }

  function clearMessage(form) {
    const shell = form.closest('.demo-shell');
    const message = shell?.querySelector('[data-scan-message]');
    if (message) message.hidden = true;
  }

  async function runLiveScan(form, target) {
    const shell = form.closest('.demo-shell');
    const result = shell?.querySelector('[data-live-results]');
    const button = form.querySelector('button[type="submit"]');
    if (!shell || !result || !button) return;

    clearMessage(form);
    result.classList.remove('visible');
    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = 'Checking…';
    showMessage(form, `Checking ${target}. This usually takes a few seconds.`, 'loading');

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });

      let data;
      try {
        data = await response.json();
      } catch {
        data = {};
      }

      if (!response.ok) {
        throw new Error(data.detail || `Scan failed with HTTP ${response.status}.`);
      }

      renderLiveResult(result, data);
      clearMessage(form);
      result.classList.add('visible');
      result.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      showMessage(form, error?.message || 'ForgeSec could not complete this check.', 'error');
    } finally {
      button.disabled = false;
      button.textContent = originalLabel;
    }
  }

  function renderLiveResult(container, data) {
    const summary = data.summary || {};
    const tls = data.tls || {};
    const https = data.https || {};
    const findings = Array.isArray(data.findings) ? data.findings : [];

    const findingHtml = findings.map((item) => {
      const state = item.status === 'pass' ? ['good', 'success', 'Pass', '✓']
        : item.status === 'issue' ? ['bad', 'danger', 'Issue', '×']
        : item.status === 'warn' ? ['warn', 'warning', 'Review', '!']
        : ['info', 'info', 'Info', 'i'];

      const recommendation = item.recommendation
        ? `<p class="finding-recommendation"><b>Recommended:</b> ${escapeHtml(item.recommendation)}</p>`
        : '';

      return `
        <div class="finding live-finding">
          <span class="check ${state[0]}">${state[3]}</span>
          <div class="finding-copy">
            <b>${escapeHtml(item.title)}</b>
            <small>${escapeHtml(item.detail)}</small>
            ${recommendation}
          </div>
          <span class="tag ${state[1]}">${state[2]}</span>
        </div>`;
    }).join('');

    const certificateText = tls.valid
      ? `${escapeHtml(tls.issuer || 'Trusted issuer')} · ${escapeHtml(tls.days_remaining ?? '?')} days remaining`
      : 'Trusted certificate could not be validated';

    container.innerHTML = `
      <div class="result-topline">
        <div><span>Live ForgeSec report</span><b>${escapeHtml(data.target)}</b></div>
        <span class="scan-timestamp">Checked ${escapeHtml(new Date(data.scanned_at).toLocaleString())}</span>
      </div>

      <div class="dashboard-head live-dashboard-head">
        <div><small>Security overview</small><h3>${escapeHtml(data.target)}</h3><p class="grade-label">${escapeHtml(data.grade)}</p></div>
        <div class="score-ring"><strong>${escapeHtml(data.score)}</strong><span>/100</span></div>
      </div>

      <div class="summary-row">
        <div><span class="status-dot good"></span><p><b>${escapeHtml(summary.passed ?? 0)}</b> passed</p></div>
        <div><span class="status-dot warn"></span><p><b>${escapeHtml(summary.warnings ?? 0)}</b> warnings</p></div>
        <div><span class="status-dot bad"></span><p><b>${escapeHtml(summary.issues ?? 0)}</b> issues</p></div>
      </div>

      <div class="result-meta-grid">
        <div class="result-meta-card"><span>HTTPS</span><b>${https.available ? `HTTP ${escapeHtml(https.status)}` : 'Unavailable'}</b><small>${https.response_time_ms ? `${escapeHtml(https.response_time_ms)} ms to response headers` : 'No trusted HTTPS response'}</small></div>
        <div class="result-meta-card"><span>TLS certificate</span><b>${tls.valid ? escapeHtml(tls.protocol || 'Valid') : 'Check failed'}</b><small>${certificateText}</small></div>
        <div class="result-meta-card"><span>Certificate expiry</span><b>${tls.valid ? formatDate(tls.expires_at) : 'Unavailable'}</b><small>${tls.cipher ? escapeHtml(tls.cipher) : 'Cipher unavailable'}</small></div>
      </div>

      <div class="result-section-title"><div><span>Findings</span><h3>What ForgeSec found</h3></div><small>Lightweight external configuration checks</small></div>
      <div class="finding-list live-finding-list">${findingHtml}</div>
      <p class="scope-note">${escapeHtml(data.scope_note || '')}</p>`;
  }

  const params = new URLSearchParams(window.location.search);
  const incoming = normalizeTarget(params.get('target'));
  if (incoming && isReasonableHost(incoming)) {
    const liveForm = document.querySelector('[data-scan-form][data-live-scan]');
    const input = liveForm?.querySelector('input[name="target"]');
    if (liveForm && input) {
      input.value = incoming;
      runLiveScan(liveForm, incoming);
    }
  }
})();
