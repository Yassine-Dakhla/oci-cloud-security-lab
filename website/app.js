(() => {
  const normalizeTarget = (value) => {
    let target = (value || '').trim();
    if (!target) return '';
    target = target.replace(/^https?:\/\//i, '').split('/')[0].trim();
    return target;
  };

  const isReasonableHost = (value) => {
    if (!value || value.length > 253 || value.includes(' ')) return false;
    return /^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(value) || /^localhost$/i.test(value);
  };

  document.querySelectorAll('[data-scan-form]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const input = form.querySelector('input[name="target"]');
      const target = normalizeTarget(input?.value);

      if (!isReasonableHost(target)) {
        input?.focus();
        input?.setAttribute('aria-invalid', 'true');
        if (input) input.placeholder = 'Enter a domain such as example.com';
        return;
      }

      input?.removeAttribute('aria-invalid');

      if (form.dataset.mode === 'demo') {
        showDemoResult(form, target);
        return;
      }

      window.location.href = `tools.html?target=${encodeURIComponent(target)}#scanner`;
    });
  });

  function showDemoResult(form, target) {
    const shell = form.closest('.demo-shell');
    const result = shell?.querySelector('[data-demo-results]');
    if (!result) return;

    result.classList.add('visible');
    result.querySelectorAll('[data-target-name]').forEach((node) => {
      node.textContent = target;
    });
    result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  const params = new URLSearchParams(window.location.search);
  const incoming = normalizeTarget(params.get('target'));
  if (incoming) {
    const demoForm = document.querySelector('[data-scan-form][data-mode="demo"]');
    const input = demoForm?.querySelector('input[name="target"]');
    if (demoForm && input && isReasonableHost(incoming)) {
      input.value = incoming;
      showDemoResult(demoForm, incoming);
    }
  }
})();