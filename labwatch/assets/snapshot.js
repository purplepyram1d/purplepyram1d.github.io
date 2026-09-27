// Read-only snapshot shim for the public copy of LabWatch.
// The real LabWatch runs privately on SRV01 behind Windows sign-in and talks to api.php.
// Here, the read calls are answered from static files and every write is refused,
// so the interface is the real one but nothing can be changed. The snapshot also adds a
// short plain-English explanation at the top of each incident page (from incidents.json).
(function () {
  const realFetch = window.fetch.bind(window);
  const json = (body, status = 200) => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  });
  const refuse = () => json({ error: 'This is a read-only snapshot of LabWatch. Changes are made in the private instance.' }, 403);

  let plainEnglish = {};
  const data = realFetch('incidents.json', { cache: 'no-store' }).then((r) => r.json()).then((d) => {
    plainEnglish = d.plainEnglish || {};
    return d;
  });

  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    if (!url.includes('api.php')) return realFetch(input, init);
    const method = ((init && init.method) || 'GET').toUpperCase();
    const action = new URL(url, window.location.href).searchParams.get('action');
    if (method !== 'GET') return refuse();
    if (action === 'list') return data.then((d) => json({ records: d.records || [] }));
    if (action === 'kb-list' || action === 'evidence-list') return json({ records: [] });
    if (action === 'framework-catalogs') {
      const [attack, nist] = await Promise.all([
        realFetch('assets/attack-techniques.json').then((r) => r.json()),
        realFetch('assets/nist-csf-2.json').then((r) => r.json()),
      ]);
      return json({ attack, nist });
    }
    return refuse();
  };

  // Plain-English panel under the incident header.
  function addPlainEnglish() {
    const match = window.location.hash.match(/#\/inc\/(INC-\d{4}-\d{4})/);
    if (!match) return;
    const header = document.querySelector('.incident-record-view .kb-page-header');
    const text = plainEnglish[match[1]];
    if (!header || !text) return;
    const existing = header.parentElement.querySelector('.snapshot-plain');
    if (existing && existing.dataset.id === match[1]) return;
    if (existing) existing.remove();
    const panel = document.createElement('section');
    panel.className = 'snapshot-plain';
    panel.dataset.id = match[1];
    panel.setAttribute('aria-label', 'What is this incident, in plain English');
    const label = document.createElement('p');
    label.className = 'snapshot-plain-label';
    label.textContent = 'What is this? In plain English';
    const body = document.createElement('p');
    body.textContent = text;
    panel.append(label, body);
    header.insertAdjacentElement('afterend', panel);
  }
  const start = () => {
    const main = document.getElementById('main');
    if (main) new MutationObserver(addPlainEnglish).observe(main, { childList: true, subtree: true });
    window.addEventListener('hashchange', () => setTimeout(addPlainEnglish, 0));
    data.then(addPlainEnglish);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();

  // Keep the snapshot from reading or writing anything a visitor's browser may have stored.
  try {
    localStorage.removeItem('labwatch-records-v1');
    localStorage.removeItem('labwatch-knowledge-v1');
  } catch (e) { /* storage unavailable: nothing to clear */ }
})();
