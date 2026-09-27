(() => {
  'use strict';

  const ACTIVE_STATUSES = new Set(['New', 'In Progress', 'Contained', 'Monitoring']);
  const CLOSED_STATUSES = new Set(['Resolved', 'Closed']);
  const STATUS_ORDER = ['Draft', 'New', 'In Progress', 'Contained', 'Monitoring', 'Resolved', 'Closed'];
  const SEVERITY_ORDER = ['Informational', 'Low', 'Medium', 'High', 'Critical'];
  const REQUIRED_FIELDS = ['title', 'severity', 'labRunId', 'alertSource', 'initialAlert', 'observedFacts', 'evidence', 'conclusion'];
  const KB_REQUIRED_FIELDS = ['title', 'status', 'category', 'summary', 'content'];
  const INCIDENT_CATEGORIES = ['Uncategorized', 'Endpoint', 'Identity and access', 'Network', 'Malware', 'Data security', 'Vulnerability', 'Policy and control', 'Availability', 'Threat hunting', 'Other'];
  const QUERY_OPERATORS = [
    ['is', 'is'], ['is_not', 'is not'], ['includes', 'includes'], ['excludes', 'does not include'],
    ['starts', 'starts with'], ['ends', 'ends with'], ['empty', 'is empty'], ['not_empty', 'is not empty'],
  ];
  const QUERY_FIELDS = {
    id: { label: 'Number' }, title: { label: 'Short description' }, severity: { label: 'Severity', options: ['Critical', 'High', 'Medium', 'Low', 'Informational'] },
    status: { label: 'Status', options: ['Draft', 'New', 'In Progress', 'Contained', 'Monitoring', 'Resolved', 'Closed'] },
    category: { label: 'Category', options: INCIDENT_CATEGORIES }, subcategory: { label: 'Subcategory' }, classification: { label: 'Classification', options: ['Unclassified', 'True Positive', 'Benign True Positive', 'False Positive', 'Expected Test Activity'] },
    environment: { label: 'Environment', options: ['Homelab', 'Endpoint lab', 'Network lab', 'Identity lab', 'Cloud lab', 'Corporate simulation', 'Other'] },
    detectionMethod: { label: 'Detection method', options: ['Analyst-created', 'SIEM alert', 'Threat hunt', 'User report', 'Control validation', 'Automated response', 'Manual observation', 'Other'] },
    assignmentGroup: { label: 'Assignment group', options: ['SOC Operations', 'Detection Engineering', 'Incident Response', 'Threat Hunting', 'Homelab Operations', 'Unassigned'] },
    primaryAsset: { label: 'Affected host' }, affectedUser: { label: 'Affected identity' }, sourceAddress: { label: 'Source address' },
    alertSource: { label: 'Alert source' }, assignedTo: { label: 'Assigned analyst' }, assignedToRole: { label: 'Assigned analyst role', options: ['SOC Analyst I', 'SOC Analyst II', 'Senior SOC Analyst', 'Detection Engineer', 'Incident Responder', 'Threat Hunter'] }, origin: { label: 'Origin', options: ['analyst', 'auto-ingest'] },
    callerName: { label: 'Caller' }, callerRole: { label: 'Caller role', options: ['SOC Analyst I', 'IT Support Specialist I', 'Finance', 'Human Resources', 'Employee', 'System or integration', 'Other'] },
    requestChannel: { label: 'Request channel', options: ['Self-service portal', 'Monitoring integration', 'Email', 'Chat', 'Phone', 'Walk-up', 'Analyst observation', 'Other'] }, submittedBy: { label: 'Submitted by' },
    labRunId: { label: 'Lab run ID' }, mitreTechniques: { label: 'MITRE ATT&CK' }, nistMappings: { label: 'NIST CSF' }, initialAlert: { label: 'Initial alert' }, observedFacts: { label: 'Observed facts' }, conclusion: { label: 'Final determination' },
  };
  const LOCAL_KEY = 'labwatch-records-v1';
  const KB_LOCAL_KEY = 'labwatch-knowledge-v1';
  const WAZUH_WEB_URL = 'https://10.10.10.5';
  const SPLUNK_WEB_URL = 'http://10.10.10.6:8000';
  const NIST_CSF_REFERENCE_URL = 'https://csrc.nist.gov/Projects/cybersecurity-framework/Filters#/csf/filters';
  const VIEW_TITLES = {
    all: 'Incident workspace', active: 'Active queue', mine: 'My incidents', resolved: 'Resolved incidents',
    drafts: 'Draft incidents', metrics: 'Incident metrics', frameworks: 'Framework coverage', knowledge: 'Knowledge base',
  };
  const state = {
    records: [], knowledge: [], view: 'all', severity: 'all', status: 'all', category: 'all', asset: 'all', sort: 'opened_desc',
    kbStatus: 'all', kbCategory: 'all', kbTag: '', search: '', storage: 'checking',
    queryConditions: [], appliedQueryConditions: [], attack: null, nist: null, editingMitre: [], editingNist: [],
    frameworkChart: 'bar', frameworkFamily: 'all', frameworkSearch: '',
    pendingEvidence: [], unverifiedEvidence: [], incidentBusy: false, editorVersion: 0,
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const escapeHtml = (value = '') => String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]);
  const slug = (value = '') => String(value).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
  const firstLine = (value) => String(value || '').split(/\r?\n/)[0].slice(0, 160);
  const nowForInput = () => {
    const d = new Date();
    const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
    return local.toISOString().slice(0, 16);
  };
  const formatDate = (value) => {
    if (!value) return 'Not recorded';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return escapeHtml(value);
    return new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(date);
  };

  const recordValue = (record, field) => {
    const value = record[field];
    if (field === 'mitreTechniques' && Array.isArray(value)) {
      return value.map((entry) => {
        const technique = techniqueById(entry.id);
        return `${entry.id || ''} ${technique?.name || ''} ${(technique?.tactics || []).join(' ')}`;
      }).join(' ');
    }
    if (field === 'nistMappings' && Array.isArray(value)) {
      return value.map((entry) => {
        const category = nistCategoryById(entry?.id || entry);
        return `${entry?.id || entry || ''} ${category?.name || ''} ${category?.function || ''} ${nistFunctionLabel(category?.function)}`;
      }).join(' ');
    }
    if (Array.isArray(value)) return value.join(' ');
    if (value && typeof value === 'object') return JSON.stringify(value);
    return String(value ?? '');
  };

  const distinctRecordValues = (field) => [...new Set(state.records.map((record) => recordValue(record, field).trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));

  function conditionMatches(record, condition) {
    const actual = recordValue(record, condition.field).toLowerCase();
    const expected = String(condition.value || '').trim().toLowerCase();
    if (condition.operator === 'empty') return actual.trim() === '';
    if (condition.operator === 'not_empty') return actual.trim() !== '';
    if (!expected) return true;
    if (condition.operator === 'is') return actual === expected;
    if (condition.operator === 'is_not') return actual !== expected;
    if (condition.operator === 'includes') return actual.includes(expected);
    if (condition.operator === 'excludes') return !actual.includes(expected);
    if (condition.operator === 'starts') return actual.startsWith(expected);
    if (condition.operator === 'ends') return actual.endsWith(expected);
    return true;
  }

  function activeConditions(conditions) {
    return conditions.filter((condition) => condition.field && condition.operator && (['empty', 'not_empty'].includes(condition.operator) || String(condition.value || '').trim()));
  }

  function matchesAdvancedQuery(record) {
    const conditions = activeConditions(state.appliedQueryConditions);
    if (!conditions.length) return true;
    const groups = [[]];
    conditions.forEach((condition, index) => {
      if (index > 0 && condition.join === 'OR') groups.push([]);
      groups[groups.length - 1].push(condition);
    });
    return groups.some((group) => group.every((condition) => conditionMatches(record, condition)));
  }

  function queryExpressionText(conditions = state.queryConditions) {
    const active = activeConditions(conditions);
    if (!active.length) return 'No advanced conditions applied.';
    return active.map((condition, index) => {
      const field = QUERY_FIELDS[condition.field]?.label || condition.field;
      const operator = QUERY_OPERATORS.find(([value]) => value === condition.operator)?.[1] || condition.operator;
      const join = index ? `${condition.join || 'AND'} ` : '';
      const value = ['empty', 'not_empty'].includes(condition.operator) ? '' : ` "${String(condition.value).replace(/"/g, '\\"')}"`;
      return `${join}${field} ${operator}${value}`;
    }).join(' ');
  }

  async function api(action, options = {}) {
    const response = await fetch(`api.php?action=${encodeURIComponent(action)}`, {
      cache: 'no-store', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options,
    });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
      throw new Error(problem.error || `HTTP ${response.status}`);
    }
    return response.json();
  }

  async function evidenceApi(action, options = {}) {
    const response = await fetch(`api.php?action=${encodeURIComponent(action)}${options.query || ''}`, {
      cache: 'no-store', method: options.method || 'GET', body: options.body,
    });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
      throw new Error(problem.error || `HTTP ${response.status}`);
    }
    return response.json();
  }

  function readLocal(key) {
    try { return JSON.parse(localStorage.getItem(key) || '[]'); } catch { return []; }
  }

  async function loadSeedKnowledge() {
    const stored = readLocal(KB_LOCAL_KEY);
    if (stored.length) return stored;
    try {
      const response = await fetch('seed-knowledge.json', { cache: 'no-store' });
      return response.ok ? await response.json() : [];
    } catch { return []; }
  }

  async function loadRecords() {
    await loadFrameworkCatalogs();
    try {
      const incidents = await api('list');
      state.records = Array.isArray(incidents.records) ? incidents.records : [];
      state.storage = 'server';
      setConnection('Read-only snapshot, 2026-09-27', 'online');
      try {
        const knowledge = await api('kb-list');
        state.knowledge = Array.isArray(knowledge.records) ? knowledge.records : [];
      } catch {
        state.knowledge = await loadSeedKnowledge();
        toast('The knowledge store could not be read. Showing the local test article.', 'error');
      }
    } catch {
      state.records = readLocal(LOCAL_KEY);
      state.knowledge = await loadSeedKnowledge();
      state.storage = 'browser';
      setConnection('Browser storage mode', 'offline');
      toast('The SRV01 API is unavailable. Changes made here remain in this browser.', 'error');
    }
    render();
  }

  async function loadFrameworkCatalogs() {
    try {
      const catalogs = await api('framework-catalogs');
      if (!Array.isArray(catalogs.attack?.techniques) || !catalogs.attack?.attackVersion) throw new Error('invalid ATT&CK catalog');
      if (!Array.isArray(catalogs.nist?.categories) || !catalogs.nist?.version) throw new Error('invalid NIST catalog');
      catalogs.attack.byId = Object.fromEntries(catalogs.attack.techniques.map((technique) => [technique.id, technique]));
      catalogs.nist.byId = Object.fromEntries(catalogs.nist.categories.map((category) => [category.id, category]));
      state.attack = catalogs.attack;
      state.nist = catalogs.nist;
    } catch {
      state.attack = null;
      state.nist = null;
      toast('The framework catalogs could not be loaded. MITRE and NIST mapping are unavailable.', 'error');
    }
  }

  function techniqueById(id) { return state.attack?.byId?.[String(id || '').toUpperCase()] || null; }
  function nistCategoryById(id) { return state.nist?.byId?.[String(id || '').toUpperCase()] || null; }
  function nistFunctionLabel(id) { return state.nist?.functions?.[String(id || '').toUpperCase()] || id || 'Not recorded'; }

  function normalizedMitreEntries(record = {}) {
    if (Array.isArray(record.mitreTechniques)) {
      return record.mitreTechniques.filter((entry) => techniqueById(entry?.id)).map((entry) => ({ ...entry, id: String(entry.id).toUpperCase() }));
    }
    const ids = [...String(record.mitre || '').matchAll(/\bT\d{4}(?:\.\d{3})?\b/gi)].map((match) => match[0].toUpperCase());
    return [...new Set(ids)].filter(techniqueById).map((id) => ({ id, suggested: true, ...(record.sourceRule ? { ruleId: String(record.sourceRule) } : {}) }));
  }

  function normalizedNistEntries(record = {}) {
    if (Array.isArray(record.nistMappings)) {
      return record.nistMappings.map((entry) => ({ id: String(entry?.id || entry || '').toUpperCase() })).filter((entry) => nistCategoryById(entry.id));
    }
    const ids = [...String(record.nist || '').matchAll(/\b(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}\b/gi)].map((match) => match[0].toUpperCase());
    return [...new Set(ids)].filter(nistCategoryById).map((id) => ({ id }));
  }

  function tacticClass(technique) {
    const tactic = technique?.tactics?.[0];
    const index = Math.max(0, state.attack?.tacticOrder?.indexOf(tactic) ?? 0);
    return `tactic-${index % 15}`;
  }

  function tacticLabel(technique) {
    return (technique?.tactics || []).map((tactic) => state.attack?.tactics?.[tactic] || tactic).join(', ') || 'Tactic not recorded';
  }

  function mitreTechniqueUrl(id) {
    const match = String(id || '').toUpperCase().match(/^T(\d{4})(?:\.(\d{3}))?$/);
    if (!match) return 'https://attack.mitre.org/techniques/enterprise/';
    return `https://attack.mitre.org/techniques/T${match[1]}/${match[2] ? `${match[2]}/` : ''}`;
  }

  function nistCategoryUrl() { return NIST_CSF_REFERENCE_URL; }

  async function saveRecord(record) {
    if (state.storage === 'server') {
      const result = await api('save', { method: 'POST', body: JSON.stringify(record) });
      return result.record;
    }
    return saveLocal(record, 'incident');
  }

  async function saveKnowledge(record) {
    if (state.storage === 'server') {
      const result = await api('kb-save', { method: 'POST', body: JSON.stringify(record) });
      return result.record;
    }
    return saveLocal(record, 'knowledge');
  }

  function saveLocal(record, kind) {
    const collection = kind === 'knowledge' ? state.knowledge : state.records;
    const key = kind === 'knowledge' ? KB_LOCAL_KEY : LOCAL_KEY;
    const prefix = kind === 'knowledge' ? 'KB' : 'INC';
    const existing = collection.find((item) => item.id === record.id);
    const timestamp = new Date().toISOString();
    const saved = { ...record, id: record.id || nextLocalId(collection, prefix), createdAt: existing?.createdAt || timestamp, updatedAt: timestamp };
    localStorage.setItem(key, JSON.stringify(collection.filter((item) => item.id !== saved.id).concat(saved)));
    return saved;
  }

  function nextLocalId(collection, prefix) {
    const year = new Date().getFullYear();
    const max = collection.reduce((value, item) => {
      const match = String(item.id || '').match(new RegExp(`^${prefix}-${year}-(\\d+)$`));
      return match ? Math.max(value, Number(match[1])) : value;
    }, 0);
    return `${prefix}-${year}-${String(max + 1).padStart(4, '0')}`;
  }

  function setConnection(label, mode) {
    const element = $('#connectionState');
    element.className = `connection ${mode}`;
    element.innerHTML = `<i></i>${escapeHtml(label)}`;
  }

  function filteredRecords() {
    const query = state.search.trim().toLowerCase();
    const records = [...state.records].filter((record) => {
      if (state.view === 'active' && !ACTIVE_STATUSES.has(record.status)) return false;
      if (state.view === 'mine' && String(record.assignedTo).toLowerCase() !== 'johnny meintel') return false;
      if (state.view === 'resolved' && !CLOSED_STATUSES.has(record.status)) return false;
      if (state.view === 'drafts' && record.status !== 'Draft') return false;
      if (state.severity !== 'all' && record.severity !== state.severity) return false;
      if (state.status !== 'all' && record.status !== state.status) return false;
      if (state.category !== 'all' && (record.category || 'Uncategorized') !== state.category) return false;
      if (state.asset !== 'all' && record.primaryAsset !== state.asset) return false;
      if (!matchesAdvancedQuery(record)) return false;
      if (query && !JSON.stringify(record).toLowerCase().includes(query)) return false;
      return true;
    });
    return sortRecords(records);
  }

  function sortRecords(records) {
    const [field, direction] = String(state.sort || 'opened_desc').split('_');
    const multiplier = direction === 'asc' ? 1 : -1;
    const text = (value) => String(value || '').toLowerCase();
    const date = (value) => {
      const timestamp = new Date(value || 0).getTime();
      return Number.isNaN(timestamp) ? 0 : timestamp;
    };
    const incidentNumber = (record) => {
      const match = String(record.id || '').match(/INC-(\d{4})-(\d+)/i);
      return match ? (Number(match[1]) * 1000000) + Number(match[2]) : 0;
    };
    const compareText = (a, b) => text(a).localeCompare(text(b), undefined, { numeric: true, sensitivity: 'base' });
    return records.sort((a, b) => {
      let result = 0;
      if (field === 'number') result = incidentNumber(a) - incidentNumber(b);
      else if (field === 'status') result = STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status);
      else if (field === 'severity') result = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      else if (field === 'opened') result = date(a.openedAt || a.createdAt) - date(b.openedAt || b.createdAt);
      else if (field === 'category') result = compareText(a.category || 'Uncategorized', b.category || 'Uncategorized');
      else if (field === 'asset') result = compareText(a.primaryAsset || '', b.primaryAsset || '');
      else result = date(a.updatedAt || a.openedAt) - date(b.updatedAt || b.openedAt);
      return (result * multiplier) || (incidentNumber(b) - incidentNumber(a));
    });
  }

  function filteredKnowledge() {
    const query = state.search.trim().toLowerCase();
    return [...state.knowledge].filter((article) => {
      if (state.kbStatus !== 'all' && article.status !== state.kbStatus) return false;
      if (state.kbCategory !== 'all' && article.category !== state.kbCategory) return false;
      if (state.kbTag && !knowledgeTags(article).some((tag) => tag.toLowerCase() === state.kbTag.toLowerCase())) return false;
      if (query && !Object.values(article).join(' ').toLowerCase().includes(query)) return false;
      return true;
    }).sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
  }

  function render() {
    renderMetadataDatalists();
    renderMetrics();
    renderNavigationCounts();
    applyViewChrome();
    const routedIncident = incidentRoute();
    const routedArticle = knowledgeRoute();
    const routedFramework = frameworkRoute();
    const routedKnowledgeTag = knowledgeTagRoute();
    if (routedIncident) renderIncidentPage(routedIncident);
    else if (routedArticle) renderKnowledgeArticlePage(routedArticle);
    else if (routedFramework) { state.view = 'frameworks'; renderAnalytics(); }
    else if (routedKnowledgeTag) { state.view = 'knowledge'; state.kbTag = routedKnowledgeTag; renderKnowledge(); }
    else if (state.view === 'knowledge') renderKnowledge();
    else if (state.view === 'metrics' || state.view === 'frameworks') renderAnalytics();
    else renderQueue();
  }

  function applyViewChrome() {
    const incident = Boolean(incidentRoute());
    const knowledge = !incident && (state.view === 'knowledge' || Boolean(knowledgeRoute()) || Boolean(knowledgeTagRoute()));
    const recordPage = incident || Boolean(knowledgeRoute()) || Boolean(frameworkRoute());
    $('.page-heading').classList.toggle('hidden', recordPage || knowledge);
    $('.notice').classList.toggle('hidden', recordPage || knowledge);
    $('#globalSearch').placeholder = knowledge ? 'Search knowledge articles' : 'Search incidents';
    $('#exportAll').title = 'Export LabWatch data';
    $('#exportAll').setAttribute('aria-label', 'Export LabWatch data');
  }

  function renderMetrics() {
    $('#metricActive').textContent = state.records.filter((r) => ACTIVE_STATUSES.has(r.status)).length;
    $('#metricCritical').textContent = state.records.filter((r) => r.severity === 'Critical' && !CLOSED_STATUSES.has(r.status)).length;
    $('#metricReview').textContent = state.records.filter((r) => r.status === 'Monitoring').length;
    $('#metricResolved').textContent = state.records.filter((r) => CLOSED_STATUSES.has(r.status)).length;
  }

  function renderNavigationCounts() {
    $('#navAll').textContent = state.records.length;
    $('#navActive').textContent = state.records.filter((r) => ACTIVE_STATUSES.has(r.status)).length;
    $('#navMine').textContent = state.records.filter((r) => String(r.assignedTo).toLowerCase() === 'johnny meintel').length;
    $('#navResolved').textContent = state.records.filter((r) => CLOSED_STATUSES.has(r.status)).length;
    $('#navDrafts').textContent = state.records.filter((r) => r.status === 'Draft').length;
    $('#navKnowledge').textContent = state.knowledge.length;
  }

  function hideContentViews() {
    $('#queueView').classList.add('hidden');
    $('#analyticsView').classList.add('hidden');
    $('#knowledgeView').classList.add('hidden');
    $('#incidentRecordView').classList.add('hidden');
    $('#knowledgeArticleView').classList.add('hidden');
  }

  function renderQueue() {
    hideContentViews();
    $('#queueView').classList.remove('hidden');
    document.title = 'LabWatch';
    $('#metricGrid').classList.remove('hidden');
    renderQuickIncidentFilters();
    renderQueryBuilder();
    const records = filteredRecords();
    $('#resultSummary').textContent = `${records.length} ${records.length === 1 ? 'record' : 'records'}`;
    $('#incidentRows').innerHTML = records.map((record) => `
      <tr data-id="${escapeHtml(record.id)}" tabindex="0">
        <td><span class="incident-number">${escapeHtml(record.id)}</span></td>
        <td class="incident-title"><span class="incident-title-line"><span class="incident-title-copy">${escapeHtml(record.title)}</span>${record.origin === 'auto-ingest' ? '<span class="origin-badge">Auto</span>' : ''}</span><small>${escapeHtml(firstLine(record.conclusion || record.initialAlert))}</small></td>
        <td><span class="badge ${slug(record.severity)}">${escapeHtml(record.severity)}</span></td>
        <td><span class="badge status-badge ${slug(record.status)}">${escapeHtml(record.status)}</span></td>
        <td>${escapeHtml(record.category || 'Uncategorized')}</td><td>${escapeHtml(record.alertSource || 'Not recorded')}</td><td>${escapeHtml(record.primaryAsset || 'Not recorded')}</td>
        <td>${formatDate(record.openedAt || record.createdAt)}</td><td>${formatDate(record.updatedAt)}</td>
      </tr>`).join('');
    $('#emptyState').classList.toggle('hidden', records.length !== 0 || state.records.length !== 0);
    $('.table-wrap').classList.toggle('hidden', records.length === 0);
    if (state.records.length && records.length === 0) {
      $('#emptyState').classList.remove('hidden');
      $('#emptyState h3').textContent = 'No records match these filters';
      $('#emptyState p').textContent = 'Clear one or more filters to return to the complete incident queue.';
      $('#emptyCreate').classList.add('hidden');
    } else {
      $('#emptyState h3').textContent = 'No incidents recorded';
      $('#emptyState p').textContent = 'Complete a homelab exercise, preserve its evidence, then create the incident record from what actually happened.';
      $('#emptyCreate').classList.remove('hidden');
    }
    $$('#incidentRows tr').forEach((row) => {
      row.addEventListener('click', () => navigateToIncident(row.dataset.id));
      row.addEventListener('keydown', (event) => { if (event.key === 'Enter') navigateToIncident(row.dataset.id); });
    });
  }

  function setFilterOptions(select, values, allLabel, selected) {
    const choices = [...new Set(values.filter(Boolean))];
    select.innerHTML = `<option value="all">${escapeHtml(allLabel)}</option>` + choices.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
    select.value = selected === 'all' || choices.includes(selected) ? selected : 'all';
    return select.value;
  }

  function renderQuickIncidentFilters() {
    const recordedCategories = distinctRecordValues('category');
    state.category = setFilterOptions($('#categoryFilter'), [...INCIDENT_CATEGORIES, ...recordedCategories], 'All categories', state.category);
    state.asset = setFilterOptions($('#assetFilter'), distinctRecordValues('primaryAsset'), 'All hosts', state.asset);
    $('#queueSort').value = state.sort;
  }

  function renderMetadataDatalists() {
    const sets = [
      ['#assetOptions', 'primaryAsset'], ['#identityOptions', 'affectedUser'], ['#sourceAddressOptions', 'sourceAddress'],
    ];
    sets.forEach(([selector, field]) => {
      $(selector).innerHTML = distinctRecordValues(field).map((value) => `<option value="${escapeHtml(value)}"></option>`).join('');
    });
  }

  function queryValueControl(condition, index) {
    if (['empty', 'not_empty'].includes(condition.operator)) return '<span class="query-no-value">No value needed</span>';
    const metadata = QUERY_FIELDS[condition.field] || {};
    const values = metadata.options || distinctRecordValues(condition.field);
    if (metadata.options) {
      return `<select data-query-value="${index}"><option value="">Select value</option>${values.map((value) => `<option value="${escapeHtml(value)}"${condition.value === value ? ' selected' : ''}>${escapeHtml(value)}</option>`).join('')}</select>`;
    }
    const listId = `query-values-${index}`;
    return `<input data-query-value="${index}" list="${listId}" value="${escapeHtml(condition.value || '')}" placeholder="Enter or select a value"><datalist id="${listId}">${values.map((value) => `<option value="${escapeHtml(value)}"></option>`).join('')}</datalist>`;
  }

  function renderQueryBuilder() {
    const rows = $('#queryRows');
    rows.innerHTML = state.queryConditions.length ? state.queryConditions.map((condition, index) => {
      const join = index === 0 ? '<span class="query-where">WHERE</span>' : `<select data-query-join="${index}" aria-label="Boolean operator"><option${condition.join !== 'OR' ? ' selected' : ''}>AND</option><option${condition.join === 'OR' ? ' selected' : ''}>OR</option></select>`;
      const fields = Object.entries(QUERY_FIELDS).map(([value, metadata]) => `<option value="${value}"${condition.field === value ? ' selected' : ''}>${escapeHtml(metadata.label)}</option>`).join('');
      const operators = QUERY_OPERATORS.map(([value, label]) => `<option value="${value}"${condition.operator === value ? ' selected' : ''}>${escapeHtml(label)}</option>`).join('');
      return `<div class="query-row">${join}<select data-query-field="${index}" aria-label="Field">${fields}</select><select data-query-operator="${index}" aria-label="Operator">${operators}</select><div class="query-value">${queryValueControl(condition, index)}</div><button class="query-remove" data-query-remove="${index}" type="button" aria-label="Remove condition">×</button></div>`;
    }).join('') : '<div class="query-empty">Add a condition to build a metadata query.</div>';
    $('#queryExpression').textContent = queryExpressionText();
    const appliedCount = activeConditions(state.appliedQueryConditions).length;
    $('#queryConditionCount').textContent = appliedCount;
    $('#toggleQueryBuilder').classList.toggle('active', appliedCount > 0);

    $$('[data-query-join]', rows).forEach((select) => select.addEventListener('change', () => { state.queryConditions[Number(select.dataset.queryJoin)].join = select.value; $('#queryExpression').textContent = queryExpressionText(); }));
    $$('[data-query-field]', rows).forEach((select) => select.addEventListener('change', () => { const condition = state.queryConditions[Number(select.dataset.queryField)]; condition.field = select.value; condition.value = ''; renderQueryBuilder(); }));
    $$('[data-query-operator]', rows).forEach((select) => select.addEventListener('change', () => { const condition = state.queryConditions[Number(select.dataset.queryOperator)]; condition.operator = select.value; renderQueryBuilder(); }));
    $$('[data-query-value]', rows).forEach((input) => input.addEventListener('input', () => { state.queryConditions[Number(input.dataset.queryValue)].value = input.value; $('#queryExpression').textContent = queryExpressionText(); }));
    $$('[data-query-remove]', rows).forEach((button) => button.addEventListener('click', () => { state.queryConditions.splice(Number(button.dataset.queryRemove), 1); renderQueryBuilder(); }));
  }

  function renderKnowledge() {
    hideContentViews();
    $('#knowledgeView').classList.remove('hidden');
    $('#metricGrid').classList.add('hidden');
    document.title = 'Knowledge base | LabWatch';
    const categories = [...new Set(state.knowledge.map((item) => item.category).filter(Boolean))].sort();
    const category = $('#kbCategoryFilter');
    category.innerHTML = '<option value="all">All categories</option>' + categories.map((item) => `<option value="${escapeHtml(item)}">${escapeHtml(item)}</option>`).join('');
    category.value = categories.includes(state.kbCategory) ? state.kbCategory : 'all';
    state.kbCategory = category.value;
    const articles = filteredKnowledge();
    $('#kbResultSummary').textContent = `${articles.length} ${articles.length === 1 ? 'article' : 'articles'}${state.kbTag ? ` tagged ${state.kbTag}` : ''}`;
    const tagFilter = $('#kbTagFilter');
    tagFilter.classList.toggle('hidden', !state.kbTag);
    tagFilter.innerHTML = state.kbTag ? `<span>Tag filter</span><strong>${escapeHtml(state.kbTag)}</strong><button type="button" data-clear-kb-tag>Clear</button>` : '';
    $('#knowledgeCards').innerHTML = articles.map((article) => {
      const linked = linkedIncidentsForArticle(article);
      return `<article class="kb-card" data-kb-id="${escapeHtml(article.id)}" tabindex="0">
        <div class="kb-card-top"><span class="incident-number">${escapeHtml(article.id)}</span><span class="kb-status ${slug(article.status)}">${escapeHtml(article.status)}</span></div>
        <h3>${escapeHtml(article.title)}</h3><p>${escapeHtml(article.summary || 'No summary recorded.')}</p>
        <div class="kb-card-meta"><span>${escapeHtml(article.category || 'Uncategorized')}</span><span>${linked.length} linked ${linked.length === 1 ? 'incident' : 'incidents'}</span><span>Updated ${formatDate(article.updatedAt)}</span></div>
      </article>`;
    }).join('');
    $('#kbEmptyState').classList.toggle('hidden', articles.length !== 0);
    $$('#knowledgeCards .kb-card').forEach((card) => {
      card.addEventListener('click', () => navigateToKnowledge(card.dataset.kbId));
      card.addEventListener('keydown', (event) => { if (event.key === 'Enter') navigateToKnowledge(card.dataset.kbId); });
    });
    $('[data-clear-kb-tag]', tagFilter)?.addEventListener('click', () => {
      state.kbTag = '';
      history.pushState(null, '', `${window.location.pathname}${window.location.search}`);
      render();
    });
  }

  function knowledgeRoute() {
    const match = window.location.hash.match(/^#\/kb\/(KB-\d{4}-\d{4})$/i);
    if (!match) return null;
    return state.knowledge.find((article) => article.id.toUpperCase() === match[1].toUpperCase()) || null;
  }

  function knowledgeTagRoute() {
    const match = window.location.hash.match(/^#\/knowledge\/tag\/(.+)$/i);
    if (!match) return '';
    try { return decodeURIComponent(match[1]).trim(); } catch { return ''; }
  }

  function incidentRoute() {
    const match = window.location.hash.match(/^#\/inc\/(INC-\d{4}-\d{4})$/i);
    if (!match) return null;
    return state.records.find((record) => record.id.toUpperCase() === match[1].toUpperCase()) || null;
  }

  function frameworkRoute() {
    const match = window.location.hash.match(/^#\/framework\/(mitre|nist)\/((?:T\d{4}(?:\.\d{3})?)|(?:(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}))$/i);
    return match ? { family: match[1].toLowerCase(), id: match[2].toUpperCase() } : null;
  }

  function navigateToIncident(id) {
    const nextHash = `#/inc/${encodeURIComponent(id)}`;
    if (window.location.hash === nextHash) render();
    else window.location.hash = nextHash;
  }

  function leaveIncidentPage() {
    history.pushState(null, '', `${window.location.pathname}${window.location.search}`);
    state.view = 'all';
    $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === 'all'));
    render();
  }

  function navigateToKnowledge(id) {
    const nextHash = `#/kb/${encodeURIComponent(id)}`;
    if (window.location.hash === nextHash) render();
    else window.location.hash = nextHash;
  }

  function navigateToKnowledgeTag(tag) {
    const nextHash = `#/knowledge/tag/${encodeURIComponent(tag)}`;
    if (window.location.hash === nextHash) render();
    else window.location.hash = nextHash;
  }

  function leaveKnowledgeArticle() {
    state.view = 'knowledge';
    $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === 'knowledge'));
    if (state.kbTag) window.location.hash = `#/knowledge/tag/${encodeURIComponent(state.kbTag)}`;
    else {
      history.pushState(null, '', `${window.location.pathname}${window.location.search}`);
      render();
    }
  }

  function knowledgeTags(article) {
    return [...new Set(String(article?.tags || '').split(/[,\r\n]+/).map((tag) => tag.trim()).filter(Boolean))];
  }

  function renderKnowledgeInline(value) {
    return escapeHtml(value)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g, '<em>$1</em>');
  }

  function renderKnowledgeBody(value) {
    const lines = String(value || '').replace(/\r\n?/g, '\n').split('\n');
    const output = [];
    let paragraph = [];
    let listType = '';
    let listItems = [];
    let quoteLines = [];
    let inCode = false;
    let codeLines = [];

    const flushParagraph = () => {
      if (!paragraph.length) return;
      output.push(`<p>${paragraph.map(renderKnowledgeInline).join(' ')}</p>`);
      paragraph = [];
    };
    const flushList = () => {
      if (!listItems.length) return;
      output.push(`<${listType}>${listItems.map((item) => `<li>${renderKnowledgeInline(item)}</li>`).join('')}</${listType}>`);
      listType = '';
      listItems = [];
    };
    const flushQuote = () => {
      if (!quoteLines.length) return;
      output.push(`<blockquote>${quoteLines.map((line) => `<p>${renderKnowledgeInline(line)}</p>`).join('')}</blockquote>`);
      quoteLines = [];
    };
    const flushText = () => { flushParagraph(); flushList(); flushQuote(); };

    lines.forEach((line) => {
      const fence = line.match(/^\s*```/);
      if (inCode) {
        if (fence) {
          output.push(`<pre><code>${escapeHtml(codeLines.join('\n'))}</code></pre>`);
          codeLines = [];
          inCode = false;
        } else codeLines.push(line);
        return;
      }
      if (fence) {
        flushText();
        inCode = true;
        return;
      }
      if (!line.trim()) {
        flushText();
        return;
      }
      const heading = line.match(/^\s*(#{1,6})\s+(.+)$/);
      if (heading) {
        flushText();
        const level = Math.min(6, Math.max(3, heading[1].length + 1));
        output.push(`<h${level}>${renderKnowledgeInline(heading[2].trim())}</h${level}>`);
        return;
      }
      if (/^\s*(?:---+|___+|\*\*\*+)\s*$/.test(line)) {
        flushText();
        output.push('<hr>');
        return;
      }
      const unordered = line.match(/^\s*[-+*]\s+(.+)$/);
      const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
      if (unordered || ordered) {
        flushParagraph();
        flushQuote();
        const nextType = ordered ? 'ol' : 'ul';
        if (listType && listType !== nextType) flushList();
        listType = nextType;
        listItems.push((ordered || unordered)[1]);
        return;
      }
      const quote = line.match(/^\s*>\s?(.*)$/);
      if (quote) {
        flushParagraph();
        flushList();
        quoteLines.push(quote[1]);
        return;
      }
      flushList();
      flushQuote();
      paragraph.push(line.trim());
    });
    if (inCode) output.push(`<pre><code>${escapeHtml(codeLines.join('\n'))}</code></pre>`);
    flushText();
    return output.join('') || '<p>Not recorded</p>';
  }

  function renderKnowledgeReferences(article, family) {
    const ids = knowledgeFrameworkIds(article, family);
    const raw = String(family === 'mitre' ? article.mitre || '' : article.nist || '');
    if (!ids.length) return renderKnowledgeBody(raw || 'Not recorded');
    const label = family === 'mitre' ? 'MITRE ATT&CK' : 'NIST CSF 2.0';
    const cards = ids.map((id) => {
      const reference = family === 'mitre' ? techniqueById(id) : nistCategoryById(id);
      const group = family === 'mitre' ? tacticLabel(reference) : nistFunctionLabel(reference.function);
      const official = family === 'mitre' ? mitreTechniqueUrl(id) : nistCategoryUrl(id);
      const route = `#/framework/${family}/${encodeURIComponent(id)}`;
      return `<div class="kb-reference-card"><div><span>${escapeHtml(id)}</span><strong>${escapeHtml(reference.name)}</strong><small>${escapeHtml(group)}</small></div><div><a href="${route}">Related records</a><a href="${escapeHtml(official)}" target="_blank" rel="noopener noreferrer">Official ${escapeHtml(label)} reference ↗</a></div></div>`;
    }).join('');
    return `<div class="kb-reference-list">${cards}</div>${raw ? `<details class="kb-reference-source"><summary>Authored reference notes</summary>${renderKnowledgeBody(raw)}</details>` : ''}`;
  }

  function renderKnowledgeTags(article) {
    const tags = knowledgeTags(article);
    if (!tags.length) return '<p>Not recorded</p>';
    return `<div class="kb-tag-list">${tags.map((tag) => `<button type="button" data-kb-tag="${escapeHtml(tag)}">#${escapeHtml(tag)}</button>`).join('')}</div>`;
  }

  function renderKnowledgeSection(article, title, value, kind = 'body') {
    const empty = !String(value || '').trim();
    let content = renderKnowledgeBody(value || 'Not recorded');
    if (kind === 'mitre' || kind === 'nist') content = renderKnowledgeReferences(article, kind);
    if (kind === 'tags') content = renderKnowledgeTags(article);
    if (kind === 'first-incident') {
      const first = firstIncidentForArticle(article);
      content = first ? `<p><a href="#/inc/${encodeURIComponent(first.id)}">${escapeHtml(first.id)}</a>: ${escapeHtml(first.title)}</p><p>First occurrence: ${formatDate(first.openedAt || first.createdAt)}.</p>` : '<p>No incident recorded.</p>';
    }
    return `<section class="kb-content-section${empty ? ' empty' : ''}"><h2>${escapeHtml(title)}</h2><div class="kb-rich-body">${content}</div></section>`;
  }

  function renderKnowledgeArticlePage(article) {
    hideContentViews();
    $('#metricGrid').classList.add('hidden');
    $('#knowledgeArticleView').classList.remove('hidden');
    state.view = 'knowledge';
    document.title = `${article.id} | ${article.title} | LabWatch`;
    $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === 'knowledge'));
    const linked = linkedIncidentsForArticle(article);
    const sections = [
      ['Summary', article.summary, 'body'], ['Purpose and scope', article.purpose, 'body'], ['Prerequisites', article.prerequisites, 'body'],
      ['Article body', article.content, 'body'], ['First Incident', 'First Incident', 'first-incident'], ['Validation', article.validation, 'body'], ['Escalation and exceptions', article.escalation, 'body'],
      ['MITRE ATT&CK references', article.mitre, 'mitre'], ['NIST references', article.nist, 'nist'], ['Tags', article.tags, 'tags'],
    ];
    $('#knowledgeArticleView').innerHTML = `
      <header class="kb-page-header">
        <button class="kb-back" data-kb-action="back"><span>←</span> Knowledge base</button>
        <div class="kb-page-heading"><div><p class="eyebrow">${escapeHtml(article.id)}</p><h1>${escapeHtml(article.title)}</h1></div><span class="kb-status ${slug(article.status)}">${escapeHtml(article.status)}</span></div>
        <div class="detail-actions"><button class="primary-button" data-kb-action="edit">Edit article</button><button class="secondary-button" data-kb-action="copy">Copy link</button><button class="secondary-button" data-kb-action="export">Export JSON</button><button class="secondary-button" data-kb-action="print">Print article</button></div>
      </header>
      <div class="kb-page-summary"><div><span>Status</span><strong>${escapeHtml(article.status)}</strong></div><div><span>Type</span><strong>${escapeHtml(article.articleType || 'Not recorded')}</strong></div><div><span>Category</span><strong>${escapeHtml(article.category)}</strong></div><div><span>Audience</span><strong>${escapeHtml(article.audience || 'Not recorded')}</strong></div><div><span>Author</span><strong>${escapeHtml(article.author || 'Not recorded')}</strong></div><div><span>Reviewer</span><strong>${escapeHtml(article.reviewedBy || 'Not reviewed')}</strong></div><div><span>Review date</span><strong>${escapeHtml(article.reviewDate || 'Not scheduled')}</strong></div><div><span>Updated</span><strong>${formatDate(article.updatedAt)}</strong></div></div>
      <div class="kb-page-layout">
        <aside class="kb-page-rail"><h2>Article details</h2>${relationSection('Linked incidents', linked, 'data-open-incident', 'No incidents linked.')}${renderAudit(article)}<div class="record-integrity"><span>✓</span><div>Created ${formatDate(article.createdAt)}.<br>Updated ${formatDate(article.updatedAt)}.</div></div>${renderHashStatus(article)}</aside>
        <div class="kb-page-content">${sections.map(([title, value, kind]) => renderKnowledgeSection(article, title, value, kind)).join('')}</div>
      </div>`;
    $('[data-kb-action="back"]').addEventListener('click', leaveKnowledgeArticle);
    $('[data-kb-action="edit"]').addEventListener('click', () => openKnowledgeEditor(article));
    $('[data-kb-action="copy"]').addEventListener('click', copyKnowledgeLink);
    $('[data-kb-action="export"]').addEventListener('click', () => downloadJson(`${article.id}.json`, article));
    $('[data-kb-action="print"]').addEventListener('click', () => window.print());
    $$('[data-open-incident]', $('#knowledgeArticleView')).forEach((button) => button.addEventListener('click', () => navigateToIncident(button.dataset.openIncident)));
    $$('[data-kb-tag]', $('#knowledgeArticleView')).forEach((button) => button.addEventListener('click', () => navigateToKnowledgeTag(button.dataset.kbTag)));
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  async function copyKnowledgeLink() {
    try {
      await navigator.clipboard.writeText(window.location.href);
      toast('Knowledge article link copied.');
    } catch {
      toast(`Copy this link: ${window.location.href}`);
    }
  }

  function renderAnalytics() {
    hideContentViews();
    $('#analyticsView').classList.remove('hidden');
    $('#metricGrid').classList.toggle('hidden', state.view === 'frameworks');
    const target = $('#analyticsView');
    if (state.view === 'metrics') {
      if (!state.records.length) {
        target.innerHTML = '<section class="analytics-card framework-empty"><div><strong>No incident evidence is available yet</strong>Metrics will be calculated from recorded incidents.</div></section>';
        return;
      }
      target.innerHTML = chartCard('Incidents by severity', countsFor('severity')) + chartCard('Incidents by category', countsFor('category')) + chartCard('Incidents by classification', countsFor('classification')) + chartCard('Incidents by alert source', countsFor('alertSource'));
      return;
    }
    renderFrameworkWorkspace(target);
  }

  function knowledgeFrameworkIds(article, family) {
    const text = String(family === 'mitre' ? article.mitre || '' : article.nist || '');
    const pattern = family === 'mitre' ? /\bT\d{4}(?:\.\d{3})?\b/gi : /\b(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}\b/gi;
    const ids = [...text.matchAll(pattern)].map((match) => match[0].toUpperCase());
    return [...new Set(ids)].filter((id) => family === 'mitre' ? techniqueById(id) : nistCategoryById(id));
  }

  function frameworkInventory() {
    const mappings = new Map();
    const ensure = (family, id) => {
      const key = `${family}:${id}`;
      if (!mappings.has(key)) {
        const reference = family === 'mitre' ? techniqueById(id) : nistCategoryById(id);
        if (!reference) return null;
        mappings.set(key, {
          key, family, id, name: reference.name,
          group: family === 'mitre' ? tacticLabel(reference) : nistFunctionLabel(reference.function),
          incidents: [], knowledge: [],
        });
      }
      return mappings.get(key);
    };
    state.records.forEach((record) => {
      normalizedMitreEntries(record).filter((entry) => !entry.suggested).forEach((entry) => ensure('mitre', entry.id)?.incidents.push(record));
      normalizedNistEntries(record).forEach((entry) => ensure('nist', entry.id)?.incidents.push(record));
    });
    state.knowledge.forEach((article) => {
      knowledgeFrameworkIds(article, 'mitre').forEach((id) => ensure('mitre', id)?.knowledge.push(article));
      knowledgeFrameworkIds(article, 'nist').forEach((id) => ensure('nist', id)?.knowledge.push(article));
    });
    return [...mappings.values()].map((entry) => ({ ...entry, count: entry.incidents.length + entry.knowledge.length }))
      .sort((a, b) => b.count - a.count || a.family.localeCompare(b.family) || a.id.localeCompare(b.id));
  }

  function frameworkRouteUrl(entry) { return `#/framework/${entry.family}/${encodeURIComponent(entry.id)}`; }

  function frameworkOfficialUrl(entry) {
    return entry.family === 'mitre' ? mitreTechniqueUrl(entry.id) : nistCategoryUrl(entry.id);
  }

  function frameworkBarChart(entries) {
    if (!entries.length) return '<div class="framework-chart-empty">No mapped records match this view.</div>';
    const max = Math.max(...entries.map((entry) => entry.count), 1);
    return `<div class="framework-bar-chart">${entries.map((entry) => `<a class="framework-bar-row" href="${frameworkRouteUrl(entry)}" target="_blank" rel="noopener noreferrer"><span class="framework-bar-label"><strong>${escapeHtml(entry.id)}</strong><span>${escapeHtml(entry.name)}</span></span><span class="framework-bar-track"><i class="${entry.family}" style="width:${Math.max(4, (entry.count / max) * 100)}%"></i></span><span class="framework-bar-count">${entry.count}</span></a>`).join('')}</div>`;
  }

  function frameworkDonutChart(entries) {
    if (!entries.length) return '<div class="framework-chart-empty">No mapped records match this view.</div>';
    const colors = ['#4dc6c6', '#58a6ff', '#a78bfa', '#efb64c', '#50cf8f', '#ff7f98', '#6ba4ef', '#dd83d7'];
    const total = entries.reduce((sum, entry) => sum + entry.count, 0) || 1;
    let cursor = 0;
    const segments = entries.map((entry, index) => {
      const start = cursor;
      cursor += (entry.count / total) * 100;
      return `${colors[index % colors.length]} ${start}% ${cursor}%`;
    }).join(', ');
    return `<div class="framework-donut-layout"><div class="framework-donut" style="background:conic-gradient(${segments})"><span><strong>${total}</strong>references</span></div><div class="framework-donut-legend">${entries.map((entry, index) => `<a href="${frameworkRouteUrl(entry)}" target="_blank" rel="noopener noreferrer"><i style="background:${colors[index % colors.length]}"></i><span><strong>${escapeHtml(entry.id)}</strong>${escapeHtml(entry.name)}</span><b>${entry.count}</b></a>`).join('')}</div></div>`;
  }

  function frameworkTimelineChart(entries) {
    const allowed = new Set(entries.map((entry) => entry.key));
    const byDate = new Map();
    state.records.forEach((record) => {
      const dateValue = new Date(record.openedAt || record.createdAt || '');
      if (Number.isNaN(dateValue.getTime())) return;
      const date = dateValue.toISOString().slice(0, 10);
      if (!byDate.has(date)) byDate.set(date, { mitre: 0, nist: 0 });
      const bucket = byDate.get(date);
      normalizedMitreEntries(record).filter((entry) => !entry.suggested && allowed.has(`mitre:${entry.id}`)).forEach(() => { bucket.mitre += 1; });
      normalizedNistEntries(record).filter((entry) => allowed.has(`nist:${entry.id}`)).forEach(() => { bucket.nist += 1; });
    });
    const dates = [...byDate.keys()].sort();
    if (!dates.length) return '<div class="framework-chart-empty">No mapped incident dates match this view.</div>';
    const width = 760; const height = 230; const left = 42; const right = 18; const top = 18; const bottom = 38;
    const values = dates.flatMap((date) => [byDate.get(date).mitre, byDate.get(date).nist]);
    const max = Math.max(...values, 1);
    const x = (index) => dates.length === 1 ? (left + width - right) / 2 : left + (index / (dates.length - 1)) * (width - left - right);
    const y = (value) => top + (1 - value / max) * (height - top - bottom);
    const points = (family) => dates.map((date, index) => `${x(index).toFixed(1)},${y(byDate.get(date)[family]).toFixed(1)}`).join(' ');
    const circles = (family, color) => dates.map((date, index) => `<circle cx="${x(index).toFixed(1)}" cy="${y(byDate.get(date)[family]).toFixed(1)}" r="4" fill="${color}"><title>${escapeHtml(date)}: ${byDate.get(date)[family]} ${family.toUpperCase()} references</title></circle>`).join('');
    const labelIndexes = [...new Set([0, Math.floor((dates.length - 1) / 2), dates.length - 1])];
    return `<div class="framework-timeline"><div class="framework-line-legend"><span class="mitre">MITRE ATT&amp;CK</span><span class="nist">NIST CSF</span></div><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Mapped incident references by opened date"><line x1="${left}" y1="${height - bottom}" x2="${width - right}" y2="${height - bottom}" class="axis"></line><line x1="${left}" y1="${top}" x2="${left}" y2="${height - bottom}" class="axis"></line><text x="${left - 8}" y="${top + 4}" text-anchor="end">${max}</text><text x="${left - 8}" y="${height - bottom + 4}" text-anchor="end">0</text><polyline points="${points('mitre')}" class="line mitre"></polyline><polyline points="${points('nist')}" class="line nist"></polyline>${circles('mitre', '#58a6ff')}${circles('nist', '#4dc6c6')}${labelIndexes.map((index) => `<text x="${x(index).toFixed(1)}" y="${height - 12}" text-anchor="middle">${escapeHtml(dates[index].slice(5))}</text>`).join('')}</svg></div>`;
  }

  function frameworkRecordCard(record, kind) {
    const route = kind === 'incident' ? `#/inc/${encodeURIComponent(record.id)}` : `#/kb/${encodeURIComponent(record.id)}`;
    const meta = kind === 'incident' ? `${record.status || 'Not recorded'} · ${record.severity || 'Not assessed'}` : `${record.status || 'Not recorded'} · ${record.articleType || 'Article'}`;
    return `<a class="framework-result-card" href="${route}"><span>${escapeHtml(record.id)}</span><strong>${escapeHtml(record.title)}</strong><small>${escapeHtml(meta)}</small></a>`;
  }

  function renderFrameworkSelection(entry) {
    if (!entry) return '<section class="framework-selection-empty"><strong>Select a mapping to inspect its records</strong><p>Every mapping card opens an addressable result in a new tab with matching incidents and knowledge articles.</p></section>';
    const label = entry.family === 'mitre' ? 'MITRE ATT&CK' : 'NIST CSF 2.0';
    return `<section class="framework-selection"><header><div><p class="eyebrow">${escapeHtml(label)} records</p><h2><span>${escapeHtml(entry.id)}</span> ${escapeHtml(entry.name)}</h2><p>${escapeHtml(entry.group)} · ${entry.incidents.length} incidents · ${entry.knowledge.length} knowledge articles</p></div><div><a class="secondary-button" href="${escapeHtml(frameworkOfficialUrl(entry))}" target="_blank" rel="noopener noreferrer">Official reference ↗</a><button class="secondary-button" type="button" data-clear-framework>Back to coverage</button></div></header><div class="framework-result-columns"><section><h3>Incidents</h3><div class="framework-result-list">${entry.incidents.length ? entry.incidents.map((record) => frameworkRecordCard(record, 'incident')).join('') : '<p>No incident records carry this confirmed mapping.</p>'}</div></section><section><h3>Knowledge articles</h3><div class="framework-result-list">${entry.knowledge.length ? entry.knowledge.map((article) => frameworkRecordCard(article, 'knowledge')).join('') : '<p>No knowledge articles reference this mapping.</p>'}</div></section></div></section>`;
  }

  function renderFrameworkWorkspace(target) {
    document.title = 'Framework coverage | LabWatch';
    $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === 'frameworks'));
    const inventory = frameworkInventory();
    const needle = state.frameworkSearch.trim().toLowerCase();
    const entries = inventory.filter((entry) => (state.frameworkFamily === 'all' || entry.family === state.frameworkFamily) && (!needle || `${entry.id} ${entry.name} ${entry.group}`.toLowerCase().includes(needle)));
    const route = frameworkRoute();
    let selected = route ? inventory.find((entry) => entry.family === route.family && entry.id === route.id) : null;
    if (route && !selected) {
      const reference = route.family === 'mitre' ? techniqueById(route.id) : nistCategoryById(route.id);
      if (reference) selected = { family: route.family, id: route.id, name: reference.name, group: route.family === 'mitre' ? tacticLabel(reference) : nistFunctionLabel(reference.function), incidents: [], knowledge: [], count: 0 };
    }
    if (route && selected) {
      document.title = `${selected.id} | Framework records | LabWatch`;
      target.innerHTML = `<section class="framework-query-page">${renderFrameworkSelection(selected)}</section>`;
      $$('[data-clear-framework]', target).forEach((button) => button.addEventListener('click', () => {
        history.pushState(null, '', `${window.location.pathname}${window.location.search}`);
        state.view = 'frameworks';
        renderAnalytics();
      }));
      return;
    }
    const mappedIncidents = new Set(inventory.flatMap((entry) => entry.incidents.map((record) => record.id))).size;
    const mappedKnowledge = new Set(inventory.flatMap((entry) => entry.knowledge.map((record) => record.id))).size;
    const chart = state.frameworkChart === 'donut' ? frameworkDonutChart(entries) : state.frameworkChart === 'timeline' ? frameworkTimelineChart(entries) : frameworkBarChart(entries);
    target.innerHTML = `<section class="framework-workspace"><header class="framework-header"><div><p class="eyebrow">Evidence mapping explorer</p><h1>Framework coverage</h1><p>Query confirmed mappings across incident records and knowledge articles. Rule suggestions do not count as coverage.</p></div><div class="framework-summary"><span><strong>${inventory.length}</strong>mapped controls</span><span><strong>${mappedIncidents}</strong>incidents</span><span><strong>${mappedKnowledge}</strong>KB articles</span></div></header><div class="framework-toolbar"><label><span>Framework</span><select id="frameworkFamily"><option value="all"${state.frameworkFamily === 'all' ? ' selected' : ''}>MITRE and NIST</option><option value="mitre"${state.frameworkFamily === 'mitre' ? ' selected' : ''}>MITRE ATT&CK</option><option value="nist"${state.frameworkFamily === 'nist' ? ' selected' : ''}>NIST CSF 2.0</option></select></label><label class="framework-search"><span>Find mapping</span><input id="frameworkSearch" type="search" value="${escapeHtml(state.frameworkSearch)}" placeholder="ID, name, or function"></label><div class="framework-chart-switch" aria-label="Chart type"><button type="button" data-framework-chart="bar" class="${state.frameworkChart === 'bar' ? 'active' : ''}">Bars</button><button type="button" data-framework-chart="donut" class="${state.frameworkChart === 'donut' ? 'active' : ''}">Donut</button><button type="button" data-framework-chart="timeline" class="${state.frameworkChart === 'timeline' ? 'active' : ''}">Timeline</button></div></div><section class="framework-visual"><div class="framework-visual-heading"><div><h2>${state.frameworkChart === 'timeline' ? 'Mapped incident references over time' : 'Mapping references'}</h2><p>${entries.length} mappings shown. Counts combine matching incidents and KB articles except in the incident-only timeline.</p></div></div>${chart}</section></section>`;
    $('#frameworkFamily').addEventListener('change', (event) => { state.frameworkFamily = event.target.value; renderAnalytics(); });
    $('#frameworkSearch').addEventListener('input', (event) => { state.frameworkSearch = event.target.value; const cursor = event.target.selectionStart; renderAnalytics(); const input = $('#frameworkSearch'); input.focus(); input.setSelectionRange(cursor, cursor); });
    $$('[data-framework-chart]').forEach((button) => button.addEventListener('click', () => { state.frameworkChart = button.dataset.frameworkChart; renderAnalytics(); }));
  }

  function countsFor(field) {
    return state.records.reduce((counts, record) => { const key = record[field] || 'Not recorded'; counts[key] = (counts[key] || 0) + 1; return counts; }, {});
  }

  function chartCard(title, counts) {
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    if (!entries.length) return `<section class="analytics-card"><h2>${escapeHtml(title)}</h2><p class="detail-section">No confirmed mappings recorded.</p></section>`;
    const max = Math.max(...entries.map((entry) => entry[1]), 1);
    return `<section class="analytics-card"><h2>${escapeHtml(title)}</h2>${entries.map(([label, count]) => `<div class="bar-row"><span>${escapeHtml(label)}</span><div class="bar-track"><div class="bar-fill" style="width:${(count / max) * 100}%"></div></div><strong>${count}</strong></div>`).join('')}</section>`;
  }

  function renderRelationPicker(container, records, selected, name, emptyMessage) {
    const chosen = new Set(Array.isArray(selected) ? selected : []);
    container.innerHTML = records.length ? records.map((record) => `<label class="relation-option"><input type="checkbox" name="${name}" value="${escapeHtml(record.id)}"${chosen.has(record.id) ? ' checked' : ''}><span><strong>${escapeHtml(record.id)}</strong>${escapeHtml(record.title)}</span></label>`).join('') : `<p>${escapeHtml(emptyMessage)}</p>`;
  }

  function openEditor(record = null) {
    if (state.incidentBusy) return;
    state.editorVersion += 1;
    state.pendingEvidence = [];
    state.unverifiedEvidence = [];
    const form = $('#incidentForm');
    form.reset();
    renderMetadataDatalists();
    $('#editorTitle').textContent = record ? `Edit ${record.id}` : 'New incident';
    if (record) {
      Object.entries(record).forEach(([key, value]) => {
        const field = form.elements.namedItem(key);
        if (field && typeof value !== 'object') field.value = value ?? '';
      });
      $('#integrityConfirm').checked = Boolean(record.integrityConfirmed);
    } else {
      form.elements.namedItem('status').value = 'Draft';
      form.elements.namedItem('assignedTo').value = 'Johnny Meintel';
      form.elements.namedItem('openedAt').value = nowForInput();
      form.elements.namedItem('category').value = 'Uncategorized';
      form.elements.namedItem('subcategory').value = 'Unspecified';
      form.elements.namedItem('environment').value = 'Homelab';
      form.elements.namedItem('detectionMethod').value = 'Analyst-created';
      form.elements.namedItem('assignmentGroup').value = 'SOC Operations';
      form.elements.namedItem('requestChannel').value = 'Self-service portal';
    }
    state.editingMitre = normalizedMitreEntries(record || {});
    state.editingNist = normalizedNistEntries(record || {});
    renderMitreEditor();
    renderNistEditor();
    renderRelationPicker($('#kbLinkPicker'), state.knowledge, record?.linkedKbIds || [], 'linkedKbIds', 'No knowledge articles available.');
    renderEvidenceManager(record?.id || '');
    showFormSection('identity');
    $('#editorBackdrop').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    setTimeout(() => $('#title').focus(), 20);
  }

  function closeEditor(force = false) {
    if (state.incidentBusy && force !== true) { toast('Wait for the evidence upload and save to finish.', 'error'); return; }
    if (force !== true && (state.pendingEvidence.length || state.unverifiedEvidence.length) && !window.confirm('Some selected files are not yet confirmed attached. Discard the pending selection and close?')) return;
    state.pendingEvidence = []; state.unverifiedEvidence = [];
    $('#editorBackdrop').classList.add('hidden'); document.body.style.overflow = '';
  }
  function showFormSection(section) {
    $$('.form-nav button').forEach((button) => button.classList.toggle('active', button.dataset.formSection === section));
    $$('.form-section').forEach((element) => element.classList.toggle('active', element.dataset.section === section));
  }

  function renderMitreEditor() {
    const input = $('#mitreTechniqueSearch');
    const addButton = $('#addMitreTechnique');
    const list = $('#attackTechniqueOptions');
    const target = $('#mitreTechniqueChips');
    const catalogReady = Boolean(state.attack?.techniques?.length);
    input.disabled = !catalogReady;
    addButton.disabled = !catalogReady;
    input.placeholder = catalogReady ? 'Type an ID or technique name' : 'ATT&CK catalog unavailable';
    list.innerHTML = catalogReady ? state.attack.techniques.map((technique) => `<option value="${escapeHtml(technique.id)} | ${escapeHtml(technique.name)}"></option>`).join('') : '';
    target.innerHTML = state.editingMitre.length ? state.editingMitre.map((entry) => mitreChip(entry, true)).join('') : '<p class="mitre-empty">No techniques mapped.</p>';
    $$('[data-remove-mitre]', target).forEach((button) => button.addEventListener('click', () => {
      state.editingMitre = state.editingMitre.filter((entry) => entry.id !== button.dataset.removeMitre);
      renderMitreEditor();
    }));
    $$('[data-confirm-mitre]', target).forEach((button) => button.addEventListener('click', () => {
      const entry = state.editingMitre.find((item) => item.id === button.dataset.confirmMitre);
      if (!entry) return;
      entry.suggested = false;
      entry.confirmedAt = new Date().toISOString();
      entry.confirmedBy = $('#incidentForm').elements.namedItem('assignedTo').value.trim() || 'Johnny Meintel';
      delete entry.ruleId;
      renderMitreEditor();
      toast(`${entry.id} confirmed against analyst-reviewed evidence.`);
    }));
  }

  function mitreChip(entry, editable = false) {
    const technique = techniqueById(entry.id);
    if (!technique) return '';
    const suggested = Boolean(entry.suggested);
    const stateLabel = suggested ? `Suggested${entry.ruleId ? ` by rule ${entry.ruleId}` : ''}` : `Confirmed${entry.confirmedBy ? ` by ${entry.confirmedBy}` : ''}`;
    const tactic = tacticLabel(technique);
    const referenceLabel = `Open ${technique.id} ${technique.name} on the official MITRE ATT&CK website`;
    return `<span class="mitre-chip ${tacticClass(technique)}${suggested ? ' suggested' : ' confirmed'}"><a class="mapping-reference-link" href="${escapeHtml(mitreTechniqueUrl(technique.id))}" target="_blank" rel="noopener noreferrer" aria-label="${escapeHtml(referenceLabel)}"><span class="mapping-code">${escapeHtml(technique.id)}</span><span class="mapping-copy"><strong>${escapeHtml(technique.name)}</strong><small>${escapeHtml(tactic)} · ${escapeHtml(stateLabel)}</small></span><span class="mapping-external" aria-hidden="true">↗</span></a>${editable && suggested ? `<button type="button" data-confirm-mitre="${escapeHtml(technique.id)}">Confirm</button>` : ''}${editable ? `<button type="button" class="mitre-remove" data-remove-mitre="${escapeHtml(technique.id)}" aria-label="Remove ${escapeHtml(technique.id)}">×</button>` : ''}</span>`;
  }

  function addMitreTechnique() {
    const input = $('#mitreTechniqueSearch');
    const idMatch = input.value.match(/\bT\d{4}(?:\.\d{3})?\b/i);
    let technique = idMatch ? techniqueById(idMatch[0]) : null;
    if (!technique) {
      const needle = input.value.trim().toLowerCase();
      const matches = (state.attack?.techniques || []).filter((item) => item.name.toLowerCase().includes(needle));
      if (needle && matches.length === 1) technique = matches[0];
    }
    if (!technique) { toast('Select a valid technique from the pinned ATT&CK catalog.', 'error'); return; }
    if (state.editingMitre.some((entry) => entry.id === technique.id)) { toast(`${technique.id} is already mapped.`, 'error'); return; }
    state.editingMitre.push({ id: technique.id, suggested: false, confirmedAt: new Date().toISOString(), confirmedBy: $('#incidentForm').elements.namedItem('assignedTo').value.trim() || 'Johnny Meintel' });
    input.value = '';
    renderMitreEditor();
  }

  function renderNistEditor() {
    const functionFilter = $('#nistFunctionFilter');
    const categorySelect = $('#nistCategorySelect');
    const addButton = $('#addNistMapping');
    const target = $('#nistMappingChips');
    const catalogReady = Boolean(state.nist?.categories?.length);
    const selectedFunction = functionFilter.value || 'all';
    functionFilter.disabled = !catalogReady;
    categorySelect.disabled = !catalogReady;
    addButton.disabled = !catalogReady;
    functionFilter.innerHTML = '<option value="all">All functions</option>' + (state.nist?.functionOrder || []).map((id) => `<option value="${escapeHtml(id)}">${escapeHtml(id)} · ${escapeHtml(nistFunctionLabel(id))}</option>`).join('');
    functionFilter.value = selectedFunction === 'all' || (state.nist?.functionOrder || []).includes(selectedFunction) ? selectedFunction : 'all';
    const available = (state.nist?.categories || []).filter((category) => functionFilter.value === 'all' || category.function === functionFilter.value);
    categorySelect.innerHTML = catalogReady ? '<option value="">Select a category</option>' + available.map((category) => `<option value="${escapeHtml(category.id)}">${escapeHtml(category.id)} · ${escapeHtml(category.name)}</option>`).join('') : '<option value="">NIST catalog unavailable</option>';
    target.innerHTML = renderNistGroups(state.editingNist, true);
    $$('[data-remove-nist]', target).forEach((button) => button.addEventListener('click', () => {
      state.editingNist = state.editingNist.filter((entry) => entry.id !== button.dataset.removeNist);
      renderNistEditor();
    }));
  }

  function renderNistGroups(entries, editable = false) {
    if (!entries.length) return '<p class="nist-empty">No NIST CSF categories mapped.</p>';
    const grouped = new Map();
    entries.forEach((entry) => {
      const category = nistCategoryById(entry.id);
      if (!category) return;
      if (!grouped.has(category.function)) grouped.set(category.function, []);
      grouped.get(category.function).push(category);
    });
    return (state.nist?.functionOrder || []).filter((id) => grouped.has(id)).map((id) => `<div class="nist-function-group"><div class="nist-function-label"><strong>${escapeHtml(id)}</strong><span>${escapeHtml(nistFunctionLabel(id))}</span></div><div class="nist-function-items">${grouped.get(id).map((category) => `<span class="nist-chip"><a class="mapping-reference-link" href="${escapeHtml(nistCategoryUrl(category.id))}" target="_blank" rel="noopener noreferrer" aria-label="Open ${escapeHtml(category.id)} ${escapeHtml(category.name)} in the official NIST CSF 2.0 Reference Tool"><span class="mapping-code">${escapeHtml(category.id)}</span><span class="mapping-copy"><strong>${escapeHtml(category.name)}</strong><small>Official CSF 2.0 reference</small></span><span class="mapping-external" aria-hidden="true">↗</span></a>${editable ? `<button type="button" data-remove-nist="${escapeHtml(category.id)}" aria-label="Remove ${escapeHtml(category.id)}">×</button>` : ''}</span>`).join('')}</div></div>`).join('');
  }

  function addNistMapping() {
    const select = $('#nistCategorySelect');
    const category = nistCategoryById(select.value);
    if (!category) { toast('Select a NIST CSF category.', 'error'); return; }
    if (state.editingNist.some((entry) => entry.id === category.id)) { toast(`${category.id} is already mapped.`, 'error'); return; }
    state.editingNist.push({ id: category.id });
    renderNistEditor();
  }

  async function submitForm(event) {
    event.preventDefault();
    if (state.incidentBusy) return;
    const form = event.currentTarget;
    const formData = new FormData(form);
    const values = Object.fromEntries(formData.entries());
    values.linkedKbIds = formData.getAll('linkedKbIds');
    values.mitreTechniques = state.editingMitre.map((entry) => ({ ...entry }));
    values.attackVersion = state.attack?.attackVersion || '';
    values.nistMappings = state.editingNist.map((entry) => ({ id: entry.id }));
    values.nistVersion = state.nist?.version || '';
    delete values.mitre;
    delete values.nist;
    const closing = CLOSED_STATUSES.has(values.status);
    const minimumFields = ['title', 'severity', 'alertSource', 'initialAlert'];
    const missing = (closing ? REQUIRED_FIELDS : minimumFields).filter((name) => !String(values[name] || '').trim());
    if (missing.length) {
      const first = form.elements.namedItem(missing[0]);
      showFormSection(first.closest('.form-section').dataset.section);
      first.focus();
      $('#formStatus').textContent = 'Complete every required field.';
      toast(closing ? 'Resolved and closed incidents require the complete evidence record.' : 'Complete the minimum incident fields before saving.', 'error');
      return;
    }
    if (closing && !$('#integrityConfirm').checked) {
      showFormSection('review'); $('#integrityConfirm').focus();
      toast('Confirm the author attestation before resolving or closing the incident.', 'error'); return;
    }
    values.integrityConfirmed = $('#integrityConfirm').checked;
    const hadEvidence = state.pendingEvidence.length > 0 || state.unverifiedEvidence.length > 0;
    try { validatePendingEvidence(); }
    catch (error) { showFormSection('evidence'); $('#evidenceUploadNote').textContent = error.message; toast(error.message, 'error'); return; }
    const submit = form.querySelector('[type="submit"]');
    const unlock = lockIncidentEditor();
    submit.textContent = 'Saving...';
    try {
      // A new incident needs an ID before attachment storage can accept its files.
      // Persist it as a draft first so a failed upload cannot finalize the case.
      if (!values.id && state.pendingEvidence.length) {
        const draft = await saveRecord({ ...values, status: 'Draft', integrityConfirmed: false });
        values.id = draft.id;
        form.elements.namedItem('id').value = draft.id;
        $('#editorTitle').textContent = `Edit ${draft.id}`;
        state.records = state.records.filter((item) => item.id !== draft.id).concat(draft);
      }
      if (state.pendingEvidence.length || state.unverifiedEvidence.length) {
        submit.textContent = 'Attaching evidence...';
        await attachPendingEvidence(values.id);
      }
      submit.textContent = 'Saving...';
      const saved = await saveRecord(values);
      state.records = state.records.filter((item) => item.id !== saved.id).concat(saved);
      closeEditor(true); toast(hadEvidence ? `${saved.id} saved. Selected evidence is attached.` : `${saved.id} saved.`); navigateToIncident(saved.id);
    } catch (error) {
      $('#formStatus').textContent = `Save not completed: ${error.message} Your form remains open.`;
      $('#evidenceUploadNote').textContent = `${error.message} ${pendingEvidenceText()}`;
      toast(`Save not completed: ${error.message}`, 'error');
    }
    finally { unlock(); submit.textContent = 'Save incident'; }
  }

  function openKnowledgeEditor(article = null, linkedIncidentIds = []) {
    const form = $('#knowledgeForm');
    form.reset();
    $('#kbEditorTitle').textContent = article ? `Edit ${article.id}` : 'New article';
    if (article) {
      Object.entries(article).forEach(([key, value]) => {
        const field = form.elements.namedItem(key);
        if (field && typeof value !== 'object') field.value = value ?? '';
      });
    } else {
      form.elements.namedItem('status').value = 'Draft';
      form.elements.namedItem('articleType').value = 'Procedure';
      form.elements.namedItem('author').value = 'Johnny Meintel';
    }
    renderRelationPicker($('#incidentLinkPicker'), state.records, article?.linkedIncidentIds || linkedIncidentIds, 'linkedIncidentIds', 'No incidents available.');
    $('#kbEditorBackdrop').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    setTimeout(() => $('#kbTitle').focus(), 20);
  }

  function closeKnowledgeEditor() { $('#kbEditorBackdrop').classList.add('hidden'); document.body.style.overflow = ''; }

  async function submitKnowledgeForm(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const values = Object.fromEntries(formData.entries());
    values.linkedIncidentIds = formData.getAll('linkedIncidentIds');
    const missing = KB_REQUIRED_FIELDS.filter((name) => !String(values[name] || '').trim());
    if (missing.length) {
      form.elements.namedItem(missing[0]).focus();
      $('#kbFormStatus').textContent = 'Complete every required field.';
      toast('The article cannot be saved until its required fields are complete.', 'error');
      return;
    }
    const submit = form.querySelector('[type="submit"]');
    submit.disabled = true; submit.textContent = 'Saving...';
    try {
      const saved = await saveKnowledge(values);
      state.knowledge = state.knowledge.filter((item) => item.id !== saved.id).concat(saved);
      closeKnowledgeEditor(); toast(`${saved.id} saved.`); navigateToKnowledge(saved.id);
    } catch (error) { toast(`Save failed: ${error.message}`, 'error'); }
    finally { submit.disabled = false; submit.textContent = 'Save article'; }
  }

  function linkedArticlesForIncident(record) {
    const direct = new Set(Array.isArray(record.linkedKbIds) ? record.linkedKbIds : []);
    state.knowledge.forEach((article) => { if ((article.linkedIncidentIds || []).includes(record.id)) direct.add(article.id); });
    return state.knowledge.filter((article) => direct.has(article.id));
  }

  function renderProvenance(record) {
    if (record.origin !== 'auto-ingest') return '';
    const occurrences = Number(record.sourceEventCount) || 1;
    const relatedCount = Array.isArray(record.relatedEvents) ? record.relatedEvents.length : 0;
    return `<section class="provenance-block"><div class="provenance-label"><span class="origin-badge">Auto</span><strong>Machine-created draft</strong></div><p>Ingested from <strong>${escapeHtml(record.sourceSystem || 'SIEM')}</strong>${record.sourceRule ? ` rule <strong>${escapeHtml(record.sourceRule)}</strong>` : ''} at ${formatDate(record.ingestedAt)}.</p><div class="provenance-facts"><span>${occurrences} ${occurrences === 1 ? 'occurrence' : 'occurrences'}</span><span>${relatedCount} related ${relatedCount === 1 ? 'event' : 'events'}</span><span>Event ${escapeHtml(record.sourceEventId || 'Not recorded')}</span></div><small>Provenance is server-controlled. Alert facts remain unconfirmed until analyst review.</small></section>`;
  }

  async function loadEvidenceFiles(incidentId) {
    if (!incidentId || state.storage !== 'server') return [];
    const result = await evidenceApi('evidence-list', { query: `&incidentId=${encodeURIComponent(incidentId)}` });
    if (!Array.isArray(result.records)) throw new Error('The server did not return an attachment list.');
    return result.records;
  }

  function pendingEvidenceText() {
    if (!state.pendingEvidence.length) return 'Choose files to attach, then save the incident or use Upload selected files.';
    return `${state.pendingEvidence.length} selected, not yet attached: ${state.pendingEvidence.map((file) => file.name).join(', ')}. Save incident will upload them.`;
  }

  function validatePendingEvidence() {
    if (state.pendingEvidence.length && state.storage !== 'server') throw new Error('Evidence uploads require the SRV01 storage service.');
    if (state.pendingEvidence.length > 20) throw new Error('Select no more than 20 evidence files at a time.');
    const allowed = new Set(['zip', '7z', 'tar', 'gz', 'tgz', 'evtx', 'pcap', 'pcapng', 'json', 'xml', 'csv', 'txt', 'log', 'md', 'pdf', 'png', 'jpg', 'jpeg', 'webp']);
    for (const file of state.pendingEvidence) {
      if (file.size < 1 || file.size > 536870912) throw new Error(`${file.name}: each file must be between 1 byte and 512 MiB.`);
      if (!allowed.has(file.name.split('.').pop().toLowerCase())) throw new Error(`${file.name}: unsupported type. Put this artifact inside ZIP or 7z.`);
    }
  }

  function lockIncidentEditor() {
    state.incidentBusy = true;
    const controls = $$('input, select, textarea, button', $('#editorBackdrop')).map((element) => [element, element.disabled]);
    controls.forEach(([element]) => { element.disabled = true; });
    return () => {
      state.incidentBusy = false;
      controls.forEach(([element, disabled]) => { element.disabled = disabled; });
      $('#uploadEvidence').disabled = state.storage !== 'server' || !$('#incidentForm').elements.namedItem('id').value;
    };
  }

  async function verifyUploadedEvidence(incidentId) {
    const files = await loadEvidenceFiles(incidentId);
    for (const receipt of state.unverifiedEvidence) {
      if (!files.some((file) => file.id === receipt.id && file.incidentId === incidentId && file.sha256 === receipt.sha256 && Number(file.size) === Number(receipt.size))) {
        throw new Error('An upload receipt could not be verified in the attachment list. Retry to check it before saving.');
      }
    }
    state.unverifiedEvidence = [];
    renderEvidenceFileList($('#evidenceEditorFiles'), files);
  }

  async function attachPendingEvidence(incidentId) {
    validatePendingEvidence();
    if (state.unverifiedEvidence.length) await verifyUploadedEvidence(incidentId);
    // One file per request keeps several valid files below the server's total POST limit.
    while (state.pendingEvidence.length) {
      const file = state.pendingEvidence[0];
      $('#evidenceUploadNote').textContent = `Uploading ${file.name}. Keep this page open until attachment is confirmed.`;
      const body = new FormData();
      body.append('incidentId', incidentId);
      body.append('evidenceFiles[]', file, file.name);
      const result = await evidenceApi('evidence-upload', { method: 'POST', body });
      const receipt = result.records?.[0];
      if (result.records?.length !== 1 || !receipt?.id || receipt.incidentId !== incidentId || !/^[a-f0-9]{64}$/i.test(receipt.sha256 || '') || Number(receipt.size) !== file.size) {
        throw new Error(`${file.name}: the server did not return a valid upload receipt.`);
      }
      state.unverifiedEvidence.push(receipt);
      state.pendingEvidence.shift();
      $('#evidenceFiles').value = '';
      await verifyUploadedEvidence(incidentId);
    }
    $('#evidenceUploadNote').textContent = `Evidence attached to ${incidentId} and verified in its attachment list.`;
  }

  async function renderEvidenceManager(incidentId) {
    const input = $('#evidenceFiles');
    const button = $('#uploadEvidence');
    const note = $('#evidenceUploadNote');
    const target = $('#evidenceEditorFiles');
    const version = state.editorVersion;
    if (state.storage !== 'server') {
      input.disabled = true; button.disabled = true;
      note.textContent = 'Evidence uploads require the SRV01 storage service.';
      target.innerHTML = '';
      return;
    }
    input.disabled = false; button.disabled = !incidentId;
    note.textContent = pendingEvidenceText();
    if (!incidentId) { target.innerHTML = '<p class="evidence-empty">Selected files will attach when you save this new incident.</p>'; return; }
    target.innerHTML = '<p class="evidence-loading">Loading attached evidence...</p>';
    try { const files = await loadEvidenceFiles(incidentId); if (version === state.editorVersion) renderEvidenceFileList(target, files); }
    catch (error) { if (version === state.editorVersion) target.innerHTML = `<p class="evidence-error">Could not load evidence packages: ${escapeHtml(error.message)}</p>`; }
  }

  async function uploadEvidenceFiles() {
    if (state.incidentBusy) return;
    const incidentId = $('#incidentForm').elements.namedItem('id').value;
    const button = $('#uploadEvidence');
    if (!incidentId) { toast('Save the incident before uploading evidence.', 'error'); return; }
    if (!state.pendingEvidence.length && !state.unverifiedEvidence.length) { toast('Choose at least one evidence file.', 'error'); return; }
    try { validatePendingEvidence(); } catch (error) { $('#evidenceUploadNote').textContent = error.message; toast(error.message, 'error'); return; }
    const unlock = lockIncidentEditor();
    button.textContent = 'Uploading...';
    try {
      await attachPendingEvidence(incidentId);
      toast('Evidence attached and verified.');
    } catch (error) { $('#evidenceUploadNote').textContent = `Upload not completed: ${error.message} ${pendingEvidenceText()}`; toast(`Evidence upload failed: ${error.message}`, 'error'); }
    finally { unlock(); button.textContent = 'Upload selected files'; }
  }

  function renderEvidenceFileList(target, files) {
    if (!files.length) {
      target.innerHTML = '<p class="evidence-empty">No evidence packages attached.</p>';
      return;
    }
    target.innerHTML = files.map((file) => `<article class="evidence-file">
      <div class="evidence-file-icon">${escapeHtml(String(file.originalName || '').split('.').pop().slice(0, 4).toUpperCase() || 'FILE')}</div>
      <div class="evidence-file-copy"><strong>${escapeHtml(file.originalName)}</strong><span>${formatBytes(file.size)} · Uploaded ${formatDate(file.uploadedAt)} by ${escapeHtml(file.uploadedBy || 'authenticated-user')}</span><code>SHA-256 ${escapeHtml(file.sha256)}</code></div>
      <button class="secondary-button" type="button" data-download-evidence="${escapeHtml(file.id)}">Download</button>
    </article>`).join('');
    $$('[data-download-evidence]', target).forEach((button) => button.addEventListener('click', () => {
      window.location.assign(`api.php?action=evidence-download&id=${encodeURIComponent(button.dataset.downloadEvidence)}`);
    }));
  }

  function formatBytes(value) {
    const bytes = Number(value) || 0;
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KiB', 'MiB', 'GiB'];
    let amount = bytes / 1024; let unit = units[0];
    for (let index = 1; index < units.length && amount >= 1024; index += 1) { amount /= 1024; unit = units[index]; }
    return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${unit}`;
  }

  function linkedIncidentsForArticle(article) {
    const direct = new Set(Array.isArray(article.linkedIncidentIds) ? article.linkedIncidentIds : []);
    state.records.forEach((record) => { if ((record.linkedKbIds || []).includes(article.id)) direct.add(record.id); });
    return state.records.filter((record) => direct.has(record.id));
  }

  function firstIncidentForArticle(article) {
    const timestamp = (record) => {
      const opened = Date.parse(record.openedAt);
      if (Number.isFinite(opened)) return opened;
      const created = Date.parse(record.createdAt);
      return Number.isFinite(created) ? created : Infinity;
    };
    return linkedIncidentsForArticle(article).sort((a, b) => {
      const first = timestamp(a); const second = timestamp(b);
      return first === second ? a.id.localeCompare(b.id) : first - second;
    })[0] || null;
  }

  function relationSection(title, records, attribute, empty) {
    return `<section class="detail-section"><h3>${escapeHtml(title)}</h3><div class="relation-chips">${records.length ? records.map((record) => `<button class="relation-chip" ${attribute}="${escapeHtml(record.id)}"><strong>${escapeHtml(record.id)}</strong>${escapeHtml(record.title)}</button>`).join('') : `<p>${escapeHtml(empty)}</p>`}</div></section>`;
  }

  function sourceTimeWindow(record) {
    const opened = new Date(record.openedAt || record.createdAt || Date.now());
    const latest = new Date(record.sourceLastEventAt || record.openedAt || record.createdAt || Date.now());
    const openedMs = Number.isNaN(opened.getTime()) ? Date.now() : opened.getTime();
    const latestMs = Number.isNaN(latest.getTime()) ? openedMs : latest.getTime();
    const paddingMs = record.sourceLastEventAt ? 5000 : 30 * 60000;
    return {
      from: new Date(Math.min(openedMs, latestMs) - paddingMs).toISOString(),
      to: new Date(Math.max(openedMs, latestMs) + paddingMs).toISOString(),
    };
  }

  function exactSourceTimeWindow(record) {
    const eventTime = new Date(record.openedAt || record.createdAt || Date.now());
    const eventMs = Number.isNaN(eventTime.getTime()) ? Date.now() : eventTime.getTime();
    return {
      from: new Date(eventMs - 5000).toISOString(),
      to: new Date(eventMs + 5000).toISOString(),
    };
  }

  function escapeSplunkValue(value) {
    return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  function splunkIncidentUrl(record, related = false) {
    const field = related ? 'lw_correlation' : 'lw_eventid';
    const value = related ? record.correlationKey : record.sourceEventId;
    if (!value) return '';
    const window = related ? sourceTimeWindow(record) : exactSourceTimeWindow(record);
    const query = `| savedsearch labwatch_ingestion_feed | search ${field}="${escapeSplunkValue(value)}"${related ? '' : ' | head 1'}`;
    const params = new URLSearchParams({ earliest: window.from, latest: window.to, q: query });
    return `${SPLUNK_WEB_URL}/en-US/app/search/search?${params.toString()}`;
  }

  function risonString(value) {
    return `'${String(value || '').replace(/!/g, '!!').replace(/'/g, "!'")}'`;
  }

  function wazuhIncidentUrl(record) {
    if (!record.sourceRule && !record.primaryAsset) return '';
    const window = exactSourceTimeWindow(record);
    const queryParts = [];
    if (record.sourceRule) queryParts.push(`rule.id:"${String(record.sourceRule).replace(/"/g, '\\"')}"`);
    if (record.primaryAsset) queryParts.push(`agent.name:"${String(record.primaryAsset).split('.')[0].replace(/"/g, '\\"')}"`);
    queryParts.push(`timestamp >= "${window.from}"`, `timestamp <= "${window.to}"`);
    const appState = `(discover:(columns:!(timestamp,agent.name,rule.description,rule.level,rule.id),isDirty:!f,sort:!()),metadata:(indexPattern:'wazuh-alerts-*',view:discover))`;
    const globalState = `(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:${risonString(window.from)},to:${risonString(window.to)}))`;
    const queryState = `(filters:!(),query:(language:kuery,query:${risonString(queryParts.join(' and '))}))`;
    return `${WAZUH_WEB_URL}/app/data-explorer/discover#?_a=${encodeURIComponent(appState)}&_g=${encodeURIComponent(globalState)}&_q=${encodeURIComponent(queryState)}`;
  }

  function renderSourceActions(record) {
    if (record.origin !== 'auto-ingest') return '';
    const source = String(record.sourceSystem || record.alertSource || '').toLowerCase();
    const wazuhUrl = source.includes('wazuh') ? wazuhIncidentUrl(record) : '';
    const splunkUrl = splunkIncidentUrl(record);
    const eventCount = Number(record.sourceEventCount) || 1;
    const relatedUrl = eventCount > 1 && record.correlationKey ? splunkIncidentUrl(record, true) : '';
    return `${wazuhUrl ? `<a class="secondary-button source-link wazuh-link" href="${escapeHtml(wazuhUrl)}" target="_blank" rel="noopener noreferrer">Open exact event in Wazuh</a>` : ''}${splunkUrl ? `<a class="secondary-button source-link splunk-link" href="${escapeHtml(splunkUrl)}" target="_blank" rel="noopener noreferrer">Open exact event in Splunk</a>` : ''}${relatedUrl ? `<a class="secondary-button source-link splunk-link related-link" href="${escapeHtml(relatedUrl)}" target="_blank" rel="noopener noreferrer">Open ${eventCount}-event correlation in Splunk</a>` : ''}`;
  }

  function incidentKnowledgeSection(record) {
    const linked = linkedArticlesForIncident(record);
    return `<section class="detail-section"><div class="detail-section-heading"><h3>Linked knowledge articles</h3><div class="relation-actions"><button class="secondary-button compact-button" type="button" data-incident-action="link-kb">Link existing KB</button><button class="secondary-button compact-button" type="button" data-incident-action="create-kb">Create KB</button></div></div><div class="relation-chips">${linked.length ? linked.map((article) => `<button class="relation-chip" data-open-kb="${escapeHtml(article.id)}"><strong>${escapeHtml(article.id)}</strong>${escapeHtml(article.title)}</button>`).join('') : '<p>No knowledge articles linked.</p>'}</div></section>`;
  }

  function openIncidentKnowledgeLinker(record) {
    openEditor(record);
    showFormSection('review');
    setTimeout(() => $('#kbLinkPicker').scrollIntoView({ block: 'center', behavior: 'smooth' }), 20);
  }

  function summaryItem(label, value, className = '') {
    return `<div class="summary-item${className ? ` ${className}` : ''}"><span>${escapeHtml(label)}</span><strong>${value}</strong></div>`;
  }

  function incidentSummary(record) {
    const groups = [
      ['State and disposition', 'summary-group-state', [
        summaryItem('Severity', escapeHtml(record.severity || 'Not assessed'), `state-tile severity-${slug(record.severity || 'informational')}`),
        summaryItem('Status', escapeHtml(record.status || 'Not recorded'), `state-tile status-${slug(record.status || 'new')}`),
        summaryItem('Classification', escapeHtml(record.classification || 'Not recorded'), `state-tile classification-${slug(record.classification || 'unclassified')}`),
        summaryItem('Confidence', escapeHtml(record.confidence || 'Not assessed'), `state-tile confidence-${slug(record.confidence || 'not-assessed')}`),
      ]],
      ['Case context', 'summary-group-context', [
        summaryItem('Category', escapeHtml(record.category || 'Uncategorized')),
        summaryItem('Subcategory', escapeHtml(record.subcategory || 'Unspecified')),
        summaryItem('Environment', escapeHtml(record.environment || 'Not recorded')),
        summaryItem('Detection method', escapeHtml(record.detectionMethod || 'Not recorded')),
      ]],
      ['Ownership and intake', 'summary-group-ownership', [
        summaryItem('Assignment group', escapeHtml(record.assignmentGroup || 'Not recorded')),
        summaryItem('Assigned analyst', escapeHtml(record.assignedTo || 'Unassigned')),
        summaryItem('Analyst role', escapeHtml(record.assignedToRole || 'Not recorded')),
        summaryItem('Caller', escapeHtml(record.callerName || 'Not recorded')),
        summaryItem('Caller role', escapeHtml(record.callerRole || 'Not recorded')),
        summaryItem('Request channel', escapeHtml(record.requestChannel || 'Not recorded')),
        summaryItem('Submitted by', escapeHtml(record.submittedBy || 'Not recorded')),
      ]],
      ['Evidence scope', 'summary-group-scope', [
        summaryItem('Lab run', escapeHtml(record.labRunId || 'Not recorded')),
        summaryItem('Source', escapeHtml(record.alertSource || 'Not recorded')),
        summaryItem('Affected host', escapeHtml(record.primaryAsset || 'Not recorded')),
        summaryItem('Affected identity', escapeHtml(record.affectedUser || 'Not recorded')),
        summaryItem('Opened', formatDate(record.openedAt || record.createdAt)),
        summaryItem('Updated', formatDate(record.updatedAt)),
      ]],
    ];
    return `<div class="incident-page-summary">${groups.map(([title, className, items]) => `<section class="summary-group ${className}"><h2><span></span>${escapeHtml(title)}</h2><div class="summary-group-grid">${items.join('')}</div></section>`).join('')}</div>`;
  }

  function renderIncidentSectionBody(value) {
    const lines = String(value || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (!lines.length) return '<p>Not recorded</p>';
    if (lines.length === 1) return `<p>${escapeHtml(lines[0])}</p>`;
    return `<ul class="incident-line-list">${lines.map((line) => `<li><span aria-hidden="true">›</span><p>${escapeHtml(line)}</p></li>`).join('')}</ul>`;
  }

  function renderIncidentPage(record) {
    hideContentViews();
    $('#metricGrid').classList.add('hidden');
    $('#incidentRecordView').classList.remove('hidden');
    state.view = 'all';
    document.title = `${record.id} | ${record.title} | LabWatch`;
    $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === 'all'));
    const sections = [
      ['Initial alert', record.initialAlert], ['Observed facts', record.observedFacts], ['Scope determination', record.scope],
      ['Attribution assessment', record.attribution], ['Impact assessment', record.impact],
      ['Incident timeline', record.timeline], ['Evidence inventory', record.evidence],
      ['Queries and commands', record.queries], ['Detection assessment', record.detection], ['Containment', record.containment],
      ['Eradication', record.eradication], ['Recovery and monitoring', record.recovery], ['Final determination', record.conclusion],
      ['Validation performed', record.validation], ['Lessons learned and follow-up', record.lessons],
    ];
    const attestation = record.integrityConfirmed
      ? '<span>✓</span><div>Closure attestation confirmed: this record contains no invented observations and is supported by retained evidence.'
      : '<span>○</span><div>Closure attestation is not yet confirmed. This incident may still be in intake, investigation, containment, or monitoring.';
    $('#incidentRecordView').innerHTML = `
      <header class="kb-page-header">
        <button class="kb-back" data-incident-action="back"><span>←</span> Incident queue</button>
        <div class="kb-page-heading"><div><p class="eyebrow">${escapeHtml(record.id)}</p><h1>${escapeHtml(record.title)}</h1></div><span class="badge ${slug(record.severity)}">${escapeHtml(record.severity)}</span></div>
        <div class="detail-actions"><button class="primary-button" data-incident-action="edit">Edit incident</button>${renderSourceActions(record)}<button class="secondary-button" data-incident-action="export">Export JSON</button><button class="secondary-button" data-incident-action="print">Print incident</button></div>
      </header>
      ${incidentSummary(record)}
      <div class="kb-page-layout">
        <aside class="kb-page-rail"><h2>Incident details</h2>${renderProvenance(record)}${incidentKnowledgeSection(record)}<div class="record-integrity">${attestation}<br>Created ${formatDate(record.createdAt)}.<br>Updated ${formatDate(record.updatedAt)}.</div></div>${renderHashStatus(record)}</aside>
        <div class="kb-page-content"><section class="kb-content-section"><h2>Evidence packages</h2><div class="evidence-file-list" id="incidentPageEvidenceFiles"><p class="evidence-loading">Loading attached evidence...</p></div></section>${renderMitreDetail(record)}${renderNistDetail(record)}${sections.map(([title, value]) => `<section class="kb-content-section${value ? '' : ' empty'}"><h2>${escapeHtml(title)}</h2>${renderIncidentSectionBody(value)}</section>`).join('')}${renderAudit(record)}</div>
      </div>`;
    $('[data-incident-action="back"]').addEventListener('click', leaveIncidentPage);
    $('[data-incident-action="edit"]').addEventListener('click', () => openEditor(record));
    $('[data-incident-action="link-kb"]').addEventListener('click', () => openIncidentKnowledgeLinker(record));
    $('[data-incident-action="create-kb"]').addEventListener('click', () => openKnowledgeEditor(null, [record.id]));
    $('[data-incident-action="export"]').addEventListener('click', () => downloadJson(`${record.id}.json`, record));
    $('[data-incident-action="print"]').addEventListener('click', () => window.print());
    $$('[data-open-kb]', $('#incidentRecordView')).forEach((button) => button.addEventListener('click', () => navigateToKnowledge(button.dataset.openKb)));
    loadEvidenceFiles(record.id).then((files) => renderEvidenceFileList($('#incidentPageEvidenceFiles'), files)).catch((error) => { $('#incidentPageEvidenceFiles').innerHTML = `<p class="evidence-error">Could not load evidence packages: ${escapeHtml(error.message)}</p>`; });
    window.scrollTo({ top: 0, behavior: 'auto' });
  }
  function renderMitreDetail(record) {
    const entries = normalizedMitreEntries(record);
    const version = escapeHtml(record.attackVersion || state.attack?.attackVersion || 'Not recorded');
    return `<section class="kb-content-section${entries.length ? '' : ' empty'}"><h2>MITRE ATT&amp;CK mapping</h2>${entries.length ? `<div class="mitre-chip-list">${entries.map((entry) => mitreChip(entry)).join('')}</div><p class="mitre-version">Names and tactics resolved from pinned Enterprise ATT&amp;CK ${version}. Open a card for the official MITRE technique reference.</p>` : '<p>Not recorded</p>'}</section>`;
  }
  function renderNistDetail(record) {
    const entries = normalizedNistEntries(record);
    const version = escapeHtml(record.nistVersion || state.nist?.version || 'Not recorded');
    return `<section class="kb-content-section${entries.length ? '' : ' empty'}"><h2>NIST CSF mapping</h2>${entries.length ? `${renderNistGroups(entries)}<p class="nist-version">Categories resolved from NIST Cybersecurity Framework ${version}. Open a card in the official NIST CSF 2.0 Reference Tool.</p>` : '<p>Not recorded</p>'}</section>`;
  }
  function renderAudit(record) {
    if (!Array.isArray(record.history) || !record.history.length) return '';
    const actionLabels = {
      created: 'Record created', updated: 'Record updated', 'test article seeded': 'Test article created',
      'relationship synchronized': 'Relationship synchronized', 'reviewed without content changes': 'Reviewed without content changes',
      ingested: 'Draft ingested from SIEM', recurrence: 'Related alert attached',
    };
    const items = record.history.map((entry) => {
      const fields = Array.isArray(entry.changedFields) ? entry.changedFields : [];
      const fieldText = fields.includes('all') ? 'Initial article content' : fields.length ? `Changed: ${fields.map(friendlyField).join(', ')}` : 'No content fields changed';
      const action = actionLabels[entry.action] || friendlyField(entry.action || 'record event');
      return `<li><span class="audit-node" aria-hidden="true"></span><div class="audit-entry"><div class="audit-entry-head"><strong>${escapeHtml(action)}</strong><time datetime="${escapeHtml(entry.at || '')}">${formatDate(entry.at)}</time></div><span class="audit-actor">${escapeHtml(entry.actor || 'authenticated-user')}</span><p>${escapeHtml(fieldText)}</p></div></li>`;
    }).join('');
    return `<section class="detail-section audit-section"><h3>Record audit trail</h3><ol class="audit-list">${items}</ol></section>`;
  }
  function friendlyField(value) {
    const labels = { linkedKbIds: 'Linked KBs', linkedIncidentIds: 'Linked incidents', labRunId: 'Lab run ID', observedFacts: 'Observed facts', initialAlert: 'Initial alert', alertSource: 'Alert source', assignedToRole: 'Assigned analyst role', articleType: 'Article type', reviewedBy: 'Reviewed by', reviewDate: 'Review date', integrityConfirmed: 'Author attestation', callerName: 'Caller', callerRole: 'Caller role', requestChannel: 'Request channel', submittedBy: 'Submitted by', mitreTechniques: 'MITRE ATT&CK mappings', nistMappings: 'NIST CSF mappings', attackVersion: 'ATT&CK version', nistVersion: 'NIST CSF version' };
    if (labels[value]) return labels[value];
    const words = String(value || '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim();
    return words ? words.charAt(0).toUpperCase() + words.slice(1) : 'Record field';
  }
  function renderHashStatus(record) {
    if (!record.recordHash || record.hashStatus === 'not-generated') {
      return '<div class="record-hash not-generated"><strong>SHA-256 change-detection hash</strong><span>Not generated. LabWatch will create this fingerprint the next time the record is saved.</span></div>';
    }
    if (record.hashStatus === 'mismatch') {
      return `<div class="record-hash mismatch"><strong>SHA-256 change-detection hash: mismatch</strong><span>The stored content does not match its saved fingerprint. Review the data file and audit history before relying on this record.</span><code>${escapeHtml(record.recordHash)}</code></div>`;
    }
    return `<div class="record-hash verified"><strong>SHA-256 change-detection hash: verified</strong><span>The current stored content matches its saved fingerprint. This detects drift but does not prove that an authorized file editor did not alter and rehash the record.</span><code>${escapeHtml(record.recordHash)}</code></div>`;
  }
  function downloadJson(name, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
    anchor.href = url; anchor.download = name; anchor.click(); URL.revokeObjectURL(url);
  }
  function toast(message, mode = '') {
    const item = document.createElement('div'); item.className = `toast ${mode}`; item.textContent = message;
    $('#toastRegion').append(item); setTimeout(() => item.remove(), 5000);
  }

  function bindEvents() {
    $('#newIncident').addEventListener('click', () => openEditor());
    $('#emptyCreate').addEventListener('click', () => openEditor());
    $('#newKnowledge').addEventListener('click', () => openKnowledgeEditor());
    $('#addMitreTechnique').addEventListener('click', addMitreTechnique);
    $('#mitreTechniqueSearch').addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); addMitreTechnique(); } });
    $('#nistFunctionFilter').addEventListener('change', renderNistEditor);
    $('#addNistMapping').addEventListener('click', addNistMapping);
    $('#uploadEvidence').addEventListener('click', uploadEvidenceFiles);
    $('#evidenceFiles').addEventListener('change', (event) => {
      state.pendingEvidence = [...event.target.files];
      $('#evidenceUploadNote').textContent = pendingEvidenceText();
    });
    window.addEventListener('beforeunload', (event) => {
      if (state.incidentBusy || state.pendingEvidence.length || state.unverifiedEvidence.length) { event.preventDefault(); event.returnValue = ''; }
    });
    $('#incidentForm').addEventListener('submit', submitForm);
    $('#knowledgeForm').addEventListener('submit', submitKnowledgeForm);
    $$('[data-close="editor"]').forEach((button) => button.addEventListener('click', closeEditor));
    $$('[data-close="kb-editor"]').forEach((button) => button.addEventListener('click', closeKnowledgeEditor));
    $$('.form-nav button').forEach((button) => button.addEventListener('click', () => showFormSection(button.dataset.formSection)));
    $$('#primaryNav .nav-item, .sidebar-section .nav-item').forEach((button) => button.addEventListener('click', () => {
      state.view = button.dataset.view;
      state.kbTag = '';
      if (/^#\/(?:kb|inc|framework|knowledge)\//.test(window.location.hash)) history.pushState(null, '', `${window.location.pathname}${window.location.search}`);
      $$('.nav-item').forEach((item) => item.classList.toggle('active', item === button));
      $('#pageTitle').textContent = VIEW_TITLES[state.view] || 'Incident workspace';
      document.title = 'LabWatch';
      $('.sidebar').classList.remove('open'); render();
    }));
    $('#severityFilter').addEventListener('change', (event) => { state.severity = event.target.value; renderQueue(); });
    $('#statusFilter').addEventListener('change', (event) => { state.status = event.target.value; renderQueue(); });
    $('#categoryFilter').addEventListener('change', (event) => { state.category = event.target.value; renderQueue(); });
    $('#assetFilter').addEventListener('change', (event) => { state.asset = event.target.value; renderQueue(); });
    $('#queueSort').addEventListener('change', (event) => { state.sort = event.target.value; renderQueue(); });
    $('#kbStatusFilter').addEventListener('change', (event) => { state.kbStatus = event.target.value; renderKnowledge(); });
    $('#kbCategoryFilter').addEventListener('change', (event) => { state.kbCategory = event.target.value; renderKnowledge(); });
    $('#toggleQueryBuilder').addEventListener('click', () => { const builder = $('#queryBuilder'); builder.classList.toggle('hidden'); $('#toggleQueryBuilder').setAttribute('aria-expanded', String(!builder.classList.contains('hidden'))); });
    $('#addQueryCondition').addEventListener('click', () => { state.queryConditions.push({ join: 'AND', field: 'category', operator: 'is', value: '' }); renderQueryBuilder(); });
    $('#applyQuery').addEventListener('click', () => { state.appliedQueryConditions = state.queryConditions.map((condition) => ({ ...condition })); renderQueue(); toast(`${activeConditions(state.appliedQueryConditions).length} advanced ${activeConditions(state.appliedQueryConditions).length === 1 ? 'condition' : 'conditions'} applied.`); });
    $('#clearQuery').addEventListener('click', () => { state.queryConditions = []; state.appliedQueryConditions = []; renderQueryBuilder(); renderQueue(); });
    $('#copyQuery').addEventListener('click', async () => { const expression = queryExpressionText(); if (!activeConditions(state.queryConditions).length) { toast('Add a complete condition before copying.', 'error'); return; } try { await navigator.clipboard.writeText(expression); toast('Query copied.'); } catch { toast('The browser could not copy the query.', 'error'); } });
    $('#clearFilters').addEventListener('click', () => { state.severity = state.status = state.category = state.asset = 'all'; state.search = ''; state.queryConditions = []; state.appliedQueryConditions = []; $('#severityFilter').value = 'all'; $('#statusFilter').value = 'all'; $('#categoryFilter').value = 'all'; $('#assetFilter').value = 'all'; $('#globalSearch').value = ''; renderQueue(); });
    $('#globalSearch').addEventListener('input', (event) => {
      state.search = event.target.value;
      if (incidentRoute()) history.pushState(null, '', `${window.location.pathname}${window.location.search}`);
      if (state.view === 'knowledge') renderKnowledge();
      else if (!['metrics', 'frameworks'].includes(state.view)) renderQueue();
    });
    $('#exportAll').addEventListener('click', () => downloadJson(`labwatch-${new Date().toISOString().slice(0, 10)}.json`, { exportedAt: new Date().toISOString(), incidents: state.records, knowledge: state.knowledge }));
    $('#mobileMenu').addEventListener('click', () => $('.sidebar').classList.toggle('open'));
    document.addEventListener('keydown', (event) => {
      if (event.ctrlKey && event.key.toLowerCase() === 'k') { event.preventDefault(); $('#globalSearch').focus(); }
      if (event.key === 'Escape') {
        if (!$('#editorBackdrop').classList.contains('hidden')) closeEditor();
        else if (!$('#kbEditorBackdrop').classList.contains('hidden')) closeKnowledgeEditor();
      }
    });
    window.addEventListener('hashchange', render);
    window.addEventListener('popstate', render);
  }

  bindEvents();
  loadRecords();
})();
