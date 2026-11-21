import { ICONS } from './icons.js';
import { createTable } from './table.js';

const $ = (sel) => document.querySelector(sel);
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// ---------- small helpers ----------

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const store = {
  get(key, fallback) {
    try { const v = localStorage.getItem('homelabmap.' + key); return v == null ? fallback : JSON.parse(v); } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem('homelabmap.' + key, JSON.stringify(value)); } catch { /* private mode: not persisted */ }
  },
  del(key) {
    try { localStorage.removeItem('homelabmap.' + key); } catch { /* ignore */ }
  },
};

function hhmm(t) {
  return t ? new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
}

function ago(t) {
  if (!t) return 'never';
  const s = Math.round((Date.now() - new Date(t).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  return Math.round(s / 86400) + ' days ago';
}

function dateTime(t) {
  return t ? new Date(t).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—';
}

async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: 'same-origin', ...opts });
  if (res.status === 401) {
    location.href = '/signin?return=' + encodeURIComponent(location.pathname + location.hash);
    throw new Error('login required');
  }
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.status === 204 ? null : res.json();
}

// ---------- icons and colours ----------

const OS_COLOR = {
  linux: '--os-linux', debian: '--os-linux', ubuntu: '--os-linux', alpine: '--os-linux', raspberrypi: '--os-linux',
  freebsd: '--os-linux', proxmox: '--os-proxmox', homeassistant: '--os-iot', windows: '--os-windows', apple: '--os-apple',
  android: '--os-android', printer: '--os-printer', media: '--os-media', gaming: '--os-media', iot: '--os-iot',
  camera: '--os-iot', phone: '--os-phone', nas: '--os-server', server: '--os-server', unknown: '--os-unknown',
  docker: '--os-docker', stack: '--os-docker',
};
const ROLE_COLOR = { router: '--node-router', switch: '--node-switch', ap: '--node-ap' };
const ROLE_NAME = {
  router: 'Router', switch: 'Switch', ap: 'Access point', hypervisor: 'Hypervisor', server: 'Server',
  vm: 'VM', container: 'Container', printer: 'Printer', client: 'Device',
  docker: 'Docker container', stack: 'Stack',
};
const VIRTUAL_ROLES = new Set(['vm', 'container', 'docker', 'stack']);
const KIND_NAME = {
  infra: 'Cable between network devices', wired: 'Cable', wireless: 'Wi-Fi', virtual: 'Virtual (inside host)',
  inferred: 'Inferred from MAC tables', unknown: 'Location unknown',
};

const iconCache = new Map();
function iconURI(key, color) {
  const cacheKey = key + '|' + color;
  if (iconCache.has(cacheKey)) return iconCache.get(cacheKey);
  const ic = ICONS[key] || ICONS.unknown;
  const paint = ic.mode === 'stroke'
    ? `fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"`
    : `fill="${color}"`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="48" height="48" ${paint}>${ic.body}</svg>`;
  const uri = 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
  iconCache.set(cacheKey, uri);
  return uri;
}

function nodeColors(n) {
  if (n.power === 'off') {
    const c = cssVar('--off');
    return { col: c, img: iconURI(n.icon, n.infra ? '#ffffff' : c) };
  }
  if (n.infra) {
    return { col: cssVar(ROLE_COLOR[n.role] || '--node-switch'), img: iconURI(n.icon, '#ffffff') };
  }
  const c = cssVar(OS_COLOR[n.icon] || '--os-unknown');
  return { col: c, img: iconURI(n.icon, c) };
}

// ---------- state ----------

const state = {
  cy: null,
  graph: null,
  scanId: null,
  status: null,
  layout: store.get('layout', 'fcose'),
  filters: { off: true, ...store.get('filters', { edge: true, virtual: true, unknown: true, ports: false }) },
  // #table, #table/heard etc. win over the remembered view.
  view: location.hash.startsWith('#table') ? 'table'
    : location.hash.startsWith('#map') ? 'map'
      : store.get('view', 'map') === 'table' ? 'table' : 'map',
  table: null,
  mapStale: false, // laid out while hidden: fit when shown
  pollTimer: null,
};

// ---------- cytoscape ----------

function buildStyle() {
  const c = (v) => cssVar(v);
  return [
    {
      selector: 'node',
      style: {
        label: 'data(label)',
        'font-size': 11,
        color: c('--text'),
        'text-valign': 'bottom',
        'text-margin-y': 5,
        'text-wrap': 'ellipsis',
        'text-max-width': 120,
        'text-outline-color': c('--bg'),
        'text-outline-width': 2,
        'min-zoomed-font-size': 7,
        width: 30,
        height: 30,
        'background-color': c('--node-surface'),
        'background-image': 'data(img)',
        'background-fit': 'none',
        'background-width': '62%',
        'background-height': '62%',
        'border-width': 2,
        'border-color': 'data(col)',
      },
    },
    {
      selector: 'node.infra',
      style: {
        shape: 'round-rectangle',
        width: 46,
        height: 46,
        'background-color': 'data(col)',
        'border-width': 0,
        'font-size': 12.5,
        'font-weight': 650,
      },
    },
    { selector: 'node.gateway', style: { width: 56, height: 56 } },
    // VMs are rounded squares, containers hexagons; both dashed (virtual).
    { selector: 'node.virtual', style: { width: 26, height: 26, 'border-style': 'dashed', 'font-size': 10 } },
    { selector: 'node.vm', style: { shape: 'round-rectangle' } },
    { selector: 'node.container', style: { shape: 'hexagon', width: 30, height: 27 } },
    { selector: 'node.docker', style: { shape: 'hexagon', width: 30, height: 27 } },
    // A closed stack: a layered square, like a pile of containers.
    { selector: 'node.stack', style: { shape: 'round-rectangle', width: 34, height: 34, 'border-style': 'double', 'border-width': 4 } },
    // An opened stack: a dashed box around its containers, labelled on top.
    {
      selector: 'node.stackbox',
      style: {
        'background-image': 'none', 'background-color': c('--os-docker'), 'background-opacity': 0.06,
        'border-style': 'dashed', 'border-width': 1.5, 'border-color': c('--os-docker'),
        'text-valign': 'top', 'text-margin-y': -4, padding: 14, 'font-weight': 600,
      },
    },
    // Powered off: grey (see nodeColors), see-through, muted label.
    { selector: 'node.off', style: { opacity: 0.55, color: c('--muted'), 'font-style': 'italic' } },
    // Absent (not seen now, shown from history): fainter still, dotted.
    { selector: 'node.absent', style: { opacity: 0.4, 'border-style': 'dotted', 'border-width': 2 } },
    { selector: 'node.unknownloc', style: { opacity: 0.8 } },
    {
      selector: 'node.new',
      style: { 'underlay-color': c('--new'), 'underlay-padding': 6, 'underlay-opacity': 0.4, 'underlay-shape': 'ellipse' },
    },
    {
      selector: 'edge',
      style: { 'curve-style': 'bezier', width: 1.5, 'line-color': c('--edge-wired'), opacity: 0.9 },
    },
    { selector: 'edge.infra', style: { width: 4, 'line-color': c('--edge-infra') } },
    { selector: 'edge.wireless', style: { width: 2, 'line-style': 'dotted', 'line-color': c('--edge-wireless') } },
    { selector: 'edge.virtual', style: { width: 1.5, 'line-style': 'dotted', 'line-color': c('--edge-virtual') } },
    { selector: 'edge.inferred', style: { width: 1.2, 'line-style': 'dashed', 'line-color': c('--edge-guess') } },
    {
      selector: 'edge.unknown',
      style: { width: 1, 'line-style': 'dashed', 'line-dash-pattern': [2, 6], 'line-color': c('--edge-guess') },
    },
    {
      selector: 'edge.ports',
      style: {
        'source-label': 'data(sourcePort)',
        'target-label': 'data(targetPort)',
        'source-text-offset': 26,
        'target-text-offset': 26,
        'font-size': 9,
        color: c('--muted'),
        'text-background-color': c('--surface'),
        'text-background-opacity': 0.9,
        'text-background-padding': 2,
        'min-zoomed-font-size': 8,
      },
    },
    { selector: 'edge.off', style: { opacity: 0.35 } },
    { selector: 'edge.absent', style: { opacity: 0.25, 'line-style': 'dotted' } },
    { selector: '.faded', style: { opacity: 0.12 } },
    { selector: 'node.match', style: { 'border-width': 4, 'border-color': c('--accent') } },
    { selector: 'node:selected', style: { 'overlay-color': c('--accent'), 'overlay-opacity': 0.18, 'overlay-padding': 7 } },
    { selector: 'edge:selected', style: { 'line-color': c('--accent') } },
    { selector: '.hidden', style: { display: 'none' } },
  ];
}

// toElements turns the graph into Cytoscape elements. Stacks are shown
// closed (one node per stack, members hidden) unless "Open stacks" is on;
// then each stack is a compound box around its containers.
function toElements(graph) {
  const els = [];
  const open = state.filters.stacks === true;
  const shown = new Set();
  const stackOf = new Map();
  for (const n of graph.nodes || []) {
    if (n.role === 'docker' && n.stack) {
      stackOf.set(n.id, n.stack);
      if (!open) continue;
    }
    shown.add(n.id);
    const cls = [n.infra ? 'infra' : 'edge', n.role];
    if (VIRTUAL_ROLES.has(n.role)) cls.push('virtual');
    if (n.role === 'stack' && open) cls.push('stackbox');
    if (n.connection === 'unknown') cls.push('unknownloc');
    if (n.new) cls.push('new');
    if (n.power === 'off') cls.push('off');
    if (n.absent) cls.push('absent');
    if (n.location === 'gateway') cls.push('gateway');
    // Cytoscape reads data.parent as a compound parent and would draw the
    // hypervisor as a box around its guests; keep it under another name.
    // Only an opened stack is a compound parent (its box); everything else
    // keeps its host under another name.
    const { parent, ...rest } = n;
    const data = { ...rest, host: parent, ...nodeColors(n) };
    if (open && n.role === 'docker' && n.stack) data.parent = n.stack;
    els.push({ group: 'nodes', data, classes: cls.join(' ') });
  }
  const off = new Set((graph.nodes || []).filter((n) => n.power === 'off').map((n) => n.id));
  for (const e of graph.edges || []) {
    if (!shown.has(e.source) || !shown.has(e.target)) continue;
    if (stackOf.get(e.target) === e.source) continue; // the box shows membership
    const cls = [e.kind];
    if (off.has(e.source) || off.has(e.target)) cls.push('off');
    if (e.absent) cls.push('absent');
    els.push({ group: 'edges', data: { ...e }, classes: cls.join(' ') });
  }
  return els;
}

function initCy() {
  state.cy = cytoscape({
    container: $('#map'),
    style: buildStyle(),
    wheelSensitivity: 0.25,
    minZoom: 0.1,
    maxZoom: 3,
    boxSelectionEnabled: false,
  });
  const cy = state.cy;
  cy.on('mouseover', 'node', (e) => showTooltip(e.target));
  cy.on('mouseover', 'edge', (e) => showTooltip(e.target));
  cy.on('mouseout', 'node, edge', hideTooltip);
  cy.on('pan zoom drag', hideTooltip);
  cy.on('tap', 'node', (e) => showDetails(e.target));
  cy.on('tap', (e) => { if (e.target === cy) closeDetails(); });
  cy.on('dragfree', 'node', savePositions);
}

// ---------- layout ----------

function positionsKey() { return 'pos.' + state.layout; }

function savePositions() {
  const pos = {};
  state.cy.nodes().forEach((n) => { pos[n.id()] = n.position(); });
  store.set(positionsKey(), pos);
}

function gatewayNode() {
  const gw = state.cy.nodes('.gateway');
  return gw.length ? gw : state.cy.nodes('.infra').filter((n) => n.data('depth') === 0);
}

function runLayout({ fresh = false } = {}) {
  const cy = state.cy;
  const visible = cy.elements().not('.hidden');
  if (visible.nodes().length === 0) return;
  const saved = fresh ? {} : store.get(positionsKey(), {});
  const known = visible.nodes().filter((n) => saved[n.id()]);
  known.forEach((n) => n.position(saved[n.id()]));

  if (known.length === visible.nodes().length) {
    cy.fit(visible, 40);
    return;
  }

  let opts;
  if (state.layout === 'tree') {
    opts = {
      name: 'breadthfirst', roots: gatewayNode(), directed: true, spacingFactor: 1.05,
      avoidOverlap: true, nodeDimensionsIncludeLabels: true,
    };
  } else if (state.layout === 'radial') {
    const maxDepth = Math.max(1, ...cy.nodes().map((n) => n.data('depth')));
    opts = {
      name: 'concentric', minNodeSpacing: 14, avoidOverlap: true, nodeDimensionsIncludeLabels: true,
      concentric: (n) => (n.data('depth') < 0 ? 0 : maxDepth + 1 - n.data('depth')),
      levelWidth: () => 1,
    };
  } else {
    opts = {
      name: 'fcose', quality: 'proof', animate: false, randomize: known.length === 0,
      nodeDimensionsIncludeLabels: true, packComponents: true, tile: true,
      idealEdgeLength: (e) => (e.hasClass('infra') ? 160 : e.hasClass('virtual') ? 45 : 70),
      nodeRepulsion: (n) => (n.hasClass('infra') ? 30000 : 6500),
      edgeElasticity: (e) => (e.hasClass('infra') ? 0.25 : 0.45),
      gravity: 0.25, gravityRange: 3.8, numIter: 3000,
      fixedNodeConstraint: known.length ? known.map((n) => ({ nodeId: n.id(), position: saved[n.id()] })) : undefined,
    };
  }
  const layout = visible.layout(opts);
  layout.one('layoutstop', () => { cy.fit(visible, 40); savePositions(); });
  layout.run();
}

// ---------- graph loading ----------

async function loadGraph() {
  const graph = await api('/api/graph');
  state.graph = graph;
  const cy = state.cy;
  const isFirst = cy.elements().length === 0;
  const before = new Set(cy.nodes().map((n) => n.id()));

  cy.batch(() => {
    const els = toElements(graph);
    const ids = new Set(els.map((e) => e.data.id));
    cy.elements().filter((e) => !ids.has(e.id())).remove();
    for (const el of els) {
      const existing = cy.getElementById(el.data.id);
      if (existing.length) {
        existing.data(el.data);
        existing.classes(el.classes);
      } else {
        // New nodes start next to a neighbour so incremental layout is calm.
        cy.add(el);
      }
    }
  });
  const added = cy.nodes().filter((n) => !before.has(n.id()));
  added.forEach((n) => {
    const anchor = n.neighborhood('node').filter((m) => before.has(m.id())).first();
    if (anchor.length) {
      const p = anchor.position();
      n.position({ x: p.x + (Math.random() - 0.5) * 60, y: p.y + (Math.random() - 0.5) * 60 });
    }
  });

  applyFilters();
  renderWarnings(graph.warnings || []);
  renderEmpty();
  if (isFirst || added.length) {
    runLayout();
    if (state.view !== 'map') state.mapStale = true;
  }
  if (!$('#details').hidden) {
    const id = $('#details').dataset.id;
    const n = cy.getElementById(id);
    if (n.length) showDetails(n); else closeDetails();
  }
}

function renderEmpty() {
  const empty = $('#empty');
  const hasNodes = (state.graph?.nodes || []).length > 0;
  empty.hidden = hasNodes;
  if (hasNodes) return;
  const st = state.status;
  let msg = '<strong>No map yet</strong>';
  if (!st?.scannerOnline) {
    msg += 'The scanner has not connected. Check that the homelabmap-scanner container is running.';
  } else if (st?.active) {
    msg += 'The first scan is running. The map will appear when it finishes.';
  } else {
    msg += 'Start a scan with “Scan now”.';
  }
  empty.innerHTML = `<div>${msg}</div>`;
}

function renderWarnings(warnings) {
  const box = $('#warnings');
  box.hidden = warnings.length === 0;
  if (!warnings.length) return;
  box.querySelector('summary').textContent = `${warnings.length} data-quality warning${warnings.length > 1 ? 's' : ''}`;
  box.querySelector('ul').innerHTML = warnings.map((w) => `<li>${esc(w)}</li>`).join('');
}

// ---------- status ----------

async function refreshStatus() {
  let st;
  try {
    st = await api('/api/status');
  } catch (err) {
    $('#status').innerHTML = `<span class="dot bad"></span><span class="bad-text">${esc(err.message)}</span>`;
    schedulePoll(30000);
    return;
  }
  state.status = st;
  $('#user').textContent = st.user?.name || st.user?.email || '';

  const parts = [];
  if (st.active) {
    const what = st.active.status === 'running' ? `Scanning since ${hhmm(st.active.startedAt)}` : 'Scan queued';
    parts.push(`<span class="dot busy"></span>${what}…`);
  } else if (st.scannerOnline) {
    parts.push('<span class="dot ok"></span>Scanner online');
  } else {
    parts.push(`<span class="dot bad"></span><span class="bad-text">Scanner offline (last seen ${esc(ago(st.scannerLastSeen))})</span>`);
  }
  if (st.latest) {
    parts.push(`map from ${hhmm(st.latest.finishedAt)} · ${st.latest.nodes} devices, ${st.latest.edges} links`);
  }
  if (!st.active) parts.push(`next scan ${hhmm(st.nextScanAt)}`);
  if (st.lastSightingAt && Date.now() - new Date(st.lastSightingAt).getTime() < 30 * 60 * 1000) {
    parts.push(`<span title="Last ARP/IPv6 neighbour discovery report ${esc(ago(st.lastSightingAt))}">listening for new devices</span>`);
  }
  $('#status').innerHTML = parts.join(' · ');
  $('#scan-now').disabled = Boolean(st.active);
  $('#scan-now').textContent = st.active ? 'Scanning…' : 'Scan now';

  const latestId = st.latest?.id ?? null;
  if (latestId !== state.scanId) {
    state.scanId = latestId;
    await loadGraph();
  } else {
    renderEmpty();
  }
  if (state.view === 'table') state.table.refresh();
  schedulePoll(st.active ? 4000 : 15000);
}

function schedulePoll(ms) {
  clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(refreshStatus, ms);
}

async function scanNow() {
  $('#scan-now').disabled = true;
  try {
    await api('/api/scan', { method: 'POST', headers: { 'X-Homelabmap-Request': '1' } });
  } catch (err) {
    $('#scan-now').disabled = false;
    alert('Could not start a scan: ' + err.message);
    return;
  }
  refreshStatus();
}

// ---------- filters and search ----------

// isVisible applies the "Show" filters to a node's data (map and table).
function isVisible(d) {
  const f = state.filters;
  const virtual = VIRTUAL_ROLES.has(d.role);
  return !((!f.edge && !d.infra) || (!f.virtual && virtual) || (!f.unknown && d.connection === 'unknown') ||
    (f.off === false && d.power === 'off'));
}

// matchesQuery is the search box's test (q already lower-cased).
function matchesQuery(d, q) {
  if (!q) return true;
  const hay = [d.label, d.os, d.vendor, d.location, d.model, d.image, ...(d.ips || []), ...(d.ipv6 || []), ...(d.macs || []), ...(d.otherMacs || []), ...(d.dns || [])]
    .join(' ').toLowerCase();
  return hay.includes(q);
}

function applyFilters() {
  const f = state.filters;
  const cy = state.cy;
  cy.batch(() => {
    cy.nodes().forEach((n) => n.toggleClass('hidden', !isVisible(n.data())));
    cy.edges().toggleClass('ports', f.ports);
  });
  if (state.view === 'table') state.table.render();
}

function applySearch(q) {
  const cy = state.cy;
  q = q.trim().toLowerCase();
  cy.batch(() => {
    cy.elements().removeClass('faded match');
    if (!q) return;
    const hits = cy.nodes().filter((n) => matchesQuery(n.data(), q));
    cy.elements().not(hits).not(hits.connectedEdges()).addClass('faded');
    hits.addClass('match');
  });
  return cy.nodes('.match');
}

// ---------- tooltip and details ----------

function row(label, value, cls = '') {
  if (value == null || value === '' || (Array.isArray(value) && value.length === 0)) return '';
  const v = Array.isArray(value) ? value.map(esc).join('<br>') : esc(value);
  return `<dt>${esc(label)}</dt><dd class="${cls}">${v}</dd>`;
}

function nodeHeader(d, tag = 'h3') {
  const role = ROLE_NAME[d.role] || d.role;
  return `<${tag}>${esc(d.label)} <span class="tag">${esc(role)}</span>${d.new ? '<span class="tag new">new</span>' : ''}</${tag}>`;
}

function powerLine(d) {
  if (d.absent) return d.lastSeen ? `Not seen since ${ago(d.lastSeen)}` : 'Not seen recently';
  if (!d.power) return '';
  const word = d.power === 'on' ? 'On' : 'Off';
  return d.powerState && d.powerState !== 'online' ? `${word} (${d.powerState})` : word;
}

function osLine(d) {
  if (!d.os) return 'unknown';
  return d.os;
}

function showTooltip(el) {
  const tip = $('#tooltip');
  if (el.isNode() && (el.data('role') === 'docker' || el.data('role') === 'stack')) {
    const d = el.data();
    tip.innerHTML = nodeHeader(d) + '<dl class="kv">' +
      row('Image', d.image, 'mono') +
      row(d.role === 'stack' ? 'Containers' : 'Status', d.status) +
      row('Power', powerLine(d), d.power === 'off' ? 'off' : '') +
      row('Network', d.network) +
      row('URL', d.urls) +
      row('Where', d.location) +
      '</dl>';
  } else if (el.isNode()) {
    const d = el.data();
    tip.innerHTML = nodeHeader(d) + '<dl class="kv">' +
      row('IP', d.ips?.length ? d.ips : '—', 'mono') +
      row('MAC', d.macs?.length ? d.macs[0] + (d.macs.length > 1 ? ` (+${d.macs.length - 1})` : '') : '—', 'mono') +
      (d.otherMacs?.length ? row('Earlier MACs', `${d.otherMacs.length} private address${d.otherMacs.length > 1 ? 'es' : ''}`) : '') +
      row('DNS', d.dns?.length ? d.dns : '—') +
      row('OS', osLine(d)) +
      row('Power', powerLine(d), d.power === 'off' ? 'off' : '') +
      row('Vendor', d.vendor) +
      row('Where', d.location) +
      '</dl>';
  } else {
    const d = el.data();
    const s = state.cy.getElementById(d.source).data('label');
    const t = state.cy.getElementById(d.target).data('label');
    const sp = d.sourcePort ? ` ${d.sourcePort}` : '';
    const tp = d.targetPort ? ` ${d.targetPort}` : '';
    tip.innerHTML = `<h3>${esc(KIND_NAME[d.kind] || d.kind)}</h3><dl class="kv">` +
      row('From', s + sp) + row('To', t + tp) + row('Seen by', (d.sources || []).join(', ')) + '</dl>';
  }
  tip.hidden = false;
  const wrap = $('.map-wrap').getBoundingClientRect();
  const p = el.isNode() ? el.renderedPosition() : el.renderedMidpoint();
  const r = tip.getBoundingClientRect();
  let x = p.x + 18;
  let y = p.y + 18;
  if (x + r.width > wrap.width - 8) x = p.x - r.width - 18;
  if (y + r.height > wrap.height - 8) y = Math.max(8, wrap.height - r.height - 8);
  tip.style.left = Math.max(8, x) + 'px';
  tip.style.top = Math.max(8, y) + 'px';
}

function hideTooltip() { $('#tooltip').hidden = true; }

function showDetails(node) {
  const d = node.data();
  const panel = $('#details');
  panel.dataset.id = d.id;
  const links = node.connectedEdges().map((e) => {
    const other = e.source().id() === d.id ? e.target() : e.source();
    const mine = e.source().id() === d.id ? e.data('sourcePort') : e.data('targetPort');
    const theirs = e.source().id() === d.id ? e.data('targetPort') : e.data('sourcePort');
    const ports = [mine && `here ${mine}`, theirs && `there ${theirs}`].filter(Boolean).join(', ');
    return `<li><a data-goto="${esc(other.id())}">${esc(other.data('label'))}</a>` +
      ` <span class="src">${esc(KIND_NAME[e.data('kind')] || e.data('kind'))}${ports ? ' · ' + esc(ports) : ''}</span></li>`;
  });
  $('#details-body').innerHTML = nodeHeader(d, 'h2') +
    '<dl class="kv">' +
    row('IP', d.ips, 'mono') +
    row('IPv6', d.ipv6, 'mono') +
    row('MAC', d.macs, 'mono') +
    row('Earlier private MACs', d.otherMacs, 'mono') +
    row('DNS', d.dns) +
    row('OS', osLine(d)) +
    (d.osSource ? row('OS from', d.osSource) : '') +
    row('Power', powerLine(d), d.power === 'off' ? 'off' : '') +
    row('Vendor', d.vendor) +
    row('Model', d.model) +
    row('Where', d.location) +
    row('First seen', d.firstSeen ? dateTime(d.firstSeen) : '') +
    row('Last seen', d.lastSeen ? `${ago(d.lastSeen)} (${dateTime(d.lastSeen)})` : '') +
    row('Image', d.image, 'mono') +
    row('Status', d.status) +
    row('Network', d.network) +
    row('Published', d.published, 'mono') +
    '</dl>' +
    urlSection(d) +
    membersSection(d) +
    (d.openPorts?.length ? `<section><h4>Open ports</h4><div class="mono">${d.openPorts.map(esc).join('<br>')}</div></section>` : '') +
    (links.length ? `<section><h4>Connections</h4><ul>${links.join('')}</ul></section>` : '') +
    `<section><h4>Sources</h4><div class="src">${esc((d.sources || []).join(', '))}</div></section>`;
  panel.hidden = false;
  state.cy.resize();
}

// urlSection lists reverse-proxy routes as links. They are always
// https://<host> built by homelabmap from the Cosmos configuration.
function urlSection(d) {
  if (!d.urls?.length) return '';
  const items = d.urls.map((u) => `<li><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u.replace(/^https:\/\//, ''))}</a></li>`);
  return `<section><h4>Open in browser</h4><ul>${items.join('')}</ul></section>`;
}

// membersSection lists a stack's containers; with stacks closed they
// aren't on the map, so they're listed without links.
function membersSection(d) {
  if (!d.members?.length) return '';
  const byId = new Map((state.graph?.nodes || []).map((n) => [n.id, n]));
  const items = d.members.map((id) => {
    const m = byId.get(id);
    if (!m) return '';
    const name = state.cy.getElementById(id).length ? `<a data-goto="${esc(id)}">${esc(m.label)}</a>` : esc(m.label);
    return `<li>${name} <span class="src">${esc(m.power === 'off' ? m.powerState || 'stopped' : m.status || 'running')} · ${esc(m.image || '')}</span></li>`;
  });
  return `<section><h4>Containers</h4><ul>${items.join('')}</ul></section>`;
}

function closeDetails() {
  $('#details').hidden = true;
  state.cy?.resize();
}

// ---------- legend ----------

function renderLegend() {
  const infra = (role, label) =>
    `<div class="item"><span class="sw infra" style="background:${cssVar(ROLE_COLOR[role])}"><img alt="" src="${iconURI(role, '#ffffff')}"></span>${label}</div>`;
  const os = (icon, label) => {
    const c = cssVar(OS_COLOR[icon]);
    return `<div class="item"><span class="sw edge" style="border-color:${c}"><img alt="" src="${iconURI(icon, c)}"></span>${label}</div>`;
  };
  const shape = (kind, label) => {
    const grey = kind === 'off' || kind === 'absent';
    const c = cssVar(grey ? '--off' : '--os-linux');
    const body = kind === 'container'
      ? '<polygon points="12,2 21,7 21,17 12,22 3,17 3,7"/>'
      : kind === 'vm'
        ? '<rect x="3" y="3" width="18" height="18" rx="5"/>'
        : '<circle cx="12" cy="12" r="9"/>';
    const dash = kind === 'off' ? '' : kind === 'absent' ? ' stroke-dasharray="1 2.5"' : ' stroke-dasharray="3 2"';
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="${cssVar('--node-surface')}" stroke="${c}" stroke-width="2"${dash}>${body}</svg>`;
    return `<div class="item"><span class="sw shape${grey ? ' ' + kind : ''}"><img alt="" src="data:image/svg+xml;utf8,${encodeURIComponent(svg)}"></span>${label}</div>`;
  };
  const line = (cls, label) => `<div class="item full"><span class="line ${cls}"></span>${label}</div>`;
  $('#legend').innerHTML =
    infra('router', 'Router') + infra('switch', 'Switch') + infra('ap', 'Access point') +
    os('proxmox', 'Proxmox') + os('linux', 'Linux') + os('windows', 'Windows') + os('apple', 'Apple') +
    os('android', 'Android') + os('printer', 'Printer') + os('media', 'TV / media') + os('iot', 'IoT') +
    os('phone', 'Phone (private MAC)') + os('unknown', 'Unknown') +
    shape('vm', 'VM') + shape('container', 'Container') + shape('off', 'Powered off') + shape('absent', 'Not seen now') +
    os('docker', 'Docker container') + os('stack', 'Docker stack') +
    line('infra', 'Cable between network devices') + line('', 'Cable to a device') + line('wireless', 'Wi-Fi') +
    line('virtual', 'VM / container on host') + line('guess', 'Inferred or unknown location');
}

// ---------- theme ----------

function restyle() {
  iconCache.clear();
  const cy = state.cy;
  cy.batch(() => cy.nodes().forEach((n) => n.data(nodeColors(n.data()))));
  cy.style(buildStyle());
  renderLegend();
}

// ---------- views ----------

function setView(view) {
  state.view = view;
  store.set('view', view);
  document.body.dataset.view = view;
  if (view === 'map') history.replaceState(null, '', state.filters.stacks ? '#map/stacks' : '#map');
  document.querySelectorAll('[data-view]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === view)));
  $('.map-wrap').hidden = view !== 'map';
  $('#table-view').hidden = view !== 'table';
  hideTooltip();
  if (view === 'map') {
    state.cy.resize();
    if (state.mapStale) {
      state.mapStale = false;
      state.cy.fit(state.cy.elements().not('.hidden'), 40);
    }
  } else {
    state.table.render();
  }
}

// selectNode shows a device's details from anywhere (table rows, links in
// the details panel); on the map it also centres it.
function selectNode(id) {
  let n = state.cy.getElementById(id);
  if (!n.length) {
    // A container in a closed stack isn't drawn: show its stack.
    const stack = (state.graph?.nodes || []).find((g) => g.id === id)?.stack;
    if (stack) n = state.cy.getElementById(stack);
  }
  if (!n.length) return;
  state.cy.$(':selected').unselect();
  n.select();
  showDetails(n);
  if (state.view === 'map') state.cy.animate({ center: { eles: n }, duration: 250 });
  else state.table.highlight(id);
}

// ---------- wiring ----------

function bindControls() {
  document.querySelectorAll('[data-view]').forEach((b) => b.addEventListener('click', () => setView(b.dataset.view)));
  $('#scan-now').addEventListener('click', scanNow);
  $('#fit').addEventListener('click', () => state.cy.fit(state.cy.elements().not('.hidden'), 40));
  $('#relayout').addEventListener('click', () => { store.del(positionsKey()); runLayout({ fresh: true }); });
  $('#details-close').addEventListener('click', closeDetails);
  $('#details-body').addEventListener('click', (e) => {
    const id = e.target.closest('[data-goto]')?.dataset.goto;
    if (id) selectNode(id);
  });

  const stacks = $('#f-stacks');
  stacks.checked = state.filters.stacks === true;
  stacks.addEventListener('change', async () => {
    state.filters.stacks = stacks.checked;
    store.set('filters', state.filters);
    history.replaceState(null, '', stacks.checked ? '#map/stacks' : '#map');
    closeDetails();
    // Opening or closing stacks changes which nodes exist: rebuild.
    state.cy.elements().remove();
    await loadGraph();
  });
  for (const [id, key] of [['#f-edge', 'edge'], ['#f-virtual', 'virtual'], ['#f-unknown', 'unknown'], ['#f-off', 'off'], ['#f-ports', 'ports']]) {
    const box = $(id);
    box.checked = state.filters[key];
    box.addEventListener('change', () => {
      state.filters[key] = box.checked;
      store.set('filters', state.filters);
      applyFilters();
    });
  }

  document.querySelectorAll('[data-layout]').forEach((btn) => {
    btn.setAttribute('aria-pressed', String(btn.dataset.layout === state.layout));
    btn.addEventListener('click', () => {
      state.layout = btn.dataset.layout;
      store.set('layout', state.layout);
      document.querySelectorAll('[data-layout]').forEach((b) => b.setAttribute('aria-pressed', String(b === btn)));
      runLayout();
    });
  });

  const search = $('#search');
  search.addEventListener('input', () => {
    applySearch(search.value);
    if (state.view === 'table') state.table.render();
  });
  search.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && state.view === 'map') {
      const hits = applySearch(search.value);
      if (hits.length) state.cy.animate({ fit: { eles: hits, padding: 120 }, duration: 300 });
    } else if (e.key === 'Escape') {
      search.value = '';
      applySearch('');
      if (state.view === 'table') state.table.render();
      search.blur();
    }
  });
  document.addEventListener('keydown', (e) => {
    const typing = ['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName);
    if (e.key === '/' && !typing) { e.preventDefault(); search.focus(); }
    if (e.key === 'Escape' && !typing) closeDetails();
  });

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', restyle);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshStatus(); });
}

// #map/stacks opens the stacks (bookmarkable).
if (location.hash === '#map/stacks') state.filters.stacks = true;
initCy();
state.table = createTable({
  esc, dateTime, ago, api, store, powerLine,
  roleName: (r) => ROLE_NAME[r] || r,
  kindName: (k) => KIND_NAME[k] || k,
  graph: () => state.graph,
  query: () => $('#search').value.trim().toLowerCase(),
  visible: isVisible,
  matches: matchesQuery,
  select: selectNode,
  initial: location.hash.split('/')[1],
});
renderLegend();
bindControls();
setView(state.view);
refreshStatus();
