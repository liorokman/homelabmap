// Table view: everything homelabmap knows, as sortable tables with CSV export.
//
// Devices and Links come from the current map; Sightings (what the passive
// listener heard) and Scans are fetched when shown.

const VIEWS = ['devices', 'containers', 'links', 'sightings', 'scans'];
// URL names (#table/heard) for each view.
const SLUG = { devices: 'devices', containers: 'containers', links: 'links', sightings: 'heard', scans: 'scans' };
const fromSlug = (s) => Object.keys(SLUG).find((k) => SLUG[k] === s);

// ipKey sorts IPv4 numerically and IPv6 after IPv4.
function ipKey(ip) {
  if (!ip) return '~';
  if (ip.includes(':')) return '1' + ip;
  return '0' + ip.split('.').map((o) => o.padStart(3, '0')).join('.');
}

const timeKey = (t) => (t ? new Date(t).getTime() : 0);

export function createTable(ctx) {
  const { esc, dateTime, ago, roleName, kindName, powerLine, api, store } = ctx;
  const root = document.querySelector('#table-view');
  const body = root.querySelector('.table-scroll');
  const count = root.querySelector('#table-count');

  const state = {
    view: fromSlug(ctx.initial) || (VIEWS.includes(store.get('table.view')) ? store.get('table.view') : 'devices'),
    sort: store.get('table.sort', {}),
    sightings: null,
    scans: null,
    loading: null,
    selected: null,
  };

  const labelByID = () => new Map((ctx.graph()?.nodes || []).map((n) => [n.id, n.label]));
  const nodeByMAC = () => {
    const m = new Map();
    for (const n of ctx.graph()?.nodes || []) for (const mac of n.macs || []) m.set(mac, n);
    return m;
  };

  // Column: label, text (display and CSV), optional html, sort key, class.
  const col = (label, text, opts = {}) => ({ label, text, ...opts });
  const list = (a) => (a || []).join(', ');
  const listHTML = (a, cls = '') => (a || []).map((x) => `<div class="${cls}">${esc(x)}</div>`).join('');

  function columns(view) {
    switch (view) {
      case 'devices':
        return [
          col('Name', (n) => n.label, { html: (n) => `<a data-node="${esc(n.id)}">${esc(n.label)}</a>${n.new ? ' <span class="tag new">new</span>' : ''}` }),
          col('Type', (n) => roleName(n.role)),
          col('Power', (n) => powerLine(n), { cls: (n) => (n.power === 'off' ? 'off' : ''), sort: (n) => (n.absent ? 2 : n.power === 'off' ? 1 : 0) }),
          col('IPv4', (n) => list(n.ips), { html: (n) => listHTML(n.ips, 'mono'), sort: (n) => ipKey(n.ips?.[0]) }),
          col('IPv6', (n) => list(n.ipv6), { html: (n) => listHTML(n.ipv6, 'mono'), sort: (n) => n.ipv6?.[0] || '~' }),
          col('MAC', (n) => list(n.macs), { html: (n) => listHTML(n.macs, 'mono') }),
          col('Earlier MACs', (n) => list(n.otherMacs), { html: (n) => listHTML(n.otherMacs, 'mono') }),
          col('Vendor', (n) => n.vendor || '', { wrap: true }),
          col('OS', (n) => n.os || '', { wrap: true }),
          col('OS from', (n) => n.osSource || ''),
          col('Model', (n) => n.model || '', { wrap: true }),
          col('Location', (n) => n.location || '', { wrap: true }),
          col('DNS', (n) => list(n.dns), { html: (n) => listHTML(n.dns) }),
          col('Open ports', (n) => list(n.openPorts), { html: (n) => listHTML(n.openPorts, 'mono') }),
          col('Sources', (n) => list(n.sources), { wrap: true }),
          col('First seen', (n) => dateTime(n.firstSeen), { sort: (n) => timeKey(n.firstSeen) }),
          col('Last seen', (n) => (n.lastSeen ? ago(n.lastSeen) : ''), { title: (n) => dateTime(n.lastSeen), sort: (n) => timeKey(n.lastSeen) }),
        ];
      case 'containers': {
        const label = labelByID();
        return [
          col('Name', (n) => n.label, { html: (n) => `<a data-node="${esc(n.id)}">${esc(n.label)}</a>` }),
          col('Stack', (n) => (n.stack ? label.get(n.stack) || '' : '')),
          col('State', (n) => (n.power === 'on' ? n.status || 'running' : n.powerState || 'stopped'), { cls: (n) => (n.power === 'off' ? 'off' : '') }),
          col('Image', (n) => n.image || '', { cls: () => 'mono' }),
          col('Network', (n) => n.network || ''),
          col('Published', (n) => list(n.published), { html: (n) => listHTML(n.published, 'mono') }),
          col('URL', (n) => list(n.urls), {
            html: (n) => (n.urls || []).map((u) => `<div><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u.replace(/^https:\/\//, ''))}</a></div>`).join(''),
          }),
          col('Host', (n) => {
            const host = n.stack ? (ctx.graph()?.nodes || []).find((s) => s.id === n.stack)?.parent : n.parent;
            return label.get(host) || '';
          }),
          col('Created', (n) => dateTime(n.firstSeen), { sort: (n) => timeKey(n.firstSeen) }),
        ];
      }
      case 'links': {
        const label = labelByID();
        return [
          col('From', (e) => label.get(e.source) || e.source, { html: (e) => `<a data-node="${esc(e.source)}">${esc(label.get(e.source) || e.source)}</a>` }),
          col('Port', (e) => e.sourcePort || '', { cls: () => 'mono' }),
          col('To', (e) => label.get(e.target) || e.target, { html: (e) => `<a data-node="${esc(e.target)}">${esc(label.get(e.target) || e.target)}</a>` }),
          col('Port ', (e) => e.targetPort || '', { cls: () => 'mono' }),
          col('Kind', (e) => kindName(e.kind)),
          col('Seen by', (e) => list(e.sources)),
        ];
      }
      case 'sightings': {
        const byMAC = nodeByMAC();
        return [
          col('MAC', (s) => s.mac, { cls: () => 'mono' }),
          col('Device', (s) => byMAC.get(s.mac)?.label || '', {
            html: (s) => {
              const n = byMAC.get(s.mac);
              return n ? `<a data-node="${esc(n.id)}">${esc(n.label)}</a>` : '<span class="src">not on the map</span>';
            },
          }),
          col('IP', (s) => s.ip, { cls: () => 'mono', sort: (s) => ipKey(s.ip) }),
          col('Heard via', (s) => (s.via === 'ndp' ? 'IPv6 neighbour discovery' : 'ARP')),
          col('First heard', (s) => dateTime(s.firstSeen), { sort: (s) => timeKey(s.firstSeen) }),
          col('Last heard', (s) => ago(s.lastSeen), { title: (s) => dateTime(s.lastSeen), sort: (s) => timeKey(s.lastSeen) }),
        ];
      }
      case 'scans':
        return [
          col('#', (s) => String(s.id), { sort: (s) => s.id }),
          col('Kind', (s) => (s.trigger === 'probe' ? 'Probe (new device)' : s.trigger === 'manual' ? 'Full (manual)' : 'Full (scheduled)')),
          col('Status', (s) => s.status, { cls: (s) => (s.status === 'failed' ? 'bad-text' : '') }),
          col('Requested', (s) => dateTime(s.requestedAt), { sort: (s) => timeKey(s.requestedAt) }),
          col('Took', (s) => took(s), { sort: (s) => (s.startedAt && s.finishedAt ? timeKey(s.finishedAt) - timeKey(s.startedAt) : -1) }),
          col('Devices', (s) => (s.status === 'done' ? String(s.nodes) : ''), { sort: (s) => s.nodes }),
          col('Links', (s) => (s.status === 'done' ? String(s.edges) : ''), { sort: (s) => s.edges }),
          col('Probed', (s) => (s.targets || []).map((t) => t.mac).join(', '), { cls: () => 'mono' }),
          col('Error', (s) => s.error || '', { cls: () => 'bad-text', wrap: true }),
        ];
    }
    return [];
  }

  function took(s) {
    if (!s.startedAt || !s.finishedAt) return '';
    const sec = Math.round((timeKey(s.finishedAt) - timeKey(s.startedAt)) / 1000);
    return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
  }

  function rows(view) {
    const g = ctx.graph();
    const q = ctx.query();
    switch (view) {
      case 'devices':
        return (g?.nodes || []).filter((n) => n.role !== 'docker' && n.role !== 'stack' && ctx.visible(n) && ctx.matches(n, q));
      case 'containers':
        return (g?.nodes || []).filter((n) => n.role === 'docker' && ctx.matches(n, q));
      case 'links': {
        const nodes = new Map((g?.nodes || []).map((n) => [n.id, n]));
        return (g?.edges || []).filter((e) => {
          const a = nodes.get(e.source);
          const b = nodes.get(e.target);
          return a && b && ctx.visible(a) && ctx.visible(b) && (!q || ctx.matches(a, q) || ctx.matches(b, q));
        });
      }
      case 'sightings': {
        const byMAC = nodeByMAC();
        return (state.sightings || []).filter((s) => !q || [s.mac, s.ip, byMAC.get(s.mac)?.label].join(' ').toLowerCase().includes(q));
      }
      case 'scans':
        return (state.scans || []).filter((s) => !q || [s.id, s.trigger, s.status, s.error, ...(s.targets || []).map((t) => t.mac)].join(' ').toLowerCase().includes(q));
    }
    return [];
  }

  function sorted(view, cols, data) {
    const s = state.sort[view];
    const c = s && cols.find((x) => x.label === s.col);
    if (!c) return data;
    const key = c.sort || c.text;
    const dir = s.dir === 'desc' ? -1 : 1;
    return [...data].sort((a, b) => {
      const ka = key(a);
      const kb = key(b);
      const r = typeof ka === 'number' && typeof kb === 'number'
        ? ka - kb
        : String(ka).localeCompare(String(kb), undefined, { numeric: true, sensitivity: 'base' });
      return r * dir;
    });
  }

  function render() {
    history.replaceState(null, '', '#table/' + SLUG[state.view]);
    root.querySelectorAll('[data-table]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.table === state.view)));
    const view = state.view;
    if ((view === 'sightings' && !state.sightings) || (view === 'scans' && !state.scans)) {
      body.innerHTML = '<p class="table-empty">Loading…</p>';
      count.textContent = '';
      refresh();
      return;
    }
    const cols = columns(view);
    const data = sorted(view, cols, rows(view));
    const s = state.sort[view] || {};
    count.textContent = `${data.length} ${data.length === 1 ? 'row' : 'rows'}`;
    if (!data.length) {
      const why = view === 'sightings'
        ? 'Nothing heard yet. The scanner reports ARP and IPv6 neighbour discovery as devices talk.'
        : 'No rows match the search and filters.';
      body.innerHTML = `<p class="table-empty">${esc(why)}</p>`;
      return;
    }
    const head = cols.map((c) => {
      const aria = s.col === c.label ? (s.dir === 'desc' ? 'descending' : 'ascending') : 'none';
      return `<th scope="col" aria-sort="${aria}"><button type="button" data-sort="${esc(c.label)}">${esc(c.label.trim())}</button></th>`;
    }).join('');
    const bodyRows = data.map((r) => {
      const id = view === 'devices' ? r.id : '';
      const sel = id && id === state.selected ? ' class="selected"' : '';
      return `<tr${id ? ` data-row="${esc(id)}"` : ''}${sel}>` + cols.map((c) => {
        const cls = [c.cls ? c.cls(r) : '', c.wrap ? 'wrap' : ''].filter(Boolean).join(' ');
        const title = c.title ? ` title="${esc(c.title(r))}"` : '';
        return `<td${cls ? ` class="${cls}"` : ''}${title}>${c.html ? c.html(r) : esc(c.text(r))}</td>`;
      }).join('') + '</tr>';
    }).join('');
    body.innerHTML = `<table class="data"><thead><tr>${head}</tr></thead><tbody>${bodyRows}</tbody></table>`;
  }

  async function refresh() {
    if (state.loading) return state.loading;
    state.loading = (async () => {
      try {
        if (state.view === 'sightings') state.sightings = await api('/api/sightings');
        if (state.view === 'scans') state.scans = await api('/api/scans');
      } catch (err) {
        body.innerHTML = `<p class="table-empty bad-text">${esc(err.message)}</p>`;
        return;
      } finally {
        state.loading = null;
      }
      render();
    })();
    return state.loading;
  }

  function csv() {
    const cols = columns(state.view);
    const data = sorted(state.view, cols, rows(state.view));
    const cell = (v) => {
      const s = String(v ?? '');
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = [cols.map((c) => cell(c.label.trim())), ...data.map((r) => cols.map((c) => cell(c.text(r))))];
    const blob = new Blob([lines.map((l) => l.join(',')).join('\r\n') + '\r\n'], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `homelabmap-${state.view}-${new Date().toISOString().slice(0, 16).replace(':', '')}.csv`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  root.addEventListener('click', (e) => {
    const tab = e.target.closest('[data-table]');
    if (tab) {
      state.view = tab.dataset.table;
      store.set('table.view', state.view);
      render();
      if (state.view === 'sightings' || state.view === 'scans') refresh();
      return;
    }
    const sortBtn = e.target.closest('[data-sort]');
    if (sortBtn) {
      const cur = state.sort[state.view];
      const colName = sortBtn.dataset.sort;
      state.sort[state.view] = { col: colName, dir: cur?.col === colName && cur.dir === 'asc' ? 'desc' : 'asc' };
      store.set('table.sort', state.sort);
      render();
      return;
    }
    if (e.target.closest('#table-csv')) {
      csv();
      return;
    }
    const link = e.target.closest('[data-node]');
    const row = e.target.closest('[data-row]');
    const id = link?.dataset.node || row?.dataset.row;
    if (id) ctx.select(id);
  });

  return {
    render,
    // refresh reloads the fetched views (sightings, scans) if one is shown.
    refresh: () => (state.view === 'sightings' || state.view === 'scans' ? refresh() : render()),
    highlight(id) {
      state.selected = id;
      body.querySelectorAll('tr.selected').forEach((tr) => tr.classList.remove('selected'));
      const tr = body.querySelector(`tr[data-row="${CSS.escape(id)}"]`);
      if (tr) {
        tr.classList.add('selected');
        tr.scrollIntoView({ block: 'nearest' });
      }
    },
  };
}
