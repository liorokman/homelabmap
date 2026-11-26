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

// Columns hidden until the viewer picks their own. The first column of
// each view is always shown.
const DEFAULT_HIDDEN = {
  devices: ['Earlier MACs', 'OS from', 'Model', 'DNS', 'Open ports', 'Sources', 'First seen'],
};

// Views whose rows can be absent: seen before, not in the latest scan.
const HAS_ABSENT = new Set(['devices', 'containers', 'links']);

export function createTable(ctx) {
  const { esc, dateTime, ago, roleName, kindName, powerLine, api, store } = ctx;
  const root = document.querySelector('#table-view');
  const body = root.querySelector('.table-scroll');
  const count = root.querySelector('#table-count');
  const colsButton = root.querySelector('#table-cols-button');
  const colsList = root.querySelector('#table-cols-list');

  const state = {
    view: fromSlug(ctx.initial) || (VIEWS.includes(store.get('table.view')) ? store.get('table.view') : 'devices'),
    sort: store.get('table.sort', {}),
    hidden: store.get('table.hidden', {}),
    open: new Set(), // folded cells the viewer opened: rowKey|column
    rowByKey: new Map(),
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
  // A list column (items) shows its first item and folds the rest.
  const col = (label, text, opts = {}) => ({ label, text, ...opts });
  const list = (a) => (a || []).join(', ');
  const listHTML = (a, cls = '') => (a || []).map((x) => `<div class="${cls}">${esc(x)}</div>`).join('');
  const listCol = (label, items, opts = {}) => col(label, (r) => list(items(r)), { items, ...opts });

  function columns(view) {
    switch (view) {
      case 'devices':
        return [
          col('Name', (n) => n.label, { html: (n) => `<a data-node="${esc(n.id)}">${esc(n.label)}</a>${n.new ? ' <span class="tag new">new</span>' : ''}` }),
          col('Type', (n) => roleName(n.role)),
          col('Power', (n) => (n.absent ? 'Not seen' : powerLine(n)), { cls: (n) => (n.power === 'off' ? 'off' : ''), sort: (n) => (n.absent ? 2 : n.power === 'off' ? 1 : 0) }),
          listCol('IPv4', (n) => n.ips, { itemCls: 'mono', sort: (n) => ipKey(n.ips?.[0]) }),
          listCol('IPv6', (n) => n.ipv6, { itemCls: 'mono', sort: (n) => n.ipv6?.[0] || '~' }),
          listCol('MAC', (n) => n.macs, { itemCls: 'mono' }),
          listCol('Earlier MACs', (n) => n.otherMacs, { itemCls: 'mono' }),
          col('Vendor', (n) => n.vendor || '', { clip: true }),
          col('OS', (n) => n.os || '', { clip: true }),
          col('OS from', (n) => n.osSource || ''),
          col('Model', (n) => n.model || '', { clip: true }),
          col('Location', (n) => n.location || '', { clip: true }),
          listCol('DNS', (n) => n.dns),
          listCol('Open ports', (n) => n.openPorts, { itemCls: 'mono' }),
          col('Sources', (n) => list(n.sources), { clip: true }),
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
          listCol('Published', (n) => n.published, { itemCls: 'mono' }),
          listCol('URL', (n) => n.urls, {
            itemHTML: (u) => `<div><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u.replace(/^https:\/\//, ''))}</a></div>`,
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
          col('Error', (s) => s.error || '', { cls: () => 'bad-text', clip: true }),
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

  // sorted applies the chosen sort; absent rows always come last, in the
  // same order among themselves.
  function sorted(view, cols, data) {
    const s = state.sort[view];
    const c = s && cols.find((x) => x.label === s.col);
    let out = [...data];
    if (c) {
      const key = c.sort || c.text;
      const dir = s.dir === 'desc' ? -1 : 1;
      out.sort((a, b) => {
        const ka = key(a);
        const kb = key(b);
        const r = typeof ka === 'number' && typeof kb === 'number'
          ? ka - kb
          : String(ka).localeCompare(String(kb), undefined, { numeric: true, sensitivity: 'base' });
        return r * dir;
      });
    }
    if (HAS_ABSENT.has(view)) out = [...out.filter((r) => !r.absent), ...out.filter((r) => r.absent)];
    return out;
  }

  // ---------- columns ----------

  function hiddenSet(view) {
    return new Set(state.hidden[view] ?? DEFAULT_HIDDEN[view] ?? []);
  }

  function shownColumns(view) {
    const hidden = hiddenSet(view);
    return columns(view).filter((c, i) => i === 0 || !hidden.has(c.label));
  }

  function renderColumnPicker() {
    const hidden = hiddenSet(state.view);
    const items = columns(state.view).map((c, i) => {
      const on = i === 0 || !hidden.has(c.label);
      return `<label class="colpick-item"><input type="checkbox" data-col="${esc(c.label)}"${on ? ' checked' : ''}${i === 0 ? ' disabled' : ''}> ${esc(c.label.trim())}</label>`;
    }).join('');
    colsList.innerHTML = items + '<div class="colpick-foot"><button type="button" class="link-btn" data-col-reset>Reset to default</button></div>';
  }

  function setColumnsOpen(open) {
    if (open) renderColumnPicker();
    colsList.hidden = !open;
    colsButton.setAttribute('aria-expanded', String(open));
  }

  // ---------- cells ----------

  const rowKey = (r) => String(r.id ?? r.mac ?? '');

  function cellHTML(c, r) {
    if (!c.items) return c.html ? c.html(r) : esc(c.text(r));
    const items = c.items(r) || [];
    const one = c.itemHTML || ((x) => `<div class="${c.itemCls || ''}">${esc(x)}</div>`);
    if (items.length <= 1) return items.map(one).join('');
    const k = rowKey(r) + '|' + c.label;
    if (state.open.has(k)) {
      return items.map(one).join('') +
        `<button type="button" class="fold" data-fold="${esc(k)}" aria-expanded="true">Show less</button>`;
    }
    // Folded: the first item and the button on one line.
    return `<div class="folded">${one(items[0])}<button type="button" class="fold" data-fold="${esc(k)}" aria-expanded="false" title="${esc(items.slice(1).join('\n'))}">+${items.length - 1}</button></div>`;
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
    const all = columns(view);
    const cols = shownColumns(view);
    const data = sorted(view, all, rows(view));
    const s = state.sort[view] || {};
    const absent = data.filter((r) => r.absent).length;
    count.textContent = `${data.length} ${data.length === 1 ? 'row' : 'rows'}` + (absent ? `, ${absent} not seen recently` : '');
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
    state.rowByKey = new Map(data.map((r) => [rowKey(r), r]));
    const bodyRows = data.map((r, i) => {
      const id = view === 'devices' ? r.id : '';
      const trCls = [id && id === state.selected ? 'selected' : '', r.absent ? 'inactive' : ''].filter(Boolean).join(' ');
      const group = r.absent && !data[i - 1]?.absent
        ? `<tr class="group"><th colspan="${cols.length}" scope="rowgroup">Not seen recently (${absent})</th></tr>`
        : '';
      return group + `<tr data-key="${esc(rowKey(r))}"${id ? ` data-row="${esc(id)}"` : ''}${trCls ? ` class="${trCls}"` : ''}>` + cols.map((c) => {
        const cls = [c.cls ? c.cls(r) : '', c.clip ? 'clip' : ''].filter(Boolean).join(' ');
        const tip = c.title ? c.title(r) : c.clip ? c.text(r) : '';
        const title = tip ? ` title="${esc(tip)}"` : '';
        return `<td data-col="${esc(c.label)}"${cls ? ` class="${cls}"` : ''}${title}>${cellHTML(c, r)}</td>`;
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

  // csv exports the shown columns, with lists in full.
  function csv() {
    const cols = shownColumns(state.view);
    const data = sorted(state.view, columns(state.view), rows(state.view));
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

  colsList.addEventListener('change', (e) => {
    const box = e.target.closest('input[data-col]');
    if (!box) return;
    const hidden = hiddenSet(state.view);
    if (box.checked) hidden.delete(box.dataset.col); else hidden.add(box.dataset.col);
    state.hidden[state.view] = [...hidden];
    store.set('table.hidden', state.hidden);
    render();
  });

  document.addEventListener('click', (e) => {
    if (!colsList.hidden && !e.target.closest('#table-cols')) setColumnsOpen(false);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !colsList.hidden) {
      setColumnsOpen(false);
      colsButton.focus();
    }
  });

  root.addEventListener('click', (e) => {
    if (e.target.closest('#table-cols-button')) {
      setColumnsOpen(colsList.hidden);
      return;
    }
    if (e.target.closest('[data-col-reset]')) {
      delete state.hidden[state.view];
      store.set('table.hidden', state.hidden);
      renderColumnPicker();
      render();
      return;
    }
    if (e.target.closest('#table-cols-list')) return;
    const fold = e.target.closest('[data-fold]');
    if (fold) {
      const k = fold.dataset.fold;
      if (state.open.has(k)) state.open.delete(k); else state.open.add(k);
      const td = fold.closest('td');
      const r = state.rowByKey.get(td.parentElement.dataset.key);
      const c = columns(state.view).find((x) => x.label === td.dataset.col);
      if (r && c) {
        td.innerHTML = cellHTML(c, r);
        td.querySelector('[data-fold]')?.focus();
      }
      return;
    }
    const tab = e.target.closest('[data-table]');
    if (tab) {
      setColumnsOpen(false);
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
