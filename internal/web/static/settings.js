// The Settings page: edits a copy of the settings and saves it whole.
// Secrets never reach the browser: saved ones come as KEEP, and sending
// KEEP back keeps them.
//
// Each section is a tab. Plain settings are edited in place and saved with
// the bar at the bottom; credentials (SNMP hosts, Proxmox, Cosmos, UniFi)
// are listed in a table and edited in a dialog whose Save saves at once.

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const KEEP = '__keep__';

const root = $('#settings');
let saved = null; // the settings as last loaded or saved
let model = null; // the copy being edited
let meta = { lost: [], scannerOnline: true };
let errors = {}; // field path -> message, from the last save attempt
let summary = ''; // the last save attempt's message
const hadSecret = new Set(); // secret paths with a saved value
const cleared = new Set(); // ... that the user chose to remove
let src = null; // what the field helpers read: the model, or the dialog's draft

function newID() {
  const b = new Uint8Array(6);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

const getPath = (obj, path) => path.split('.').reduce((o, k) => o?.[k], obj);
function setPath(obj, path, v) {
  const keys = path.split('.');
  const last = keys.pop();
  keys.reduce((o, k) => o[k], obj)[last] = v;
}

// Go sends empty lists as null; the page wants arrays.
function fill(s) {
  s.scan.subnets ||= [];
  s.snmp.hosts ||= [];
  s.snmp.seeds ||= [];
  s.proxmox ||= [];
  s.unifi ||= [];
  s.cosmos ||= [];
  return s;
}

// secretPaths maps each secret's bind path (by index) to its stable path
// (by entry ID), the one the server uses for errors and lost secrets.
function secretPaths(s) {
  const out = [];
  const cred = (bind, stable) => ['community', 'authPass', 'privPass'].forEach((k) => out.push([`${bind}.${k}`, `${stable}.${k}`]));
  cred('snmp.default', 'snmp.default');
  s.snmp.hosts.forEach((h, i) => cred(`snmp.hosts.${i}.credentials`, `snmp.hosts.${h.id}`));
  s.proxmox.forEach((e, i) => out.push([`proxmox.${i}.tokenSecret`, `proxmox.${e.id}.tokenSecret`]));
  s.unifi.forEach((e, i) => out.push([`unifi.${i}.apiKey`, `unifi.${e.id}.apiKey`]));
  s.cosmos.forEach((e, i) => out.push([`cosmos.${i}.token`, `cosmos.${e.id}.token`]));
  return out;
}

function accept(body) {
  saved = fill(body.settings);
  model = fill(structuredClone(saved));
  meta = { lost: body.lost || [], scannerOnline: body.scannerOnline };
  errors = {};
  hadSecret.clear();
  cleared.clear();
  for (const [bind, stable] of secretPaths(saved)) {
    if (getPath(saved, bind) === KEEP) hadSecret.add(stable);
  }
  render();
}

const dirty = () => model && JSON.stringify(model) !== JSON.stringify(saved);

// ---------- fields ----------

const fid = (bind) => 'f-' + bind.replace(/\./g, '-');

function fieldError(err) {
  const lost = meta.lost.includes(err) && !errors[err];
  const msg = errors[err] || (lost ? "Can't be decrypted (the agent token changed?): enter it again." : '');
  return msg ? `<small class="field-err" id="${fid(err)}-err">${esc(msg)}</small>` : '';
}

function wrap(label, bind, err, inner, help) {
  const bad = errors[err] ? ' invalid' : '';
  return `<label class="field${bad}" data-err="${esc(err)}"><span>${esc(label)}</span>${inner}` +
    `${help ? `<small class="help">${help}</small>` : ''}${fieldError(err)}</label>`;
}

function described(err) {
  return errors[err] ? ` aria-invalid="true" aria-describedby="${fid(err)}-err"` : '';
}

function text(label, bind, err, { help = '', placeholder = '', kind = 'text', attrs = '' } = {}) {
  const v = getPath(src, bind);
  return wrap(label, bind, err,
    `<input id="${fid(bind)}" data-bind="${bind}" data-kind="${kind}" value="${esc(v)}" placeholder="${esc(placeholder)}" ${attrs}${described(err)}>`, help);
}

function int(label, bind, err, opts = {}) {
  return text(label, bind, err, { ...opts, kind: 'int', attrs: `type="number" inputmode="numeric" step="1" ${opts.attrs || ''}` });
}

function list(label, bind, err, { help = '', placeholder = '' } = {}) {
  const v = (getPath(src, bind) || []).join('\n');
  return wrap(label, bind, err,
    `<textarea id="${fid(bind)}" data-bind="${bind}" data-kind="list" rows="3" placeholder="${esc(placeholder)}" spellcheck="false"${described(err)}>${esc(v)}</textarea>`, help);
}

function check(label, bind, help = '') {
  const v = getPath(src, bind);
  return `<label class="check"><input type="checkbox" id="${fid(bind)}" data-bind="${bind}" data-kind="check"${v ? ' checked' : ''}>` +
    `<span>${esc(label)}${help ? `<small class="help">${help}</small>` : ''}</span></label>`;
}

function select(label, bind, err, options, { rerender = false } = {}) {
  const v = getPath(src, bind);
  const opts = options.map(([val, name]) => `<option value="${esc(val)}"${val === v ? ' selected' : ''}>${esc(name)}</option>`).join('');
  return wrap(label, bind, err,
    `<select id="${fid(bind)}" data-bind="${bind}" data-kind="text"${rerender ? ' data-rerender="1"' : ''}${described(err)}>${opts}</select>`);
}

function secret(label, bind, err, help = '') {
  const v = getPath(src, bind);
  let placeholder = '';
  let action = '';
  if (v === KEEP) {
    placeholder = 'Saved · type to replace';
    action = `<button type="button" class="link" data-action="clear-secret" data-bind="${bind}" data-stable="${esc(err)}">Remove</button>`;
  } else if (cleared.has(err)) {
    placeholder = 'Removed when you save';
    action = `<button type="button" class="link" data-action="undo-secret" data-bind="${bind}" data-stable="${esc(err)}">Undo</button>`;
  }
  const value = v === KEEP ? '' : v;
  return wrap(label, bind, err,
    `<span class="secret"><input id="${fid(bind)}" type="password" autocomplete="off" data-bind="${bind}" data-kind="secret" data-stable="${esc(err)}"` +
    ` value="${esc(value)}" placeholder="${esc(placeholder)}"${described(err)}>${action}</span>`, help);
}

const AUTH = ['SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5'];
const PRIV = ['AES', 'AES192', 'AES256', 'DES'];

function credEditor(bind, stable, { optional }) {
  const c = getPath(src, bind);
  const versions = [['2c', 'SNMP v2c (community)'], ['3', 'SNMP v3 (user)']];
  if (optional) versions.unshift(['', 'None: no SNMP by default']);
  let out = select('Version', `${bind}.version`, `${stable}.version`, versions, { rerender: true });
  if (c.version === '2c') {
    out += secret('Community', `${bind}.community`, `${stable}.community`, 'A read-only community.');
  } else if (c.version === '3') {
    out += text('User', `${bind}.user`, `${stable}.user`, { attrs: 'autocomplete="off" spellcheck="false"' });
    out += `<div class="row2">${select('Authentication', `${bind}.authProto`, `${stable}.authProto`, AUTH.map((p) => [p, p]))}` +
      `${secret('Authentication password', `${bind}.authPass`, `${stable}.authPass`)}</div>`;
    out += `<div class="row2">${select('Privacy', `${bind}.privProto`, `${stable}.privProto`, PRIV.map((p) => [p, p]))}` +
      `${secret('Privacy password', `${bind}.privPass`, `${stable}.privPass`, 'Leave empty for no encryption.')}</div>`;
  }
  return out;
}

const hostHelp = (port) => `A hostname, host:port (default ${port}) or URL.`;
const describe = (err, placeholder) =>
  text('Description', 'd.description', err, { placeholder, help: 'Optional: a note for yourself.', attrs: 'maxlength="200"' });
const skipTLS = () => check('Skip TLS verification', 'd.insecureTls', 'Only for a self-signed certificate; better give the server one the scanner trusts.');

// ---------- table cells ----------

// secretCell shows whether a secret is set, never the secret itself.
function secretCell(value, stable) {
  if (cleared.has(stable) || (!value && meta.lost.includes(stable))) return '<span class="pill bad">Enter again</span>';
  if (value === KEEP) return '<span class="pill" title="Saved; edit to replace it">••••••••</span>';
  if (value) return '<span class="pill">•••••••• <em>unsaved</em></span>';
  return '<span class="pill bad">Missing</span>';
}
const tlsCell = (e) => (e.insecureTls
  ? '<span class="tls-skip" title="The certificate isn\'t checked">Not verified</span>'
  : '<span class="muted">Verified</span>');
const plain = (v) => (v ? esc(v) : '<span class="muted">—</span>');

// ---------- credential kinds ----------

// Each kind of credential: where its list lives, its table and its form.
// Forms bind to "d", the dialog's draft entry.
const KINDS = {
  snmp: {
    list: 'snmp.hosts',
    stable: (e) => `snmp.hosts.${e.id}`,
    noun: 'SNMP host',
    name: (e) => e.match,
    blank: () => ({ id: newID(), match: '', description: '', credentials: { version: '2c', community: '', user: '', authProto: 'SHA', authPass: '', privProto: 'AES', privPass: '' } }),
    columns: [
      ['Host', (e) => `<code>${plain(e.match)}</code>`],
      ['Description', (e) => plain(e.description)],
      ['Version', (e) => (e.credentials.version === '3' ? 'v3' : 'v2c')],
      ['Credentials', (e) => {
        const c = e.credentials;
        const st = `snmp.hosts.${e.id}`;
        if (c.version !== '3') return secretCell(c.community, `${st}.community`);
        const sec = c.privPass ? `${c.authProto} / ${c.privProto}` : (c.authPass ? `${c.authProto}, no privacy` : 'no authentication');
        return `<code>${plain(c.user)}</code> <span class="muted">${esc(sec)}</span>`;
      }],
    ],
    form: (e) => {
      const st = `snmp.hosts.${e.id}`;
      return text('Host', 'd.match', `${st}.match`, { placeholder: '192.168.1.2, 192.168.1.0/28 or switch.example.net', help: 'An IP address, a subnet or a hostname. The most specific match wins.', attrs: 'spellcheck="false"' }) +
        describe(`${st}.description`, 'Core switch') +
        credEditor('d.credentials', st, { optional: false });
    },
  },
  proxmox: {
    list: 'proxmox',
    stable: (e) => `proxmox.${e.id}`,
    noun: 'Proxmox cluster',
    name: (e) => e.host,
    blank: () => ({ id: newID(), host: '', description: '', tokenId: '', tokenSecret: '', insecureTls: false }),
    columns: [
      ['Host', (e) => `<code>${plain(e.host)}</code>`],
      ['Description', (e) => plain(e.description)],
      ['Token ID', (e) => `<code>${plain(e.tokenId)}</code>`],
      ['TLS', tlsCell],
      ['Token secret', (e) => secretCell(e.tokenSecret, `proxmox.${e.id}.tokenSecret`)],
    ],
    form: (e) => {
      const st = `proxmox.${e.id}`;
      return text('Host', 'd.host', `${st}.host`, { placeholder: 'pve.example.net', help: 'Any node of the cluster. ' + hostHelp(8006), attrs: 'spellcheck="false"' }) +
        describe(`${st}.description`, 'Homelab cluster') +
        `<div class="row2">${text('API token ID', 'd.tokenId', `${st}.tokenId`, { placeholder: 'homelabmap@pve!scanner', attrs: 'autocomplete="off" spellcheck="false"' })}` +
        `${secret('Token secret', 'd.tokenSecret', `${st}.tokenSecret`)}</div>` +
        skipTLS();
    },
  },
  cosmos: {
    list: 'cosmos',
    stable: (e) => `cosmos.${e.id}`,
    noun: 'Cosmos server',
    name: (e) => e.host,
    blank: () => ({ id: newID(), host: '', description: '', token: '', insecureTls: false }),
    columns: [
      ['Host', (e) => `<code>${plain(e.host)}</code>`],
      ['Description', (e) => plain(e.description)],
      ['TLS', tlsCell],
      ['API token', (e) => secretCell(e.token, `cosmos.${e.id}.token`)],
    ],
    form: (e) => {
      const st = `cosmos.${e.id}`;
      return text('Host', 'd.host', `${st}.host`, { placeholder: 'cosmos.example.net', help: hostHelp(443), attrs: 'spellcheck="false"' }) +
        describe(`${st}.description`, 'Main Cosmos host') +
        secret('API token', 'd.token', `${st}.token`, 'Only "Resources Read" and "Configuration Read": see the guide under the table.') +
        skipTLS();
    },
  },
  unifi: {
    list: 'unifi',
    stable: (e) => `unifi.${e.id}`,
    noun: 'UniFi console',
    name: (e) => e.host,
    blank: () => ({ id: newID(), host: '', description: '', apiKey: '', site: 'default', insecureTls: false, historyHours: 720 }),
    columns: [
      ['Host', (e) => `<code>${plain(e.host)}</code>`],
      ['Description', (e) => plain(e.description)],
      ['Site', (e) => `<code>${plain(e.site)}</code>`],
      ['Disconnected clients', (e) => (e.historyHours ? `last ${e.historyHours} h` : '<span class="muted">Not shown</span>')],
      ['TLS', tlsCell],
      ['API key', (e) => secretCell(e.apiKey, `unifi.${e.id}.apiKey`)],
    ],
    form: (e) => {
      const st = `unifi.${e.id}`;
      return text('Host', 'd.host', `${st}.host`, { placeholder: 'unifi.example.net', help: hostHelp(443), attrs: 'spellcheck="false"' }) +
        describe(`${st}.description`, 'Cloud Gateway') +
        `<div class="row2">${secret('API key', 'd.apiKey', `${st}.apiKey`)}` +
        `${text('Site', 'd.site', `${st}.site`, { placeholder: 'default', attrs: 'spellcheck="false"' })}</div>` +
        `<div class="row2">${int('Show disconnected clients from the last (hours)', 'd.historyHours', `${st}.historyHours`, { help: '0 shows only connected clients.', attrs: 'min="0" max="8760"' })}<span></span></div>` +
        skipTLS();
    },
  },
};

const entryErrors = (kind, e) => {
  const prefix = KINDS[kind].stable(e) + '.';
  return Object.keys(errors).filter((k) => k.startsWith(prefix));
};
const entryLost = (kind, e) => {
  const prefix = KINDS[kind].stable(e) + '.';
  return meta.lost.some((k) => k.startsWith(prefix));
};

function table(kind) {
  const K = KINDS[kind];
  const items = getPath(model, K.list);
  const head = K.columns.map(([h]) => `<th scope="col">${esc(h)}</th>`).join('') + '<th scope="col"><span class="sr-only">Actions</span></th>';
  const rows = items.map((e, i) => {
    const bad = entryErrors(kind, e).length > 0;
    const name = K.name(e) || `new ${K.noun}`;
    const cells = K.columns.map(([h, f], c) =>
      (c === 0
        ? `<th scope="row" data-label="${esc(h)}">${f(e)}${bad ? ' <span class="pill bad">Needs fixing</span>' : ''}</th>`
        : `<td data-label="${esc(h)}">${f(e)}</td>`)).join('');
    return `<tr class="${bad ? 'invalid' : ''}" data-kind="${kind}" data-index="${i}">${cells}` +
      '<td class="row-actions">' +
      `<button type="button" class="btn small" data-action="edit" data-kind="${kind}" data-index="${i}" aria-label="Edit ${esc(name)}">Edit</button>` +
      `<button type="button" class="btn small ghost danger" data-action="remove" data-kind="${kind}" data-index="${i}" aria-label="Remove ${esc(name)}">Remove</button>` +
      '</td></tr>';
  }).join('');
  const empty = `<tr class="empty"><td colspan="${K.columns.length + 1}">None yet.</td></tr>`;
  const listErr = errors[K.list] ? `<p class="field-err" role="alert">${esc(errors[K.list])}</p>` : '';
  return `${listErr}<div class="table-wrap"><table class="grid">` +
    `<thead><tr>${head}</tr></thead><tbody>${rows || empty}</tbody></table></div>`;
}

function guide(topic, title) {
  const tpl = document.getElementById(`help-${topic}`);
  return tpl ? `<section class="guide" aria-label="${esc(title)}"><h3>${esc(title)}</h3>${tpl.innerHTML}</section>` : '';
}

// ---------- tabs ----------

const TABS = [
  { id: 'scan', label: 'Scanning', errs: ['scan.'], panel: panelScan },
  { id: 'snmp', label: 'SNMP', errs: ['snmp.'], panel: panelSNMP, count: () => model.snmp.hosts.length },
  { id: 'proxmox', label: 'Proxmox VE', errs: ['proxmox'], panel: () => panelKind('proxmox'), count: () => model.proxmox.length },
  { id: 'cosmos', label: 'Cosmos', errs: ['cosmos'], panel: () => panelKind('cosmos'), count: () => model.cosmos.length },
  { id: 'unifi', label: 'UniFi', errs: ['unifi'], panel: () => panelKind('unifi'), count: () => model.unifi.length },
  { id: 'login', label: 'Sign-in', errs: ['login.'], panel: panelLogin },
];
const tabOf = (field) => TABS.find((t) => t.errs.some((p) => field.startsWith(p)));
const tabHasErrors = (t) => [...Object.keys(errors), ...meta.lost].some((f) => tabOf(f) === t);

let current = TABS.find((t) => '#' + t.id === location.hash) || TABS[0];

function tabList() {
  return '<nav class="tabs" role="tablist" aria-label="Settings" aria-orientation="vertical">' + TABS.map((t) => {
    const on = t === current;
    const n = t.count ? t.count() : 0;
    return `<button type="button" role="tab" id="tab-${t.id}" aria-controls="panel" aria-selected="${on}" tabindex="${on ? 0 : -1}" data-tab="${t.id}">` +
      `<span class="tab-label">${esc(t.label)}</span>${n ? `<span class="count">${n}</span>` : ''}` +
      `${tabHasErrors(t) ? '<span class="dot" title="Needs fixing"><span class="sr-only">(needs fixing)</span></span>' : ''}</button>`;
  }).join('') + '</nav>';
}

function selectTab(id, { focus = false } = {}) {
  const t = TABS.find((x) => x.id === id);
  if (!t) return;
  current = t;
  history.replaceState(null, '', '#' + t.id);
  render();
  if (focus) document.getElementById(`tab-${t.id}`)?.focus();
}

function panelHead(title, blurb, action = '') {
  return `<div class="panel-head"><div><h2>${esc(title)}</h2><p class="muted">${esc(blurb)}</p></div>${action}</div>`;
}

function panelScan() {
  src = model;
  const b = 'scan';
  return panelHead('Scanning', 'What the scanner sweeps, how often, and how long the map remembers.') +
    `<div class="card">
    ${list('Subnets', `${b}.subnets`, `${b}.subnets`, { placeholder: '192.168.1.0/24', help: 'One per line. The scanner host needs an interface in each.' })}
    <div class="row3">
      ${text('Full scan every', `${b}.interval`, `${b}.interval`, { help: 'e.g. 30m, 1h' })}
      ${text('Scan timeout', `${b}.jobTimeout`, `${b}.jobTimeout`, { help: 'Longest a scan may run.' })}
      ${text('Keep scan history for', `${b}.retention`, `${b}.retention`, { help: 'e.g. 14d' })}
    </div>
    <div class="row3">
      ${text('Absent devices leave the map after', `${b}.forgetAfter`, `${b}.forgetAfter`, { help: 'e.g. 30d' })}
      ${text('Re-fingerprint a device after', `${b}.osRescan`, `${b}.osRescan`, { help: 'nmap OS detection, e.g. 7d' })}
      ${int('OS fingerprints per scan', `${b}.osScanMax`, `${b}.osScanMax`, { help: '0 turns OS detection off.', attrs: 'min="0" max="1000"' })}
    </div>
    <div class="row3">
      ${int('Quick scans of new devices per hour', `${b}.probeMaxPerHour`, `${b}.probeMaxPerHour`, { help: '0 turns them off.', attrs: 'min="0" max="1000"' })}
    </div>
    ${check('Listen for new devices between scans', `${b}.passive`, 'ARP and IPv6 neighbour discovery on the scanner host.')}
    ${check('Discover UPnP devices (SSDP)', `${b}.ssdp`, 'TVs, consoles, media servers and NAS boxes describe themselves.')}
  </div>`;
}

function panelSNMP() {
  src = model;
  const advOpen = ['snmp.seeds', 'snmp.timeout', 'snmp.retries', 'snmp.concurrency'].some((k) => errors[k]);
  return panelHead('SNMP', 'Interfaces, LLDP/CDP neighbours, switch MAC tables and ARP from switches, routers, Linux hosts and printers: this is what places devices on their switch port.') +
    `<div class="card">
      <h3>Default credentials</h3>
      <p class="muted">Tried on every host in the subnets that has no credentials of its own.</p>
      ${credEditor('snmp.default', 'snmp.default', { optional: true })}
    </div>
    <div class="card">
      <div class="card-head"><h3>Per-host credentials</h3>
        <button type="button" class="btn small primary" data-action="add" data-kind="snmp">Add host</button></div>
      <p class="muted">For hosts that need other credentials. Hosts listed by IP or hostname are queried even if the sweep misses them.</p>
      ${table('snmp')}
    </div>
    <details class="card advanced"${advOpen ? ' open' : ''}>
      <summary>Advanced</summary>
      ${list('Extra hosts to query', 'snmp.seeds', 'snmp.seeds', { placeholder: '192.168.1.2', help: 'IP addresses to query even if the sweep misses them.' })}
      <div class="row3">
        ${text('Timeout', 'snmp.timeout', 'snmp.timeout', { help: 'Per request, e.g. 1500ms' })}
        ${int('Retries', 'snmp.retries', 'snmp.retries', { attrs: 'min="0" max="5"' })}
        ${int('Hosts queried at once', 'snmp.concurrency', 'snmp.concurrency', { attrs: 'min="1" max="256"' })}
      </div>
    </details>
    ${guide('snmp', 'Setting up SNMP')}`;
}

const KIND_PAGES = {
  proxmox: { title: 'Proxmox VE', add: 'Add cluster', guide: 'Setting up a Proxmox API token',
    blurb: 'VMs and containers with their MAC addresses and status, placed on the host they run on.' },
  cosmos: { title: 'Cosmos', add: 'Add server', guide: 'Setting up a Cosmos API token',
    blurb: 'Docker containers and their reverse-proxy routes, under the host that runs them.' },
  unifi: { title: 'UniFi', add: 'Add console', guide: 'Setting up a UniFi API key',
    blurb: 'Wi-Fi clients under their access points, wired clients on UniFi switches, device aliases, and recently disconnected clients.' },
};

function panelKind(kind) {
  const p = KIND_PAGES[kind];
  return panelHead(p.title, p.blurb, `<button type="button" class="btn primary" data-action="add" data-kind="${kind}">${esc(p.add)}</button>`) +
    `<div class="card flush">${table(kind)}</div>` +
    guide(kind, p.guide);
}

function panelLogin() {
  src = model;
  return panelHead('Sign-in', 'How long a sign-in lasts.') +
    `<div class="card">
      <div class="row3">${text('Stay signed in for', 'login.sessionTtl', 'login.sessionTtl', { help: 'e.g. 12h. Applies to new sign-ins.' })}</div>
      <p class="muted">The OpenID Connect provider, the public URL and the agent token are set in the environment.</p>
    </div>`;
}

function notices() {
  let out = '';
  if (summary) {
    const n = Object.keys(errors).length;
    out += `<div class="notice bad" role="alert">${esc(summary)}${n ? ' Tabs with problems are marked.' : ''}</div>`;
  }
  if (meta.lost.length) {
    out += `<div class="notice bad">${meta.lost.length} saved secret${meta.lost.length > 1 ? 's' : ''} can't be decrypted, ` +
      'probably because HOMELABMAP_AGENT_TOKEN changed. Enter them again where marked.</div>';
  }
  if (!meta.scannerOnline) {
    out += '<div class="notice">The scanner hasn\'t checked in recently. Settings are saved, and it picks them up when it does.</div>';
  }
  return out;
}

// ---------- rendering ----------

function render() {
  const focused = document.activeElement?.id;
  root.removeAttribute('aria-busy');
  src = model;
  root.innerHTML = tabList() +
    `<section class="panel" id="panel" role="tabpanel" aria-labelledby="tab-${current.id}">${notices()}${current.panel()}</section>`;
  if (focused && root.contains(document.getElementById(focused))) document.getElementById(focused).focus();
  updateBar();
}

function updateBar(msg) {
  const bar = $('#savebar');
  const d = dirty();
  bar.hidden = !d && !msg;
  $('#save').disabled = !d;
  $('#discard').hidden = !d;
  $('#save-msg').textContent = msg ?? (d ? 'Unsaved changes' : '');
}

// ---------- editing in place ----------

function readField(el, target) {
  const bind = el.dataset.bind;
  switch (el.dataset.kind) {
    case 'int': setPath(target, bind, el.value === '' ? 0 : Number(el.value)); break;
    case 'check': setPath(target, bind, el.checked); break;
    case 'list': setPath(target, bind, el.value.split(/[\s,;]+/).filter(Boolean)); break;
    case 'secret': {
      const stable = el.dataset.stable;
      if (el.value) {
        cleared.delete(stable);
        setPath(target, bind, el.value);
      } else {
        setPath(target, bind, hadSecret.has(stable) && !cleared.has(stable) ? KEEP : '');
      }
      break;
    }
    default: setPath(target, bind, el.value);
  }
}

// Secret Remove/Undo, in place or in the dialog.
function secretAction(btn, target) {
  if (btn.dataset.action === 'clear-secret') {
    cleared.add(btn.dataset.stable);
    setPath(target, btn.dataset.bind, '');
  } else {
    cleared.delete(btn.dataset.stable);
    setPath(target, btn.dataset.bind, KEEP);
  }
}

root.addEventListener('input', (e) => {
  const el = e.target.closest('[data-bind]');
  if (!el || el.tagName === 'SELECT') return;
  readField(el, model);
  updateBar();
});
root.addEventListener('change', (e) => {
  const el = e.target.closest('[data-bind]');
  if (!el) return;
  readField(el, model);
  if (el.dataset.rerender) render();
  else updateBar();
});

root.addEventListener('click', (e) => {
  const tab = e.target.closest('[role="tab"]');
  if (tab) {
    selectTab(tab.dataset.tab);
    return;
  }
  const btn = e.target.closest('[data-action]');
  if (btn) {
    const { action, kind } = btn.dataset;
    const i = Number(btn.dataset.index);
    switch (action) {
      case 'add': openEditor(kind, -1); break;
      case 'edit': openEditor(kind, i); break;
      case 'remove': removeEntry(kind, i); break;
      case 'clear-secret':
      case 'undo-secret': secretAction(btn, model); render(); break;
    }
    return;
  }
  // A click anywhere else on a row edits it.
  const row = e.target.closest('tr[data-kind]');
  if (row && !e.target.closest('a, button, input')) openEditor(row.dataset.kind, Number(row.dataset.index));
});

// Arrow keys move between tabs (up/down, or left/right when they wrap
// into a row on narrow screens).
root.addEventListener('keydown', (e) => {
  const tab = e.target.closest('[role="tab"]');
  if (!tab) return;
  const i = TABS.findIndex((t) => t.id === tab.dataset.tab);
  const next = { ArrowDown: i + 1, ArrowRight: i + 1, ArrowUp: i - 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[e.key];
  if (next === undefined) return;
  e.preventDefault();
  selectTab(TABS[(next + TABS.length) % TABS.length].id, { focus: true });
});

// ---------- the edit dialog ----------

const dialog = $('#edit-dialog');
const dbody = $('#edit-body');
// dlg: the open dialog's kind, index (-1: a new entry), draft ({d: entry}),
// the model and removed secrets as they were when it opened, its title,
// message, whether it tried to save and succeeded, and the message to show
// after it closes.
let dlg = null;

function renderDialog() {
  const focused = document.activeElement?.id;
  $('#edit-title').textContent = dlg.title;
  src = dlg.draft;
  dbody.innerHTML = KINDS[dlg.kind].form(dlg.draft.d);
  src = model;
  const lost = dlg.isEdit && entryLost(dlg.kind, dlg.draft.d);
  $('#edit-msg').textContent = dlg.msg || (lost ? 'A secret here must be entered again.' : '');
  if (focused && dbody.contains(document.getElementById(focused))) document.getElementById(focused).focus();
}

function openEditor(kind, index) {
  const K = KINDS[kind];
  const items = getPath(model, K.list);
  const isEdit = index >= 0;
  dlg = {
    kind, index, isEdit,
    draft: { d: structuredClone(isEdit ? items[index] : K.blank()) },
    before: { model: structuredClone(model), cleared: new Set(cleared) },
    title: isEdit ? `Edit ${K.name(items[index]) || K.noun}` : `Add ${K.noun}`,
    msg: '',
    done: false,
  };
  renderDialog();
  dialog.showModal();
  const first = dbody.querySelector('.field.invalid input, .field.invalid select') || dbody.querySelector('input, select');
  first?.focus();
}

dialog.addEventListener('input', (e) => {
  const el = e.target.closest('[data-bind]');
  if (el && el.tagName !== 'SELECT') readField(el, dlg.draft);
});
dialog.addEventListener('change', (e) => {
  const el = e.target.closest('[data-bind]');
  if (!el) return;
  readField(el, dlg.draft);
  if (el.dataset.rerender) renderDialog();
});
dialog.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-action="clear-secret"], [data-action="undo-secret"]');
  if (btn) {
    secretAction(btn, dlg.draft);
    renderDialog();
    dbody.querySelector(`[data-bind="${btn.dataset.bind}"]`)?.focus();
  }
});
$('#edit-cancel').addEventListener('click', () => dialog.close());

// Closing without saving (Cancel or Esc) undoes what the dialog changed.
dialog.addEventListener('close', () => {
  if (!dlg) return;
  const { kind, index, isEdit, done, tried, after } = dlg;
  if (!done) {
    model = dlg.before.model;
    cleared.clear();
    dlg.before.cleared.forEach((k) => cleared.add(k));
    // The failed save's problems were about what was just undone.
    if (tried) {
      errors = {};
      summary = '';
    }
  }
  dlg = null;
  render();
  if (after) updateBar(after);
  const back = isEdit && root.querySelector(`[data-action="edit"][data-kind="${kind}"][data-index="${index}"]`);
  (back || root.querySelector(`[data-action="add"][data-kind="${kind}"]`))?.focus();
});

$('#edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const K = KINDS[dlg.kind];
  const items = getPath(model, K.list);
  const entry = structuredClone(dlg.draft.d);
  if (dlg.index < 0) {
    items.push(entry);
    dlg.index = items.length - 1;
  } else {
    items[dlg.index] = entry;
  }
  $('#edit-save').disabled = true;
  $('#edit-msg').textContent = 'Saving…';
  dlg.tried = true;
  const ok = await save();
  $('#edit-save').disabled = false;
  if (!dlg) return;
  if (ok) {
    dlg.done = true;
    dlg.after = `Saved ${K.name(entry) || K.noun}.`;
    dialog.close();
    return;
  }
  if (entryErrors(dlg.kind, entry).length || !Object.keys(errors).length) {
    // The problem is here (or not with any one field): stay, and show it.
    dlg.msg = Object.keys(errors).length ? 'Fix the fields marked above.' : summary;
    renderDialog();
    (dbody.querySelector('.field.invalid input, .field.invalid select') || $('#edit-save')).focus();
    return;
  }
  // The problem is in another setting: keep this change, unsaved, and
  // show where.
  dlg.done = true;
  dialog.close();
  showFirstError();
});

async function removeEntry(kind, index) {
  const K = KINDS[kind];
  const items = getPath(model, K.list);
  const name = K.name(items[index]) || `this ${K.noun}`;
  if (!confirm(`Remove ${name} and its credentials?`)) return;
  items.splice(index, 1);
  render();
  if (await save()) updateBar(`Removed ${name}.`);
  else showFirstError();
}

// ---------- loading and saving ----------

async function load() {
  let res;
  try {
    res = await fetch('/api/settings', { credentials: 'same-origin' });
  } catch (err) {
    root.innerHTML = `<div class="notice bad">Couldn't load the settings: ${esc(err.message)}</div>`;
    return;
  }
  if (res.status === 401) {
    location.href = '/signin?return=' + encodeURIComponent('/settings');
    return;
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    root.innerHTML = `<div class="notice bad">${esc(body.error || `Couldn't load the settings (HTTP ${res.status}).`)}</div>`;
    return;
  }
  accept(body);
}

// save saves the whole model and says whether it worked; when it didn't,
// errors and summary say why.
async function save() {
  $('#save').disabled = true;
  updateBar('Saving…');
  let res;
  try {
    res = await fetch('/api/settings', {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Homelabmap-Request': '1' },
      body: JSON.stringify(model),
    });
  } catch (err) {
    summary = "Couldn't reach the server: " + err.message;
    errors = {};
    render();
    updateBar(summary);
    return false;
  }
  if (res.status === 401) {
    location.href = '/signin?return=' + encodeURIComponent('/settings');
    return false;
  }
  const body = await res.json().catch(() => ({}));
  if (res.ok) {
    summary = '';
    accept(body);
    updateBar('Saved. The next scan uses them.');
    return true;
  }
  summary = body.error || `Couldn't save (HTTP ${res.status}).`;
  errors = {};
  for (const e of body.errors || []) errors[e.field] = errors[e.field] ? errors[e.field] + ' ' + e.message : e.message;
  render();
  updateBar(summary);
  return false;
}

// showFirstError switches to the first tab with a problem and focuses it.
function showFirstError() {
  const t = TABS.find((x) => Object.keys(errors).some((f) => tabOf(f) === x));
  if (t && t !== current) selectTab(t.id);
  const first = root.querySelector('.field.invalid input, .field.invalid select, .field.invalid textarea, tr.invalid [data-action="edit"]') ||
    root.querySelector('.notice.bad');
  first?.scrollIntoView({ block: 'center' });
  first?.focus?.();
}

$('#save').addEventListener('click', async () => {
  if (!(await save())) showFirstError();
});
$('#discard').addEventListener('click', () => {
  model = fill(structuredClone(saved));
  cleared.clear();
  errors = {};
  summary = '';
  render();
});
window.addEventListener('beforeunload', (e) => {
  if (dirty()) e.preventDefault();
});
window.addEventListener('hashchange', () => {
  const t = TABS.find((x) => '#' + x.id === location.hash);
  if (t && t !== current) selectTab(t.id);
});
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    if (dialog.open) $('#edit-form').requestSubmit();
    else if (dirty()) save().then((ok) => ok || showFirstError());
  }
});

load();
