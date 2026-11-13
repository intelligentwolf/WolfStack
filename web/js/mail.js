/* Mail Manager — Stalwart mail clusters across WolfStack nodes */
/* (C) IntelligentWolf Ltd */
//
// Persona + story: a WolfStack admin wants company mail running across their
// servers, and to add a mailbox for a new starter in under a minute, without
// learning Stalwart.
//
// Flow: empty page → "Install Stalwart" wizard (basics → servers + checks →
// mailstore → coordinator → review → live install log) → the cluster appears
// with tabs: Domains · Mailboxes · DNS records · Status · Settings.
//
// Every request goes to the node that OWNS the cluster record (the Galera
// cluster's home node), through the node proxy. Backend: src/stalwart/api.rs.

(function () {
    'use strict';

    const state = {
        clusters: [],        // records, each with _via = the allNodes id it came from
        loadErrors: [],
        selected: null,      // cluster id
        tab: 'domains',
        domains: [],
        domainSel: '',
        accounts: [],
        busy: false,
    };

    // ─── Utilities ───────────────────────────────────────────────────

    const esc = (s) => (typeof escapeHtml === 'function' ? escapeHtml(String(s == null ? '' : s)) : String(s));
    const nodes = () => (Array.isArray(allNodes) ? allNodes : []).filter(n => n.node_type !== 'proxmox');
    const stableId = (n) => n.self_id || n.id;
    const nodeLabel = (n) => n.display_name || n.hostname || n.id;
    const toast = (msg, type) => { if (typeof showToast === 'function') showToast(msg, type || 'info', type === 'error' ? 0 : 5000); };

    function fmtBytes(b) {
        if (!b) return '0 B';
        const u = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0, v = b;
        while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
        return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`;
    }

    function url(via, path) {
        return typeof nodeApiUrl === 'function' ? nodeApiUrl(via, path) : path;
    }

    async function call(via, path, opts = {}) {
        const r = await fetch(url(via, path), {
            method: opts.method || 'GET',
            headers: opts.body ? { 'Content-Type': 'application/json' } : undefined,
            body: opts.body ? JSON.stringify(opts.body) : undefined,
        });
        let data = null;
        try { data = await r.json(); } catch (_) { data = null; }
        if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`);
        return data;
    }

    const cluster = () => state.clusters.find(c => c.id === state.selected) || null;
    const capi = (path, opts) => {
        const c = cluster();
        return call(c._via, `/api/stalwart/clusters/${encodeURIComponent(c.id)}${path}`, opts);
    };

    // ─── Accessible dialog ───────────────────────────────────────────
    // role=dialog / aria-modal / aria-labelledby, focus moved in and returned,
    // Tab trapped, Escape closes (W3C WAI-ARIA APG dialog pattern).

    let dialogSeq = 0;
    function openDialog(title, bodyHtml, { width = 560, onClose } = {}) {
        const opener = document.activeElement;
        const id = `mail-dlg-${++dialogSeq}`;
        const overlay = document.createElement('div');
        overlay.className = 'mail-dialog-overlay';
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:100000;display:flex;align-items:flex-start;justify-content:center;padding:5vh 16px;overflow-y:auto;';
        overlay.innerHTML = `
            <div role="dialog" aria-modal="true" aria-labelledby="${id}-t"
                 style="background:var(--bg-card,#1e2028);border:1px solid var(--border);border-radius:12px;padding:22px 24px;max-width:${width}px;width:100%;color:var(--text-primary);">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;gap:12px;">
                    <h2 id="${id}-t" tabindex="-1" style="margin:0;font-size:16px;">${esc(title)}</h2>
                    <button type="button" class="btn btn-sm" data-close aria-label="Close">×</button>
                </div>
                <div data-body>${bodyHtml}</div>
            </div>`;
        const box = overlay.firstElementChild;
        const close = () => {
            document.removeEventListener('keydown', onKey, true);
            overlay.remove();
            if (onClose) onClose();
            if (opener && typeof opener.focus === 'function') opener.focus();
        };
        const onKey = (e) => {
            if (e.key === 'Escape') { e.preventDefault(); close(); return; }
            if (e.key !== 'Tab') return;
            const f = [...box.querySelectorAll('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])')]
                .filter(el => !el.disabled && el.offsetParent !== null);
            if (!f.length) return;
            if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
            else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
        };
        document.addEventListener('keydown', onKey, true);
        box.querySelector('[data-close]').onclick = close;
        document.body.appendChild(overlay);
        const first = box.querySelector('input,select,textarea');
        (first || box.querySelector(`#${id}-t`)).focus();
        return { box, close };
    }

    // Yes/no confirm with specifics; Cancel is focused and the destructive
    // button sits apart from it (NN/G proximity of consequential options).
    function confirmDialog(title, message, actionLabel, { typed } = {}) {
        return new Promise((resolve) => {
            let done = false;
            const finish = (v) => { if (!done) { done = true; resolve(v); } };
            const typedRow = typed ? `
                <label style="display:block;font-size:12px;margin-top:12px;">Type <code>${esc(typed)}</code> to confirm
                    <input type="text" class="form-control" data-typed autocomplete="off" style="margin-top:4px;">
                </label>` : '';
            const d = openDialog(title, `
                <p style="font-size:13px;line-height:1.6;color:var(--text-secondary);margin:0;">${esc(message)}</p>
                ${typedRow}
                <div style="display:flex;justify-content:space-between;margin-top:20px;gap:24px;">
                    <button type="button" class="btn" data-cancel>Cancel</button>
                    <button type="button" class="btn btn-danger" data-ok ${typed ? 'disabled' : ''}>${esc(actionLabel)}</button>
                </div>`, { width: 480, onClose: () => finish(false) });
            const ok = d.box.querySelector('[data-ok]');
            const cancel = d.box.querySelector('[data-cancel]');
            if (typed) {
                const inp = d.box.querySelector('[data-typed]');
                inp.oninput = () => { ok.disabled = inp.value.trim() !== typed; };
                inp.focus();
            } else {
                cancel.focus();
            }
            cancel.onclick = () => { finish(false); d.close(); };
            ok.onclick = () => { finish(true); d.close(); };
        });
    }

    // Streamed job (install / remove): live log in a role=log region, final
    // result in role=status or role=alert, Close enabled when it ends.
    async function streamJob(title, via, path, body) {
        const d = openDialog(title, `
            <pre data-log role="log" aria-live="polite" style="background:var(--bg-input);border:1px solid var(--border);border-radius:8px;padding:12px;font-size:12px;line-height:1.5;max-height:50vh;overflow:auto;white-space:pre-wrap;word-break:break-word;margin:0;">Starting…</pre>
            <div data-result style="margin-top:12px;font-size:13px;"></div>`, { width: 720 });
        const log = d.box.querySelector('[data-log]');
        const result = d.box.querySelector('[data-result]');
        const append = (line) => {
            if (log.textContent === 'Starting…') log.textContent = '';
            log.textContent += (log.textContent ? '\n' : '') + line;
            log.scrollTop = log.scrollHeight;
        };
        let ok = null, msg = '';
        try {
            // Accept: text/event-stream lets the node proxy keep a long job's
            // log open past its normal request timeout (node_proxy).
            const resp = await fetch(url(via, path), { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' }, body: JSON.stringify(body) });
            if (!resp.ok && (resp.headers.get('content-type') || '').includes('application/json')) {
                const e = await resp.json();
                throw new Error(e.error || `HTTP ${resp.status}`);
            }
            if (!resp.body) throw new Error(`HTTP ${resp.status}`);
            const reader = resp.body.getReader();
            const dec = new TextDecoder();
            let buf = '';
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += dec.decode(value, { stream: true });
                const lines = buf.split('\n');
                buf = lines.pop();
                let event = [];
                for (const line of lines) {
                    if (line.startsWith('data: ')) { event.push(line.slice(6)); continue; }
                    if (line === '' && event.length) {
                        const m = event.join('\n');
                        event = [];
                        if (m.startsWith('RESULT:OK:')) { ok = true; msg = m.slice(10); }
                        else if (m.startsWith('RESULT:ERR:')) { ok = false; msg = m.slice(11); }
                        else append(m);
                    }
                }
                if (event.length) { // flush a trailing event split across reads
                    buf = event.map(e => 'data: ' + e).join('\n') + '\n' + buf;
                }
            }
        } catch (e) {
            ok = false;
            msg = (e && e.message) || String(e);
        }
        if (ok === true) {
            result.setAttribute('role', 'status');
            result.innerHTML = `<div style="color:var(--success);">✓ ${esc(msg || 'Done')}</div>`;
        } else {
            result.setAttribute('role', 'alert');
            result.innerHTML = `<div style="color:var(--danger);white-space:pre-wrap;">✗ ${esc(msg || 'The job ended without a result — check the log above.')}</div>`;
        }
        return ok === true;
    }

    // ─── Loading ─────────────────────────────────────────────────────

    async function loadClusters() {
        const out = [], errors = [];
        await Promise.all(nodes().filter(n => n.online !== false).map(async (n) => {
            try {
                const list = await call(n.id, '/api/stalwart/clusters');
                (list || []).forEach(c => out.push(Object.assign(c, { _via: n.id, _viaLabel: nodeLabel(n) })));
            } catch (e) {
                // A node on an older WolfStack has no Mail Manager — not an error
                // worth showing; anything else is.
                if (!/HTTP 404/.test(e.message)) errors.push(`${nodeLabel(n)}: ${e.message}`);
            }
        }));
        out.sort((a, b) => a.name.localeCompare(b.name));
        state.clusters = out;
        state.loadErrors = errors;
        if (state.selected && !cluster()) state.selected = null;
    }

    async function loadGaleraOptions() {
        const out = [];
        await Promise.all(nodes().filter(n => n.online !== false).map(async (n) => {
            try {
                const list = await call(n.id, '/api/galera/clusters');
                (list || []).forEach(g => out.push(Object.assign(g, { _via: n.id, _viaLabel: nodeLabel(n) })));
            } catch (_) { /* node without Galera support */ }
        }));
        return out;
    }

    // ─── Page shell ──────────────────────────────────────────────────

    function root() { return document.getElementById('mail-root'); }

    // The server list arrives with the first node poll; a deep link to
    // #mail can open this page before it has. Wait briefly rather than
    // asking no servers and showing a false "no mail servers yet".
    async function waitForNodes() {
        for (let i = 0; i < 40 && !nodes().length; i++) {
            await new Promise(r => setTimeout(r, 250));
        }
    }

    let initRunning = false;
    async function init() {
        const r = root();
        if (!r || initRunning) return; // selectView and the deep-link start can both call this
        initRunning = true;
        try { await initInner(r); } finally { initRunning = false; }
    }

    async function initInner(r) {
        r.innerHTML = '<div style="padding:24px;color:var(--text-muted);" role="status">Loading mail clusters…</div>';
        await waitForNodes();
        if (!nodes().length) {
            r.innerHTML = `<div role="alert" style="padding:24px;">The server list hasn't loaded, so mail clusters can't be found. <button type="button" class="btn btn-sm" onclick="mailInit()">Retry</button></div>`;
            return;
        }
        await loadClusters();
        render();
    }

    function render() {
        const r = root();
        if (!r) return;
        const errs = state.loadErrors.length
            ? `<div role="alert" style="margin-bottom:12px;padding:10px 14px;border-left:3px solid var(--warning,#f59e0b);background:var(--bg-input);font-size:12px;">Some servers could not be asked for mail clusters:<br>${state.loadErrors.map(esc).join('<br>')}</div>`
            : '';
        if (!state.clusters.length) {
            r.innerHTML = `${errs}
                <div style="max-width:560px;margin:48px auto;text-align:center;">
                    <h2 style="font-size:20px;margin-bottom:8px;">No mail servers yet</h2>
                    <p style="color:var(--text-secondary);line-height:1.6;">Run your own mail on your servers with Stalwart: SMTP, IMAP and webmail-ready accounts with two-factor sign-in, sharing one Galera database so any server can fail without losing mail.</p>
                    <button type="button" class="btn btn-primary" style="margin-top:12px;" onclick="Mail.openWizard()">Install Stalwart</button>
                </div>`;
            return;
        }
        // One cluster: open it rather than asking the operator to pick it.
        if (!state.selected && state.clusters.length === 1) state.selected = state.clusters[0].id;
        const c = cluster();
        r.innerHTML = `${errs}
            <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px;">
                <div style="display:flex;gap:8px;flex-wrap:wrap;" role="list" aria-label="Mail clusters">
                    ${state.clusters.map(x => `
                        <button type="button" role="listitem" class="btn ${x.id === state.selected ? 'btn-primary' : ''}" onclick="Mail.select('${esc(x.id)}')"
                            aria-pressed="${x.id === state.selected}">
                            ${esc(x.name)} <span style="font-size:11px;opacity:0.8;">${esc(x.public_hostname)}</span>
                            ${statusPill(x.status)}
                        </button>`).join('')}
                </div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    ${c && c.status === 'ready' && c.admin_user ? `<button type="button" class="btn btn-primary" onclick="Mail.revealAdmin()" title="Stalwart's own admin, for settings WolfStack doesn't cover — administrators only">Sign in to Stalwart admin</button>` : ''}
                    <button type="button" class="btn" onclick="Mail.openWizard()">+ Install another</button>
                </div>
            </div>
            ${c ? clusterView(c) : '<p style="color:var(--text-muted);">Choose a mail cluster above.</p>'}`;
        if (c) loadTab();
    }

    function statusPill(status) {
        const map = { ready: ['Running', 'var(--success,#22c55e)', '●'], installing: ['Installing', 'var(--warning,#f59e0b)', '◐'], failed: ['Install failed', 'var(--danger,#ef4444)', '✗'] };
        const [label, color, icon] = map[status] || [status || 'Unknown', 'var(--text-muted)', '○'];
        return `<span style="font-size:11px;color:${color};margin-left:6px;">${icon} ${esc(label)}</span>`;
    }

    const TABS = [['domains', 'Domains'], ['mailboxes', 'Mailboxes'], ['dns', 'DNS records'], ['status', 'Status'], ['settings', 'Settings']];

    function clusterView(c) {
        const failed = c.status === 'failed'
            ? `<div role="alert" style="margin-bottom:14px;padding:12px 14px;border-left:3px solid var(--danger);background:var(--bg-input);font-size:13px;">
                   <strong>The install did not finish.</strong>
                   <pre style="white-space:pre-wrap;font-size:12px;margin:8px 0;">${esc(c.last_error)}</pre>
                   Fix the cause above, then retry — WolfStack clears what this attempt left behind and installs again with the same settings.
                   <div style="margin-top:10px;"><button type="button" class="btn btn-primary btn-sm" onclick="Mail.retry()">Retry install</button></div>
               </div>` : '';
        return `${failed}
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">
                ${c.mail_nodes.length} server${c.mail_nodes.length === 1 ? '' : 's'}: ${c.mail_nodes.map(n => esc(n.label)).join(', ')}
                · coordinator: ${esc({ keep: 'Stalwart Keep', redis: 'Redis Sentinel', none: 'none (single server)' }[c.coordinator] || c.coordinator)}
                · database: <code>${esc(c.db_name)}</code> on Galera via ${esc(c.db_host)}:${esc(c.db_port)}
                · managed from ${esc(c._viaLabel)}
            </div>
            <div role="tablist" aria-label="Mail cluster sections" style="display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:16px;flex-wrap:wrap;">
                ${TABS.map(([id, label]) => `
                    <button type="button" role="tab" id="mail-tab-${id}" aria-selected="${state.tab === id}" aria-controls="mail-panel"
                        class="btn btn-sm" style="border-radius:6px 6px 0 0;${state.tab === id ? 'border-bottom:2px solid var(--accent);' : ''}"
                        onclick="Mail.tab('${id}')">${label}</button>`).join('')}
            </div>
            <div id="mail-panel" role="tabpanel" aria-labelledby="mail-tab-${state.tab}"></div>`;
    }

    function panel() { return document.getElementById('mail-panel'); }

    function panelError(e, retry) {
        const p = panel();
        if (p) p.innerHTML = `<div role="alert" style="padding:14px;border-left:3px solid var(--danger);background:var(--bg-input);font-size:13px;">
            Couldn't load this from the mail servers: ${esc(e.message || e)}
            <div style="margin-top:8px;"><button type="button" class="btn btn-sm" onclick="${retry}">Retry</button></div></div>`;
    }

    async function loadTab() {
        const p = panel();
        if (!p) return;
        const c = cluster();
        if (c.status !== 'ready' && !['settings', 'status'].includes(state.tab)) {
            p.innerHTML = '<p style="color:var(--text-muted);">Domains and mailboxes are available once the install has finished.</p>';
            return;
        }
        p.innerHTML = '<div role="status" style="color:var(--text-muted);padding:8px 0;">Loading…</div>';
        try {
            if (state.tab === 'domains') await renderDomains();
            else if (state.tab === 'mailboxes') await renderMailboxes();
            else if (state.tab === 'dns') await renderDns();
            else if (state.tab === 'status') await renderStatus();
            else renderSettings();
        } catch (e) {
            panelError(e, 'Mail.tab(Mail.currentTab())');
        }
    }

    async function ensureDomains() {
        state.domains = await capi('/domains');
        state.domains.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
        if (!state.domains.some(d => d.id === state.domainSel)) state.domainSel = state.domains[0] ? state.domains[0].id : '';
    }

    function domainPicker(onchange) {
        return `<label style="font-size:12px;color:var(--text-muted);display:inline-flex;align-items:center;gap:8px;">Domain
            <select class="form-control" style="width:auto;" onchange="${onchange}(this.value)">
                ${state.domains.map(d => `<option value="${esc(d.id)}" ${d.id === state.domainSel ? 'selected' : ''}>${esc(d.name)}</option>`).join('')}
            </select></label>`;
    }

    // ─── Domains ─────────────────────────────────────────────────────

    async function renderDomains() {
        await ensureDomains();
        const rows = state.domains.map(d => `
            <tr>
                <td style="padding:8px;">${esc(d.name)}${d.description ? `<div style="font-size:11px;color:var(--text-muted);">${esc(d.description)}</div>` : ''}</td>
                <td style="padding:8px;font-size:12px;">${d.certificateManagement && d.certificateManagement['@type'] === 'Automatic' ? 'Automatic (ACME)' : 'Manual'}</td>
                <td style="padding:8px;text-align:right;white-space:nowrap;">
                    <button type="button" class="btn btn-sm" onclick="Mail.showDns('${esc(d.id)}')">DNS records</button>
                    <button type="button" class="btn btn-sm" style="margin-left:16px;" onclick="Mail.deleteDomain('${esc(d.id)}')">Delete…</button>
                </td>
            </tr>`).join('');
        panel().innerHTML = `
            <form onsubmit="Mail.addDomain(event)" novalidate style="display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap;margin-bottom:16px;">
                <div>
                    <label for="mail-new-domain" style="display:block;font-size:12px;color:var(--text-muted);">Add a domain</label>
                    <input id="mail-new-domain" class="form-control" placeholder="example.com" aria-describedby="mail-new-domain-err" style="width:260px;">
                    <div id="mail-new-domain-err" style="font-size:12px;color:var(--danger);min-height:16px;"></div>
                </div>
                <label style="font-size:12px;display:inline-flex;align-items:center;gap:6px;margin-top:20px;" title="Stalwart requests certificates for this domain's mta-sts / autoconfig names. Their DNS must point at your mail servers first, or the request fails.">
                    <input type="checkbox" id="mail-new-domain-cert"> Request TLS certificate
                </label>
                <button type="submit" class="btn btn-primary" style="margin-top:18px;">Add domain</button>
            </form>
            ${state.domains.length ? `
            <div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:13px;">
                <thead><tr style="text-align:left;color:var(--text-muted);font-size:12px;"><th style="padding:8px;">Domain</th><th style="padding:8px;">Certificate</th><th></th></tr></thead>
                <tbody>${rows}</tbody></table></div>`
            : '<p style="color:var(--text-muted);">No domains yet. Add the domain your addresses will end in.</p>'}`;
    }

    async function addDomain(ev) {
        ev.preventDefault();
        const inp = document.getElementById('mail-new-domain');
        const err = document.getElementById('mail-new-domain-err');
        const name = inp.value.trim().toLowerCase();
        const valid = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(name);
        if (!valid) {
            inp.setAttribute('aria-invalid', 'true');
            err.textContent = 'Enter a domain name like example.com';
            inp.focus();
            return;
        }
        inp.removeAttribute('aria-invalid');
        err.textContent = '';
        try {
            await capi('/domains', { method: 'POST', body: { name, request_tls_certificate: document.getElementById('mail-new-domain-cert').checked } });
            toast(`Domain ${name} added — set up its DNS records next`, 'success');
            state.domainSel = '';
            await renderDomains();
        } catch (e) {
            inp.setAttribute('aria-invalid', 'true');
            err.textContent = e.message;
        }
    }

    async function deleteDomain(id) {
        const d = state.domains.find(x => x.id === id);
        if (!d) return;
        const ok = await confirmDialog('Delete domain', `Delete ${d.name} from the mail servers? Mail for its addresses will be rejected from then on. Stalwart refuses while mailboxes still use the domain — delete or move those first.`, 'Delete domain', { typed: d.name });
        if (!ok) return;
        try {
            await capi(`/domains/${encodeURIComponent(id)}`, { method: 'DELETE' });
            toast(`Domain ${d.name} deleted`, 'success');
            await renderDomains();
        } catch (e) { toast(`Couldn't delete ${d.name}: ${e.message}`, 'error'); }
    }

    // ─── Mailboxes ───────────────────────────────────────────────────

    async function renderMailboxes() {
        await ensureDomains();
        if (!state.domains.length) {
            panel().innerHTML = '<p style="color:var(--text-muted);">Add a domain first — every mailbox address ends in one.</p><button type="button" class="btn btn-primary" onclick="Mail.tab(\'domains\')">Go to Domains</button>';
            return;
        }
        state.accounts = await capi(`/domains/${encodeURIComponent(state.domainSel)}/accounts`);
        state.accounts.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
        const domName = (state.domains.find(d => d.id === state.domainSel) || {}).name || '';
        const rows = state.accounts.map(a => {
            const quota = a.quotas && a.quotas.maxDiskQuota ? fmtBytes(a.quotas.maxDiskQuota) : 'unlimited';
            const used = fmtBytes(a.usedDiskQuota || 0);
            const aliases = a.aliases ? Object.values(a.aliases).map(x => x.name).filter(Boolean) : [];
            return `<tr>
                <td style="padding:8px;"><strong>${esc(a.emailAddress || (a.name + '@' + domName))}</strong>
                    ${a.description ? `<div style="font-size:11px;color:var(--text-muted);">${esc(a.description)}</div>` : ''}
                    ${aliases.length ? `<div style="font-size:11px;color:var(--text-muted);">also: ${aliases.map(esc).join(', ')}</div>` : ''}</td>
                <td style="padding:8px;font-size:12px;font-variant-numeric:tabular-nums;text-align:right;">${used} of ${quota}</td>
                <td style="padding:8px;font-size:12px;">${a.two_factor ? '✓ on' : 'off'} · ${a.app_password_count} app password${a.app_password_count === 1 ? '' : 's'}</td>
                <td style="padding:8px;font-size:12px;">${a.suspended ? '<span style="color:var(--warning,#f59e0b);">⏸ Suspended</span>' : '<span style="color:var(--success,#22c55e);">● Active</span>'}</td>
                <td style="padding:8px;text-align:right;white-space:nowrap;">
                    <select class="form-control" style="width:auto;display:inline-block;" aria-label="Actions for ${esc(a.name)}" onchange="Mail.accountAction('${esc(a.id)}', this.value); this.value='';">
                        <option value="">Actions…</option>
                        <option value="password">Set new password</option>
                        <option value="app-password">Create app password</option>
                        ${a.two_factor ? '<option value="reset-two-factor">Turn off two-factor</option>' : ''}
                        <option value="quota">Change quota</option>
                        <option value="aliases">Edit aliases</option>
                        <option value="suspend">${a.suspended ? 'Resume' : 'Suspend'}</option>
                        <option value="delete">Delete mailbox…</option>
                    </select>
                </td></tr>`;
        }).join('');
        panel().innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px;">
                ${domainPicker('Mail.pickDomainForMailboxes')}
                <button type="button" class="btn btn-primary" onclick="Mail.newAccount()">+ New mailbox</button>
            </div>
            <p style="font-size:12px;color:var(--text-muted);margin:0 0 12px;">People sign in to webmail and turn on two-factor at <code>https://${esc(cluster().public_hostname)}/account</code>. With two-factor on, phone and desktop mail apps need an app password.</p>
            ${state.accounts.length ? `<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:13px;">
                <thead><tr style="text-align:left;color:var(--text-muted);font-size:12px;"><th style="padding:8px;">Mailbox</th><th style="padding:8px;text-align:right;">Storage</th><th style="padding:8px;">Two-factor</th><th style="padding:8px;">State</th><th></th></tr></thead>
                <tbody>${rows}</tbody></table></div>`
            : `<p style="color:var(--text-muted);">No mailboxes on ${esc(domName)} yet. Create the first one.</p>`}`;
    }

    function genPassword() {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
        const a = new Uint32Array(20);
        crypto.getRandomValues(a);
        return [...a].map(x => chars[x % chars.length]).join('');
    }

    function fieldHtml(id, label, attrs = '', help = '') {
        return `<div style="margin-bottom:12px;">
            <label for="${id}" style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px;">${label}</label>
            <input id="${id}" class="form-control" ${attrs} aria-describedby="${id}-err${help ? ` ${id}-help` : ''}">
            ${help ? `<div id="${id}-help" style="font-size:11px;color:var(--text-muted);margin-top:3px;">${help}</div>` : ''}
            <div id="${id}-err" style="font-size:12px;color:var(--danger);min-height:14px;"></div>
        </div>`;
    }

    function setFieldError(box, id, msg) {
        const inp = box.querySelector('#' + id);
        const err = box.querySelector('#' + id + '-err');
        if (msg) { inp.setAttribute('aria-invalid', 'true'); err.textContent = msg; } else { inp.removeAttribute('aria-invalid'); err.textContent = ''; }
        return !msg;
    }

    function newAccount() {
        const domName = (state.domains.find(d => d.id === state.domainSel) || {}).name || '';
        const pw = genPassword();
        const d = openDialog(`New mailbox on ${domName}`, `
            <form novalidate>
                <div role="alert" data-summary style="display:none;margin-bottom:12px;padding:8px 12px;border-left:3px solid var(--danger);font-size:12px;" tabindex="-1"></div>
                ${fieldHtml('mail-acc-name', `Address (before @${esc(domName)})`, 'placeholder="jane" autocomplete="off"')}
                ${fieldHtml('mail-acc-desc', 'Full name (optional)', 'placeholder="Jane Doe"')}
                ${fieldHtml('mail-acc-pw', 'Password', `value="${esc(pw)}" autocomplete="new-password"`, 'A strong password is filled in — copy it to give to the person, or type your own (12+ characters).')}
                ${fieldHtml('mail-acc-quota', 'Storage limit in GB (0 = unlimited)', 'type="number" min="0" step="1" value="5" inputmode="numeric"')}
                <label style="font-size:12px;display:flex;align-items:center;gap:6px;margin-bottom:16px;" title="Can manage every domain and mailbox in Stalwart's own admin. WolfStack administrators only.">
                    <input type="checkbox" id="mail-acc-admin"> Stalwart administrator
                </label>
                <div style="display:flex;justify-content:flex-end;gap:8px;">
                    <button type="button" class="btn" data-cancel>Cancel</button>
                    <button type="submit" class="btn btn-primary">Create mailbox</button>
                </div>
            </form>`);
        d.box.querySelector('[data-cancel]').onclick = d.close;
        d.box.querySelector('form').onsubmit = async (ev) => {
            ev.preventDefault();
            const b = d.box;
            const name = b.querySelector('#mail-acc-name').value.trim().toLowerCase();
            const password = b.querySelector('#mail-acc-pw').value;
            const gb = Number(b.querySelector('#mail-acc-quota').value || 0);
            const errs = [];
            if (!setFieldError(b, 'mail-acc-name', /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(name) && !name.endsWith('.') ? '' : 'Enter the part before the @, using letters, digits and . _ - +')) errs.push('Address');
            if (!setFieldError(b, 'mail-acc-pw', password.length >= 12 ? '' : 'Use at least 12 characters')) errs.push('Password');
            if (!setFieldError(b, 'mail-acc-quota', Number.isFinite(gb) && gb >= 0 ? '' : 'Enter 0 or a whole number of GB')) errs.push('Storage limit');
            const summary = b.querySelector('[data-summary]');
            if (errs.length) {
                summary.style.display = 'block';
                summary.textContent = `Check: ${errs.join(', ')}`;
                summary.focus();
                return;
            }
            summary.style.display = 'none';
            try {
                await capi('/accounts', { method: 'POST', body: {
                    name, domain_id: state.domainSel, password,
                    description: b.querySelector('#mail-acc-desc').value.trim(),
                    quota_bytes: Math.round(gb * 1024 * 1024 * 1024),
                    admin: b.querySelector('#mail-acc-admin').checked,
                } });
                d.close();
                toast(`Mailbox ${name}@${domName} created`, 'success');
                await renderMailboxes();
            } catch (e) {
                summary.style.display = 'block';
                summary.textContent = e.message;
                summary.focus();
            }
        };
    }

    function showSecret(title, intro, secret, extraHtml = '') {
        const d = openDialog(title, `
            <p style="font-size:13px;color:var(--text-secondary);line-height:1.6;margin-top:0;">${esc(intro)}</p>
            ${extraHtml}
            <div style="display:flex;gap:8px;align-items:center;">
                <input class="form-control" readonly value="${esc(secret)}" data-secret style="font-family:monospace;">
                <button type="button" class="btn" data-copy>Copy</button>
            </div>
            <div role="status" data-copied style="font-size:12px;color:var(--success);min-height:16px;margin-top:6px;"></div>
            <div style="display:flex;justify-content:flex-end;margin-top:12px;"><button type="button" class="btn btn-primary" data-done>Done</button></div>`);
        d.box.querySelector('[data-done]').onclick = d.close;
        d.box.querySelector('[data-copy]').onclick = async () => {
            try { await navigator.clipboard.writeText(secret); d.box.querySelector('[data-copied]').textContent = extraHtml ? 'Password copied' : 'Copied'; }
            catch (_) { d.box.querySelector('[data-secret]').select(); d.box.querySelector('[data-copied]').textContent = 'Press Ctrl+C to copy'; }
        };
        d.box.querySelector('[data-secret]').select();
        return d;
    }

    async function accountAction(id, action) {
        if (!action) return;
        const a = state.accounts.find(x => x.id === id);
        if (!a) return;
        const addr = a.emailAddress || a.name;
        const post = (act, body) => capi(`/accounts/${encodeURIComponent(id)}/${act}`, { method: 'POST', body: body || {} });
        try {
            if (action === 'password') {
                const pw = genPassword();
                const d = openDialog(`New password for ${addr}`, `<form novalidate>
                    ${fieldHtml('mail-pw-new', 'New password', `value="${esc(pw)}" autocomplete="new-password"`, 'Changing the password signs the account out of every connected app.')}
                    <div style="display:flex;justify-content:flex-end;gap:8px;"><button type="button" class="btn" data-cancel>Cancel</button><button type="submit" class="btn btn-primary">Set password</button></div></form>`);
                d.box.querySelector('[data-cancel]').onclick = d.close;
                d.box.querySelector('form').onsubmit = async (ev) => {
                    ev.preventDefault();
                    const v = d.box.querySelector('#mail-pw-new').value;
                    if (!setFieldError(d.box, 'mail-pw-new', v.length >= 12 ? '' : 'Use at least 12 characters')) return;
                    try { await post('password', { password: v }); d.close(); toast(`Password changed for ${addr}`, 'success'); }
                    catch (e) { setFieldError(d.box, 'mail-pw-new', e.message); }
                };
                return;
            }
            if (action === 'app-password') {
                const r = await post('app-password', { description: 'Created in WolfStack' });
                showSecret(`App password for ${addr}`, 'Use this instead of the account password in phone and desktop mail apps. It is shown only now — copy it before closing.', r.secret);
                await renderMailboxes();
                return;
            }
            if (action === 'reset-two-factor') {
                if (!await confirmDialog('Turn off two-factor', `Turn off two-factor sign-in for ${addr}? Use this when they have lost their authenticator. They should set it up again at /account straight after.`, 'Turn off two-factor')) return;
                await post('reset-two-factor');
                toast(`Two-factor turned off for ${addr}`, 'success');
            } else if (action === 'suspend') {
                const suspend = !a.suspended;
                if (suspend && !await confirmDialog('Suspend mailbox', `Suspend ${addr}? It can't sign in, send or receive mail (incoming mail bounces) until resumed. Nothing is deleted.`, 'Suspend')) return;
                await post('suspend', { suspended: suspend });
                toast(`${addr} ${suspend ? 'suspended' : 'resumed'}`, 'success');
            } else if (action === 'quota') {
                const cur = a.quotas && a.quotas.maxDiskQuota ? Math.round(a.quotas.maxDiskQuota / 1073741824) : 0;
                const d = openDialog(`Storage limit for ${addr}`, `<form novalidate>
                    ${fieldHtml('mail-q', 'Limit in GB (0 = unlimited)', `type="number" min="0" step="1" value="${cur}" inputmode="numeric"`)}
                    <div style="display:flex;justify-content:flex-end;gap:8px;"><button type="button" class="btn" data-cancel>Cancel</button><button type="submit" class="btn btn-primary">Save</button></div></form>`);
                d.box.querySelector('[data-cancel]').onclick = d.close;
                d.box.querySelector('form').onsubmit = async (ev) => {
                    ev.preventDefault();
                    const gb = Number(d.box.querySelector('#mail-q').value || 0);
                    if (!setFieldError(d.box, 'mail-q', Number.isFinite(gb) && gb >= 0 ? '' : 'Enter 0 or a whole number of GB')) return;
                    try { await post('quota', { quota_bytes: Math.round(gb * 1073741824) }); d.close(); toast(`Storage limit saved for ${addr}`, 'success'); await renderMailboxes(); }
                    catch (e) { setFieldError(d.box, 'mail-q', e.message); }
                };
                return;
            } else if (action === 'aliases') {
                const cur = a.aliases ? Object.values(a.aliases) : [];
                const domOpts = (sel) => state.domains.map(dm => `<option value="${esc(dm.id)}" ${dm.id === sel ? 'selected' : ''}>@${esc(dm.name)}</option>`).join('');
                const row = (al) => `<div data-alias style="display:flex;gap:6px;margin-bottom:6px;">
                    <input class="form-control" aria-label="Alias name" value="${esc(al.name || '')}" placeholder="sales">
                    <select class="form-control" aria-label="Alias domain" style="width:auto;">${domOpts(al.domainId || state.domainSel)}</select>
                    <button type="button" class="btn btn-sm" aria-label="Remove alias" onclick="this.parentElement.remove()">Remove</button></div>`;
                const d = openDialog(`Aliases for ${addr}`, `<form novalidate>
                    <p style="font-size:12px;color:var(--text-muted);margin-top:0;">Other addresses that deliver to this mailbox.</p>
                    <div data-list>${cur.map(row).join('')}</div>
                    <button type="button" class="btn btn-sm" data-add>+ Add alias</button>
                    <div role="alert" data-err style="font-size:12px;color:var(--danger);min-height:16px;margin-top:8px;"></div>
                    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:8px;"><button type="button" class="btn" data-cancel>Cancel</button><button type="submit" class="btn btn-primary">Save aliases</button></div></form>`);
                d.box.querySelector('[data-cancel]').onclick = d.close;
                d.box.querySelector('[data-add]').onclick = () => d.box.querySelector('[data-list]').insertAdjacentHTML('beforeend', row({}));
                d.box.querySelector('form').onsubmit = async (ev) => {
                    ev.preventDefault();
                    const aliases = [...d.box.querySelectorAll('[data-alias]')].map(r => ({ name: r.querySelector('input').value.trim(), domain_id: r.querySelector('select').value })).filter(x => x.name);
                    try { await post('aliases', { aliases }); d.close(); toast(`Aliases saved for ${addr}`, 'success'); await renderMailboxes(); }
                    catch (e) { d.box.querySelector('[data-err]').textContent = e.message; }
                };
                return;
            } else if (action === 'delete') {
                if (!await confirmDialog('Delete mailbox', `Delete ${addr} and every message in it? This cannot be undone.`, 'Delete mailbox', { typed: addr })) return;
                await capi(`/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' });
                toast(`${addr} deleted`, 'success');
            }
            await renderMailboxes();
        } catch (e) {
            toast(`${addr}: ${e.message}`, 'error');
        }
    }

    // ─── DNS ─────────────────────────────────────────────────────────

    async function renderDns() {
        await ensureDomains();
        if (!state.domains.length) {
            panel().innerHTML = '<p style="color:var(--text-muted);">Add a domain first.</p>';
            return;
        }
        const r = await capi(`/domains/${encodeURIComponent(state.domainSel)}/dns`);
        const rows = (r.records || []).map((x, i) => `<tr>
            <td style="padding:6px 8px;font-family:monospace;font-size:12px;word-break:break-all;">${esc(x.name)}</td>
            <td style="padding:6px 8px;font-size:12px;">${esc(x.type)}</td>
            <td style="padding:6px 8px;font-family:monospace;font-size:12px;word-break:break-all;">${esc(x.value)}</td>
            <td style="padding:6px 8px;"><button type="button" class="btn btn-sm" onclick="Mail.copyDns(${i})" aria-label="Copy value of ${esc(x.type)} record ${esc(x.name)}">Copy</button></td></tr>`).join('');
        state.dnsRecords = r.records || [];
        state.dnsZone = r.zone_file || '';
        const missing = (r.missing_public_ip || []).length
            ? `<p role="alert" style="font-size:12px;color:var(--warning,#f59e0b);">No public address is known for ${r.missing_public_ip.map(esc).join(', ')}, so its A record isn't listed — add it by hand.</p>` : '';
        panel().innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px;">
                ${domainPicker('Mail.pickDomainForDns')}
                <button type="button" class="btn btn-sm" onclick="Mail.copyZone()">Copy as zone file</button>
            </div>
            <p style="font-size:12px;color:var(--text-muted);margin:0 0 10px;">Add these at your DNS provider. Mail is delivered and trusted once MX, SPF, DKIM and DMARC are in place; the rest let mail apps configure themselves.</p>
            ${missing}
            <div role="status" id="mail-dns-copied" style="font-size:12px;color:var(--success);min-height:16px;"></div>
            <div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;">
                <thead><tr style="text-align:left;color:var(--text-muted);font-size:12px;"><th style="padding:6px 8px;">Name</th><th style="padding:6px 8px;">Type</th><th style="padding:6px 8px;">Value</th><th></th></tr></thead>
                <tbody>${rows}</tbody></table></div>`;
    }

    async function copyText(text, what) {
        const out = document.getElementById('mail-dns-copied');
        try { await navigator.clipboard.writeText(text); if (out) out.textContent = `${what} copied`; }
        catch (_) { toast('Copy failed — your browser blocked clipboard access', 'error'); }
    }

    // ─── Status ──────────────────────────────────────────────────────

    async function renderStatus() {
        const h = await capi('/health');
        const rows = h.nodes.map(n => `<tr>
            <td style="padding:8px;">${esc(n.label)}<div style="font-size:11px;color:var(--text-muted);">${esc(n.stalwart_hostname)}</div></td>
            <td style="padding:8px;font-size:12px;">${n.ready ? '<span style="color:var(--success);">● Ready</span>' : `<span style="color:var(--danger);">✗ ${esc(n.state)}</span>`}</td>
            <td style="padding:8px;font-size:12px;">${n.lease ? esc(n.lease) : (cluster().mail_nodes.length > 1 ? '—' : 'single server')}</td></tr>`).join('');
        panel().innerHTML = `
            ${h.error ? `<div role="alert" style="margin-bottom:10px;font-size:12px;color:var(--danger);">${esc(h.error)}</div>` : ''}
            <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:14px;">
                <thead><tr style="text-align:left;color:var(--text-muted);font-size:12px;"><th style="padding:8px;">Server</th><th style="padding:8px;">Health</th><th style="padding:8px;">Cluster lease</th></tr></thead>
                <tbody>${rows}</tbody></table>
            <p style="font-size:13px;">Outbound queue: <strong style="font-variant-numeric:tabular-nums;">${h.queued_messages == null ? 'unknown' : h.queued_messages}</strong> message${h.queued_messages === 1 ? '' : 's'} waiting.</p>
            <button type="button" class="btn btn-sm" onclick="Mail.tab('status')">Refresh</button>`;
    }

    // ─── Settings ────────────────────────────────────────────────────

    function renderSettings() {
        const c = cluster();
        panel().innerHTML = `
            <section style="margin-bottom:24px;">
                <h3 style="font-size:14px;margin:0 0 6px;">Stalwart's own admin</h3>
                <p style="font-size:12px;color:var(--text-muted);margin:0 0 8px;">For settings WolfStack doesn't cover (spam filter, routing, logging), sign in to Stalwart's web admin. WolfStack administrators only; each reveal is logged.</p>
                <button type="button" class="btn btn-sm" onclick="Mail.revealAdmin()" ${c.admin_user ? '' : 'disabled'}>Show admin sign-in</button>
            </section>
            <section style="border-top:1px solid var(--border);padding-top:16px;">
                <h3 style="font-size:14px;margin:0 0 6px;color:var(--danger);">Remove this mail cluster</h3>
                <p style="font-size:12px;color:var(--text-muted);margin:0 0 8px;">Stops and removes the mail containers on every server. The mail database is kept unless you choose to delete it too. The Galera cluster itself (including one the installer built) keeps running — remove it on the Galera page if nothing else uses it.</p>
                <label style="font-size:12px;display:flex;align-items:center;gap:6px;margin-bottom:10px;">
                    <input type="checkbox" id="mail-remove-db"> Also delete the mail database <code>${esc(c.db_name)}</code> (every message and account — cannot be undone)
                </label>
                <button type="button" class="btn btn-danger btn-sm" onclick="Mail.removeCluster()">Remove mail cluster…</button>
            </section>`;
    }

    async function revealAdmin() {
        try {
            const r = await capi('/admin-password');
            const c = cluster();
            // Stalwart's WebUI signs in ONLY over HTTPS on the server name:
            // over plain HTTP (port 8080 included) it answers "Unknown client
            // id", over HTTPS on an IP it answers "Client metadata documents
            // are disabled" (Stalwart docs install/troubleshooting.md,
            // install/platform/linux.md "Step 5"). So the one link is the
            // server name — the per-server WolfNet links offered before
            // 2026-11-13 could never sign in.
            const testHint = c.request_tls_certificate ? '' : `
                <div style="font-size:12px;color:var(--text-secondary);border-left:3px solid var(--warning,#f59e0b);padding:6px 10px;margin-top:8px;">
                    This cluster has no certificate yet, so the servers present a self-signed one. Until ${esc(c.public_hostname)} has real DNS and a certificate, you can reach it for <strong>testing only</strong> by pointing the name at one server in this computer's hosts file — e.g. <code>${esc((c.mail_nodes[0] || {}).wolfnet_ip || '')} ${esc(c.public_hostname)}</code> (WolfNet address) — and accepting the browser's certificate warning. Never accept that warning for a live mail server.
                </div>`;
            const links = `
                <div style="font-size:13px;margin-bottom:12px;">
                    <div style="margin-bottom:4px;">Open the admin page:</div>
                    <a href="${esc(r.admin_url)}" target="_blank" rel="noopener" style="color:var(--accent-light,#60a5fa);">${esc(r.admin_url)}</a>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">Stalwart accepts sign-in only at this address, over HTTPS — not on a server's IP or port 8080.</div>
                    ${testHint}
                </div>
                <label for="mail-admin-user" style="display:block;font-size:13px;margin-bottom:4px;">Username</label>
                <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;">
                    <input id="mail-admin-user" class="form-control" readonly value="${esc(r.user)}" style="font-family:monospace;">
                    <button type="button" class="btn" data-copy-user>Copy</button>
                </div>
                <div style="font-size:13px;margin-bottom:4px;">Password</div>`;
            const d = showSecret('Sign in to Stalwart admin', 'WolfStack manages the cluster with its own key, so turning on two-factor for this account is safe.', r.password, links);
            d.box.querySelector('[data-copy-user]').onclick = async () => {
                const out = d.box.querySelector('[data-copied]');
                try { await navigator.clipboard.writeText(r.user); out.textContent = 'Username copied'; }
                catch (_) { d.box.querySelector('#mail-admin-user').select(); out.textContent = 'Press Ctrl+C to copy'; }
            };
        } catch (e) { toast(e.message, 'error'); }
    }

    async function removeCluster() {
        const c = cluster();
        const dropDb = document.getElementById('mail-remove-db').checked;
        const msg = dropDb
            ? `Remove ${c.name} from every server AND delete its database ${c.db_name}? Every mailbox and message is lost. This cannot be undone.`
            : `Remove ${c.name}'s containers from every server? Mail stops being delivered. The database ${c.db_name} is kept.`;
        if (!await confirmDialog('Remove mail cluster', msg, 'Remove', { typed: c.id })) return;
        const ok = await streamJob(`Removing ${c.name}`, c._via, `/api/stalwart/clusters/${encodeURIComponent(c.id)}/remove`, { drop_database: dropDb });
        if (ok) { state.selected = null; await loadClusters(); render(); }
    }

    async function retryInstall() {
        const c = cluster();
        if (!await confirmDialog('Retry install', `Clear what the failed install of ${c.name} left on its servers — including its empty mail database ${c.db_name} — and install again with the same settings?`, 'Retry install')) return;
        const ok = await streamJob(`Retrying ${c.name}`, c._via, `/api/stalwart/clusters/${encodeURIComponent(c.id)}/retry`, {});
        await loadClusters();
        state.selected = c.id;
        state.tab = ok ? 'domains' : 'settings';
        render();
    }

    // ─── Install wizard ──────────────────────────────────────────────

    const wiz = { step: 0, data: null, checks: [], galera: [], dialog: null };
    const STEPS = ['Basics', 'Servers', 'Mailstore', 'Coordination', 'Review'];

    async function openWizard() {
        // One wizard at a time: a second would share `wiz` and duplicate
        // every field id, crossing the two dialogs' input.
        if (wiz.dialog && wiz.dialog.box.isConnected) wiz.dialog.close();
        wiz.step = 0;
        wiz.checks = [];
        wiz.data = { id: 'mail', name: '', domain: '', hostname: '', cert: true, nodes: [], coordinator: 'keep', coordNodes: null, galera: 'new' };
        wiz.dialog = openDialog('Install Stalwart mail', '<div data-wiz></div>', { width: 760 });
        renderWizard();
        loadGaleraOptions().then(g => { wiz.galera = g; if (wiz.step === 2) renderWizard(); });
    }

    function wizBox() { return wiz.dialog && wiz.dialog.box.querySelector('[data-wiz]'); }

    function stepper() {
        return `<ol aria-label="Steps" style="display:flex;gap:6px;list-style:none;padding:0;margin:0 0 16px;flex-wrap:wrap;font-size:12px;">
            ${STEPS.map((s, i) => `<li ${i === wiz.step ? 'aria-current="step"' : ''} style="padding:4px 10px;border-radius:12px;${i === wiz.step ? 'background:var(--accent);color:#fff;' : 'background:var(--bg-input);color:var(--text-muted);'}">${i + 1}. ${s}</li>`).join('')}
        </ol>`;
    }

    function navButtons(nextLabel = 'Next', nextDisabled = false) {
        return `<div role="alert" data-wiz-err style="font-size:12px;color:var(--danger);min-height:16px;margin-top:10px;white-space:pre-wrap;"></div>
            <div style="display:flex;justify-content:space-between;margin-top:10px;">
                <button type="button" class="btn" onclick="Mail.wizBack()" ${wiz.step === 0 ? 'disabled' : ''}>Back</button>
                <button type="button" class="btn btn-primary" onclick="Mail.wizNext()" ${nextDisabled ? 'disabled' : ''}>${nextLabel}</button>
            </div>`;
    }

    function wizError(msg) { const e = wizBox() && wizBox().querySelector('[data-wiz-err]'); if (e) e.textContent = msg || ''; }

    const byStable = (id) => nodes().find(n => stableId(n) === id || n.id === id);
    // Results are matched by the id the browser asked with (req_id): the
    // server answers with its own stable id, which differs when the browser's
    // node list has no self_id for a node.
    const check = (id) => wiz.checks.find(c => c.req_id === id || c.node_id === id);
    const coordIds = () => wiz.data.coordNodes || wiz.data.nodes;

    function renderWizard() {
        const b = wizBox();
        if (!b) return;
        const d = wiz.data;
        let body = '';
        if (wiz.step === 0) {
            body = `
                ${fieldHtml('wz-domain', 'Mail domain — what addresses end in', `value="${esc(d.domain)}" placeholder="example.com"`)}
                ${fieldHtml('wz-host', 'Mail server name — every server answers to this', `value="${esc(d.hostname)}" placeholder="mx.example.com"`, 'Point its DNS A record at your mail servers. Mail apps and other mail servers connect to it.')}
                ${fieldHtml('wz-name', 'Cluster name (shown in WolfStack)', `value="${esc(d.name)}" placeholder="Company mail"`)}
                ${fieldHtml('wz-id', 'Short id (lowercase, used for containers and the database)', `value="${esc(d.id)}" maxlength="24"`)}
                <label style="font-size:12px;display:flex;align-items:center;gap:6px;">
                    <input type="checkbox" id="wz-cert" ${d.cert ? 'checked' : ''}> Get a free TLS certificate from Let's Encrypt (needs the server name's DNS pointing here and port 443 open)
                </label>`;
        } else if (wiz.step === 1) {
            const byCluster = {};
            nodes().forEach(n => { (byCluster[n.cluster_name || 'WolfStack'] = byCluster[n.cluster_name || 'WolfStack'] || []).push(n); });
            body = `<p style="font-size:13px;margin-top:0;">Choose the servers that run Stalwart. One server works; two or more share the mail so any one can fail. All must be in the same WolfStack cluster.</p>
                ${Object.entries(byCluster).map(([cl, ns]) => `<fieldset style="border:1px solid var(--border);border-radius:8px;padding:8px 12px;margin-bottom:10px;">
                    <legend style="font-size:12px;color:var(--text-muted);padding:0 4px;">${esc(cl)}</legend>
                    ${ns.map(n => `<label style="display:flex;align-items:center;gap:8px;font-size:13px;padding:3px 0;">
                        <input type="checkbox" value="${esc(stableId(n))}" data-wz-node data-cluster="${esc(cl)}" ${d.nodes.includes(stableId(n)) ? 'checked' : ''} ${n.online === false ? 'disabled' : ''}>
                        ${esc(nodeLabel(n))} ${n.online === false ? '<span style="color:var(--text-muted);font-size:11px;">(offline)</span>' : ''}</label>`).join('')}
                </fieldset>`).join('')}
                <button type="button" class="btn btn-sm" onclick="Mail.wizCheck()">Check these servers</button>
                <div data-wz-checks style="margin-top:12px;">${checksTable(d.nodes)}</div>`;
        } else if (wiz.step === 2) {
            const cl = (byStable(d.nodes[0]) || {}).cluster_name || 'WolfStack';
            const opts = wiz.galera.filter(g => !g.cluster || g.cluster === cl);
            const n = d.nodes.length;
            const newNote = n >= 3
                ? 'Three database members, one on each of the first three mail servers, plus a MaxScale proxy.'
                : `Three database members on ${n === 1 ? 'that one server' : 'your two servers (one carries two)'}, plus a MaxScale proxy. The database keeps working if one member stops, but not if ${n === 1 ? 'the server' : 'the server holding two'} fails.`;
            body = `<p style="font-size:13px;margin-top:0;">Mail, accounts and settings live in one shared Galera database, so every mail server sees the same mail. Build a new one for mail, or use a Galera cluster you already run — WolfStack creates a separate database and user for mail either way.</p>
                <label style="display:flex;gap:10px;align-items:flex-start;padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;cursor:pointer;">
                    <input type="radio" name="wz-galera" value="new" ${d.galera === 'new' ? 'checked' : ''} style="margin-top:3px;">
                    <span><strong>Create a new Galera cluster for mail</strong> <span style="font-size:11px;color:var(--text-muted);">recommended · adds several minutes to the install</span><br>
                    <span style="font-size:12px;color:var(--text-muted);">${esc(newNote)} Needs LXC on those servers.</span></span></label>
                ${opts.length ? opts.map(g => {
                    const proxy = (g.proxies || [])[0];
                    const key = `${g._via}|${g.id}`;
                    return `<label style="display:flex;gap:10px;align-items:flex-start;padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;${proxy ? 'cursor:pointer;' : 'opacity:0.6;'}">
                        <input type="radio" name="wz-galera" value="${esc(key)}" ${d.galera === key ? 'checked' : ''} ${proxy ? '' : 'disabled'} style="margin-top:3px;">
                        <span><strong>${esc(g.name)}</strong> <span style="font-size:11px;color:var(--text-muted);">${g.nodes.length} members · on ${esc(g._viaLabel)}</span><br>
                        <span style="font-size:12px;color:var(--text-muted);">${proxy ? `Stalwart connects through MaxScale at ${esc(proxy.address)}:${esc(proxy.listener_port)}` : 'No MaxScale proxy — Stalwart can only connect to one database address, so it needs the proxy to keep working when a Galera member is down. Add one on the Galera page first.'}</span></span></label>`;
                }).join('') : ''}`;
        } else if (wiz.step === 3) {
            body = coordinationStep();
        } else {
            const g = d.galera === 'new' ? { name: 'new (3 members + MaxScale)' } : (wiz.galera.find(x => `${x._via}|${x.id}` === d.galera) || {});
            const label = (id) => { const n = byStable(id); return n ? nodeLabel(n) : id; };
            body = `<dl style="display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;font-size:13px;margin:0;">
                    <dt style="color:var(--text-muted);">Addresses</dt><dd style="margin:0;">name@${esc(d.domain)}</dd>
                    <dt style="color:var(--text-muted);">Server name</dt><dd style="margin:0;">${esc(d.hostname)} ${d.cert ? '(Let\'s Encrypt certificate)' : '(no certificate requested)'}</dd>
                    <dt style="color:var(--text-muted);">Mail servers</dt><dd style="margin:0;">${d.nodes.map(label).map(esc).join(', ')}</dd>
                    <dt style="color:var(--text-muted);">Database</dt><dd style="margin:0;">Galera "${esc(g.name || '?')}" — new database stalwart_${esc(d.id.replace(/-/g, '_'))}</dd>
                    <dt style="color:var(--text-muted);">Coordination</dt><dd style="margin:0;">${d.nodes.length < 2 ? 'Not needed for one server' : `${d.coordinator === 'keep' ? 'Stalwart Keep' : 'Redis (Valkey + Sentinel)'} on ${coordIds().map(label).map(esc).join(', ')}`}</dd>
                </dl>
                <p style="font-size:12px;color:var(--text-muted);margin-top:14px;">Installing takes a few minutes. Stalwart's admin password is shown when it finishes and stays available under Settings.</p>`;
        }
        b.innerHTML = stepper() + body + navButtons(wiz.step === 4 ? 'Install' : 'Next');
    }

    function checksTable(ids) {
        if (!wiz.checks.length) return '<p style="font-size:12px;color:var(--text-muted);">Checks run before anything is installed: Docker, WolfNet, free mail ports, the clock, the kernel and whether outgoing mail (port 25) is allowed.</p>';
        const rows = ids.map(id => {
            const c = check(id);
            const n = byStable(id);
            if (!c) return `<tr><td style="padding:6px;">${esc(n ? nodeLabel(n) : id)}</td><td colspan="5" style="padding:6px;color:var(--text-muted);">not checked yet</td></tr>`;
            if (!c.ok) return `<tr><td style="padding:6px;">${esc(c.label)}</td><td colspan="5" style="padding:6px;color:var(--danger);">✗ ${esc(c.error)}</td></tr>`;
            const p = c.report;
            const yes = (v, okText, badText) => v ? `<span style="color:var(--success);">✓ ${okText}</span>` : `<span style="color:var(--danger);">✗ ${badText}</span>`;
            return `<tr>
                <td style="padding:6px;">${esc(c.label)}<div style="font-size:11px;color:var(--text-muted);">${esc(p.os_pretty_name)}</div></td>
                <td style="padding:6px;">${yes(p.docker, 'Docker', esc(p.docker_detail))}</td>
                <td style="padding:6px;">${yes(!!p.wolfnet_ip, esc(p.wolfnet_ip || ''), 'no WolfNet')}</td>
                <td style="padding:6px;">${p.port_conflicts.length ? `<span style="color:var(--danger);" title="${esc(p.port_conflicts.join('\n'))}">✗ port in use</span>` : '<span style="color:var(--success);">✓ ports free</span>'}</td>
                <td style="padding:6px;">${p.ntp_synchronized === false ? '<span style="color:var(--warning,#f59e0b);" title="Run: timedatectl set-ntp true">⚠ clock not synced</span>' : '<span style="color:var(--success);">✓ clock</span>'}</td>
                <td style="padding:6px;">${p.outbound_smtp === false ? `<span style="color:var(--warning,#f59e0b);" title="${esc(p.outbound_smtp_detail)}">⚠ port 25 blocked</span>` : (p.outbound_smtp ? '<span style="color:var(--success);">✓ port 25</span>' : '<span style="color:var(--text-muted);">? port 25</span>')}</td></tr>`;
        }).join('');
        const unreach = ids.map(check).filter(c => c && c.ok && (c.wolfnet_unreachable || []).length);
        const blocked = ids.map(check).filter(c => c && c.ok && c.report.outbound_smtp === false);
        return `<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:12px;">${rows}</table></div>
            ${unreach.length ? `<p role="alert" style="font-size:12px;color:var(--danger);">✗ ${unreach.map(c => `${esc(c.label)} can't reach ${c.wolfnet_unreachable.map(esc).join(', ')}`).join('; ')} over WolfNet. The mail servers talk to each other over WolfNet — check the WolfNet peering between them (Networking → WolfNet) and check again.</p>` : ''}
            ${blocked.length ? `<p style="font-size:12px;color:var(--warning,#f59e0b);">⚠ Outgoing port 25 is blocked on ${blocked.map(c => esc(c.label)).join(', ')}: those servers can receive mail but not deliver it to other domains until your provider unblocks it.</p>` : ''}`;
    }

    function coordinationStep() {
        const d = wiz.data;
        if (d.nodes.length < 2) return '<p style="font-size:13px;margin-top:0;">One mail server needs no coordination service. Press Next.</p>';
        const ids = coordIds();
        const all = nodes().filter(n => (n.cluster_name || 'WolfStack') === ((byStable(d.nodes[0]) || {}).cluster_name || 'WolfStack'));
        const old = ids.map(check).filter(c => c && c.ok && !c.report.kernel_ok_for_keep);
        const unchecked = ids.filter(id => !check(id));
        const kernelBlock = old.length ? `
            <div role="alert" style="border-left:3px solid var(--warning,#f59e0b);padding:10px 14px;background:var(--bg-input);margin:12px 0;font-size:13px;">
                <strong>Stalwart Keep needs Linux kernel 6.12 or newer.</strong> These servers are older:
                <ul style="margin:6px 0 0;padding-left:18px;">
                ${old.map(c => {
                    const g = c.report.kernel_guidance || {};
                    return `<li style="margin-bottom:8px;"><strong>${esc(c.label)}</strong> — kernel ${esc(c.report.kernel)} (${esc(c.report.os_pretty_name)})
                        <div style="font-size:12px;margin-top:4px;">${esc(g.summary || '')}</div>
                        ${(g.commands || []).length ? `<pre style="font-size:11px;background:var(--bg-primary);padding:6px 8px;border-radius:6px;white-space:pre-wrap;margin:4px 0;">${(g.commands || []).map(esc).join('\n')}</pre>` : ''}
                        ${(g.notes || []).map(x => `<div style="font-size:11px;color:var(--text-muted);">• ${esc(x)}</div>`).join('')}
                        ${g.source ? `<div style="font-size:11px;"><a href="${esc(g.source)}" target="_blank" rel="noopener">Source</a></div>` : ''}</li>`;
                }).join('')}
                </ul>
                <div style="font-size:12px;margin-top:6px;">Upgrade and reboot them, then <button type="button" class="btn btn-sm" onclick="Mail.wizRecheck()">Re-check kernels</button> — or choose Redis below, which works on any kernel. The coordinator is one setting for the whole cluster, so a single old server means upgrading it or using Redis everywhere.</div>
            </div>` : '';
        return `<p style="font-size:13px;margin-top:0;">With more than one mail server, a small coordination service lets them share locks and tell each other about changes.</p>
            <fieldset style="border:none;padding:0;margin:0 0 12px;"><legend style="font-size:12px;color:var(--text-muted);">Coordinator</legend>
                <label style="display:flex;gap:8px;align-items:flex-start;font-size:13px;margin-bottom:6px;"><input type="radio" name="wz-coord" value="keep" ${d.coordinator === 'keep' ? 'checked' : ''} onchange="Mail.wizSetCoord('keep')" style="margin-top:3px;">
                    <span><strong>Stalwart Keep</strong> (recommended) — Stalwart's own fast coordinator. Needs kernel 6.12+.</span></label>
                <label style="display:flex;gap:8px;align-items:flex-start;font-size:13px;"><input type="radio" name="wz-coord" value="redis" ${d.coordinator === 'redis' ? 'checked' : ''} onchange="Mail.wizSetCoord('redis')" style="margin-top:3px;">
                    <span><strong>Redis</strong> (Valkey + Sentinel) — works on any kernel; one more service to run.</span></label>
            </fieldset>
            ${d.coordinator === 'keep' ? kernelBlock : ''}
            ${unchecked.length ? `<p style="font-size:12px;color:var(--text-muted);">Not checked yet: ${unchecked.map(id => esc(nodeLabel(byStable(id) || { id }))).join(', ')} — <button type="button" class="btn btn-sm" onclick="Mail.wizRecheck()">Check now</button></p>` : ''}
            <fieldset style="border:1px solid var(--border);border-radius:8px;padding:8px 12px;"><legend style="font-size:12px;color:var(--text-muted);padding:0 4px;">Servers that run the coordinator</legend>
                <p style="font-size:12px;color:var(--text-muted);margin:0 0 6px;">Use 3 or more to survive one failure — the coordinator needs a majority to keep working, so 2 survive nothing. 1 works, without failover.</p>
                ${all.map(n => `<label style="display:flex;align-items:center;gap:8px;font-size:13px;padding:2px 0;">
                    <input type="checkbox" data-wz-coord-node value="${esc(stableId(n))}" ${ids.includes(stableId(n)) ? 'checked' : ''} ${n.online === false ? 'disabled' : ''} onchange="Mail.wizCoordNodes()"> ${esc(nodeLabel(n))}</label>`).join('')}
                <div style="font-size:12px;margin-top:4px;${ids.length === 2 ? 'color:var(--danger);' : 'color:var(--text-muted);'}" ${ids.length === 2 ? 'role="alert"' : ''}>${ids.length} chosen${ids.length === 2 ? ' — choose 1, or add a third (any small server will do)' : ''}</div>
            </fieldset>`;
    }

    async function runChecks(ids) {
        const host = nodes().find(n => n.is_self) || nodes()[0];
        wizError('');
        const target = wizBox() && wizBox().querySelector('[data-wz-checks]');
        if (target) target.innerHTML = '<p role="status" style="font-size:12px;color:var(--text-muted);">Checking servers… (up to a minute)</p>';
        try {
            const r = await call(host.id, '/api/stalwart/preflight', { method: 'POST', body: { cluster_id: wiz.data.id, nodes: ids } });
            // preflight_nodes answers in request order (install.rs).
            r.forEach((c, i) => {
                c.req_id = ids[i];
                wiz.checks = wiz.checks.filter(x => x.req_id !== c.req_id);
                wiz.checks.push(c);
            });
        } catch (e) { wizError(`Couldn't run the checks: ${e.message}`); }
        renderWizard();
    }

    function readStep() {
        const b = wizBox();
        const d = wiz.data;
        if (wiz.step === 0) {
            d.domain = b.querySelector('#wz-domain').value.trim().toLowerCase();
            d.hostname = b.querySelector('#wz-host').value.trim().toLowerCase() || (d.domain ? `mx.${d.domain}` : '');
            d.name = b.querySelector('#wz-name').value.trim();
            d.id = b.querySelector('#wz-id').value.trim().toLowerCase();
            d.cert = b.querySelector('#wz-cert').checked;
        } else if (wiz.step === 1) {
            const prev = d.nodes.join(',');
            d.nodes = [...b.querySelectorAll('[data-wz-node]:checked')].map(x => x.value);
            if (d.nodes.join(',') !== prev) d.coordNodes = null;
        } else if (wiz.step === 2) {
            const r = b.querySelector('input[name="wz-galera"]:checked');
            d.galera = r ? r.value : '';
        }
    }

    function validateStep() {
        const b = wizBox();
        const d = wiz.data;
        const domRe = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
        if (wiz.step === 0) {
            const ok = [
                setFieldError(b, 'wz-domain', domRe.test(d.domain) ? '' : 'Enter the domain, like example.com'),
                setFieldError(b, 'wz-host', domRe.test(d.hostname) ? '' : 'Enter a full name, like mx.example.com'),
                setFieldError(b, 'wz-id', /^[a-z][a-z0-9-]{0,23}$/.test(d.id) ? '' : 'Start with a letter; lowercase letters, digits and - only'),
                setFieldError(b, 'wz-name', ''),
            ];
            if (state.clusters.some(c => c.id === d.id)) { setFieldError(b, 'wz-id', 'A mail cluster already uses this id'); return false; }
            const first = b.querySelector('[aria-invalid="true"]');
            if (first) first.focus();
            return ok.every(Boolean);
        }
        if (wiz.step === 1) {
            if (!d.nodes.length) return wizError('Choose at least one server.'), false;
            const clusters = new Set(d.nodes.map(id => (byStable(id) || {}).cluster_name || 'WolfStack'));
            if (clusters.size > 1) return wizError('All mail servers must be in the same WolfStack cluster — they talk over its WolfNet.'), false;
            const missing = d.nodes.filter(id => !check(id));
            if (missing.length) return wizError('Press "Check these servers" first.'), false;
            const bad = d.nodes.map(check).filter(c => !c.ok || !c.report.docker || !c.report.wolfnet_ip || c.report.port_conflicts.length || (c.wolfnet_unreachable || []).length);
            if (bad.length) return wizError(`Fix these first:\n${bad.map(c => `${c.label}: ${c.ok ? [!c.report.docker && c.report.docker_detail, !c.report.wolfnet_ip && 'WolfNet not running', (c.wolfnet_unreachable || []).length && `can't reach ${c.wolfnet_unreachable.join(', ')} over WolfNet`, ...c.report.port_conflicts].filter(Boolean).join('; ') : c.error}`).join('\n')}`), false;
            return true;
        }
        if (wiz.step === 2) {
            if (!d.galera) return wizError('Choose to create a new Galera cluster, or an existing one with a MaxScale proxy.'), false;
            return true;
        }
        if (wiz.step === 3 && d.nodes.length > 1) {
            const ids = coordIds();
            if (ids.length === 0 || ids.length === 2) return wizError('Choose 1 coordinator server, or 3 or more.'), false;
            if (ids.some(id => !check(id))) return wizError('Some coordinator servers haven\'t been checked — press "Check now".'), false;
            if (d.coordinator === 'keep') {
                const old = [...new Set([...d.nodes, ...ids])].map(check).filter(c => c && c.ok && !c.report.kernel_ok_for_keep);
                if (old.length) return wizError('Some servers are below kernel 6.12. Upgrade them and re-check, or choose Redis.'), false;
            }
            const busy = ids.map(check).filter(c => c.ok && c.report.coordinator_port_conflicts.length);
            if (busy.length) return wizError(`Coordinator ports are in use on: ${busy.map(c => `${c.label} (${c.report.coordinator_port_conflicts.join('; ')})`).join(', ')}`), false;
        }
        return true;
    }

    async function wizNext() {
        readStep();
        if (!validateStep()) return;
        if (wiz.step < 4) { wiz.step++; renderWizard(); return; }
        // Install — runs on the Galera cluster's home node, which holds the
        // database credentials the install needs.
        const d = wiz.data;
        // A new Galera cluster is owned by the node the install runs on — the
        // first mail server; an existing one by its home node.
        const firstMail = byStable(d.nodes[0]);
        const [via, galeraId] = d.galera === 'new' ? [firstMail ? firstMail.id : '', ''] : d.galera.split('|');
        const body = {
            id: d.id, name: d.name || d.id, public_hostname: d.hostname, default_domain: d.domain,
            galera_cluster_id: galeraId, mail_nodes: d.nodes,
            coordinator: d.nodes.length > 1 ? d.coordinator : '',
            coordinator_nodes: d.nodes.length > 1 ? coordIds() : [],
            request_tls_certificate: d.cert,
            cluster: (byStable(d.nodes[0]) || {}).cluster_name || '',
        };
        if (d.galera === 'new') body.new_galera = { hosts: d.nodes };
        wiz.dialog.close();
        const ok = await streamJob(`Installing ${body.name}`, via, '/api/stalwart/install', body);
        await loadClusters();
        state.selected = body.id;
        state.tab = ok ? 'domains' : 'settings';
        render();
    }

    function wizBack() { readStep(); if (wiz.step > 0) { wiz.step--; renderWizard(); } }

    // ─── Exports (inline handlers) ───────────────────────────────────

    window.mailInit = init;
    window.Mail = {
        openWizard,
        wizNext,
        wizBack,
        wizCheck: () => { readStep(); runChecks(wiz.data.nodes); },
        wizRecheck: () => runChecks([...new Set([...wiz.data.nodes, ...coordIds()])]),
        wizSetCoord: (v) => { wiz.data.coordinator = v; renderWizard(); },
        wizCoordNodes: () => { wiz.data.coordNodes = [...wizBox().querySelectorAll('[data-wz-coord-node]:checked')].map(x => x.value); renderWizard(); },
        select: (id) => { state.selected = id; state.tab = 'domains'; render(); },
        tab: (t) => { state.tab = t; render(); },
        currentTab: () => state.tab,
        addDomain,
        deleteDomain,
        showDns: (id) => { state.domainSel = id; state.tab = 'dns'; render(); },
        pickDomainForMailboxes: (id) => { state.domainSel = id; loadTab(); },
        pickDomainForDns: (id) => { state.domainSel = id; loadTab(); },
        copyDns: (i) => { const r = (state.dnsRecords || [])[i]; if (r) copyText(r.value, `${r.type} record value`); },
        copyZone: () => copyText(state.dnsZone || '', 'Zone file'),
        newAccount,
        accountAction,
        revealAdmin,
        removeCluster,
        retry: retryInstall,
    };

    // A deep link (#mail) selects the page before this file has loaded, when
    // selectView's `typeof mailInit` check still fails — start now instead.
    const page = document.getElementById('page-mail');
    if (page && page.style.display !== 'none') init();
})();
