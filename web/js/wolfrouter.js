// WolfRouter frontend — table views + rack view.
// Written by Paul Clevett / IntelligentWolf Ltd

(function () {
    'use strict';

    // ─── Styles (injected once) ───
    const css = `
    .wr-tab {
        padding: 6px 14px; background: transparent; color: var(--text-muted);
        border: none; border-bottom: 2px solid transparent; cursor: pointer;
        font-size: 13px; font-weight: 500; transition: all 0.15s;
    }
    .wr-tab:hover { color: var(--text); }
    .wr-tab.active {
        color: var(--primary, #a855f7);
        border-bottom-color: var(--primary, #a855f7);
    }
    .wr-tab-panel { min-height: 280px; }
    .wr-port {
        transition: filter 0.15s ease-out;
        cursor: pointer;
    }
    .wr-port:hover { filter: brightness(1.4); }
    .wr-wire { stroke-linecap: round; fill: none; pointer-events: none; }
    .wr-wire-active {
        stroke-dasharray: 8 6;
        animation: wr-flow 1s linear infinite;
    }
    @keyframes wr-flow { to { stroke-dashoffset: -14; } }
    .wr-rack-unit {
        fill: var(--bg-card, #1e293b);
        stroke: var(--border, #334155);
        stroke-width: 1.5;
    }
    .wr-node-name {
        fill: var(--text, #f1f5f9);
        font-family: system-ui, sans-serif;
        font-size: 13px;
        font-weight: 600;
    }
    .wr-port-label {
        fill: var(--text-muted, #94a3b8);
        font-family: var(--font-mono, monospace);
        font-size: 9px;
        text-anchor: middle;
        pointer-events: none;
    }
    .wr-device-badge {
        fill: var(--bg-secondary, #0f172a);
        stroke: var(--border, #334155);
        stroke-width: 1;
    }
    .wr-device-text {
        fill: var(--text, #f1f5f9);
        font-family: system-ui, sans-serif;
        font-size: 11px;
    }
    .wr-cloud {
        fill: url(#wr-cloud-grad);
        stroke: var(--border, #334155);
        stroke-width: 1;
    }
    `;
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);

    // ─── State ───
    let wrState = {
        view: 'rack',          // 'rack' | 'table'
        activeTab: 'firewall', // firewall | lans | leases | zones | connections | logs
        cluster: null,         // active cluster name — scopes every fetch (cluster view)
        nodeCluster: null,     // per-host view: that node's own cluster name, sent
                               // through the proxy so the node answers exactly as
                               // its own WolfRouter UI would
        topology: null,
        rules: [],
        lans: [],
        proxies: [],
        zones: { assignments: {} },
        rollbackTimerInterval: null,
        rollbackDeadline: null,
        pollInterval: null,
    };

    // Builds an /api/router/* URL for the active scope. Scope is read
    // from wrState only — never from the global currentNodeId, which
    // is a lexical `let` in app.js (not window.currentNodeId) and can
    // be stale here. Pass {local:true} for node-local endpoints that
    // carry no cluster context (recovery, http-proxy ops).
    function wrUrl(path, opts) {
        const local = !!(opts && opts.local);
        // Cluster view — filter by the active cluster name. Unchanged.
        if (wrState.cluster) {
            if (local) return path;
            const sep = path.includes('?') ? '&' : '?';
            return path + sep + 'cluster=' + encodeURIComponent(wrState.cluster);
        }
        // Per-host view — showWolfRouterForNode set nodeCluster, and
        // selectServerView set currentNodeId. Proxy the call to that
        // node via apiUrl(); for non-local endpoints carry the node's
        // own cluster name so it answers exactly as its own WolfRouter
        // UI would. node_proxy forwards the query string, so ?cluster=
        // survives the hop.
        if (wrState.nodeCluster) {
            let p = path;
            if (!local) {
                const sep = path.includes('?') ? '&' : '?';
                p = path + sep + 'cluster=' + encodeURIComponent(wrState.nodeCluster);
            }
            return (typeof apiUrl === 'function') ? apiUrl(p) : p;
        }
        return path;
    }

    // ─── Recovery banner ───
    //
    // When startup load failed and saves are blocked, render a
    // bright dismissible-but-pinned banner at the top of the
    // WolfRouter page with: (a) the parse error verbatim,
    // (b) every available rollback snapshot with one-click restore,
    // (c) a "Reconstruct from artefacts" button when nothing
    // restorable exists. The user gets out of the recovery state
    // without leaving the WolfRouter page or touching a CLI.

    async function wrFetchRecoveryState() {
        try {
            const r = await fetch(wrUrl('/api/router/recovery', {local:true}));
            if (!r.ok) return null;
            return await r.json();
        } catch (_) { return null; }
    }

    function wrRenderRecoveryBanner(rec) {
        const host = document.getElementById('page-wolfrouter');
        if (!host) return;
        // Idempotent: replace any existing banner so re-fetches don't pile up.
        let bar = document.getElementById('wr-recovery-banner');
        if (!bar) {
            bar = document.createElement('div');
            bar.id = 'wr-recovery-banner';
            host.insertBefore(bar, host.firstChild);
        }
        const err = (rec.load_error && rec.load_error.error) || 'config.json failed to load';
        const quarantine = (rec.load_error && rec.load_error.quarantine_path) || '';
        const snaps = Array.isArray(rec.snapshots) ? rec.snapshots : [];
        const reconAvail = !!rec.artifact_reconstruction_available;

        const snapRows = snaps.map(s => {
            const ageS = Math.max(0, Math.floor(Date.now() / 1000 - (s.timestamp || 0)));
            const ageStr = ageS < 60 ? `${ageS}s ago`
                : ageS < 3600 ? `${Math.floor(ageS/60)}m ago`
                : ageS < 86400 ? `${Math.floor(ageS/3600)}h ago`
                : `${Math.floor(ageS/86400)}d ago`;
            const kindBadge = s.kind === 'broken'
                ? '<span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;">QUARANTINED</span>'
                : '<span style="background:#16a34a;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;">BACKUP</span>';
            const parsesBadge = s.parses
                ? '<span style="color:#16a34a;font-size:11px;">parses</span>'
                : '<span style="color:#dc2626;font-size:11px;font-weight:600;">does NOT parse with this build</span>';
            const safePath = String(s.path || '').replace(/'/g, "\\'");
            return `
                <tr>
                    <td style="padding:6px 10px;">${kindBadge}</td>
                    <td style="padding:6px 10px;font-family:monospace;font-size:12px;">${escapeHtml(s.path || '')}</td>
                    <td style="padding:6px 10px;font-size:12px;color:#555;">${ageStr}</td>
                    <td style="padding:6px 10px;font-size:12px;color:#555;">${(s.size_bytes||0).toLocaleString()} B</td>
                    <td style="padding:6px 10px;">${parsesBadge}</td>
                    <td style="padding:6px 10px;">
                        <button class="btn btn-sm btn-primary"
                                onclick="wrRestoreSnapshot('${safePath}')">
                            Restore this
                        </button>
                    </td>
                </tr>`;
        }).join('');

        const noSnapsBlock = snaps.length === 0
            ? `<div style="padding:12px;background:#fee2e2;border-radius:4px;margin:12px 0;color:#7f1d1d;">
                  <strong>No rollback snapshots are available.</strong>
                  This usually means the wipe happened on a build that
                  did not yet keep rolling backups (anything before this
                  fix). Use <em>Reconstruct from artefacts</em> below to
                  rebuild what's recoverable from the dnsmasq snippets
                  and PPPoE peer files that survive on disk independently.
               </div>`
            : '';

        const reconBlock = `
            <div style="margin-top:14px;padding:12px;background:#fef3c7;border-radius:4px;border:1px solid #fbbf24;">
                <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
                    <div>
                        <strong>Reconstruct from system artefacts</strong>
                        <div style="font-size:12px;color:#78350f;margin-top:4px;">
                            Rebuild a best-effort config.json from the dnsmasq
                            snippets in /etc/wolfstack/router/dnsmasq.d/ and the
                            PPPoE peer files in /etc/ppp/peers/. Firewall rules,
                            zones, proxies, and subnet routes can NOT be
                            reconstructed — those will need to be re-entered.
                            ${reconAvail ? '' : '<br>(No artefacts found — nothing to reconstruct.)'}
                        </div>
                    </div>
                    <button class="btn btn-sm ${reconAvail ? 'btn-primary' : 'btn-disabled'}"
                            ${reconAvail ? '' : 'disabled'}
                            onclick="wrPreviewReconstruction()">
                        Preview reconstruction
                    </button>
                </div>
            </div>`;

        bar.innerHTML = `
            <div style="background:#fef2f2;border:2px solid #dc2626;border-radius:6px;padding:16px 20px;margin:0 0 16px 0;">
                <div style="display:flex;align-items:flex-start;gap:12px;">
                    <span style="font-size:24px;line-height:1;"></span>
                    <div style="flex:1;">
                        <div style="font-size:16px;font-weight:700;color:#991b1b;">
                            WolfRouter is in recovery mode — config.json failed to load
                        </div>
                        <div style="font-size:13px;color:#7f1d1d;margin-top:4px;">
                            Your saved WolfRouter configuration could not be
                            parsed at startup. Saves are <strong>blocked</strong>
                            so the unparseable file will not be overwritten.
                            Pick a snapshot below to roll back, or reconstruct
                            from on-disk artefacts.
                        </div>
                        <details style="margin-top:8px;">
                            <summary style="cursor:pointer;color:#7f1d1d;font-size:12px;">
                                Parser error
                            </summary>
                            <pre style="background:#fff;border:1px solid #fecaca;padding:8px;border-radius:4px;font-size:11px;color:#7f1d1d;white-space:pre-wrap;margin-top:6px;">${escapeHtml(err)}</pre>
                            ${quarantine ? `<div style="font-size:11px;color:#7f1d1d;margin-top:4px;">
                                Original file copied to <code>${escapeHtml(quarantine)}</code> for inspection.
                            </div>` : ''}
                        </details>
                        ${noSnapsBlock}
                        ${snaps.length > 0 ? `
                            <div style="margin-top:12px;">
                                <div style="font-weight:600;color:#7f1d1d;margin-bottom:6px;">Available snapshots (newest first):</div>
                                <table style="width:100%;background:#fff;border-radius:4px;border-collapse:collapse;">
                                    <thead>
                                        <tr style="background:#f9fafb;font-size:11px;text-transform:uppercase;color:#6b7280;">
                                            <th style="padding:6px 10px;text-align:left;">Kind</th>
                                            <th style="padding:6px 10px;text-align:left;">Path</th>
                                            <th style="padding:6px 10px;text-align:left;">Age</th>
                                            <th style="padding:6px 10px;text-align:left;">Size</th>
                                            <th style="padding:6px 10px;text-align:left;">Parseable</th>
                                            <th style="padding:6px 10px;"></th>
                                        </tr>
                                    </thead>
                                    <tbody>${snapRows}</tbody>
                                </table>
                            </div>
                        ` : ''}
                        ${reconBlock}
                    </div>
                </div>
            </div>`;
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // Soft (non-blocking) banner shown when the backend auto-recovered
    // config.json from a `.bak.<ts>` snapshot at startup. v24.7.9
    // sponsor klasSponsor's 14-node cluster hit a torn write that
    // corrupted every node's config.json simultaneously; v24.7.8
    // prevented future torn writes but did nothing for the already-
    // corrupted state. With this banner, the operator audits and
    // dismisses — no per-node manual rollback. Dismiss POSTs to
    // /api/router/recovery/acknowledge-auto.
    function wrRenderAutoRecoveryBanner(rec) {
        const host = document.getElementById('page-wolfrouter');
        if (!host) return;
        const note = rec && rec.auto_recovery;
        let bar = document.getElementById('wr-auto-recovery-banner');
        if (!note) {
            // Notice was cleared (or never present) — drop any stale banner.
            if (bar) bar.remove();
            return;
        }
        if (!bar) {
            bar = document.createElement('div');
            bar.id = 'wr-auto-recovery-banner';
            host.insertBefore(bar, host.firstChild);
        }
        const ts = Number(note.from_timestamp || 0);
        const when = ts > 0 ? new Date(ts * 1000).toLocaleString() : 'unknown';
        const err = note.parse_error || '';
        const fromBak = note.from_backup || '';
        const broken = note.broken_quarantine || '';
        bar.innerHTML = `
            <div style="background:#fffbeb;border:2px solid #f59e0b;border-radius:6px;padding:14px 18px;margin:0 0 16px 0;">
                <div style="display:flex;align-items:flex-start;gap:12px;">
                    <div style="flex:1;">
                        <div style="font-size:15px;font-weight:700;color:#92400e;">
                            WolfRouter auto-recovered config.json from a backup at startup
                        </div>
                        <div style="font-size:13px;color:#78350f;margin-top:4px;">
                            The live <code>config.json</code> failed to parse, so
                            the most recent backup that did parse was promoted
                            into place automatically. Review the LANs / WANs /
                            zones / rules below and confirm they match what you
                            expected — then dismiss this banner.
                        </div>
                        <div style="font-size:12px;color:#78350f;margin-top:8px;">
                            <div>Backup adopted: <code>${escapeHtml(fromBak)}</code> (taken ${escapeHtml(when)})</div>
                            ${broken ? `<div style="margin-top:2px;">Broken file preserved at: <code>${escapeHtml(broken)}</code></div>` : ''}
                        </div>
                        <details style="margin-top:8px;">
                            <summary style="cursor:pointer;color:#78350f;font-size:12px;">
                                Original parser error
                            </summary>
                            <pre style="background:#fff;border:1px solid #fde68a;padding:8px;border-radius:4px;font-size:11px;color:#78350f;white-space:pre-wrap;margin-top:6px;">${escapeHtml(err)}</pre>
                        </details>
                        <div style="margin-top:10px;display:flex;gap:8px;">
                            <button class="btn btn-sm btn-primary"
                                    onclick="wrAcknowledgeAutoRecovery()">
                                Dismiss — config looks correct
                            </button>
                        </div>
                    </div>
                </div>
            </div>`;
    }

    async function wrAcknowledgeAutoRecovery() {
        try {
            await fetch(wrUrl('/api/router/recovery/acknowledge-auto', {local:true}), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
        } catch (_) {
            // Best-effort: even if the POST fails, drop the local banner so
            // the operator isn't stuck looking at it. Reloading the page
            // will resurface it from the backend.
        }
        const bar = document.getElementById('wr-auto-recovery-banner');
        if (bar) bar.remove();
    }
    window.wrAcknowledgeAutoRecovery = wrAcknowledgeAutoRecovery;

    async function wrRestoreSnapshot(path) {
        if (!confirm(`Restore this snapshot?\n\n${path}\n\nThe currently-live config.json will be saved to a fresh .bak.<ts> first so this rollback is itself reversible.`)) {
            return;
        }
        try {
            const r = await fetch(wrUrl('/api/router/recovery/restore', {local:true}), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path }),
            });
            const data = await r.json();
            if (data.ok) {
                alert(data.message || 'Restored.');
                // Reload the WolfRouter page so the rack picks up the
                // restored config.
                if (wrState && wrState.cluster) {
                    showWolfRouterForCluster(wrState.cluster);
                } else {
                    window.location.reload();
                }
            } else {
                alert('Restore failed: ' + (data.message || 'unknown error'));
            }
        } catch (e) {
            alert('Restore request failed: ' + (e && e.message ? e.message : e));
        }
    }
    window.wrRestoreSnapshot = wrRestoreSnapshot;

    async function wrPreviewReconstruction() {
        try {
            const r = await fetch(wrUrl('/api/router/recovery/reconstruct', {local:true}));
            if (!r.ok) {
                alert('Could not load reconstruction preview.');
                return;
            }
            const recon = await r.json();
            const items = (recon.recovered_items || []).map(s => `  • ${s}`).join('\n')
                       || '  (nothing recoverable)';
            const notes = (recon.notes || []).map(s => `  • ${s}`).join('\n');
            const proceed = confirm(
                `Artefact reconstruction preview:\n\n` +
                `RECOVERED ITEMS:\n${items}\n\n` +
                `IMPORTANT NOTES:\n${notes}\n\n` +
                `Click OK to commit this reconstruction as your new config.json. ` +
                `The currently-live file (if any) is rotated to a .bak.<ts> first.`
            );
            if (!proceed) return;
            const c = await fetch(wrUrl('/api/router/recovery/reconstruct', {local:true}), { method: 'POST' });
            if (c.ok) {
                alert('Reconstruction committed. Reloading WolfRouter…');
                if (wrState && wrState.cluster) {
                    showWolfRouterForCluster(wrState.cluster);
                } else {
                    window.location.reload();
                }
            } else {
                const err = await c.json().catch(() => ({}));
                alert('Commit failed: ' + (err.error || c.statusText));
            }
        } catch (e) {
            alert('Reconstruction request failed: ' + (e && e.message ? e.message : e));
        }
    }
    window.wrPreviewReconstruction = wrPreviewReconstruction;

    // Expose hooks the HTML and app.js call directly.
    // wrState is exposed so the Threat Intel tab (rendered from app.js)
    // can read the active cluster name and pass it as ?cluster= when
    // calling /api/threat-intel/cluster-status. Without this, the
    // status table leaks every node from every cluster a bastion
    // manages into every cluster's view.
    window.wrState = wrState;
    window.wrLoadAll = wrLoadAll;
    window.wrStartPolling = wrStartPolling;
    window.showWolfRouterForCluster = showWolfRouterForCluster;
    window.showWolfRouterForNode = showWolfRouterForNode;
    window.wrClearDiagnosticsPanel = () => wrClearDiagnosticsPanel();
    window.wrSwitchView = wrSwitchView;
    window.wrSelectTab = wrSelectTab;
    window.wrShowRuleEditor = wrShowRuleEditor;
    window.wrShowLanEditor = wrShowLanEditor;
    window.wrTestRules = wrTestRules;
    window.wrConfirmRules = wrConfirmRules;
    window.wrDeleteRule = wrDeleteRule;
    window.wrDeleteLan = wrDeleteLan;
    window.wrToggleRule = wrToggleRule;
    window.wrSaveRule = wrSaveRule;
    window.wrSaveLan = wrSaveLan;
    window.wrAssignZone = wrAssignZone;
    window.wrShowProxyEditor = wrShowProxyEditor;
    window.wrSaveProxy = wrSaveProxy;
    window.wrDeleteProxy = wrDeleteProxy;
    window.wrToggleProxy = wrToggleProxy;
    window.wrProxyBackendKindChanged = wrProxyBackendKindChanged;
    window.wrProxyAddBackend = wrProxyAddBackend;
    window.wrProxyRemoveBackend = wrProxyRemoveBackend;

    // Hook into the existing networking page loader so WolfRouter
    // kicks in whenever the page is shown.
    const origLoadNetworking = window.loadNetworking;
    window.loadNetworking = async function (...args) {
        if (typeof origLoadNetworking === 'function') {
            try { await origLoadNetworking.apply(this, args); } catch (e) {}
        }
        await wrLoadAll();
        wrStartPolling();
    };

    // ─── Data loading ───

    // Entry point used by the cluster-scoped sidebar item. Sets the
    // active cluster, switches the page, then loads.
    async function showWolfRouterForCluster(clusterName) {
        if (typeof closeSidebarMobile === 'function') closeSidebarMobile();
        const previousCluster = wrState.cluster;
        wrState.cluster = clusterName;
        if (typeof currentPage !== 'undefined') window.currentPage = 'wolfrouter-cluster';
        if (typeof currentNodeId !== 'undefined') window.currentNodeId = null;

        document.querySelectorAll('.page-view').forEach(p => p.style.display = 'none');
        const el = document.getElementById('page-wolfrouter');
        if (el) el.style.display = 'block';

        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const item = document.querySelector(`.wolfrouter-cluster-item[data-cluster="${clusterName}"]`);
        if (item) item.classList.add('active');

        const titleEl = document.getElementById('page-title');
        if (titleEl) titleEl.textContent = `WolfRouter — ${clusterName}`;

        // When switching between clusters, the previous cluster's topology
        // lingers on screen until the new fetch returns — confusing,
        // because the rack view keeps showing the wrong nodes. Clear
        // state and show a loading shim so it's unambiguous that a
        // switch is in flight.
        if (previousCluster && previousCluster !== clusterName) {
            wrState.topology = null;
            wrState.lans = [];
            wrState.rules = [];
            wrState.proxies = [];
            wrState.zones = { assignments: {} };
            wrState.wan = [];
            wrState.lastRackHash = '';  // force a full re-render once data arrives
        }
        wrShowClusterLoading(clusterName);

        try {
            // Recovery banner runs FIRST and supersedes everything
            // else when the on-disk config failed to load. The banner
            // surfaces the rollback snapshot list and the artefact
            // reconstruction button — without it the page would just
            // render a blank rack and the user would have no idea
            // why their LANs / WANs / rules vanished. See
            // /api/router/recovery (backend gates persistence on the
            // same load_failed flag).
            const rec = await wrFetchRecoveryState();
            if (rec && rec.load_failed) {
                wrRenderRecoveryBanner(rec);
                // Still load topology underneath so the user sees
                // the live rack — but every save endpoint returns an
                // error until they pick a snapshot, so we leave the
                // banner pinned to the top of the page.
            } else if (rec && rec.auto_recovery) {
                // Soft self-heal banner — saves are allowed; the
                // operator just needs to audit and dismiss.
                wrRenderAutoRecoveryBanner(rec);
            }
            wrClearDiagnosticsPanel();
            const pf = await wrRunPreflight();
            await wrLoadAll();
            if (pf && pf.status === 'error') {
                wrRenderPreflight(pf, clusterName);
            } else if (pf && pf.status === 'warning') {
                wrRenderPreflightBanner(pf);
            }
        } finally {
            wrHideClusterLoading();
        }
        wrStartPolling();
    }

    // Per-host WolfRouter — opened from a host node via
    // selectServerView('<node>', 'wolfrouter'), which has already set
    // currentNodeId, shown #page-wolfrouter, highlighted the tree item
    // and set the page title. wrUrl() keys off currentNodeId, so every
    // /api/router/* call is proxied to this node with its own cluster
    // name — the node answers exactly as its own WolfRouter UI would.
    async function showWolfRouterForNode(nodeId, hostname, clusterName) {
        if (typeof closeSidebarMobile === 'function') closeSidebarMobile();
        wrState.cluster = null;
        wrState.nodeCluster = clusterName || 'WolfStack';
        // Drop stale topology so the rack doesn't flash the wrong
        // nodes before this host's data lands.
        wrState.topology = null;
        wrState.lans = [];
        wrState.rules = [];
        wrState.proxies = [];
        wrState.zones = { assignments: {} };
        wrState.wan = [];
        wrState.lastRackHash = '';
        const label = hostname || nodeId;
        try {
            const rec = await wrFetchRecoveryState();
            if (rec && rec.load_failed) wrRenderRecoveryBanner(rec);
            else if (rec && rec.auto_recovery) wrRenderAutoRecoveryBanner(rec);
            wrClearDiagnosticsPanel();
            const pf = await wrRunPreflight();
            await wrLoadAll();
            if (pf && pf.status === 'error') wrRenderPreflight(pf, label);
            else if (pf && pf.status === 'warning') wrRenderPreflightBanner(pf);
        } catch (e) { /* wrLoadAll renders its own fetch-failure UI */ }
        wrStartPolling();
    }

    // ─── Preflight ───

    // Call /api/router/preflight. Returns null if the request itself
    // failed so the caller can fall through to the normal load path
    // (the preflight endpoint being unreachable isn't a reason to
    // block the page — wrLoadAll handles its own errors and the
    // per-endpoint fetch-report already exists).
    async function wrRunPreflight() {
        // Fetch local + cluster preflight in parallel. The cluster
        // variant fans out to every node — that's the user's "check
        // every node in the cluster that WolfRouter is on" ask. If
        // any peer reports errors/warnings, we lift them into the
        // local checks list with a `[<node_id>] ` prefix on the name
        // so the existing renderer surfaces them — no new UI needed
        // for the cluster fan-out.
        const [localRes, clusterRes] = await Promise.allSettled([
            fetch(wrUrl('/api/router/preflight')),
            fetch(wrUrl('/api/router/preflight-cluster')),
        ]);
        let local = null;
        try {
            if (localRes.status === 'fulfilled' && localRes.value.ok) {
                local = await localRes.value.json();
            }
        } catch (e) {}
        if (!local) {
            // Local fetch failed entirely — fall through; caller treats
            // null as "skip preflight gating".
            return null;
        }
        local.actions = local.actions || {};
        local.checks  = local.checks || [];
        try {
            if (clusterRes.status === 'fulfilled' && clusterRes.value.ok) {
                const data = await clusterRes.value.json();
                const peers = (data && Array.isArray(data.nodes)) ? data.nodes : [];
                for (const peer of peers) {
                    if (peer.is_self) continue; // already in `local`
                    if (peer.error) {
                        local.checks.push({
                            id: 'peer_' + (peer.node_id || 'unknown'),
                            name: 'Peer ' + (peer.node_id || 'unknown'),
                            ok: false,
                            severity: 'warning',
                            message: 'Could not fetch this node\'s preflight: ' + (peer.error || 'unknown error') + '. The node may be offline or its API unreachable. Configs on this node have NOT been validated this run.',
                        });
                        continue;
                    }
                    const pf = peer.preflight || {};
                    const pchecks = pf.checks || [];
                    const pactions = pf.actions || {};
                    for (const c of pchecks) {
                        if (c.ok) continue; // skip ok rows from peers
                        const tag = '[' + (peer.node_id || '') + (peer.cluster_name ? ' / ' + peer.cluster_name : '') + ']';
                        const newId = 'peer_' + peer.node_id + '_' + c.id;
                        local.checks.push({
                            id: newId,
                            name: tag + ' ' + c.name,
                            ok: c.ok,
                            severity: c.severity,
                            message: c.message,
                            fix: c.fix,
                        });
                        // Re-key the action under the new id so the UI
                        // wires up its Fix button to the same handler.
                        // Note: action URL still points at the local
                        // node's API surface — the fix endpoints proxy
                        // cross-node where it matters (set-interface,
                        // wan/{id}/reapply, tick-pppoe-default-route).
                        // A few (enable-ip-forward,
                        // purge-self-loop-routes, dhclient) DON'T
                        // proxy and would land on the wrong host —
                        // strip those so we don't fix the wrong box.
                        const a = pactions[c.id];
                        const isLocalOnlyHostFix = a && (
                            a.url === '/api/router/fix/enable-ip-forward' ||
                            a.url === '/api/router/fix/purge-self-loop-routes' ||
                            a.url === '/api/router/fix/dhclient'
                        );
                        if (a && !isLocalOnlyHostFix) {
                            local.actions[newId] = a;
                        }
                    }
                }
                // Recompute aggregate status if peer rows pushed it.
                const hasError = local.checks.some(c => !c.ok && c.severity === 'error');
                const hasWarn  = local.checks.some(c => !c.ok && c.severity === 'warning');
                local.status = hasError ? 'error' : (hasWarn ? 'warning' : 'ok');
                local.ok = !hasError;
            }
        } catch (e) {
            console.warn('cluster preflight fan-out failed', e);
        }
        return local;
    }

    // Diagnostic panel shown in the canvas when one or more preflight
    // checks failed with severity=error. Blocks the normal load path.
    // Renders preflight output (error or warning) into the diagnostics
    // panel underneath the rack canvas — never into the canvas itself.
    // Keeping the rack visible even when preflight says "broken" means
    // the user can still see whatever topology data DID come back, which
    // is the usual case for the domain-name-based clusters this UI gets
    // used to triage: the rack mostly works, but ONE peer failed and
    // they want to know why without losing the diagram.
    function wrRenderPreflight(pf, clusterName) {
        const safeName = (clusterName || '').replace(/'/g, "\\'");
        wrShowDiagnosticsPanel({
            severity: 'error',
            title: 'WolfRouter preflight found blocking issues',
            subtitle: `Cluster: <code>${escHtml(clusterName || '')}</code>. Items marked must be fixed before the rack view can render reliably; the diagram above shows whatever topology data is currently reachable.`,
            checks: pf.checks || [],
            checkActions: pf.actions || {},
            actions: `
                <button onclick="(async () => { wrClearDiagnosticsPanel(); const pf = await (window.wrRunPreflight ? window.wrRunPreflight() : null); await wrLoadAll(); if (pf && pf.status === 'error') { wrRenderPreflight(pf, '${safeName}'); } else if (pf && pf.status === 'warning') { wrRenderPreflightBanner(pf); } })()" class="btn btn-primary btn-sm">Re-run preflight</button>
            `,
        });
        // Make the functions reachable by inline buttons.
        window.wrRunPreflight = wrRunPreflight;
        window.wrRenderPreflight = wrRenderPreflight;
        window.wrRenderPreflightBanner = wrRenderPreflightBanner;
        window.wrClearDiagnosticsPanel = wrClearDiagnosticsPanel;
    }

    /// One-click Fix button handler shared by every preflight row + the
    /// LAN Health tab. Confirms (when the action requested it),
    /// POSTs to the action URL, surfaces success/error, then triggers a
    /// re-render so the panel reflects the new state.
    async function wrRunPreflightFix(action) {
        try {
            if (action.confirm && !confirm(action.confirm)) return;
            const r = await fetch(wrUrl(action.url), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(action.body || {}),
            });
            let payload = null;
            try { payload = await r.json(); } catch (e) {}
            if (!r.ok || (payload && payload.success === false)) {
                const msg = (payload && (payload.error || payload.message)) || ('HTTP ' + r.status);
                alert('Fix failed: ' + msg);
                return;
            }
            const ok = (payload && payload.message) || 'Done.';
            alert('' + ok);
            // Re-run whichever panel is currently open: preflight,
            // health, or both. Cheap on a small cluster; the user gets
            // immediate feedback that the issue cleared.
            try {
                const pf = await wrRunPreflight();
                wrClearDiagnosticsPanel();
                if (pf && pf.status === 'error') {
                    wrRenderPreflight(pf, wrState.cluster || '');
                } else if (pf && pf.status === 'warning') {
                    wrRenderPreflightBanner(pf);
                }
            } catch (e) {}
            try { if (typeof wrRenderLanHealth === 'function') await wrRenderLanHealth(); } catch (e) {}
        } catch (e) {
            alert('Fix failed: ' + String(e));
        }
    }
    window.wrRunPreflightFix = wrRunPreflightFix;

    // Shared renderer for the below-rack diagnostics panel. Accepts a
    // severity ('error' | 'warning' | 'info'), a title/subtitle header,
    // a list of preflight `checks`, optional raw `failures` (fetch-fail
    // rows, same shape wrShowFetchReport used to build), and an optional
    // trailing actions row. Multiple calls in one render pass are
    // additive — later blocks append so the user sees preflight + fetch
    // diagnostics together without one wiping the other out.
    function wrShowDiagnosticsPanel({ severity, title, subtitle, checks, failures, actions, replace, checkActions }) {
        const panel = document.getElementById('wr-diagnostics-panel');
        const content = document.getElementById('wr-diagnostics-content');
        if (!panel || !content) return;
        const accent = severity === 'error' ? '#ef4444' : severity === 'warning' ? '#eab308' : '#60a5fa';
        // Per-row Fix actions, keyed by check id, supplied by the
        // backend preflight response. Each entry has {label, url,
        // detail, confirm, body?}. Renders a clickable button under the
        // row's message when present, so the operator doesn't have to
        // copy-paste shell commands.
        const actionMap = checkActions || {};
        const checkRows = (checks || []).map(c => {
            const icon  = c.ok ? '' : (c.severity === 'error' ? '' : c.severity === 'warning' ? '' : 'ℹ️');
            const color = c.ok ? '#10b981' : (c.severity === 'error' ? '#ef4444' : '#eab308');
            const action = (!c.ok && actionMap[c.id]) ? actionMap[c.id] : null;
            const actionBtn = action ? `
                <div style="margin-top:8px;">
                    <button class="btn btn-primary btn-sm" title="${escHtml(action.detail || '')}"
                            onclick='wrRunPreflightFix(${JSON.stringify(action).replace(/'/g, "&#39;")})'>
                        ${escHtml(action.label)}
                    </button>
                </div>` : '';
            return `
                <tr>
                    <td style="padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top; width:220px;">${icon} <strong style="color:${color};">${escHtml(c.name)}</strong></td>
                    <td style="padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top;">
                        <div>${escHtml(c.message || '')}</div>
                        ${c.fix ? `<pre style="margin:8px 0 0 0; padding:8px 10px; background:var(--bg-primary); border:1px solid var(--border); border-radius:4px; font-size:11px; white-space:pre-wrap;">${escHtml(c.fix)}</pre>` : ''}
                        ${actionBtn}
                    </td>
                </tr>`;
        }).join('');
        const failureRows = (failures || []).map(f => `<tr>
            <td style="padding:6px 10px; border-bottom:1px solid var(--border);"><strong>${escHtml(f.ep.label)}</strong></td>
            <td style="padding:6px 10px; border-bottom:1px solid var(--border); font-family:monospace; font-size:11px;">${escHtml(f.ep.url)}</td>
            <td style="padding:6px 10px; border-bottom:1px solid var(--border); color:#ef4444;">${escHtml(f.error)}</td>
            <td style="padding:6px 10px; border-bottom:1px solid var(--border); font-family:monospace; font-size:11px; color:var(--text-muted); max-width:380px; word-break:break-all;">${escHtml(f.detail || '—')}</td>
        </tr>`).join('');

        const block = `
            <div style="margin-bottom:14px; border-left:3px solid ${accent}; padding-left:12px;">
                <div style="color:${accent}; font-weight:700; font-size:14px; margin-bottom:4px;">${escHtml(title || '')}</div>
                ${subtitle ? `<div style="color:var(--text-muted); font-size:12px; margin-bottom:10px;">${subtitle}</div>` : ''}
                ${checkRows ? `<table style="width:100%; font-size:13px; border-collapse:collapse; border:1px solid var(--border); border-radius:6px; overflow:hidden; margin-bottom:${failureRows || actions ? '10px' : '0'};">
                    <thead><tr style="background:var(--bg-tertiary);"><th style="padding:8px 12px; text-align:left; width:220px;">Check</th><th style="padding:8px 12px; text-align:left;">Result / Fix</th></tr></thead>
                    <tbody>${checkRows}</tbody>
                </table>` : ''}
                ${failureRows ? `<table style="width:100%; font-size:12px; border-collapse:collapse; border:1px solid var(--border); border-radius:6px; overflow:hidden;">
                    <thead><tr style="background:var(--bg-tertiary);"><th style="padding:8px 10px; text-align:left;">Section</th><th style="padding:8px 10px; text-align:left;">Endpoint</th><th style="padding:8px 10px; text-align:left;">Error</th><th style="padding:8px 10px; text-align:left;">Detail</th></tr></thead>
                    <tbody>${failureRows}</tbody>
                </table>` : ''}
                ${actions ? `<div style="margin-top:12px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">${actions}</div>` : ''}
            </div>
        `;
        if (replace) {
            content.innerHTML = block;
        } else {
            content.innerHTML += block;
        }
        panel.style.display = 'block';
    }

    // Clear whatever is in the diagnostics panel and hide it. Called on
    // clean re-renders so stale issues don't persist across cluster
    // switches.
    function wrClearDiagnosticsPanel() {
        const panel = document.getElementById('wr-diagnostics-panel');
        const content = document.getElementById('wr-diagnostics-content');
        if (content) content.innerHTML = '';
        if (panel) panel.style.display = 'none';
    }

    // Warning-only preflight results go into the same below-rack panel
    // as errors — same location, different severity accent. Non-blocking
    // by nature; the rack renders normally and the user sees the panel
    // underneath if they scroll.
    function wrRenderPreflightBanner(pf) {
        const warnings = (pf.checks || []).filter(c => !c.ok && c.severity === 'warning');
        if (!warnings.length) return;
        wrShowDiagnosticsPanel({
            severity: 'warning',
            title: 'Preflight warnings',
            subtitle: 'The rack view loaded, but these checks flagged issues that may affect reliability.',
            checks: warnings,
            checkActions: pf.actions || {},
        });
    }

    /// Full-card loading overlay shown while a cluster switch is in flight.
    /// Replaces the rack canvas + table panels so the user sees a clear
    /// "loading cluster X" instead of the previous cluster's data.
    function wrShowClusterLoading(clusterName) {
        const canvas = document.getElementById('wr-rack-canvas');
        if (canvas) {
            canvas.innerHTML = `
                <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; padding:80px 20px; color:var(--text-muted); gap:14px;">
                    <div class="wr-spinner" style="width:42px; height:42px; border:3px solid rgba(168,85,247,0.25); border-top-color:#a855f7; border-radius:50%; animation: wr-spin 0.8s linear infinite;"></div>
                    <div style="font-size:14px;">Loading <strong style="color:var(--text);">${escHtml(clusterName)}</strong>…</div>
                    <div style="font-size:11px; color:var(--text-muted); max-width:360px; text-align:center;">Fetching topology, firewall rules, LAN segments, and WAN connections from every node in this cluster.</div>
                </div>
                <style>@keyframes wr-spin { to { transform: rotate(360deg); } }</style>
            `;
        }
        // Hide the table-view panels while loading — they'd show stale data otherwise.
        document.querySelectorAll('.wr-tab-panel').forEach(p => {
            p.dataset.wrWasDisplay = p.style.display || '';
            p.style.display = 'none';
        });
    }

    function wrHideClusterLoading() {
        // Nothing special to undo for the canvas — wrRenderAll will repaint.
        // Restore panel displays so the user's last-active table-view tab reappears.
        document.querySelectorAll('.wr-tab-panel').forEach(p => {
            if (p.dataset.wrWasDisplay !== undefined) {
                p.style.display = p.dataset.wrWasDisplay;
                delete p.dataset.wrWasDisplay;
            }
        });
    }

    async function wrLoadAll() {
        // Fetch every endpoint independently so one failure doesn't
        // black-hole the whole page. Customers were seeing a bare
        // "failed to fetch" with no clue which endpoint was broken or
        // what data HAD loaded — we now render whatever came back and
        // list the specific endpoints that failed in a banner above
        // the rack canvas.
        const endpoints = [
            { key: 'topology',  url: '/api/router/topology',         label: 'Topology',           critical: true,  stateKey: 'topology' },
            { key: 'rules',     url: '/api/router/rules',            label: 'Firewall rules',     stateKey: 'rules',    fallback: [] },
            { key: 'lans',      url: '/api/router/segments',         label: 'LAN segments',       stateKey: 'lans',     fallback: [] },
            { key: 'zones',     url: '/api/router/zones',            label: 'Security zones',     stateKey: 'zones',    fallback: { assignments: {} } },
            { key: 'managed',   url: '/api/router/managed-overview', label: 'Managed overview',   stateKey: 'managed',  fallback: null },
            { key: 'snapshot',  url: '/api/router/host-snapshot',    label: 'Host snapshot',      stateKey: 'snapshot', fallback: null },
            { key: 'wan',       url: '/api/router/wan',              label: 'WAN connections',    stateKey: 'wan',      fallback: [] },
            { key: 'wan_status',url: '/api/router/wan-status',       label: 'WAN live status',    stateKey: 'wanStatus',fallback: [] },
            { key: 'proxies',   url: '/api/router/proxies',          label: 'Reverse proxies',    stateKey: 'proxies',  fallback: [] },
            { key: 'subnet_routes', url: '/api/router/subnet-routes', label: 'Subnet routes',     stateKey: 'subnet_routes', fallback: [] },
        ];

        // Launch all in parallel; track outcome per endpoint.
        const outcomes = await Promise.all(endpoints.map(async (ep) => {
            try {
                const r = await fetch(wrUrl(ep.url));
                if (!r.ok) {
                    const body = await r.text().catch(() => '');
                    return { ep, ok: false, error: `HTTP ${r.status} ${r.statusText}`, detail: body.slice(0, 240) };
                }
                try {
                    const data = await r.json();
                    return { ep, ok: true, data };
                } catch (e) {
                    return { ep, ok: false, error: 'Invalid JSON response', detail: String(e.message || e).slice(0, 240) };
                }
            } catch (e) {
                // Network-level failure (DNS, TLS, CORS, offline, etc.).
                return { ep, ok: false, error: `Network error: ${e.message || e}`, detail: '' };
            }
        }));

        // Apply every successful outcome so partially-loaded state is
        // still rendered; each fallback is used when the endpoint
        // failed, so downstream code never sees undefined.
        const failures = [];
        let topologyOk = false;
        for (const o of outcomes) {
            if (o.ok) {
                wrState[o.ep.stateKey] = o.data;
                if (o.ep.key === 'topology') topologyOk = true;
            } else {
                if (o.ep.fallback !== undefined) wrState[o.ep.stateKey] = o.ep.fallback;
                failures.push(o);
                console.error(`wolfrouter: ${o.ep.label} (${o.ep.url}) — ${o.error}`, o.detail);
            }
        }

        // If topology failed we can't draw the rack, but we can still
        // show the Firewall / LANs / Zones tables from whatever DID
        // load. Put a full error panel in the canvas and still render
        // the rest of the page.
        if (!topologyOk) {
            const topoFail = failures.find(f => f.ep.key === 'topology');
            wrShowFetchReport(failures, topoFail);
            // Render what we can in the table tabs.
            try { wrRenderAll(); } catch (_) { /* rack renderer may bail; fine */ }
            return;
        }

        wrRenderAll();
        // Fetch failures append to whatever diagnostics are already
        // showing (preflight warnings, for example). The entry-point
        // flow — showWolfRouterForCluster, polling retry — is responsible
        // for clearing the panel before a fresh cycle.
        if (failures.length) wrShowPartialFailureBanner(failures);
    }

    // Partial-fetch failures go into the below-rack diagnostics panel.
    // The rack is unaffected — it rendered from topology which loaded
    // fine, so we don't need to swap its contents or prepend a banner.
    function wrShowPartialFailureBanner(failures) {
        wrShowDiagnosticsPanel({
            severity: 'warning',
            title: `${failures.length} section${failures.length === 1 ? '' : 's'} failed to load`,
            subtitle: 'The rack rendered from topology (which loaded), but the table panels below may be missing data from these endpoints.',
            failures,
            actions: `<button onclick="wrLoadAll()" class="btn btn-sm">Retry</button>`,
        });
    }

    // Alias kept for callers that still reference the old name — now
    // just clears the whole diagnostics panel. Safe to call on every
    // successful render.
    function wrClearPartialFailureBanner() {
        wrClearDiagnosticsPanel();
    }

    // Topology endpoint failed — render a full diagnostics block below
    // the rack. The rack itself shows its existing empty state (or a
    // message from the topology renderer) rather than being overwritten.
    function wrShowFetchReport(failures, topoFail) {
        const others = failures.filter(f => f.ep.key !== 'topology');
        const topoBlock = topoFail ? `
            <div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:6px; padding:12px; margin-bottom:${others.length ? '12px' : '0'};">
                <strong style="font-size:13px;">Topology endpoint</strong><br>
                <code style="font-size:11px;">${escHtml(topoFail.ep.url)}</code><br>
                <span style="color:#ef4444;">${escHtml(topoFail.error)}</span>
                ${topoFail.detail ? `<pre style="margin-top:8px; padding:8px; background:var(--bg-primary); border-radius:4px; font-size:11px; white-space:pre-wrap;">${escHtml(topoFail.detail)}</pre>` : ''}
            </div>` : '';
        wrShowDiagnosticsPanel({
            severity: 'error',
            title: 'WolfRouter: topology could not be loaded',
            subtitle: `${topoBlock}${others.length ? 'Other endpoints that failed:' : ''}`,
            failures: others,
            actions: `<button onclick="wrLoadAll()" class="btn btn-primary btn-sm">Retry</button>
                <span style="color:var(--text-muted); font-size:11px;">Full details with response bodies are in the browser console (F12) and the server log.</span>`,
        });
    }

    function wrStartPolling() {
        if (wrState.pollInterval) clearInterval(wrState.pollInterval);
        wrState.pollInterval = setInterval(async () => {
            // WolfRouter has its own page now, but stay tolerant of being
            // embedded elsewhere. If neither page is visible, suspend.
            const wr = document.getElementById('page-wolfrouter');
            const net = document.getElementById('page-networking');
            const visible = (wr && wr.style.display !== 'none') ||
                            (net && net.style.display !== 'none');
            if (!visible) return;
            try {
                const r = await fetch(wrUrl('/api/router/topology'));
                if (r.ok) {
                    wrState.topology = await r.json();
                    if (wrState.view === 'rack') wrRenderRack();
                }
                if (wrState.activeTab === 'leases' && wrState.view === 'table') {
                    wrRenderLeases();
                }
                if (wrState.activeTab === 'connections' && wrState.view === 'table') {
                    wrRenderConnections();
                }
                if (wrState.activeTab === 'health' && wrState.view === 'table') {
                    // Health endpoint fans out to every node — heavier
                    // than a topology poll, so don't spam at 3s. Tick at
                    // every 4th cycle (~12s).
                    wrState._healthTick = ((wrState._healthTick || 0) + 1) % 4;
                    if (wrState._healthTick === 0) wrRenderLanHealth();
                }
            } catch (e) {}
        }, 3000);
    }

    // ─── View switching ───

    function wrSwitchView(view) {
        wrState.view = view;
        const rack = document.getElementById('wr-rack-container');
        const tabs = document.getElementById('wr-tabs');
        const btnRack = document.getElementById('wr-view-rack');
        const btnTable = document.getElementById('wr-view-table');
        if (!rack || !tabs) return;
        if (view === 'rack') {
            rack.style.display = 'block';
            // Keep the tab bar visible in rack view too (Gary KO4BSR 2026-06-24:
            // the tools were hidden until you switched to table view). The tabs
            // are always-on navigation — clicking one switches to that tool
            // (wrSelectTab forces table view). Only the tab PANELS are hidden so
            // they don't render under the 3D rack.
            tabs.style.display = 'flex';
            document.querySelectorAll('.wr-tab-panel').forEach(p => p.style.display = 'none');
            btnRack.classList.add('btn-primary');
            btnTable.classList.remove('btn-primary');
            wrRenderRack();
        } else {
            rack.style.display = 'none';
            tabs.style.display = 'flex';
            btnRack.classList.remove('btn-primary');
            btnTable.classList.add('btn-primary');
            wrSelectTab(wrState.activeTab);
        }
    }

    function wrSelectTab(tab) {
        wrState.activeTab = tab;
        // Selecting a tab implies we want the table view — force the rack
        // container hidden and the tab bar visible. Without this, a stale
        // state or a direct wrSelectTab call leaves the rack container
        // open and the tab panel ends up rendering UNDER the graphical
        // router instead of replacing it.
        wrState.view = 'table';
        const rack = document.getElementById('wr-rack-container');
        const tabs = document.getElementById('wr-tabs');
        const btnRack = document.getElementById('wr-view-rack');
        const btnTable = document.getElementById('wr-view-table');
        if (rack) rack.style.display = 'none';
        if (tabs) tabs.style.display = 'flex';
        if (btnRack) btnRack.classList.remove('btn-primary');
        if (btnTable) btnTable.classList.add('btn-primary');
        document.querySelectorAll('.wr-tab').forEach(t => {
            t.classList.toggle('active', t.dataset.tab === tab);
        });
        document.querySelectorAll('.wr-tab-panel').forEach(p => p.style.display = 'none');
        const panel = document.getElementById('wr-tab-' + tab);
        if (panel) panel.style.display = 'block';
        if (tab === 'firewall')     wrRenderRules();
        if (tab === 'lans')         wrRenderLans();
        if (tab === 'leases')       wrRenderLeases();
        if (tab === 'health')       wrRenderLanHealth();
        if (tab === 'zones')        wrRenderZones();
        if (tab === 'policy')       wrRenderPolicyMap();
        if (tab === 'wan')          wrRenderWan();
        if (tab === 'proxy')        wrRenderProxies();
        if (tab === 'http-proxies') hpLoad();
        if (tab === 'subnet-routes') wrRenderSubnetRoutes();
        if (tab === 'connections')  wrRenderConnections();
        if (tab === 'packets')      wrRenderPackets();
        if (tab === 'tools')        wrRenderDnsTools();
        if (tab === 'traceroute')   wrRenderTraceroute();
        if (tab === 'logs')         wrRenderLogs();
        if (tab === 'threat-intel') {
            // Defined in app.js (so it shares the toast/dialog primitives).
            if (typeof tiRenderTab === 'function') tiRenderTab();
        }
    }

    // ─── Master render ───

    function wrRenderAll() {
        if (wrState.view === 'rack') {
            wrRenderRack();
        } else {
            wrSelectTab(wrState.activeTab);
        }
    }

    // ─── Table: firewall rules ───

    function wrRenderRules() {
        // Also render the "managed elsewhere" port-forwards panel — IP
        // mappings owned by WolfStack's existing Networking page.
        const mPanel = document.getElementById('wr-managed-mappings');
        const mBody = document.getElementById('wr-mappings-tbody');
        const mappings = (wrState.managed?.ip_mappings) || [];
        if (mPanel && mBody) {
            if (mappings.length) {
                mPanel.style.display = 'block';
                mBody.innerHTML = mappings.map(m => `
                    <tr style="${m.enabled ? '' : 'opacity:0.5;'}">
                        <td><code>${escHtml(m.public_ip)}</code></td>
                        <td><code>${escHtml(m.wolfnet_ip)}</code></td>
                        <td>${escHtml(m.ports || 'all')}${m.dest_ports ? ` → ${escHtml(m.dest_ports)}` : ''}</td>
                        <td>${escHtml(m.protocol || 'all').toUpperCase()}</td>
                        <td>${escHtml(m.label || '')}</td>
                        <td style="text-align:right;"><span class="badge" style="background:rgba(59,130,246,0.15); color:#60a5fa; font-size:10px;">external</span></td>
                    </tr>
                `).join('');
            } else {
                mPanel.style.display = 'none';
            }
        }

        // Discovered iptables rules — what's already on the host. Always
        // visible so the firewall tab is never empty even when no
        // WolfRouter rules exist yet.
        wrRenderHostFirewall();

        const tbody = document.getElementById('wr-rules-tbody');
        if (!tbody) return;
        if (!wrState.rules.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--text-muted); padding:24px;">No firewall rules yet. Click <strong>+ Rule</strong> to create one.</td></tr>';
            return;
        }
        const rows = [...wrState.rules].sort((a,b) => a.order - b.order);
        tbody.innerHTML = rows.map((r, i) => {
            const actionBadge = {
                allow: 'rgba(34,197,94,0.2); color:#22c55e',
                deny: 'rgba(239,68,68,0.2); color:#ef4444',
                reject: 'rgba(239,68,68,0.2); color:#ef4444',
                log: 'rgba(59,130,246,0.2); color:#60a5fa',
            }[r.action] || '';
            const ports = (r.ports || []).map(p => p.port).join(', ') || '—';
            return `<tr style="${r.enabled ? '' : 'opacity:0.5;'}">
                <td>${i+1}</td>
                <td><span class="badge" style="background:${actionBadge}; font-size:10px; padding:2px 6px;">${r.action.toUpperCase()}</span></td>
                <td style="font-size:11px; color:var(--text-muted);">${r.direction}</td>
                <td>${endpointHtml(r.from)}</td>
                <td>${endpointHtml(r.to)}</td>
                <td>${r.protocol.toUpperCase()}</td>
                <td>${ports}</td>
                <td style="color:var(--text-muted); font-size:11px;">${escHtml(r.comment || '')}</td>
                <td>
                    <button class="btn btn-sm" title="Toggle" onclick="wrToggleRule('${r.id}')">${r.enabled ? '' : '⬜'}</button>
                    <button class="btn btn-sm" title="Delete" onclick="wrDeleteRule('${r.id}')"><span class="ws-icon-clean-wrap" data-icon="trash"></span></button>
                </td>
            </tr>`;
        }).join('');
    }

    function endpointHtml(ep) {
        if (!ep) return 'any';
        switch (ep.kind) {
            case 'any': return '<span style="color:var(--text-muted);">any</span>';
            case 'zone': return `<span class="badge" style="background:rgba(168,85,247,0.15); color:#a855f7; font-size:10px;">${zoneHuman(ep.zone)}</span>`;
            case 'interface': return `<code>${escHtml(ep.name)}</code>`;
            case 'ip': return `<code>${escHtml(ep.cidr)}</code>`;
            case 'vm': return `${escHtml(ep.name)}`;
            case 'container': return `${escHtml(ep.name)}`;
            case 'lan': return `${escHtml(ep.id)}`;
        }
        return JSON.stringify(ep);
    }

    function zoneHuman(z) {
        if (!z) return '?';
        if (z.kind === 'wan') return 'WAN';
        if (z.kind === 'lan') return 'LAN ' + (z.id || '0');
        if (z.kind === 'dmz') return 'DMZ';
        if (z.kind === 'wolfnet') return 'WolfNet';
        if (z.kind === 'trusted') return 'Trusted';
        if (z.kind === 'custom') return z.id || 'Custom';
        return JSON.stringify(z);
    }

    async function wrToggleRule(id) {
        const r = wrState.rules.find(x => x.id === id);
        if (!r) return;
        r.enabled = !r.enabled;
        await fetch(wrUrl('/api/router/rules/' + id), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(r) });
        await wrLoadAll();
    }

    async function wrDeleteRule(id) {
        if (!confirm('Delete this rule?')) return;
        await fetch(wrUrl('/api/router/rules/' + id), { method: 'DELETE' });
        await wrLoadAll();
    }

    async function wrTestRules() {
        const r = await fetch(wrUrl('/api/router/rules/test'), { method: 'POST' });
        const result = await r.json();
        if (result.ok) {
            if (typeof showToast === 'function') showToast('Ruleset passes iptables-restore --test', 'success');
            else alert('Ruleset OK');
        } else {
            const msgs = (result.issues || []).map(i => i.message).join('\n');
            alert('Ruleset has issues:\n' + msgs);
        }
    }

    async function wrConfirmRules() {
        await fetch(wrUrl('/api/router/rules/confirm'), { method: 'POST' });
        clearInterval(wrState.rollbackTimerInterval);
        wrState.rollbackTimerInterval = null;
        wrState.rollbackDeadline = null;
        const sm = document.getElementById('wr-rules-safemode');
        if (sm) sm.style.display = 'none';
        if (typeof showToast === 'function') showToast('Firewall rules confirmed — safe-mode timer cleared', 'success');
    }

    // Rule editor modal
    function wrShowRuleEditor(existing) {
        const r = existing || {
            id: '', enabled: true, order: 0,
            action: 'allow', direction: 'forward',
            from: { kind: 'any' }, to: { kind: 'any' },
            protocol: 'any', ports: [],
            state_track: true, log_match: false, comment: '',
            node_id: null,
        };
        // Cluster-scoped views require every rule to be pinned to a
        // node in the cluster (cluster_guard_node_id on the backend
        // rejects cluster-agnostic rules with HTTP 403). Build the
        // node options from the loaded topology so the user has the
        // same picker the LAN/WAN editors do. Default to the first
        // node — that's the user's own host on a single-node setup,
        // which is the overwhelmingly common case.
        const topoNodes = (wrState.topology?.nodes || []);
        const defaultNodeId = r.node_id || topoNodes[0]?.node_id || '';
        const nodeOptions = topoNodes.map(n =>
            `<option value="${escHtml(n.node_id)}"${n.node_id === defaultNodeId ? ' selected' : ''}>${escHtml(n.node_name || n.node_id)}</option>`
        ).join('');
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:640px;">
                <div class="modal-header">
                    <h3>${existing ? 'Edit' : 'New'} firewall rule</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        <label style="grid-column:1/-1;">Node
                            <select id="wr-f-node" class="form-control">
                                ${nodeOptions || '<option value="">(no nodes loaded — refresh the page)</option>'}
                            </select>
                            <span style="font-size:11px;color:var(--text-muted);">Rules are node-scoped. Pick which node enforces this rule.</span>
                        </label>
                        <label>Action
                            <select id="wr-f-action" class="form-control">
                                <option value="allow">Allow</option>
                                <option value="deny">Deny (silent drop)</option>
                                <option value="reject">Reject (ICMP)</option>
                            </select>
                        </label>
                        <label>Direction
                            <select id="wr-f-dir" class="form-control">
                                <option value="forward">Forward (between interfaces)</option>
                                <option value="input">Input (to WolfStack host)</option>
                                <option value="output">Output (from WolfStack host)</option>
                            </select>
                        </label>
                        <label style="grid-column:1/-1;">From (source)
                            <div style="display:flex; gap:4px;">
                                <select id="wr-f-from-kind" class="form-control" style="flex:0 0 140px;" onchange="wrRenderEndpointValue('from')">
                                    <option value="any">Any</option>
                                    <option value="zone">Zone</option>
                                    <option value="lan">LAN segment</option>
                                    <option value="interface">Interface</option>
                                    <option value="ip">IP / CIDR</option>
                                    <option value="vm">VM</option>
                                    <option value="container">Container</option>
                                </select>
                                <div id="wr-f-from-value-wrap" style="flex:1;"></div>
                            </div>
                        </label>
                        <label style="grid-column:1/-1;">To (destination)
                            <div style="display:flex; gap:4px;">
                                <select id="wr-f-to-kind" class="form-control" style="flex:0 0 140px;" onchange="wrRenderEndpointValue('to')">
                                    <option value="any">Any</option>
                                    <option value="zone">Zone</option>
                                    <option value="lan">LAN segment</option>
                                    <option value="interface">Interface</option>
                                    <option value="ip">IP / CIDR</option>
                                    <option value="vm">VM</option>
                                    <option value="container">Container</option>
                                </select>
                                <div id="wr-f-to-value-wrap" style="flex:1;"></div>
                            </div>
                        </label>
                        <label>Protocol
                            <select id="wr-f-proto" class="form-control">
                                <option value="any">Any</option>
                                <option value="tcp">TCP</option>
                                <option value="udp">UDP</option>
                                <option value="icmp">ICMP</option>
                            </select>
                        </label>
                        <label>Ports (comma-separated, ranges with -)
                            <input id="wr-f-ports" class="form-control" placeholder="80, 443, 8000-8100"/>
                        </label>
                        <label style="grid-column:1/-1;">Comment
                            <input id="wr-f-comment" class="form-control" placeholder="Why does this rule exist?"/>
                        </label>
                        <label style="display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="wr-f-log" />
                            Log matches (to Logs tab)
                        </label>
                        <label style="display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="wr-f-enabled" checked />
                            Enabled
                        </label>
                    </div>
                    <!-- Live warnings — rule analyser flags lockout
                         risks, duplicates, and no-op rules as the
                         user fills in the fields. -->
                    <div id="wr-f-warnings" style="margin-top:12px;"></div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="wrSaveRule('${r.id}')">${existing ? 'Save' : 'Create'}</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);

        // Initial population: set kinds + value widgets from the rule being edited.
        document.getElementById('wr-f-action').value = r.action;
        document.getElementById('wr-f-dir').value = r.direction;
        document.getElementById('wr-f-from-kind').value = r.from?.kind || 'any';
        document.getElementById('wr-f-to-kind').value = r.to?.kind || 'any';
        wrRenderEndpointValue('from', r.from);
        wrRenderEndpointValue('to', r.to);
        document.getElementById('wr-f-proto').value = r.protocol;
        document.getElementById('wr-f-ports').value = (r.ports || []).map(p => p.port).join(', ');
        document.getElementById('wr-f-comment').value = r.comment || '';
        document.getElementById('wr-f-log').checked = !!r.log_match;
        document.getElementById('wr-f-enabled').checked = r.enabled !== false;

        // Wire live-warning refresh on every field change. setTimeout
        // defers the first run until after the initial render settles.
        setTimeout(() => {
            ['wr-f-action','wr-f-dir','wr-f-from-kind','wr-f-to-kind',
             'wr-f-proto','wr-f-ports','wr-f-log','wr-f-enabled'].forEach(id => {
                const el = document.getElementById(id);
                if (!el) return;
                el.addEventListener('input', wrRenderRuleWarnings);
                el.addEventListener('change', wrRenderRuleWarnings);
            });
            // The value widgets are rebuilt on kind-change; use a delegated
            // listener so handlers apply to whichever input is current.
            ['wr-f-from-value-wrap', 'wr-f-to-value-wrap'].forEach(id => {
                const wrap = document.getElementById(id);
                if (!wrap) return;
                wrap.addEventListener('input', wrRenderRuleWarnings);
                wrap.addEventListener('change', wrRenderRuleWarnings);
            });
            wrRenderRuleWarnings();
        }, 50);
    }

    /// Render the "value" side of an endpoint picker based on the kind.
    /// side = 'from' | 'to'. seed (optional) = Endpoint to pre-select.
    function wrRenderEndpointValue(side, seed) {
        const kindSel = document.getElementById(`wr-f-${side}-kind`);
        const wrap = document.getElementById(`wr-f-${side}-value-wrap`);
        if (!kindSel || !wrap) return;
        const kind = kindSel.value;
        // If a seed was passed (populating on first open), sync the kind select to it too.
        if (seed && seed.kind) kindSel.value = seed.kind;
        const effectiveKind = seed?.kind || kind;

        switch (effectiveKind) {
            case 'any': {
                wrap.innerHTML = `<input class="form-control" value="(matches any source / destination)" disabled/>`;
                break;
            }
            case 'zone': {
                const opts = wrZoneOptions().map(z =>
                    `<option value="${escHtml(z.value)}">${escHtml(z.label)}</option>`).join('');
                wrap.innerHTML = `<select id="wr-f-${side}-value" class="form-control">${opts}</select>`;
                if (seed?.zone) document.getElementById(`wr-f-${side}-value`).value = wrZoneToValue(seed.zone);
                break;
            }
            case 'lan': {
                const lans = wrState.lans || [];
                const opts = lans.length
                    ? lans.map(l => `<option value="${escHtml(l.id)}">${escHtml(l.name)} — ${escHtml(l.subnet_cidr)}</option>`).join('')
                    : '<option value="">(no LAN segments defined — create one first)</option>';
                wrap.innerHTML = `<select id="wr-f-${side}-value" class="form-control">${opts}</select>`;
                if (seed?.id) document.getElementById(`wr-f-${side}-value`).value = seed.id;
                break;
            }
            case 'interface': {
                const ifaces = wrInterfaceOptions();
                const opts = ifaces.length
                    ? ifaces.map(i => `<option value="${escHtml(i.name)}">${escHtml(i.name)}${i.zone ? ' — ' + zoneHuman(i.zone) : ''} (${escHtml(i.node_name)})</option>`).join('')
                    : '<option value="">(no interfaces available)</option>';
                wrap.innerHTML = `<select id="wr-f-${side}-value" class="form-control">${opts}</select>`;
                if (seed?.name) document.getElementById(`wr-f-${side}-value`).value = seed.name;
                break;
            }
            case 'ip': {
                wrap.innerHTML = `<input id="wr-f-${side}-value" class="form-control" placeholder="192.168.1.0/24 or 8.8.8.8/32"/>`;
                if (seed?.cidr) document.getElementById(`wr-f-${side}-value`).value = seed.cidr;
                break;
            }
            case 'vm': {
                const vms = wrVmOptions();
                const opts = vms.length
                    ? vms.map(v => `<option value="${escHtml(v.name)}">${escHtml(v.name)}${v.ip ? ' — ' + escHtml(v.ip) : ''} (${escHtml(v.node_name)})</option>`).join('')
                    : '<option value="">(no VMs found)</option>';
                wrap.innerHTML = `<select id="wr-f-${side}-value" class="form-control">${opts}</select>`;
                if (seed?.name) document.getElementById(`wr-f-${side}-value`).value = seed.name;
                break;
            }
            case 'container': {
                const cs = wrContainerOptions();
                const opts = cs.length
                    ? cs.map(c => `<option value="${escHtml(c.name)}">${escHtml(c.name)}${c.ip ? ' — ' + escHtml(c.ip) : ''} (${escHtml(c.node_name)})</option>`).join('')
                    : '<option value="">(no containers found)</option>';
                wrap.innerHTML = `<select id="wr-f-${side}-value" class="form-control">${opts}</select>`;
                if (seed?.name) document.getElementById(`wr-f-${side}-value`).value = seed.name;
                break;
            }
        }
    }
    window.wrRenderEndpointValue = wrRenderEndpointValue;

    /// Read the endpoint value widget back into a structured Endpoint.
    function wrReadEndpoint(side) {
        const kindSel = document.getElementById(`wr-f-${side}-kind`);
        if (!kindSel) return { kind: 'any' };
        const kind = kindSel.value;
        const valEl = document.getElementById(`wr-f-${side}-value`);
        const val = valEl ? valEl.value : '';
        switch (kind) {
            case 'any':       return { kind: 'any' };
            case 'zone':      return { kind: 'zone', zone: wrValueToZone(val) || { kind: 'wan' } };
            case 'lan':       return { kind: 'lan', id: val };
            case 'interface': return { kind: 'interface', name: val };
            case 'ip':        return { kind: 'ip', cidr: val };
            case 'vm':        return { kind: 'vm', name: val };
            case 'container': return { kind: 'container', name: val };
        }
        return { kind: 'any' };
    }

    /// Analyse a proposed (or edited) rule against the current state
    /// and return a list of {severity, message} warnings. Called from
    /// the rule editor whenever a field changes so users see the
    /// consequences BEFORE they click Save.
    ///
    /// Severities: "danger" (red — lockout risk or catastrophic),
    /// "warning" (amber — probably-wrong), "info" (grey — observation).
    function wrAnalyzeRule(rule) {
        const out = [];
        const fromText = (rule.from?.kind === 'any' ? 'any' :
                          rule.from?.kind === 'zone' ? ('zone ' + (rule.from.zone?.kind || ''))
                          : JSON.stringify(rule.from));
        const toText   = (rule.to?.kind === 'any' ? 'any' :
                          rule.to?.kind === 'zone' ? ('zone ' + (rule.to.zone?.kind || ''))
                          : JSON.stringify(rule.to));

        // 1. Any → Any deny = total lockout.
        if (rule.action === 'deny' && rule.from?.kind === 'any' && rule.to?.kind === 'any') {
            out.push({ severity: 'danger', message: 'Any → Any DENY blocks ALL traffic through the firewall. You will lose access to everything including this UI. Almost certainly not what you meant.' });
        }

        // 2. Any deny that includes the Trusted zone on the source side
        //    — if the admin's machine is in Trusted, this locks them out.
        if (rule.action === 'deny' && (rule.from?.kind === 'any' ||
            (rule.from?.kind === 'zone' && rule.from.zone?.kind === 'trusted')))
        {
            if (rule.direction === 'input' || rule.direction === 'forward') {
                out.push({ severity: 'danger', message: 'Deny rule with Trusted / Any as source can lock admins out of SSH and the WolfStack UI. Safe-mode will revert in 30s — be ready to click "Keep these rules" or let it roll back.' });
            }
        }

        // 3. Intra-zone deny (LAN → same LAN) — rarely what you want.
        if (rule.action === 'deny' && rule.from?.kind === 'zone' && rule.to?.kind === 'zone'
            && rule.from.zone?.kind === rule.to.zone?.kind
            && (rule.from.zone?.id === rule.to.zone?.id))
        {
            out.push({ severity: 'warning', message: `Denying ${fromText} → ${toText} isolates everything within that zone. If devices in this zone need to talk to each other, this breaks it.` });
        }

        // 4. Deny that targets WolfNet from a non-WolfNet zone —
        //    breaks inter-node traffic.
        if (rule.action === 'deny'
            && (rule.to?.kind === 'zone' && rule.to.zone?.kind === 'wolfnet'))
        {
            out.push({ severity: 'warning', message: 'Blocking traffic INTO WolfNet breaks cluster communication — nodes stop seeing each other, WolfRouter replication stops, migrations fail. Only proceed if you know why you need this.' });
        }

        // 5. Allow/deny on OUTPUT for WAN → blocks this host's own
        //    outgoing traffic (apt updates, DNS, etc).
        if (rule.action === 'deny' && rule.direction === 'output'
            && (rule.to?.kind === 'zone' && rule.to.zone?.kind === 'wan'))
        {
            out.push({ severity: 'danger', message: 'Output deny to WAN blocks this host\'s own outgoing traffic — package updates, DNS, NTP, Let\'s Encrypt renewals all fail.' });
        }

        // 6. Duplicate or contradicting rule detection.
        for (const existing of (wrState.rules || [])) {
            if (existing.id === rule.id) continue;  // editing self
            if (!existing.enabled) continue;
            const sameFrom = JSON.stringify(existing.from) === JSON.stringify(rule.from);
            const sameTo   = JSON.stringify(existing.to)   === JSON.stringify(rule.to);
            const sameProto = existing.protocol === rule.protocol;
            if (sameFrom && sameTo && sameProto) {
                if (existing.action === rule.action) {
                    out.push({ severity: 'info', message: `A rule with the same source/dest/protocol and action already exists (#${existing.id.slice(0,8)}). This would be a duplicate.` });
                } else {
                    out.push({ severity: 'warning', message: `Another enabled rule (${existing.action.toUpperCase()}, #${existing.id.slice(0,8)}) matches the same source/dest/protocol. Order matters — the lower-numbered rule wins.` });
                }
            }
        }

        // 7. Port range with protocol=any — iptables ignores ports
        //    unless proto is tcp/udp; this rule silently matches more
        //    than the user thinks.
        if ((rule.ports || []).length > 0 && rule.protocol === 'any') {
            out.push({ severity: 'warning', message: 'Ports only take effect when protocol is TCP or UDP. With Any, the ports are ignored and this rule matches every protocol (ICMP, SCTP, etc).' });
        }

        // 8. Reject without state tracking — firing on every packet
        //    of a long connection, flooding logs.
        if (rule.action === 'reject' && !rule.state_track) {
            out.push({ severity: 'info', message: 'Reject without state tracking fires once per packet, not once per connection. Log volume can be huge.' });
        }

        return out;
    }

    /// Render the warnings panel inline in the rule editor. Called
    /// from the field change handlers (see wrShowRuleEditor).
    function wrRenderRuleWarnings() {
        const panel = document.getElementById('wr-f-warnings');
        if (!panel) return;
        const rule = wrCollectRuleFromEditor();
        if (!rule) return;  // DOM not ready yet — skip analysis
        const warnings = wrAnalyzeRule(rule);
        if (!warnings.length) {
            panel.innerHTML = '<div style="color:var(--text-muted); font-size:11px; padding:6px 0;">No obvious issues detected with this rule.</div>';
            return;
        }
        const colours = {
            danger:  { bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.4)', icon: '', label: '#ef4444' },
            warning: { bg: 'rgba(251,191,36,0.10)', border: 'rgba(251,191,36,0.35)', icon: '', label: '#fbbf24' },
            info:    { bg: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.3)',   icon: 'ℹ', label: '#60a5fa' },
        };
        panel.innerHTML = warnings.map(w => {
            const c = colours[w.severity] || colours.info;
            return `<div style="margin-bottom:6px; padding:8px 10px; background:${c.bg}; border:1px solid ${c.border}; border-radius:4px; font-size:12px;">
                <span style="color:${c.label}; font-weight:600;">${c.icon} ${w.severity.toUpperCase()}</span>
                <div style="color:var(--text); margin-top:2px;">${escHtml(w.message)}</div>
            </div>`;
        }).join('');
    }

    /// Pull the current editor field values into a rule object —
    /// used by wrRenderRuleWarnings and wrSaveRule to share logic.
    function wrCollectRuleFromEditor() {
        const byId = (id) => document.getElementById(id);
        // Every element the function touches must exist before we
        // start reading — otherwise we race the modal DOM being built.
        const required = ['wr-f-action', 'wr-f-ports', 'wr-f-enabled',
            'wr-f-dir', 'wr-f-from-kind', 'wr-f-to-kind', 'wr-f-proto',
            'wr-f-log', 'wr-f-comment'];
        for (const id of required) { if (!byId(id)) return null; }
        const ports = byId('wr-f-ports').value.split(',').map(s => s.trim()).filter(Boolean)
            .map(p => ({ port: p, side: 'dst' }));
        return {
            id: '',
            enabled: byId('wr-f-enabled').checked,
            action: byId('wr-f-action').value,
            direction: byId('wr-f-dir').value,
            from: wrReadEndpoint('from'),
            to: wrReadEndpoint('to'),
            protocol: byId('wr-f-proto').value,
            ports,
            state_track: true,
            log_match: byId('wr-f-log').checked,
            comment: byId('wr-f-comment').value,
        };
    }

    function endpointToText(ep) {
        if (!ep || ep.kind === 'any') return 'any';
        if (ep.kind === 'zone') return 'zone:' + (ep.zone?.kind === 'lan' ? `lan${ep.zone.id ?? 0}` : (ep.zone?.kind || ''));
        if (ep.kind === 'interface') return 'iface:' + ep.name;
        if (ep.kind === 'ip') return 'ip:' + ep.cidr;
        return 'any';
    }

    function textToEndpoint(t) {
        t = (t || '').trim();
        if (!t || t === 'any') return { kind: 'any' };
        if (t.startsWith('zone:')) {
            const z = t.slice(5);
            const m = z.match(/^lan(\d+)$/);
            if (m) return { kind: 'zone', zone: { kind: 'lan', id: parseInt(m[1], 10) } };
            if (z === 'wan') return { kind: 'zone', zone: { kind: 'wan' } };
            if (z === 'dmz') return { kind: 'zone', zone: { kind: 'dmz' } };
            if (z === 'wolfnet') return { kind: 'zone', zone: { kind: 'wolfnet' } };
            if (z === 'trusted') return { kind: 'zone', zone: { kind: 'trusted' } };
            return { kind: 'zone', zone: { kind: 'custom', id: z } };
        }
        if (t.startsWith('iface:')) return { kind: 'interface', name: t.slice(6) };
        if (t.startsWith('ip:')) return { kind: 'ip', cidr: t.slice(3) };
        return { kind: 'any' };
    }

    async function wrSaveRule(id) {
        const action = document.getElementById('wr-f-action').value;
        const direction = document.getElementById('wr-f-dir').value;
        const from = wrReadEndpoint('from');
        const to = wrReadEndpoint('to');
        const protocol = document.getElementById('wr-f-proto').value;
        const portsRaw = document.getElementById('wr-f-ports').value;
        const ports = portsRaw.split(',').map(s => s.trim()).filter(Boolean).map(p => ({ port: p, side: 'dst' }));
        const comment = document.getElementById('wr-f-comment').value;
        const log_match = document.getElementById('wr-f-log').checked;
        const enabled = document.getElementById('wr-f-enabled').checked;
        // Node selector — required by the cluster-scoped view's
        // backend guard. Falls back to the existing rule's node_id
        // (edit case) or the first topology node (new rule, common
        // case: user's own host) so the field is never silently
        // empty.
        const nodeSel = document.getElementById('wr-f-node');
        const node_id = (nodeSel && nodeSel.value)
            || (wrState.rules.find(r => r.id === id)?.node_id)
            || (wrState.topology?.nodes?.[0]?.node_id)
            || null;
        if (!node_id) {
            alert('Cannot save: no node available to attach this rule to. Reload the WolfRouter page so topology populates, or pick a different cluster.');
            return;
        }
        const existing = wrState.rules.find(r => r.id === id);
        const rule = existing ? { ...existing } : { id: '', enabled: true, order: 0, state_track: true };
        Object.assign(rule, { enabled, action, direction, from, to, protocol, ports, comment, log_match, node_id });
        const method = id ? 'PUT' : 'POST';
        const url = wrUrl(id ? '/api/router/rules/' + id : '/api/router/rules');
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rule) });
        if (!r.ok) {
            alert('Save failed: ' + await r.text());
            return;
        }
        if (typeof showToast === 'function') showToast(`Firewall rule ${id ? 'updated' : 'created'}`, 'success');
        document.querySelector('.modal-overlay')?.remove();
        await wrLoadAll();
    }

    // ─── Table: LANs + leases ───

    function wrRenderLans() {
        const grid = document.getElementById('wr-lans-list');
        if (!grid) return;
        const discovered = (wrState.snapshot?.dhcp?.dnsmasq_processes) || [];
        const discoveredHtml = discovered.length
            ? `<div style="margin-bottom:16px; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--bg-card);">
                <h4 style="font-size:13px; margin:0 0 8px;">dnsmasq instances discovered on this host (${discovered.length})</h4>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">Other DHCP/DNS servers running independently of WolfRouter — listed so you don't accidentally double-bind a port.</div>
                ${discovered.map(p => `
                    <div style="display:grid; grid-template-columns: 60px 120px 1fr; gap:8px; padding:4px 0; font-size:12px; border-top:1px dashed var(--border);">
                        <span style="color:var(--text-muted);">PID ${escHtml(p.pid)}</span>
                        <span><code>${escHtml(p.interface || 'auto')}</code></span>
                        <span style="color:var(--text-muted); font-family:var(--font-mono); font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escHtml(p.config_file || p.command.slice(0,80))}</span>
                    </div>
                `).join('')}
            </div>`
            : '';

        if (!wrState.lans.length) {
            grid.innerHTML = discoveredHtml +
                '<div style="text-align:center; color:var(--text-muted); padding:30px;">No WolfRouter LANs yet. Create one to serve DHCP+DNS for a subnet.</div>';
            return;
        }
        grid.innerHTML = discoveredHtml + grid.innerHTML;
        grid.innerHTML = wrState.lans.map(l => `
            <div style="padding:14px; border:1px solid var(--border); border-radius:8px; background:var(--bg-card);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div>
                        <strong style="font-size:15px;">${escHtml(l.name)}</strong>
                        <span class="badge" style="background:rgba(168,85,247,0.15); color:#a855f7; margin-left:6px; font-size:10px;">${zoneHuman(l.zone)}</span>
                    </div>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-sm" onclick="wrShowLanEditor('${l.id}')">Edit</button>
                        <button class="btn btn-sm" onclick="wrDeleteLan('${l.id}')">Delete</button>
                    </div>
                </div>
                <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:8px; font-size:12px; color:var(--text-muted);">
                    <div>Interface: <code>${escHtml(l.interface)}</code></div>
                    <div>Subnet: <code>${escHtml(l.subnet_cidr)}</code></div>
                    <div>Router IP: <code>${escHtml(l.router_ip)}</code></div>
                    <div>DHCP: ${l.dhcp.enabled ? `<strong>${l.dhcp.pool_start} → ${l.dhcp.pool_end}</strong>` : '<span style="color:var(--text-muted);">disabled</span>'}</div>
                    <div>DNS forwarders: ${(l.dns.forwarders || []).join(', ') || '—'}</div>
                    <div>Node: <code>${escHtml(l.node_id || 'this node')}</code></div>
                </div>
            </div>
        `).join('');
    }

    // Render every iptables rule currently active on the host into the
    // firewall tab so it's never empty. Rules owned by WolfRouter are
    // already shown in the editable table above; this section shows
    // everything else (Docker, LXC, WolfStack DNAT, manual rules,
    // system chain defaults).
    function wrRenderHostFirewall() {
        let panel = document.getElementById('wr-host-firewall');
        if (!panel) {
            // Inject the panel once into the firewall tab.
            const fwTab = document.getElementById('wr-tab-firewall');
            if (!fwTab) return;
            panel = document.createElement('div');
            panel.id = 'wr-host-firewall';
            panel.style.marginTop = '24px';
            fwTab.appendChild(panel);
        }
        const filter = wrState.snapshot?.firewall?.filter || [];
        const nat = wrState.snapshot?.firewall?.nat || [];
        const all = filter.concat(nat);
        if (!all.length) {
            panel.innerHTML = `<h4 style="font-size:13px; margin-bottom:8px; color:var(--text-muted);">Discovered host firewall rules</h4>
                <div style="color:var(--text-muted); font-size:12px; padding:12px;">No iptables rules detected (or iptables not readable as this user — try running as root).</div>`;
            return;
        }
        // Group by owner so users see what's WolfRouter vs what's already there.
        const ownerLabel = {
            wolfrouter: 'WolfRouter (managed here)',
            wolfstack:  'WolfStack (port forwards / VM NAT)',
            docker:     'Docker',
            lxc:        'LXC',
            system:     'System / kernel',
            user:       'User-defined / other',
        };
        const ownerColor = {
            wolfrouter: '#a855f7', wolfstack: '#22c55e',
            docker: '#3b82f6', lxc: '#06b6d4',
            system: '#94a3b8', user: '#fbbf24',
        };
        const groups = {};
        for (const r of all) {
            (groups[r.owner] = groups[r.owner] || []).push(r);
        }
        const orderedKeys = Object.keys(ownerLabel).filter(k => groups[k]);
        panel.innerHTML = `
            <div style="display:flex; align-items:baseline; justify-content:space-between; margin-bottom:8px;">
                <h4 style="font-size:13px; margin:0; color:var(--text);">All firewall rules on this host (${all.length} total)</h4>
                <span style="font-size:11px; color:var(--text-muted);">read-only — discovered from <code>iptables-save</code></span>
            </div>
            ${orderedKeys.map(k => `
                <details ${k === 'wolfrouter' || k === 'wolfstack' ? 'open' : ''} style="margin-bottom:8px; border:1px solid var(--border); border-radius:6px; background:var(--bg-card);">
                    <summary style="padding:8px 12px; cursor:pointer; font-size:12px; font-weight:600;">
                        <span style="display:inline-block; width:10px; height:10px; background:${ownerColor[k]}; border-radius:50%; vertical-align:middle; margin-right:8px;"></span>
                        ${escHtml(ownerLabel[k])} <span style="color:var(--text-muted); font-weight:normal; margin-left:6px;">(${groups[k].length})</span>
                    </summary>
                    <div style="padding:0 8px 8px;">
                        <pre style="font-family:var(--font-mono); font-size:11px; background:var(--bg-secondary); padding:8px; border-radius:4px; max-height:200px; overflow:auto; margin:4px 0;">${groups[k].map(r => escHtml(`[${r.table}] ${r.raw}`)).join('\n')}</pre>
                    </div>
                </details>
            `).join('')}
        `;
    }

    async function wrDeleteLan(id) {
        if (!confirm('Delete this LAN? dnsmasq for this segment will be stopped.')) return;
        await fetch(wrUrl('/api/router/segments/' + id), { method: 'DELETE' });
        await wrLoadAll();
    }

    function wrShowLanEditor(id) {
        const existing = id ? wrState.lans.find(l => l.id === id) : null;
        // Seed a subnet that isn't already in use when creating new.
        const seeded = existing ? null : wrSuggestSubnet(0);
        const l = existing || {
            id: '', name: '', node_id: '',
            interface: '', zone: { kind: 'lan', id: 0 },
            subnet_cidr: seeded.cidr, router_ip: seeded.router_ip,
            dhcp: { enabled: true, pool_start: seeded.pool_start, pool_end: seeded.pool_end, lease_time: '12h', reservations: [], extra_options: [] },
            dns: { forwarders: ['1.1.1.1', '9.9.9.9'], local_records: [], wildcard_domains: [], cache_enabled: true, block_ads: false },
            description: '',
        };

        const nodes = wrState.topology?.nodes || [];
        const zoneOpts = wrZoneOptions().filter(z => z.value.startsWith('lan') || z.value === 'dmz' || z.value.startsWith('custom:'));
        const nodeOptionsHtml = nodes.map(n =>
            `<option value="${escHtml(n.node_id)}">${escHtml(n.node_name)}</option>`
        ).join('') || '<option value="">(no nodes)</option>';
        const zoneOptionsHtml = zoneOpts.map(z =>
            `<option value="${escHtml(z.value)}">${escHtml(z.label)}</option>`
        ).join('');

        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.id = 'wr-lan-editor-overlay';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:640px;">
                <div class="modal-header">
                    <h3>${existing ? 'Edit' : 'New'} LAN segment</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        <label>Name<input id="wr-l-name" class="form-control" placeholder="HomeLAN"/></label>
                        <label>Node<select id="wr-l-node" class="form-control" onchange="wrLanPopulateIfaces()">${nodeOptionsHtml}</select></label>
                        <label>Interface (bridge or NIC)<select id="wr-l-iface" class="form-control" onchange="wrLanOnIfaceChange()"></select></label>
                        <label>Zone<select id="wr-l-zone" class="form-control">${zoneOptionsHtml}</select></label>
                        <label>Subnet CIDR<input id="wr-l-cidr" class="form-control" placeholder="192.168.10.0/24"/></label>
                        <label>Router IP<input id="wr-l-router" class="form-control" placeholder="192.168.10.1"/></label>
                        <label style="grid-column:1/-1;">
                            <div id="wr-l-iface-info" style="padding:6px 8px; border-radius:4px; font-size:11px; background:var(--bg-secondary); color:var(--text-muted);">Pick an interface to see its current addresses.</div>
                        </label>
                        <label style="grid-column:1/-1; display:flex; gap:8px; align-items:start; padding:10px 12px; background:rgba(34,197,94,0.08); border:1px solid rgba(34,197,94,0.3); border-radius:6px;">
                            <input type="checkbox" id="wr-l-assign-ip" checked style="margin-top:3px;"/>
                            <div>
                                <strong style="color:#4ade80;">Assign router IP to interface on save</strong>
                                <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                                    dnsmasq only binds — it doesn't address the interface. With this on, WolfRouter runs <code>ip addr add</code> for you so the interface is actually reachable at the router IP. If the address already exists it's left alone.
                                </div>
                            </div>
                        </label>
                        <label style="grid-column:1/-1; display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="wr-l-dhcp-enabled"/>Enable DHCP
                        </label>
                        <label>Pool start<input id="wr-l-pool-start" class="form-control"/></label>
                        <label>Pool end<input id="wr-l-pool-end" class="form-control"/></label>
                        <label>Lease time<input id="wr-l-lease" class="form-control" value="12h"/></label>
                        <div style="grid-column:1/-1;">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                                <strong style="font-size:12px;">Static reservations</strong>
                                <button class="btn btn-sm" onclick="wrLanAddReservationRow()">+ Add reservation</button>
                            </div>
                            <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">
                                MAC-pinned IPs. Handy for servers, printers, cameras, IoT that needs a stable address. You can also use the <strong>Pin</strong> button on the DHCP Leases tab to promote an active lease here with one click.
                            </div>
                            <div id="wr-l-reservations" style="display:flex; flex-direction:column; gap:4px;"></div>
                        </div>
                        <!-- DNS mode — primary choice. Two paths:
                               • WolfRouter serves DNS (today's behaviour)
                               • Use an external DNS server on this LAN
                                 (AdGuard Home container, Pi-hole on a
                                 separate box, etc.) — WolfRouter's
                                 dnsmasq runs DHCP only.
                             The "advanced" toggle underneath exposes the
                             low-level listen_port/external_server fields
                             for operators who want to run BOTH (e.g.
                             WolfRouter on 5353, AdGuard on 53). -->
                        <div style="grid-column:1/-1; display:flex; flex-direction:column; gap:4px; padding:10px 12px; background:rgba(59,130,246,0.08); border:1px solid rgba(59,130,246,0.3); border-radius:6px;">
                            <strong style="font-size:12px; color:#3b82f6;">DNS mode</strong>
                            <label style="display:flex; gap:8px; align-items:flex-start; font-size:12px;">
                                <input type="radio" name="wr-l-dns-mode" value="wolf_router" id="wr-l-dns-mode-wolf" checked onchange="wrLanOnDnsModeChange()" style="margin-top:3px;"/>
                                <div>
                                    <strong>WolfRouter serves DNS on this LAN</strong>
                                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">dnsmasq answers queries from LAN clients and forwards upstream. The normal case.</div>
                                </div>
                            </label>
                            <label style="display:flex; gap:8px; align-items:flex-start; font-size:12px;">
                                <input type="radio" name="wr-l-dns-mode" value="external" id="wr-l-dns-mode-ext" onchange="wrLanOnDnsModeChange()" style="margin-top:3px;"/>
                                <div>
                                    <strong>Use an external DNS server on this LAN</strong>
                                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">WolfRouter's dnsmasq runs DHCP only (port 53 is freed). DHCP tells clients to use the IP you enter below — typically an AdGuard Home container on this node, or a Pi-hole on a separate box.</div>
                                </div>
                            </label>
                            <label style="display:flex; gap:6px; align-items:center; font-size:12px; margin-top:4px;">
                                <input type="checkbox" id="wr-l-dns-advanced" onchange="wrLanOnDnsModeChange()"/> Advanced — expose dnsmasq listen port and external DNS IP independently
                            </label>
                        </div>
                        <label id="wr-l-dns-ext-wrap" style="grid-column:1/-1; display:none;">DNS server advertised to clients (DHCP option 6)
                            <input id="wr-l-dns-ext" class="form-control" placeholder="e.g. 192.168.10.2 (the AdGuard container or Pi-hole IP)"/>
                            <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">This is what LAN clients will be told to use for DNS. Must be reachable from the LAN.</div>
                        </label>
                        <label id="wr-l-dns-port-wrap" style="grid-column:1/-1; display:none;">WolfRouter DNS listen port
                            <input id="wr-l-dns-port" class="form-control" type="number" min="1" max="65535" value="53" style="max-width:140px;"/>
                            <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">Leave at 53 for the normal case. Set to e.g. 5353 if you want to run a container on port 53 on the same interface while keeping WolfRouter's dnsmasq for DHCP and secondary DNS — then set the DNS server above to the container's IP so DHCP points clients there.</div>
                        </label>
                        <label id="wr-l-fwd-wrap" style="grid-column:1/-1;">DNS provider
                            <select id="wr-l-fwd-preset" class="form-control" onchange="wrLanApplyDnsPreset()">${wrDnsPresetOptionsHtml()}</select>
                            <input id="wr-l-fwd" class="form-control" value="1.1.1.1, 1.0.0.1" style="margin-top:4px;" placeholder="comma-separated IPs"/>
                        </label>
                        <label style="grid-column:1/-1; display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="wr-l-ads"/>Block ads/trackers via DNS (hosts-file block list)
                        </label>
                        <div style="grid-column:1/-1; display:flex; flex-direction:column; gap:3px; padding:8px 10px; background:var(--bg-secondary,#161622); border:1px solid var(--border,#333); border-radius:6px;">
                            <label style="display:flex; gap:8px; align-items:center; font-weight:500;">
                                <input type="checkbox" id="wr-l-ecs"/>Forward client IP to upstream (EDNS Client Subnet)
                            </label>
                            <span style="font-size:11px; color:var(--text-muted); line-height:1.5;">
                                Tags every forwarded query with the real LAN client's IP so upstream resolvers like <strong>AdGuard Home</strong>, <strong>Pi-hole</strong>, or <strong>NextDNS</strong> can attribute traffic to individual clients instead of seeing them all come from this router. Particularly useful for AdGuard running in a Docker bridge container, which otherwise sees every query as coming from <code>172.17.0.1</code>. The upstream must have ECS enabled too (AdGuard: Settings → DNS server → "Enable EDNS Client Subnet"). Leave off if you'd rather not leak client subnets to the upstream.
                            </span>
                        </div>
                        <div style="grid-column:1/-1; display:flex; flex-direction:column; gap:4px;">
                            <label for="wr-l-wildcards" style="font-weight:500;">Wildcard local domains</label>
                            <textarea id="wr-l-wildcards" class="form-control" rows="2" placeholder="ai.home  192.168.10.2" style="font-family:monospace; font-size:12px;"></textarea>
                            <span style="font-size:11px; color:var(--text-muted); line-height:1.5;">
                                One <code>domain&nbsp;&nbsp;ip</code> per line. The domain <em>and every subdomain under it</em> resolve to that IP — e.g. <code>ai.home&nbsp;&nbsp;192.168.10.2</code> points <code>ai.home</code>, <code>sonarr.ai.home</code> and anything <code>*.ai.home</code> straight at your reverse proxy, with no per-host record. Ideal for an internal domain you can't (and don't want to) register publicly. Served authoritatively on this LAN.
                            </span>
                        </div>
                    </div>
                </div>
                <div id="wr-l-status" style="padding:0 20px; font-size:12px;"></div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button id="wr-l-save-btn" class="btn btn-primary" onclick="wrSaveLan('${l.id}')">${existing ? 'Save' : 'Create'}</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);

        // Populate node → iface cascade. Pick the LAN's own node if editing,
        // else the first node.
        const nodeSel = document.getElementById('wr-l-node');
        nodeSel.value = l.node_id || (nodes[0]?.node_id || '');
        wrLanPopulateIfaces();
        // Prefer the LAN's current iface, else a LAN-zoned iface on this node, else the first option.
        const ifaceSel = document.getElementById('wr-l-iface');
        if (l.interface) {
            ifaceSel.value = l.interface;
            if (ifaceSel.value !== l.interface) {
                // Wasn't in the current node's iface list — add it so editing doesn't silently drop it.
                const opt = document.createElement('option');
                opt.value = l.interface; opt.textContent = l.interface + ' (not found on selected node)';
                ifaceSel.appendChild(opt);
                ifaceSel.value = l.interface;
            }
        }
        wrLanOnIfaceChange();

        document.getElementById('wr-l-name').value = l.name;
        document.getElementById('wr-l-zone').value = wrZoneToValue(l.zone) || 'lan0';
        document.getElementById('wr-l-cidr').value = l.subnet_cidr;
        document.getElementById('wr-l-router').value = l.router_ip;
        document.getElementById('wr-l-dhcp-enabled').checked = !!l.dhcp.enabled;
        document.getElementById('wr-l-pool-start').value = l.dhcp.pool_start;
        document.getElementById('wr-l-pool-end').value = l.dhcp.pool_end;
        document.getElementById('wr-l-lease').value = l.dhcp.lease_time || '12h';
        document.getElementById('wr-l-fwd').value = (l.dns.forwarders || []).join(', ');
        // Match the current forwarders against the preset list so the
        // dropdown shows the right label when opened for editing.
        const presetId = wrDnsPresetFromServers(l.dns.forwarders);
        document.getElementById('wr-l-fwd-preset').value = presetId;
        document.getElementById('wr-l-ads').checked = !!l.dns.block_ads;
        document.getElementById('wr-l-ecs').checked = !!l.dns.forward_client_subnet;

        // DNS mode seed. Older LAN records (pre-v18.7.25) have no
        // `mode` field — default to WolfRouter so existing LANs keep
        // behaving exactly as before.
        const dnsMode = l.dns.mode === 'external' ? 'external' : 'wolf_router';
        const modeRadio = document.querySelector(`input[name=wr-l-dns-mode][value=${dnsMode}]`);
        if (modeRadio) modeRadio.checked = true;
        document.getElementById('wr-l-dns-ext').value = l.dns.external_server || '';
        document.getElementById('wr-l-dns-port').value = l.dns.listen_port || 53;
        const wcEl = document.getElementById('wr-l-wildcards');
        if (wcEl) wcEl.value = (l.dns.wildcard_domains || []).map(w => `${w.domain}  ${w.ip}`).join('\n');
        // Advanced toggle defaults on when the stored config diverges
        // from the simple case (non-53 port, or external_server set in
        // WolfRouter mode) — otherwise the operator would open the
        // editor and see fields that don't match what's persisted.
        const hasNonDefaults = (l.dns.listen_port && l.dns.listen_port !== 53)
            || (!!l.dns.external_server && dnsMode === 'wolf_router');
        document.getElementById('wr-l-dns-advanced').checked = hasNonDefaults;
        wrLanOnDnsModeChange();

        // Populate the reservations editor from existing data. Each row
        // is a live DOM block the user can edit; wrSaveLan reads them
        // back when saving.
        const resContainer = document.getElementById('wr-l-reservations');
        if (resContainer) {
            resContainer.innerHTML = '';
            for (const r of (l.dhcp?.reservations || [])) {
                wrLanAddReservationRow(r);
            }
        }
    }

    /// Append one reservation row to the LAN editor. `seed` (optional)
    /// pre-fills the row when opening for edit. MAC + IP validate on
    /// save; hostname is free-form because dnsmasq accepts any label.
    function wrLanAddReservationRow(seed) {
        const container = document.getElementById('wr-l-reservations');
        if (!container) return;
        const row = document.createElement('div');
        row.className = 'wr-l-res-row';
        row.style.cssText = 'display:grid; grid-template-columns: 180px 150px 1fr 32px; gap:4px; align-items:center;';
        row.innerHTML = `
            <input class="form-control wr-l-res-mac" placeholder="aa:bb:cc:dd:ee:ff" style="font-family:var(--font-mono); font-size:12px;" value="${escHtml(seed?.mac || '')}"/>
            <input class="form-control wr-l-res-ip" placeholder="192.168.10.50" style="font-family:var(--font-mono); font-size:12px;" value="${escHtml(seed?.ip || '')}"/>
            <input class="form-control wr-l-res-host" placeholder="hostname (optional)" style="font-size:12px;" value="${escHtml(seed?.hostname || '')}"/>
            <button class="btn btn-sm" title="Remove this reservation" onclick="this.closest('.wr-l-res-row').remove()">×</button>
        `;
        container.appendChild(row);
    }
    window.wrLanAddReservationRow = wrLanAddReservationRow;

    // Show/hide the advanced DNS fields based on mode + advanced toggle.
    //   • mode=External      → external_server visible, port hidden (forced 0 on save)
    //   • mode=WolfRouter    → port/forwarders visible; external_server hidden unless Advanced is on
    //   • Advanced on        → both visible in WolfRouter mode (the dual-stack case)
    function wrLanOnDnsModeChange() {
        const mode = document.querySelector('input[name=wr-l-dns-mode]:checked')?.value || 'wolf_router';
        const advanced = document.getElementById('wr-l-dns-advanced')?.checked;
        const extWrap  = document.getElementById('wr-l-dns-ext-wrap');
        const portWrap = document.getElementById('wr-l-dns-port-wrap');
        const fwdWrap  = document.getElementById('wr-l-fwd-wrap');
        if (!extWrap || !portWrap || !fwdWrap) return;
        if (mode === 'external') {
            // External DNS — clients need the IP; forwarders/port don't
            // apply because WolfRouter's dnsmasq is DHCP-only here.
            extWrap.style.display  = '';
            portWrap.style.display = 'none';
            fwdWrap.style.display  = 'none';
        } else {
            // WolfRouter serves DNS. Advanced toggle reveals the
            // low-level knobs for the dual-stack (WolfRouter on 5353,
            // external resolver on 53) case.
            extWrap.style.display  = advanced ? '' : 'none';
            portWrap.style.display = advanced ? '' : 'none';
            fwdWrap.style.display  = '';
        }
    }
    window.wrLanOnDnsModeChange = wrLanOnDnsModeChange;

    // Fill the forwarders text input from the selected preset. "custom"
    // leaves whatever the user has typed so they don't lose their work.
    function wrLanApplyDnsPreset() {
        const sel = document.getElementById('wr-l-fwd-preset');
        const input = document.getElementById('wr-l-fwd');
        if (!sel || !input) return;
        const preset = WR_DNS_PRESETS.find(p => p.id === sel.value);
        if (preset?.servers) input.value = preset.servers.join(', ');
    }
    window.wrLanApplyDnsPreset = wrLanApplyDnsPreset;

    // Populate the Interface dropdown from the selected node's interfaces + bridges.
    function wrLanPopulateIfaces() {
        const nodeSel = document.getElementById('wr-l-node');
        const ifaceSel = document.getElementById('wr-l-iface');
        if (!nodeSel || !ifaceSel) return;
        const nodeId = nodeSel.value;
        const n = (wrState.topology?.nodes || []).find(x => x.node_id === nodeId);
        const opts = [];
        if (n) {
            const bridges = (n.bridges || []).map(b => ({ name: b.name, kind: 'bridge', zone: b.zone }));
            const ifaces = (n.interfaces || []).map(i => ({ name: i.name, kind: 'iface', zone: i.zone, up: i.link_up }));
            // Bridges first — they're the canonical LAN attach point in a typical setup.
            for (const b of bridges) {
                opts.push(`<option value="${escHtml(b.name)}">${escHtml(b.name)} (bridge${b.zone ? ', ' + zoneHuman(b.zone) : ''})</option>`);
            }
            for (const ifc of ifaces) {
                const up = ifc.up ? '●' : '○';
                opts.push(`<option value="${escHtml(ifc.name)}">${up} ${escHtml(ifc.name)}${ifc.zone ? ' (' + zoneHuman(ifc.zone) + ')' : ''}</option>`);
            }
        }
        ifaceSel.innerHTML = opts.join('') || '<option value="">(no interfaces on this node)</option>';
        wrLanOnIfaceChange();
    }
    window.wrLanPopulateIfaces = wrLanPopulateIfaces;

    // When the interface selection changes, surface its current addresses so
    // the user sees up-front whether the router IP will conflict or coexist.
    function wrLanOnIfaceChange() {
        const nodeSel = document.getElementById('wr-l-node');
        const ifaceSel = document.getElementById('wr-l-iface');
        const info = document.getElementById('wr-l-iface-info');
        if (!nodeSel || !ifaceSel || !info) return;
        const nodeId = nodeSel.value, ifaceName = ifaceSel.value;
        const n = (wrState.topology?.nodes || []).find(x => x.node_id === nodeId);
        if (!n || !ifaceName) { info.textContent = 'Pick an interface to see its current addresses.'; return; }
        const ifc = (n.interfaces || []).find(i => i.name === ifaceName) || (n.bridges || []).find(b => b.name === ifaceName);
        const addrs = ifc?.addresses || [];
        if (!addrs.length) {
            info.innerHTML = `<span style="color:#fbbf24;"><code>${escHtml(ifaceName)}</code> has no IP address. Leave "Assign router IP to interface" ticked and WolfRouter will set it up on save.</span>`;
        } else {
            info.innerHTML = `Current addresses on <code>${escHtml(ifaceName)}</code>: ${addrs.map(a => `<code>${escHtml(a)}</code>`).join(', ')}. Router IP will be added alongside.`;
        }
    }
    window.wrLanOnIfaceChange = wrLanOnIfaceChange;

    async function wrSaveLan(id) {
        // Pull elements for inline status + button management. Every state
        // change below pipes through `say()` so the user sees exactly which
        // stage we're in — important because the preflight install can
        // take 30-60s on a first-time setup.
        const statusEl = document.getElementById('wr-l-status');
        const saveBtn = document.getElementById('wr-l-save-btn');
        const origLabel = saveBtn ? saveBtn.textContent : '';
        const say = (emoji, msg, colour = 'var(--text)') => {
            if (statusEl) statusEl.innerHTML =
                `<div style="padding:4px 0; color:${colour};">${emoji} ${msg}</div>` + statusEl.innerHTML;
        };
        const unlock = () => {
            if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = origLabel; }
        };
        if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = 'Working…'; }
        if (statusEl) statusEl.innerHTML = '';

        const existing = id ? wrState.lans.find(l => l.id === id) : null;
        const nodeSel = document.getElementById('wr-l-node');
        const node_id = nodeSel ? nodeSel.value : '';
        const lan = existing ? JSON.parse(JSON.stringify(existing)) : { id: '', zone: { kind: 'lan', id: 0 }, dhcp: {}, dns: {}, description: '' };
        lan.name = document.getElementById('wr-l-name').value.trim();
        lan.node_id = node_id || (wrState.topology?.nodes?.[0]?.node_id ?? '');
        lan.interface = document.getElementById('wr-l-iface').value.trim();
        lan.subnet_cidr = document.getElementById('wr-l-cidr').value.trim();
        lan.router_ip = document.getElementById('wr-l-router').value.trim();
        const zoneVal = document.getElementById('wr-l-zone').value;
        lan.zone = wrValueToZone(zoneVal) || { kind: 'lan', id: 0 };
        // Collect + validate reservations. Malformed rows abort the save
        // with a visible error so the user can fix them — skipping them
        // silently would confuse people who think they saved a reservation
        // that actually got dropped.
        const resRows = Array.from(document.querySelectorAll('#wr-l-reservations .wr-l-res-row'));
        const macRe = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
        const ipRe = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        const reservations = [];
        const seenMacs = new Set();
        for (const row of resRows) {
            const mac = row.querySelector('.wr-l-res-mac').value.trim().toLowerCase();
            const ip = row.querySelector('.wr-l-res-ip').value.trim();
            const hostname = row.querySelector('.wr-l-res-host').value.trim();
            if (!mac && !ip && !hostname) continue;  // empty row — silently drop
            if (!macRe.test(mac)) {
                say('', `Reservation has an invalid MAC: <code>${escHtml(mac || '(empty)')}</code>. Expected <code>aa:bb:cc:dd:ee:ff</code>. Save aborted.`, '#ef4444');
                unlock(); return;
            }
            if (!ipRe.test(ip)) {
                say('', `Reservation for <code>${escHtml(mac)}</code> has an invalid IP: <code>${escHtml(ip || '(empty)')}</code>. Save aborted.`, '#ef4444');
                unlock(); return;
            }
            if (seenMacs.has(mac)) {
                say('', `Duplicate MAC in reservations: <code>${escHtml(mac)}</code>. Each MAC can only be pinned to one IP. Save aborted.`, '#ef4444');
                unlock(); return;
            }
            seenMacs.add(mac);
            reservations.push({ mac, ip, hostname: hostname || null });
        }

        lan.dhcp = Object.assign(lan.dhcp || {}, {
            enabled: document.getElementById('wr-l-dhcp-enabled').checked,
            pool_start: document.getElementById('wr-l-pool-start').value.trim(),
            pool_end: document.getElementById('wr-l-pool-end').value.trim(),
            lease_time: document.getElementById('wr-l-lease').value.trim(),
            reservations,
            extra_options: lan.dhcp?.extra_options || [],
        });
        const dnsMode = document.querySelector('input[name=wr-l-dns-mode]:checked')?.value || 'wolf_router';
        const listenPort = parseInt(document.getElementById('wr-l-dns-port')?.value || '53', 10) || 53;
        const extServerRaw = (document.getElementById('wr-l-dns-ext')?.value || '').trim();
        // External DNS mode needs an IP to advertise; catch it here so
        // the user sees the error in the form instead of a 400 from the
        // backend after they've clicked Save.
        if (dnsMode === 'external' && !extServerRaw) {
            say('', 'External DNS mode needs the DNS server IP (field just above). Save aborted.', '#ef4444');
            unlock(); return;
        }
        if (dnsMode === 'wolf_router' && listenPort !== 53 && !extServerRaw) {
            say('',
                'Listen port isn\'t 53, so clients need a DNS IP they can reach on :53 — fill in the "DNS server advertised to clients" field (Advanced section).<br><br>' +
                '<strong>This is just a reference IP — it doesn\'t need to be running yet.</strong> Set it to your AdGuard/Pi-hole container\'s planned IP (e.g. <code>172.17.0.5</code>). Save will move dnsmasq off :53, freeing it for AdGuard to bind. Only then does AdGuard need to actually be up.',
                '#ef4444');
            unlock(); return;
        }
        lan.dns = Object.assign(lan.dns || {}, {
            mode: dnsMode,
            listen_port: listenPort,
            external_server: extServerRaw || null,
            forwarders: document.getElementById('wr-l-fwd').value.split(',').map(s => s.trim()).filter(Boolean),
            local_records: lan.dns?.local_records || [],
            // Wildcard domains: one "domain ip" per line (also accept = or → as
            // the separator). Strip a leading *. the user might type. Keep any
            // line that has a domain so a missing/blank IP gets a clear backend
            // error rather than vanishing silently.
            wildcard_domains: (document.getElementById('wr-l-wildcards')?.value || '').split('\n')
                .map(line => line.trim()).filter(Boolean)
                .map(line => {
                    const parts = line.replace(/[=→]/g, ' ').split(/\s+/).filter(Boolean);
                    return { domain: (parts[0] || '').replace(/^\*\./, ''), ip: parts[1] || '' };
                })
                .filter(w => w.domain),
            cache_enabled: true,
            block_ads: document.getElementById('wr-l-ads').checked,
            forward_client_subnet: document.getElementById('wr-l-ecs').checked,
        });

        // Preflight — ensure dnsmasq exists BEFORE trying to create a segment
        // that spawns it. Without this the backend's dhcp::start fails with
        // a hard-to-read error after the user has already filled the form.
        if (lan.dhcp.enabled) {
            say('', 'Checking that dnsmasq is installed (apt/dnf can take up to a minute the first time)…', 'var(--text-muted)');
            const res = await wrEnsureTool('dnsmasq');
            if (res.alreadyInstalled) {
                say('', 'dnsmasq already installed.', '#22c55e');
            } else if (res.success) {
                say('', 'dnsmasq installed via the host package manager.', '#22c55e');
            } else {
                say('', `dnsmasq not available: ${escHtml(res.message)}. Install it manually (e.g. <code>apt install dnsmasq</code>) and try again.`, '#ef4444');
                unlock();
                return;
            }
        }

        // Optional: assign the router IP to the interface first. Done before
        // saving the segment so dnsmasq can bind to a live, addressed iface.
        // Failures here are surfaced but don't block segment creation — users
        // can set the IP manually via the Network tab if needed.
        const assignIp = document.getElementById('wr-l-assign-ip')?.checked;
        if (assignIp && lan.interface && lan.router_ip) {
            const prefix = wrPrefixFromCidr(lan.subnet_cidr);
            if (prefix != null) {
                try {
                    const url = await wrNodeUrl(lan.node_id, '/api/networking/interfaces/' + encodeURIComponent(lan.interface) + '/ip');
                    const r = await fetch(url, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ address: lan.router_ip, prefix }),
                    });
                    if (r.ok) {
                        say('', `Router IP <code>${escHtml(lan.router_ip)}/${prefix}</code> assigned to <code>${escHtml(lan.interface)}</code>.`, '#22c55e');
                    } else {
                        const txt = await r.text();
                        // "File exists" is the idempotent-retry case — silently OK.
                        if (/file exists|already assigned|RTNETLINK.*File exists/i.test(txt)) {
                            say('ℹ', `Router IP already on <code>${escHtml(lan.interface)}</code>.`, 'var(--text-muted)');
                        } else {
                            say('', `IP assign warning (segment will still be saved): ${escHtml(txt)}`, '#fbbf24');
                        }
                    }
                    // Bring the interface up (best-effort; a bridge is typically already up).
                    const stateUrl = await wrNodeUrl(lan.node_id, '/api/networking/interfaces/' + encodeURIComponent(lan.interface) + '/state');
                    fetch(stateUrl, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ up: true }),
                    }).catch(() => {});
                } catch (e) {
                    say('', `Could not assign IP: ${escHtml(e.message || e)}. Continuing with segment save.`, '#fbbf24');
                }
            }
        }

        say('', 'Saving segment — dnsmasq will start…', 'var(--text-muted)');
        const url = wrUrl(id ? '/api/router/segments/' + id : '/api/router/segments');
        const method = id ? 'PUT' : 'POST';
        try {
            const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(lan) });
            if (!r.ok) {
                say('', `Save failed: ${escHtml(await r.text())}`, '#ef4444');
                unlock();
                return;
            }
        } catch (e) {
            say('', `Save errored: ${escHtml(e.message || e)}`, '#ef4444');
            unlock();
            return;
        }
        say('', 'Segment saved — dnsmasq running.', '#22c55e');
        // Unlock the button as soon as the save returns — the setTimeout
        // that removes the overlay can race against an unrelated modal
        // being opened (confirm dialog, toast-as-modal) which would
        // leave the LAN editor open with the button still stuck on
        // "Working…". Also target the LAN editor overlay by id rather
        // than querySelector('.modal-overlay'), which grabbed whichever
        // overlay was first in the DOM — sometimes a leftover from a
        // previous interaction, leaving the LAN editor behind.
        unlock();
        setTimeout(() => {
            document.getElementById('wr-lan-editor-overlay')?.remove();
            wrLoadAll();
        }, 400);
    }

    async function wrRenderLeases() {
        const container = document.getElementById('wr-leases-container');
        if (!container) return;
        const discoveredFiles = (wrState.snapshot?.dhcp?.lease_files) || [];
        // Render each discovered file with columns matched to its format:
        //   dnsmasq  → IP / MAC / Hostname / Expires (lease records)
        //   dhclient → Interface / IP / Server / Expires (client leases)
        //   unknown  → path only, no table (don't fabricate columns)
        const renderFileTable = (f) => {
            const fmt = f.format || 'dnsmasq';
            if (!f.leases.length) {
                return `<div style="color:var(--text-muted); font-size:11px; padding:8px;">${fmt === 'unknown' ? `Not a recognised lease file format &mdash; nothing to show from <code>${escHtml(f.path)}</code>.` : 'Empty'}</div>`;
            }
            if (fmt === 'dhclient') {
                return `<div style="font-size:10px; color:var(--text-muted); padding:0 8px 4px;">ISC dhclient format &mdash; this host's own DHCP client, not a DHCP server.</div>
                    <table class="data-table" style="font-size:11px;">
                        <thead><tr><th>Interface</th><th>IP</th><th>DHCP server</th><th>Expires</th></tr></thead>
                        <tbody>${f.leases.map(le => `<tr><td><code>${escHtml(le.interface || '—')}</code></td><td><code>${escHtml(le.ip || '')}</code></td><td><code>${escHtml(le.server || '—')}</code></td><td style="color:var(--text-muted);">${escHtml(le.expires || '')}</td></tr>`).join('')}</tbody>
                    </table>`;
            }
            // dnsmasq (default)
            return `<table class="data-table" style="font-size:11px;">
                <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Expires</th></tr></thead>
                <tbody>${f.leases.map(le => `<tr><td><code>${escHtml(le.ip)}</code></td><td><code>${escHtml(le.mac)}</code></td><td>${escHtml(le.hostname || '—')}</td><td style="color:var(--text-muted);">${escHtml(le.expires)}</td></tr>`).join('')}</tbody>
            </table>`;
        };
        const discoveredHtml = discoveredFiles.length
            ? `<div style="margin-bottom:16px;">
                <h4 style="font-size:13px; margin:0 0 8px;">Lease files discovered on this host</h4>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">Aggregated from /var/lib/wolfstack-router, /var/lib/dhcp, /var/lib/misc and /run.</div>
                ${discoveredFiles.map(f => `
                    <details ${f.leases.length ? 'open' : ''} style="margin-bottom:8px; border:1px solid var(--border); border-radius:6px; background:var(--bg-card);">
                        <summary style="padding:8px 12px; cursor:pointer; font-size:12px; font-weight:600;">
                            <code style="font-family:var(--font-mono);">${escHtml(f.path)}</code>
                            <span class="badge" style="background:rgba(148,163,184,0.15); color:var(--text-muted); font-size:10px; padding:1px 6px; margin-left:6px;">${escHtml(f.format || 'dnsmasq')}</span>
                            <span style="color:var(--text-muted); font-weight:normal; margin-left:6px;">(${f.leases.length} ${f.format === 'dhclient' ? 'client-lease' : 'lease'}${f.leases.length===1?'':'s'})</span>
                        </summary>
                        <div style="padding:0 8px 8px;">
                            ${renderFileTable(f)}
                        </div>
                    </details>
                `).join('')}
            </div>`
            : '';

        if (!wrState.lans.length) {
            container.innerHTML = discoveredHtml +
                '<div style="text-align:center; color:var(--text-muted); padding:18px;">No WolfRouter-managed LANs. Add one to serve DHCP from WolfRouter directly.</div>';
            return;
        }
        const parts = [discoveredHtml];
        for (const lan of wrState.lans) {
            try {
                const r = await fetch(wrUrl('/api/router/segments/' + lan.id + '/leases'));
                const leases = r.ok ? await r.json() : [];
                // Build a quick MAC → reservation map so the "Pin" button
                // shows "Pinned" instead when the lease is already static.
                const reservedMacs = new Set((lan.dhcp?.reservations || []).map(r => (r.mac || '').toLowerCase()));
                const reservedCount = (lan.dhcp?.reservations || []).length;
                parts.push(`
                    <div style="margin-bottom:18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; flex-wrap:wrap; gap:8px;">
                            <div style="font-weight:600;">${escHtml(lan.name)}
                                <span style="color:var(--text-muted); font-size:12px; font-weight:normal;">(${leases.length} active · ${reservedCount} pinned)</span>
                            </div>
                            <button class="btn btn-sm" title="Create a static reservation without waiting for the device to connect — useful for pre-pinning servers or IoT devices by their MAC."
                                    onclick="wrShowAddReservation('${escHtml(lan.id)}')">+ Add reservation</button>
                        </div>
                        <table class="data-table" style="font-size:12px;">
                            <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Expires (epoch)</th><th style="width:90px;">Action</th></tr></thead>
                            <tbody>
                                ${leases.length ? leases.map(le => {
                                    const macLc = (le.mac || '').toLowerCase();
                                    const alreadyPinned = reservedMacs.has(macLc);
                                    // Button passes identifiers via data-* attributes and
                                    // has wrPinLease read them back via `this.dataset` — keeps
                                    // user-supplied hostnames out of the inline onclick string
                                    // where a stray quote could break the JS (or worse).
                                    const btn = alreadyPinned
                                        ? `<span class="badge" style="background:rgba(34,197,94,0.15); color:#22c55e; font-size:10px;">pinned</span>`
                                        : `<button class="btn btn-sm wr-lease-pin" title="Pin this MAC → IP so it always gets this address"
                                                data-lan="${escHtml(lan.id)}"
                                                data-mac="${escHtml(le.mac)}"
                                                data-ip="${escHtml(le.ip)}"
                                                data-host="${escHtml(le.hostname || '')}"
                                                onclick="wrPinLease(this)">Pin</button>`;
                                    return `<tr><td><code>${escHtml(le.ip)}</code></td><td><code>${escHtml(le.mac)}</code></td><td>${escHtml(le.hostname || '—')}</td><td style="color:var(--text-muted);">${le.expires}</td><td>${btn}</td></tr>`;
                                }).join('')
                                : '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:12px;">No active leases</td></tr>'}
                            </tbody>
                        </table>
                    </div>
                `);
            } catch (e) {}
        }
        container.innerHTML = parts.join('');
    }

    /// Promote an active DHCP lease to a static reservation. Pre-fills
    /// mac/ip/hostname from whatever dnsmasq is currently serving for
    /// this client — 99% of the time exactly what the user wants when
    /// they see the button next to a lease.
    ///
    /// Reads its inputs from the button's data-* attributes so nothing
    /// user-supplied ever lives in the inline onclick string.
    ///
    /// Serialised via wrState.pinning so two quick clicks don't race the
    /// reload window: without the guard, a second click while wrLoadAll
    /// is still fetching would read the pre-first-click wrState.lans,
    /// issue a PUT that clobbers the first reservation we just wrote.
    async function wrPinLease(btn) {
        if (!btn) return;
        if (wrState.pinning) {
            btn.textContent = 'busy…';
            setTimeout(() => { btn.textContent = 'Pin'; }, 700);
            return;
        }
        wrState.pinning = true;
        const lanId = btn.dataset.lan || '';
        const mac = btn.dataset.mac || '';
        const ip = btn.dataset.ip || '';
        const hostname = btn.dataset.host || '';
        const origLabel = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Pinning…';
        try {
            const lan = (wrState.lans || []).find(l => l.id === lanId);
            if (!lan) { btn.textContent = 'LAN not found'; return; }
            // Defensive clone — don't mutate wrState in place; the next
            // poll will refresh anyway.
            const updated = JSON.parse(JSON.stringify(lan));
            updated.dhcp = updated.dhcp || {};
            updated.dhcp.reservations = updated.dhcp.reservations || [];
            // Skip if already present (shouldn't happen — button says "pinned"
            // in that case — but belt and braces).
            const macLc = (mac || '').toLowerCase();
            if (updated.dhcp.reservations.some(r => (r.mac || '').toLowerCase() === macLc)) {
                btn.textContent = 'already pinned';
                return;
            }
            updated.dhcp.reservations.push({
                mac: macLc,
                ip,
                hostname: hostname || null,
            });
            const r = await fetch(wrUrl('/api/router/segments/' + encodeURIComponent(lanId)), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updated),
            });
            if (r.ok) {
                btn.textContent = 'pinned';
                btn.style.background = 'rgba(34,197,94,0.15)';
                btn.style.color = '#22c55e';
                // Refresh wrState + re-render so the column flips to the
                // "pinned" badge on next render (plus any neighbouring
                // state stays fresh).
                await wrLoadAll();
            } else {
                const txt = await r.text();
                btn.textContent = 'failed';
                alert('Could not pin lease: ' + txt);
                btn.disabled = false;
                btn.textContent = origLabel;
            }
        } catch (e) {
            btn.disabled = false;
            btn.textContent = origLabel;
            alert('Pin failed: ' + (e.message || e));
        } finally {
            wrState.pinning = false;
        }
    }
    window.wrPinLease = wrPinLease;

    /// Manual static reservation — useful when the device hasn't
    /// connected yet (common case: pre-pinning a server that 20 MQTT
    /// clients address by IP, pre-configuring a printer, etc). Opens
    /// a small modal that asks for MAC/IP/hostname, validates, and
    /// appends to the segment's reservations. Same end state as pinning
    /// an active lease but doesn't require the device on the network.
    function wrShowAddReservation(lanId) {
        const lan = (wrState.lans || []).find(l => l.id === lanId);
        if (!lan) { alert('LAN not found'); return; }
        // Suggest the next free IP inside the subnet to save the user
        // from typing and accidentally colliding with the DHCP pool.
        const suggested = wrSuggestReservationIp(lan);
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:520px;">
                <div class="modal-header">
                    <h3>Add static reservation &mdash; ${escHtml(lan.name)}</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px;">
                        Subnet: <code>${escHtml(lan.subnet_cidr)}</code> &bull; DHCP pool: <code>${escHtml(lan.dhcp?.pool_start || '—')} → ${escHtml(lan.dhcp?.pool_end || '—')}</code>. Reservations usually sit outside the pool so there's no chance of a collision.
                    </div>
                    <label style="display:block; margin-bottom:8px;">MAC address
                        <input id="wr-addr-mac" class="form-control" placeholder="aa:bb:cc:dd:ee:ff" style="font-family:var(--font-mono); font-size:13px;" autofocus/>
                    </label>
                    <label style="display:block; margin-bottom:8px;">IP address
                        <input id="wr-addr-ip" class="form-control" placeholder="${escHtml(suggested || '192.168.10.10')}" value="${escHtml(suggested)}" style="font-family:var(--font-mono); font-size:13px;"/>
                    </label>
                    <label style="display:block; margin-bottom:8px;">Hostname (optional)
                        <input id="wr-addr-host" class="form-control" placeholder="mqtt-server"/>
                    </label>
                    <div id="wr-addr-status" style="font-size:12px; padding:4px 0;"></div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button id="wr-addr-btn" class="btn btn-primary" onclick="wrSaveAddReservation('${escHtml(lanId)}')">Add reservation</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
    }
    window.wrShowAddReservation = wrShowAddReservation;

    /// Suggest the first host IP outside the DHCP pool so users have a
    /// sensible default that won't collide. Falls back to the tenth
    /// host in the subnet if the pool can't be parsed.
    function wrSuggestReservationIp(lan) {
        // Try router_ip's /24 and pick a low address below the pool.
        const cidrMatch = (lan.subnet_cidr || '').match(/^(\d+)\.(\d+)\.(\d+)\.\d+\/(\d+)$/);
        if (!cidrMatch) return '';
        const base = `${cidrMatch[1]}.${cidrMatch[2]}.${cidrMatch[3]}`;
        const used = new Set();
        for (const r of (lan.dhcp?.reservations || [])) used.add(r.ip);
        if (lan.router_ip) used.add(lan.router_ip);
        const poolStart = lan.dhcp?.pool_start || `${base}.100`;
        const poolStartOct = parseInt((poolStart.split('.')[3] || '100'), 10);
        // Prefer low IPs (.2 … poolStart-1) that aren't in use.
        for (let i = 2; i < poolStartOct; i++) {
            const cand = `${base}.${i}`;
            if (!used.has(cand)) return cand;
        }
        // Fallback — .10 is almost always safe.
        return `${base}.10`;
    }

    async function wrSaveAddReservation(lanId) {
        const btn = document.getElementById('wr-addr-btn');
        const statusEl = document.getElementById('wr-addr-status');
        if (!btn || !statusEl) return;
        const mac = (document.getElementById('wr-addr-mac').value || '').trim().toLowerCase();
        const ip = (document.getElementById('wr-addr-ip').value || '').trim();
        const hostname = (document.getElementById('wr-addr-host').value || '').trim();
        const macRe = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
        const ipRe = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (!macRe.test(mac)) {
            statusEl.innerHTML = `<span style="color:#ef4444;">MAC must look like <code>aa:bb:cc:dd:ee:ff</code>.</span>`;
            return;
        }
        if (!ipRe.test(ip)) {
            statusEl.innerHTML = `<span style="color:#ef4444;">IP must be a dotted quad, e.g. <code>192.168.10.50</code>.</span>`;
            return;
        }
        const lan = (wrState.lans || []).find(l => l.id === lanId);
        if (!lan) { statusEl.innerHTML = `<span style="color:#ef4444;">LAN not found.</span>`; return; }
        if ((lan.dhcp?.reservations || []).some(r => (r.mac || '').toLowerCase() === mac)) {
            statusEl.innerHTML = `<span style="color:#ef4444;">A reservation for this MAC already exists. Edit it in the LAN editor (DHCP/LANs tab).</span>`;
            return;
        }
        btn.disabled = true;
        btn.textContent = 'Saving…';
        statusEl.innerHTML = '<span style="color:var(--text-muted);">Updating segment…</span>';

        const updated = JSON.parse(JSON.stringify(lan));
        updated.dhcp = updated.dhcp || {};
        updated.dhcp.reservations = updated.dhcp.reservations || [];
        updated.dhcp.reservations.push({ mac, ip, hostname: hostname || null });

        try {
            const r = await fetch(wrUrl('/api/router/segments/' + encodeURIComponent(lanId)), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updated),
            });
            if (r.ok) {
                statusEl.innerHTML = `<span style="color:#22c55e;">Reservation added &mdash; dnsmasq reloaded. Next time the MAC shows up on the LAN it'll be handed <code>${escHtml(ip)}</code>.</span>`;
                setTimeout(() => {
                    document.querySelector('.modal-overlay')?.remove();
                    wrLoadAll();
                }, 900);
            } else {
                const txt = await r.text();
                statusEl.innerHTML = `<span style="color:#ef4444;">Save failed: ${escHtml(txt)}</span>`;
                btn.disabled = false; btn.textContent = 'Add reservation';
            }
        } catch (e) {
            statusEl.innerHTML = `<span style="color:#ef4444;">Request failed: ${escHtml(e.message || e)}</span>`;
            btn.disabled = false; btn.textContent = 'Add reservation';
        }
    }
    window.wrSaveAddReservation = wrSaveAddReservation;

    // ─── Zones ───

    function wrRenderZones() {
        const grid = document.getElementById('wr-zones-grid');
        if (!grid) return;
        const topo = wrState.topology;
        if (!topo || !topo.nodes?.length) {
            grid.innerHTML = '<div style="color:var(--text-muted);">Loading topology...</div>';
            return;
        }

        // Drift detection — zone labels are just firewall tags, but users
        // naturally expect changing a zone to rewire the router. Surface
        // any mismatch between "what the zone says" and "what the actual
        // WanConnection / LanSegment is doing" so the user knows a
        // manual fix (edit LAN/WAN, or re-run Quick Setup) is needed
        // for the change to be more than cosmetic.
        const drifts = [];
        const wans = wrState.wan || [];
        const lans = wrState.lans || [];
        for (const node of topo.nodes) {
            for (const ifc of (node.interfaces || [])) {
                const z = ifc.zone;
                const hasEnabledWan = wans.some(w => w.enabled && w.node_id === node.node_id && w.interface === ifc.name);
                const hasLan        = lans.some(l => l.node_id === node.node_id && l.interface === ifc.name);
                const label = `<code>${escHtml(ifc.name)}</code> on <code>${escHtml(node.node_name)}</code>`;
                if (z?.kind === 'wan' && !hasEnabledWan) {
                    drifts.push({ sev: 'warn', iface: ifc.name, node: node.node_id, msg: `${label} is zoned <strong>WAN</strong> but no enabled WAN connection uses it. Either create a WAN connection for this interface, change the zone, or re-run Quick Setup.` });
                }
                if (z?.kind === 'lan' && !hasLan) {
                    drifts.push({ sev: 'warn', iface: ifc.name, node: node.node_id, msg: `${label} is zoned <strong>LAN ${z.id ?? 0}</strong> but no LAN segment serves DHCP on it. Either create a LAN segment for this interface, change the zone, or re-run Quick Setup.` });
                }
                if (hasEnabledWan && z && z.kind !== 'wan') {
                    drifts.push({ sev: 'warn', iface: ifc.name, node: node.node_id, msg: `${label} has an active WAN connection, but its zone is <strong>${escHtml(zoneHuman(z))}</strong>. Firewall rules will treat it as ${escHtml(zoneHuman(z))}; change the zone to WAN so rules match reality.` });
                }
                if (hasLan && z && z.kind !== 'lan') {
                    drifts.push({ sev: 'warn', iface: ifc.name, node: node.node_id, msg: `${label} is actively serving a LAN segment, but its zone is <strong>${escHtml(zoneHuman(z))}</strong>. Firewall rules will treat it as ${escHtml(zoneHuman(z))}; change the zone to LAN so rules match reality.` });
                }
            }
        }
        const driftBanner = drifts.length
            ? `<div style="margin-bottom:14px; padding:12px 14px; background:rgba(251,191,36,0.1); border:1px solid rgba(251,191,36,0.4); border-radius:6px; font-size:12px;">
                <strong style="color:#fbbf24;">Zone labels and running config have drifted apart (${drifts.length} issue${drifts.length===1?'':'s'}).</strong>
                <div style="color:var(--text-muted); margin-top:3px;">
                    Zones are labels that firewall rules use &mdash; changing a zone here doesn't automatically move the router IP, dnsmasq, or MASQUERADE to a different interface. Those live on LAN segments and WAN connections (their own interface fields). Drift means the rack view and rules may not match what's actually happening.
                </div>
                <ul style="margin:8px 0 0; padding-left:18px;">
                    ${drifts.map(d => `<li style="margin-bottom:4px;">${d.msg}</li>`).join('')}
                </ul>
            </div>`
            : '';

        const zones = ['wan', 'lan0', 'lan1', 'dmz', 'wolfnet', 'trusted'];
        const parts = [driftBanner];
        for (const node of topo.nodes) {
            parts.push(`<div style="margin-bottom:16px;">
                <h4 style="margin:0 0 8px; font-size:13px;">${escHtml(node.node_name)} <span style="color:var(--text-muted); font-size:11px; font-weight:normal;">(${node.node_id})</span></h4>
                <table class="data-table" style="font-size:12px;"><thead><tr><th>Interface</th><th>Current zone</th><th>Actually doing</th><th>Assign</th></tr></thead><tbody>
                ${node.interfaces.map(ifc => {
                    const current = ifc.zone ? zoneHuman(ifc.zone) : '<span style="color:var(--text-muted);">unassigned</span>';
                    const opts = ['<option value="">(unassigned)</option>'].concat(
                        zones.map(z => `<option value="${z}">${z.toUpperCase()}</option>`)
                    ).join('');
                    const cur = ifc.zone?.kind === 'lan' ? `lan${ifc.zone.id}` : (ifc.zone?.kind || '');
                    // "Actually doing" surfaces which LAN/WAN is bound
                    // to this iface — the ground truth behind the zone.
                    const lan = lans.find(l => l.node_id === node.node_id && l.interface === ifc.name);
                    const wan = wans.find(w => w.enabled && w.node_id === node.node_id && w.interface === ifc.name);
                    const actualBits = [];
                    if (wan) actualBits.push(`<span class="badge" style="background:rgba(251,191,36,0.15); color:#fbbf24; font-size:10px;">WAN: ${escHtml(wan.name)}</span>`);
                    if (lan) actualBits.push(`<span class="badge" style="background:rgba(59,130,246,0.15); color:#60a5fa; font-size:10px;">LAN: ${escHtml(lan.name)} (${escHtml(lan.subnet_cidr)})</span>`);
                    const actualCell = actualBits.length ? actualBits.join(' ') : '<span style="color:var(--text-muted); font-size:11px;">&mdash;</span>';
                    return `<tr>
                        <td><code>${escHtml(ifc.name)}</code> ${ifc.link_up ? '<span style="color:var(--success);">●</span>' : '<span style="color:var(--text-muted);">○</span>'}</td>
                        <td>${current}</td>
                        <td>${actualCell}</td>
                        <td>
                            <select class="form-control" style="font-size:12px; padding:3px 6px;" onchange="wrAssignZone('${node.node_id}', '${ifc.name}', this.value)">
                                ${opts.replace(`value="${cur}"`, `value="${cur}" selected`)}
                            </select>
                        </td>
                    </tr>`;
                }).join('')}
                </tbody></table>
            </div>`);
        }
        grid.innerHTML = parts.join('');
    }

    async function wrAssignZone(node_id, iface, zoneStr) {
        let zone = null;
        if (zoneStr) {
            const m = zoneStr.match(/^lan(\d+)$/);
            if (m) zone = { kind: 'lan', id: parseInt(m[1], 10) };
            else zone = { kind: zoneStr };
        }
        await fetch(wrUrl('/api/router/zones'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ node_id, interface: iface, zone }),
        });
        await wrLoadAll();
    }

    // ─── LAN runtime health ─────────────────────────────────────────
    //
    // Per-LAN runtime health for the WolfRouter "Health" tab. Renders
    // every LAN owned anywhere in the cluster and surfaces:
    //   • interface state, dnsmasq alive, :53 bound to router_ip
    //   • live UDP DNS probe round-trip
    //   • watchdog circuit-breaker state
    // Plus one-click "Restart dnsmasq" and "Use <iface>" actions wired
    // to the backend self-heal endpoints.

    window.wrRenderLanHealth = wrRenderLanHealth;
    window.wrLanHealthRestart = wrLanHealthRestart;
    window.wrLanHealthSetInterface = wrLanHealthSetInterface;

    async function wrRenderLanHealth() {
        const container = document.getElementById('wr-health-container');
        if (!container) return;
        // Preserve the user's open/closed toggle on the cluster
        // validation banner across the 12s auto-refresh — without this,
        // every poll re-renders the DOM and re-collapses whatever the
        // user had expanded. Saved before the fetch so the new HTML
        // can restore it after.
        const existingBanner = container.querySelector('details.wr-cluster-banner');
        const savedBannerOpen = existingBanner ? existingBanner.open : null;
        // Fetch in parallel: cluster-wide config validation banner +
        // per-LAN health cards. Either one independently failing leaves
        // the other rendered.
        const [validationRes, lansRes] = await Promise.allSettled([
            fetch(wrUrl('/api/router/validation-cluster')),
            fetch(wrUrl('/api/router/health')),
        ]);

        let banner = '';
        try {
            if (validationRes.status === 'fulfilled' && validationRes.value.ok) {
                const v = await validationRes.value.json();
                banner = renderValidationBanner(v);
            }
        } catch (e) {}

        let body = '';
        try {
            if (lansRes.status === 'fulfilled' && lansRes.value.ok) {
                const data = await lansRes.value.json();
                const lans = (data && Array.isArray(data.lans)) ? data.lans : [];
                if (!lans.length) {
                    body = `<div class="card-body" style="color:var(--text-muted);">No LANs configured anywhere in the cluster.</div>`;
                } else {
                    body = lans.map(renderLanHealthCard).join('');
                }
            } else {
                const status = lansRes.status === 'fulfilled'
                    ? `HTTP ${lansRes.value.status}`
                    : String(lansRes.reason);
                body = `<div class="card-body" style="color:var(--accent-red);">Failed to load LAN health: ${escHtml(status)}</div>`;
            }
        } catch (e) {
            body = `<div class="card-body" style="color:var(--accent-red);">Failed to load health: ${escHtml(String(e))}</div>`;
        }

        container.innerHTML = banner + body;
        // Restore the user's toggle if they had one. New banners
        // (first render, or when payload shape changes) fall through to
        // the default open/closed driven by severity.
        if (savedBannerOpen !== null) {
            const newBanner = container.querySelector('details.wr-cluster-banner');
            if (newBanner) newBanner.open = savedBannerOpen;
        }
    }

    function renderValidationBanner(payload) {
        const nodes = (payload && Array.isArray(payload.nodes)) ? payload.nodes : [];
        if (!nodes.length) return '';
        // Count NODES by status (not findings). A node is:
        //   • err  if any of its findings is an error
        //   • warn if any warning and no errors
        //   • ok   if all findings are ok (or it has no findings yet)
        // The summary line is "N nodes · X ok · Y warn · Z err" where
        // X+Y+Z+unreachable = N — operator's mental model is "how
        // many of my nodes are healthy", not "how many checks
        // succeeded across the fleet".
        let nodesOk = 0, nodesWarn = 0, nodesErr = 0;
        let unreachable = 0;
        const rows = nodes.map(n => {
            if (n.error) {
                unreachable++;
                return `<li><strong>${escHtml(n.node_id)}</strong>${n.cluster_name ? ` <span style="color:var(--text-muted);">(${escHtml(n.cluster_name)})</span>` : ''} — <span style="color:#f59e0b;">unreachable: ${escHtml(n.error)}</span></li>`;
            }
            const r = n.report || {};
            const errC  = r.error_count   || 0;
            const warnC = r.warning_count || 0;
            const okC   = r.ok_count      || 0;
            if (errC > 0) {
                nodesErr++;
            } else if (warnC > 0) {
                nodesWarn++;
            } else {
                nodesOk++;
            }
            const colour = errC > 0 ? '#ef4444' : (warnC > 0 ? '#f59e0b' : '#22c55e');
            const ts = r.generated_at ? new Date(r.generated_at * 1000).toLocaleString() : '—';
            const findings = okC + warnC + errC;
            // Per-row detail still shows the breakdown of findings
            // (informational), but the summary uses node counts.
            const inner = findings === 0
                ? `<span style="color:var(--text-muted);">no WolfRouter config on this node</span>`
                : `<span style="color:${colour};">${okC} ok · ${warnC} warn · ${errC} err checks</span>`;
            return `<li><strong>${escHtml(n.node_id)}</strong>${n.is_self ? ' <span style="color:var(--text-muted);">(this node)</span>' : ''} — ${inner} <span style="color:var(--text-muted);">@ ${escHtml(ts)}</span></li>`;
        }).join('');
        const summaryColour = nodesErr > 0 ? '#ef4444' : (nodesWarn > 0 || unreachable > 0 ? '#f59e0b' : '#22c55e');
        const summary = `${nodes.length} node(s) · ${nodesOk} ok · ${nodesWarn} warn · ${nodesErr} err${unreachable > 0 ? ` · ${unreachable} unreachable` : ''}`;
        // Only auto-open when there's something the operator should
        // act on. The wrRenderLanHealth caller preserves the user's
        // manual toggle across refreshes via the `wr-cluster-banner`
        // class — tagging it here so the selector finds it.
        return `
            <details ${(nodesErr > 0 || nodesWarn > 0 || unreachable > 0) ? 'open' : ''} class="card wr-cluster-banner" style="margin-bottom:12px;">
                <summary class="card-header" style="cursor:pointer; display:flex; gap:10px; align-items:center;">
                    <span style="color:${summaryColour}; font-weight:600;">Cluster validation:</span>
                    <span>${escHtml(summary)}</span>
                </summary>
                <div class="card-body" style="font-size:12px;">
                    <ul style="margin:0; padding-left:18px;">${rows}</ul>
                    <div style="margin-top:8px; color:var(--text-muted);">Updated at startup and every 5 minutes by the watchdog. Click "Refresh" to re-fan-out now.</div>
                </div>
            </details>
        `;
    }

    function statusPill(status) {
        const map = {
            ok:      { color:'#22c55e', label:'OK' },
            warning: { color:'#f59e0b', label:'WARN' },
            error:   { color:'#ef4444', label:'ERROR' },
            remote:  { color:'#64748b', label:'REMOTE' },
        };
        const v = map[status] || map.remote;
        return `<span style="display:inline-block; padding:2px 8px; border-radius:10px; background:${v.color}22; color:${v.color}; font-size:11px; font-weight:600; letter-spacing:.4px;">${v.label}</span>`;
    }

    function severityDot(sev, ok) {
        if (ok) return `<span style="color:#22c55e;">●</span>`;
        if (sev === 'warning') return `<span style="color:#f59e0b;">●</span>`;
        return `<span style="color:#ef4444;">●</span>`;
    }

    function renderLanHealthCard(lan) {
        const isRemote = lan.status === 'remote';
        const breakerHtml = lan.breaker
            ? renderBreaker(lan.breaker)
            : '';
        const checks = (lan.checks || []).map(c => `
            <div style="display:flex; gap:10px; padding:8px 10px; border-bottom:1px solid var(--border);">
                <div style="flex:0 0 14px; padding-top:2px;">${severityDot(c.severity, c.ok)}</div>
                <div style="flex:1; min-width:0;">
                    <div style="font-weight:600; font-size:13px;">${escHtml(c.name)}</div>
                    <div style="font-size:12px; color:var(--text-muted); margin-top:2px; white-space:pre-wrap;">${escHtml(c.message || '')}</div>
                    ${c.fix ? `<details style="margin-top:6px;"><summary style="cursor:pointer; font-size:11px; color:#60a5fa;">Show fix</summary><pre style="white-space:pre-wrap; font-size:11px; background:var(--bg-input); padding:8px; border-radius:4px; margin-top:4px;">${escHtml(c.fix)}</pre></details>` : ''}
                    ${c.action === 'restart_dnsmasq' ? `<button class="btn btn-sm" style="margin-top:6px;" onclick="wrLanHealthRestart('${escHtml(lan.lan_id)}')">↻ Restart dnsmasq</button>` : ''}
                    ${c.action === 'set_lan_interface' && lan.apply_resolution && lan.apply_resolution.kind === 'bound_to_actual_interface' ? `<button class="btn btn-sm" style="margin-top:6px;" onclick="wrLanHealthSetInterface('${escHtml(lan.lan_id)}','${escHtml(lan.apply_resolution.actual)}')">Use ${escHtml(lan.apply_resolution.actual)} as the saved interface</button>` : ''}
                </div>
            </div>
        `).join('');
        const remoteNote = isRemote
            ? `<div style="padding:10px; color:var(--text-muted); font-size:12px;">Owned by node <code>${escHtml(lan.node_id)}</code> — runtime checks proxy through that node. <button class="btn btn-sm" onclick="wrLoadLanHealthForLan('${escHtml(lan.lan_id)}')">Load checks</button></div>`
            : '';
        return `
            <div class="card" style="margin-bottom:12px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
                    <div style="display:flex; gap:10px; align-items:center;">
                        ${statusPill(lan.status)}
                        <strong style="font-size:14px;">${escHtml(lan.lan_name)}</strong>
                        <span style="color:var(--text-muted); font-size:12px;">on <code>${escHtml(lan.node_id)}</code></span>
                    </div>
                </div>
                <div class="card-body" style="padding:0;">
                    ${breakerHtml}
                    ${checks || remoteNote}
                </div>
            </div>
        `;
    }

    function renderBreaker(b) {
        if (!b.open && (!b.recent_failure_count || b.recent_failure_count === 0)) return '';
        const color = b.open ? '#ef4444' : '#f59e0b';
        const lastErr = b.last_error ? `<div style="margin-top:4px; font-family:monospace; font-size:11px; color:var(--text-muted);">${escHtml(b.last_error)}</div>` : '';
        const state = b.open
            ? `Watchdog circuit OPEN — ${b.recent_failure_count} restart failures in the last 5 minutes; auto-restart paused. Click "Restart dnsmasq" to retry now.`
            : `${b.recent_failure_count} recent restart failure(s) tracked.`;
        return `<div style="background:${color}22; color:${color}; padding:8px 10px; font-size:12px; border-bottom:1px solid var(--border);">${escHtml(state)}${lastErr}</div>`;
    }

    async function wrLoadLanHealthForLan(lanId) {
        try {
            const r = await fetch(wrUrl('/api/router/segments/' + encodeURIComponent(lanId) + '/health'));
            if (!r.ok) {
                alert('HTTP ' + r.status + ': ' + (await r.text()));
                return;
            }
            // Re-fetch the whole list so the cards refresh in place. The
            // remote node's health is now fresh in cache.
            await wrRenderLanHealth();
        } catch (e) {
            alert(String(e));
        }
    }
    window.wrLoadLanHealthForLan = wrLoadLanHealthForLan;

    async function wrLanHealthRestart(lanId) {
        if (!confirm('Restart dnsmasq for this LAN? DHCP/DNS will drop for ~1s while it respawns.')) return;
        try {
            const r = await fetch(wrUrl('/api/router/segments/' + encodeURIComponent(lanId) + '/restart-dnsmasq'), { method: 'POST' });
            const txt = await r.text();
            if (!r.ok) { alert('Restart failed: ' + txt); return; }
            await wrRenderLanHealth();
        } catch (e) {
            alert('Restart failed: ' + String(e));
        }
    }

    async function wrLanHealthSetInterface(lanId, iface) {
        if (!confirm('Update the LAN to use interface "' + iface + '"? Saves the config and re-applies dnsmasq.')) return;
        try {
            const r = await fetch(wrUrl('/api/router/segments/' + encodeURIComponent(lanId) + '/set-interface'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface }),
            });
            const txt = await r.text();
            if (!r.ok) { alert('Update failed: ' + txt); return; }
            await wrRenderLanHealth();
        } catch (e) {
            alert('Update failed: ' + String(e));
        }
    }

    // ─── Connections + Logs ───

    async function wrRenderConnections() {
        const tbody = document.getElementById('wr-conn-tbody');
        const errBox = document.getElementById('wr-conn-error');
        if (!tbody) return;
        try {
            const r = await fetch(wrUrl('/api/router/connections'));
            const data = r.ok ? await r.json() : { rows: [], error: `HTTP ${r.status}` };
            const rows = data.rows || [];
            if (errBox) {
                if (data.error) {
                    errBox.style.display = 'block';
                    errBox.textContent = data.error;
                } else {
                    errBox.style.display = 'none';
                }
            }
            if (!rows.length) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:16px;">${data.error ? 'No data — see error above.' : 'No tracked connections right now. Generate some traffic and refresh.'}</td></tr>`;
                return;
            }
            tbody.innerHTML = rows.slice(0, 200).map(c => `<tr>
                <td>${escHtml(c.proto || '')}</td>
                <td><code>${escHtml(c.src || '')}</code></td>
                <td><code>${escHtml(c.dst || '')}</code></td>
                <td>${escHtml(c.sport || '')}</td>
                <td>${escHtml(c.dport || '')}</td>
                <td>${escHtml(c.state || '')}</td>
                <td style="color:var(--text-muted); font-family:var(--font-mono); font-size:11px;">${escHtml(c.timeout || '')}</td>
            </tr>`).join('');
        } catch (e) {
            if (errBox) { errBox.style.display = 'block'; errBox.textContent = 'Network error: ' + (e.message || e); }
        }
    }

    // ─── WAN connections (DHCP / Static / PPPoE) ─────────────

    async function wrRenderWan() {
        const list = document.getElementById('wr-wan-list');
        if (!list) return;
        let conns = [];
        let status = [];
        try {
            const [r, sR] = await Promise.all([
                fetch(wrUrl('/api/router/wan')),
                fetch(wrUrl('/api/router/wan-status')),
            ]);
            if (r.ok) conns = await r.json();
            if (sR.ok) status = await sR.json();
        } catch (e) {}
        const statusById = Object.fromEntries(status.map(s => [s.id, s]));
        if (!conns.length) {
            list.innerHTML = `<div style="text-align:center; color:var(--text-muted); padding:30px;">
                No WAN connections yet. WolfRouter doesn't manage your existing DHCP — you only need to add an entry here for <strong>PPPoE</strong> dialers or <strong>static-IP overrides</strong>.
            </div>`;
            return;
        }
        list.innerHTML = conns.map(c => {
            const live = statusById[c.id] || {};
            const modeLabel = c.mode.mode || 'unknown';
            const modeColor = { dhcp: '#3b82f6', static: '#94a3b8', pppoe: '#a855f7' }[modeLabel] || '#94a3b8';
            const liveBadge = live.live_iface
                ? `<span style="color:#22c55e;">⬤ UP</span> on <code>${escHtml(live.live_iface)}</code> · ${escHtml(live.live_ip || '')}`
                : (c.enabled ? '<span style="color:#fbbf24;">⬤ down / connecting</span>' : '<span style="color:var(--text-muted);">○ disabled</span>');
            const modeDetail = (() => {
                if (modeLabel === 'pppoe') {
                    const p = c.mode.config || {};
                    return `user <code>${escHtml(p.username)}</code> · MTU ${p.mtu || 1492}`;
                }
                if (modeLabel === 'static') {
                    const s = c.mode.config || {};
                    return `<code>${escHtml(s.address_cidr)}</code> via <code>${escHtml(s.gateway)}</code>`;
                }
                return '(host DHCP client)';
            })();
            return `<div style="padding:14px; border:1px solid var(--border); border-radius:8px; background:var(--bg-card);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div>
                        <strong style="font-size:15px;">${escHtml(c.name)}</strong>
                        <span class="badge" style="background:${modeColor}22; color:${modeColor}; margin-left:6px; font-size:10px; padding:2px 8px;">${modeLabel.toUpperCase()}</span>
                    </div>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-sm" onclick="wrShowWanEditor('${c.id}')">Edit</button>
                        <button class="btn btn-sm" onclick="wrDeleteWan('${c.id}')">Delete</button>
                    </div>
                </div>
                <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:8px; font-size:12px; color:var(--text-muted);">
                    <div>Interface: <code>${escHtml(c.interface)}</code></div>
                    <div>${modeDetail}</div>
                    <div>${liveBadge}</div>
                </div>
            </div>`;
        }).join('');
    }

    function wrShowWanEditor(id) {
        const existing = id ? null : null;  // we re-fetch below for fresh data
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:640px;">
                <div class="modal-header">
                    <h3>${id ? 'Edit' : 'New'} WAN connection</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        <label>Name<input id="wr-w-name" class="form-control" placeholder="ISP uplink"/></label>
                        <label>Interface<select id="wr-w-iface" class="form-control"></select></label>
                        <label>Mode
                            <select id="wr-w-mode" class="form-control" onchange="wrToggleWanModeFields()">
                                <option value="dhcp">DHCP (most ISPs / cable / fibre router)</option>
                                <option value="static">Static IP</option>
                                <option value="pppoe">PPPoE (ADSL / VDSL / fibre with bridged ONT)</option>
                            </select>
                        </label>
                        <label style="display:flex; align-items:center; gap:6px;">
                            <input type="checkbox" id="wr-w-enabled" checked/> Enabled (start on save)
                        </label>
                    </div>

                    <div id="wr-w-static" style="display:none; margin-top:10px;">
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                            <label>Address (CIDR)<input id="wr-w-addr" class="form-control" placeholder="203.0.113.10/24"/></label>
                            <label>Gateway<input id="wr-w-gw" class="form-control" placeholder="203.0.113.1"/></label>
                            <label style="grid-column:1/-1;">DNS servers (comma-separated)<input id="wr-w-dns" class="form-control" placeholder="1.1.1.1, 9.9.9.9"/></label>
                        </div>
                    </div>

                    <div id="wr-w-pppoe" style="display:none; margin-top:10px;">
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                            <label>Username<input id="wr-w-user" class="form-control" placeholder="user@isp.example"/></label>
                            <label>Password<input id="wr-w-pass" type="password" class="form-control" placeholder="••••••"/></label>
                            <label>Service name (optional)<input id="wr-w-svc" class="form-control" placeholder="leave blank for most ISPs"/></label>
                            <label>MTU<input id="wr-w-mtu" type="number" class="form-control" value="1492" min="576" max="1500"/></label>
                            <label>LCP echo interval (s, 0=off)<input id="wr-w-lcp" type="number" class="form-control" value="30" min="0" max="600"/></label>
                            <label style="display:flex; align-items:center; gap:6px;">
                                <input type="checkbox" id="wr-w-persist" checked/> Auto-reconnect on link drops
                            </label>
                            <label style="grid-column:1/-1; display:flex; align-items:start; gap:6px; padding:8px 10px; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.3); border-radius:4px;">
                                <input type="checkbox" id="wr-w-pppoe-default-route" style="margin-top:2px;"/>
                                <div>
                                    <strong style="color:#fca5a5;">Make this PPP link the default route</strong>
                                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                                        When enabled, pppd <em>replaces</em> the system's existing default gateway the moment the link comes up. ONLY tick this when PPPoE is genuinely your server's primary internet. If the server already reaches the internet via a different NIC, turning this on will break that connectivity immediately.
                                    </div>
                                </div>
                            </label>
                            <label style="grid-column:1/-1; display:flex; align-items:start; gap:6px; padding:8px 10px; background:rgba(251,191,36,0.08); border:1px solid rgba(251,191,36,0.3); border-radius:4px;">
                                <input type="checkbox" id="wr-w-pppoe-peer-dns" style="margin-top:2px;"/>
                                <div>
                                    <strong style="color:#fbbf24;">Use ISP's DNS (overwrites /etc/resolv.conf)</strong>
                                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                                        pppd will overwrite /etc/resolv.conf with the DNS servers the ISP hands out. Clobbers any existing resolver config.
                                    </div>
                                </div>
                            </label>
                        </div>
                        <div style="margin-top:10px; padding:10px; background:rgba(168,85,247,0.08); border:1px solid rgba(168,85,247,0.3); border-radius:6px; font-size:12px; color:var(--text-muted);">
                            On save, WolfRouter writes <code>/etc/ppp/peers/wolfrouter-{id}</code> + secrets (mode 0600), auto-installs the <code>ppp</code> + <code>pppoe</code> packages if missing, then calls <code>pppd</code> to bring the link up. The resulting <code>ppp0</code> appears in the rack view as the WAN port.
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="wrSaveWan('${id || ''}')">${id ? 'Save' : 'Create'}</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);

        // Populate iface dropdown from local-node interfaces.
        const ifSel = document.getElementById('wr-w-iface');
        const ifaces = new Set();
        for (const n of (wrState.topology?.nodes || [])) {
            for (const i of (n.interfaces || [])) ifaces.add(i.name);
        }
        ifSel.innerHTML = Array.from(ifaces).sort().map(i => `<option value="${escHtml(i)}">${escHtml(i)}</option>`).join('') || '<option value="">(no interfaces)</option>';

        // Load existing values if editing.
        if (id) {
            fetch(wrUrl('/api/router/wan')).then(r => r.json()).then(arr => {
                const c = arr.find(x => x.id === id);
                if (!c) return;
                document.getElementById('wr-w-name').value = c.name;
                document.getElementById('wr-w-iface').value = c.interface;
                document.getElementById('wr-w-mode').value = c.mode?.mode || 'dhcp';
                document.getElementById('wr-w-enabled').checked = c.enabled !== false;
                if (c.mode?.mode === 'static') {
                    document.getElementById('wr-w-addr').value = c.mode.config?.address_cidr || '';
                    document.getElementById('wr-w-gw').value = c.mode.config?.gateway || '';
                    document.getElementById('wr-w-dns').value = (c.mode.config?.dns || []).join(', ');
                } else if (c.mode?.mode === 'pppoe') {
                    document.getElementById('wr-w-user').value = c.mode.config?.username || '';
                    // Password masked from server — leave blank; will preserve on save.
                    document.getElementById('wr-w-pass').value = c.mode.config?.password === '***' ? '***' : '';
                    document.getElementById('wr-w-svc').value = c.mode.config?.service_name || '';
                    document.getElementById('wr-w-mtu').value = c.mode.config?.mtu || 1492;
                    document.getElementById('wr-w-lcp').value = c.mode.config?.lcp_echo_interval ?? 30;
                    document.getElementById('wr-w-persist').checked = c.mode.config?.persist !== false;
                    document.getElementById('wr-w-pppoe-default-route').checked = !!c.mode.config?.use_default_route;
                    document.getElementById('wr-w-pppoe-peer-dns').checked = !!c.mode.config?.use_peer_dns;
                }
                wrToggleWanModeFields();
            });
        } else {
            wrToggleWanModeFields();
        }
    }
    window.wrShowWanEditor = wrShowWanEditor;

    function wrToggleWanModeFields() {
        const modeEl = document.getElementById('wr-w-mode');
        if (!modeEl) return;  // modal not open
        const m = modeEl.value;
        const staticEl = document.getElementById('wr-w-static');
        const pppoeEl = document.getElementById('wr-w-pppoe');
        if (staticEl) staticEl.style.display = m === 'static' ? 'block' : 'none';
        if (pppoeEl)  pppoeEl.style.display  = m === 'pppoe'  ? 'block' : 'none';
    }
    window.wrToggleWanModeFields = wrToggleWanModeFields;

    async function wrSaveWan(id) {
        const name = document.getElementById('wr-w-name').value.trim();
        const iface = document.getElementById('wr-w-iface').value.trim();
        const mode = document.getElementById('wr-w-mode').value;
        const enabled = document.getElementById('wr-w-enabled').checked;
        if (!name || !iface) { alert('Name and interface are required'); return; }
        let modeBlock = { mode: 'dhcp' };
        if (mode === 'static') {
            modeBlock = {
                mode: 'static',
                config: {
                    address_cidr: document.getElementById('wr-w-addr').value.trim(),
                    gateway: document.getElementById('wr-w-gw').value.trim(),
                    dns: document.getElementById('wr-w-dns').value.split(',').map(s => s.trim()).filter(Boolean),
                },
            };
        } else if (mode === 'pppoe') {
            modeBlock = {
                mode: 'pppoe',
                config: {
                    username: document.getElementById('wr-w-user').value.trim(),
                    password: document.getElementById('wr-w-pass').value,
                    service_name: document.getElementById('wr-w-svc').value.trim(),
                    mtu: parseInt(document.getElementById('wr-w-mtu').value, 10) || 1492,
                    mru: parseInt(document.getElementById('wr-w-mtu').value, 10) || 1492,
                    persist: document.getElementById('wr-w-persist').checked,
                    lcp_echo_interval: parseInt(document.getElementById('wr-w-lcp').value, 10) || 0,
                    lcp_echo_failure: 4,
                    use_default_route: document.getElementById('wr-w-pppoe-default-route').checked,
                    use_peer_dns: document.getElementById('wr-w-pppoe-peer-dns').checked,
                },
            };
        }
        const body = {
            id: id || '',
            name, interface: iface, mode: modeBlock, enabled,
            node_id: wrState.topology?.nodes?.[0]?.node_id || '',
            description: '',
        };
        const url = wrUrl(id ? '/api/router/wan/' + id : '/api/router/wan');
        const method = id ? 'PUT' : 'POST';
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!r.ok) { alert('Save failed: ' + await r.text()); return; }
        if (typeof showToast === 'function') showToast(`WAN connection '${name}' ${id ? 'updated' : 'created'}`, 'success');
        document.querySelector('.modal-overlay')?.remove();
        await wrLoadAll();
        wrRenderWan();
    }
    window.wrSaveWan = wrSaveWan;

    async function wrDeleteWan(id) {
        if (!confirm('Delete this WAN connection? Any PPPoE link will be torn down.')) return;
        await fetch(wrUrl('/api/router/wan/' + id), { method: 'DELETE' });
        await wrLoadAll();
        wrRenderWan();
    }
    window.wrDeleteWan = wrDeleteWan;
    window.wrRenderWan = wrRenderWan;

    // ─── Policy map — drag-and-drop firewall editor ─────────
    //
    // Renders the current firewall + DNAT state as a directed graph.
    // Nodes: Internet, each Zone, each LAN segment, each VM and
    // container. Edges: one per enabled WolfRouter rule (coloured by
    // action) plus one per IP mapping (DNAT). Drag from a source
    // node to a destination opens the existing rule editor
    // pre-filled. Click an edge to edit or delete it. The whole view
    // auto-populates on load so the user sees "this is what my
    // firewall is doing" before touching anything.

    /// Translate an Endpoint (the serde-tagged enum from the backend)
    /// into a node id on the policy map. Returns null when the
    /// endpoint has no representation (e.g. Any — rendered as an
    /// edge to the Internet node).
    function wrEndpointNodeId(ep) {
        if (!ep) return null;
        switch (ep.kind) {
            case 'any':       return 'internet';
            case 'zone':
                if (!ep.zone) return null;
                if (ep.zone.kind === 'lan') return `zone:lan${ep.zone.id ?? 0}`;
                if (ep.zone.kind === 'custom') return `zone:custom:${ep.zone.id || ''}`;
                return `zone:${ep.zone.kind}`;
            case 'interface': return `iface:${ep.name}`;
            case 'ip':        return `ip:${ep.cidr}`;
            case 'vm':        return `vm:${ep.name}`;
            case 'container': return `ct:${ep.name}`;
            case 'lan':       return `lan:${ep.id}`;
        }
        return null;
    }

    /// Build the full graph {nodes, edges} from the current wrState
    /// snapshot. No fetches — purely derived from data we've already
    /// loaded for the other tabs.
    function wrBuildPolicyGraph() {
        const nodes = new Map();   // id → {id, label, icon, tier, kind, meta}
        const edges = [];
        const addNode = (id, label, icon, tier, kind, meta) => {
            if (!nodes.has(id)) nodes.set(id, { id, label, icon, tier, kind, meta: meta || {} });
        };

        // Tier 0: Internet.
        addNode('internet', 'Internet', '', 0, 'internet');

        // Tier 1: WAN-ish zones (WAN, Management, Trusted).
        addNode('zone:wan',        'WAN',        '', 1, 'zone', { zone: { kind: 'wan' } });
        addNode('zone:management', 'Management', '', 1, 'zone', { zone: { kind: 'management' } });
        addNode('zone:trusted',    'Trusted',    '⭐', 1, 'zone', { zone: { kind: 'trusted' } });

        // Tier 2: LAN-ish zones (LAN0, LAN1, DMZ, WolfNet) — only show
        // zones that actually have interfaces assigned, OR the common
        // defaults so users have somewhere to drag to.
        const seenZones = new Set(['wan', 'management', 'trusted']);
        // Scan zone assignments for custom/LAN zone numbers.
        const assigns = wrState.zones?.assignments || {};
        for (const nodeId of Object.keys(assigns)) {
            for (const iface of Object.keys(assigns[nodeId] || {})) {
                const z = assigns[nodeId][iface];
                if (!z) continue;
                if (z.kind === 'lan') seenZones.add(`lan${z.id ?? 0}`);
                else seenZones.add(z.kind);
            }
        }
        // Ensure core zones exist even if nothing's assigned yet.
        for (const needed of ['lan0', 'dmz', 'wolfnet']) seenZones.add(needed);
        for (const slug of seenZones) {
            if (['wan', 'management', 'trusted'].includes(slug)) continue;  // already tier 1
            if (slug.startsWith('lan')) {
                const n = parseInt(slug.slice(3), 10) || 0;
                addNode(`zone:${slug}`, `LAN ${n}`, '', 2, 'zone', { zone: { kind: 'lan', id: n } });
            } else if (slug === 'dmz') {
                addNode('zone:dmz', 'DMZ', '', 2, 'zone', { zone: { kind: 'dmz' } });
            } else if (slug === 'wolfnet') {
                addNode('zone:wolfnet', 'WolfNet', '', 2, 'zone', { zone: { kind: 'wolfnet' } });
            } else {
                addNode(`zone:${slug}`, slug, '', 2, 'zone', { zone: { kind: slug } });
            }
        }

        // Always show the full cluster topology — ports, bridges,
        // VLANs, VMs, containers, all wired together — so the map is
        // a single "at a glance" view of where traffic flows. The
        // node selector becomes an optional filter; by default we
        // draw everything across every cluster node.
        //
        // Ports/bridges/vlans are namespaced by node_id because
        // iface names (eth0, vmbr0, docker0) collide across hosts.
        const selNode = wrPolicyUi.selectedNode || '';
        const lanTier    = 6;
        const deviceTier = 7;

        // LAN segments (served by WolfRouter with DHCP+DNS).
        for (const lan of (wrState.lans || [])) {
            addNode(`lan:${lan.id}`, lan.name, '', lanTier, 'lan', { lan, ip: lan.subnet_cidr });
        }

        // Per-cluster-node topology: ports, vlans, bridges, VMs, CTs.
        for (const n of (wrState.topology?.nodes || [])) {
            if (selNode && n.node_id !== selNode) continue;
            const nodeTag = n.node_name || n.node_id;
            for (const p of (n.interfaces || [])) {
                const ip = (p.addresses && p.addresses[0]) || '';
                const icon = p.link_up ? '' : '';
                addNode(`port:${n.node_id}:${p.name}`, `${nodeTag}·${p.name}`, icon, 3, 'port', {
                    port: p, node: n.node_id, ip,
                });
            }
            for (const v of (n.vlans || [])) {
                const ip = (v.addresses && v.addresses[0]) || '';
                addNode(`vlan:${n.node_id}:${v.name}`, `${nodeTag}·${v.name}`, '', 4, 'vlan', {
                    vlan: v, node: n.node_id, ip: ip || `VLAN ${v.vlan_id}`,
                });
            }
            for (const b of (n.bridges || [])) {
                const ip = (b.addresses && b.addresses[0]) || '';
                addNode(`br:${n.node_id}:${b.name}`, `${nodeTag}·${b.name}`, '', 5, 'bridge', {
                    bridge: b, node: n.node_id, ip,
                });
            }
            for (const vm of (n.vms || [])) {
                addNode(`vm:${vm.name}`, vm.name, '', deviceTier, 'vm', {
                    vm, node: n.node_id, ip: vm.ip || '',
                });
            }
            for (const ct of (n.containers || [])) {
                addNode(`ct:${ct.name}`, ct.name, '', deviceTier, 'container', {
                    ct, node: n.node_id, ip: ct.ip || ct.attached_to || '',
                });
            }
        }

        // ── Implicit infrastructure edges ───────────────────────
        // Without these the graph is a bunch of unconnected dots
        // whenever the user has no explicit firewall rules yet. Show
        // the TOPOLOGY as faint grey edges so the mental model is
        // always legible: Internet ↔ WAN ↔ zones ↔ LAN segments ↔
        // devices. These are visual only — no rule behind them,
        // clicking does nothing special.
        const implicitEdge = (from, to, label) => {
            if (!nodes.has(from) || !nodes.has(to)) return;
            edges.push({
                id: `implicit:${from}|${to}`,
                from, to,
                kind: 'implicit',
                action: 'implicit',
                colour: '#64748b',
                enabled: true,
                label: label || '',
            });
        };
        // Internet ↔ WAN (classic uplink). Color + label reflect
        // live WAN state from /api/router/wan-status: green when at
        // least one configured WAN is actually up (PPPoE dialed,
        // ppp0 has an IP), red when configured but every link is
        // down, grey when nothing's configured (the user is relying
        // on the host's pre-existing DHCP and WolfRouter has no
        // managed dialer to report on).
        if (nodes.has('internet') && nodes.has('zone:wan')) {
            const wans = wrState.wan || [];
            const wanStatus = wrState.wanStatus || [];
            const statusById = Object.fromEntries(wanStatus.map(s => [s.id, s]));
            const enabledWans = wans.filter(w => w.enabled);
            const liveWans = enabledWans.filter(w => statusById[w.id]?.live_iface);
            let colour = '#64748b'; // grey — nothing managed
            let label = 'uplink';
            let dashed = false;
            if (enabledWans.length > 0) {
                if (liveWans.length > 0) {
                    colour = '#22c55e'; // green — at least one up
                    const w = liveWans[0];
                    const live = statusById[w.id];
                    const mode = (w.mode?.mode || '').toUpperCase();
                    label = liveWans.length === 1
                        ? `${mode || 'WAN'} UP · ${live.live_iface}${live.live_ip ? ' · ' + live.live_ip : ''}`
                        : `${liveWans.length}/${enabledWans.length} WANs UP`;
                } else {
                    colour = '#ef4444'; // red — configured but nothing up
                    const w = enabledWans[0];
                    const mode = (w.mode?.mode || '').toUpperCase();
                    label = enabledWans.length === 1
                        ? `${mode || 'WAN'} DOWN · ${w.interface}`
                        : `${enabledWans.length} WANs DOWN`;
                    dashed = true;
                }
            } else if (wans.length > 0) {
                // Only disabled entries — show that explicitly so the
                // user doesn't think nothing is configured.
                label = 'uplink (disabled)';
                dashed = true;
            }
            edges.push({
                id: 'implicit:internet|zone:wan',
                from: 'internet', to: 'zone:wan',
                kind: 'implicit',
                action: 'implicit',
                colour,
                enabled: !dashed,
                label,
            });
        }
        // Each LAN segment belongs to its zone.
        for (const lan of (wrState.lans || [])) {
            const zId = lan.zone?.kind === 'lan'
                ? `zone:lan${lan.zone.id ?? 0}`
                : `zone:${lan.zone?.kind}`;
            implicitEdge(`lan:${lan.id}`, zId, '');
        }
        // VMs with a WolfNet IP attach to the WolfNet zone. VMs on a
        // passthrough bridge attach to the LAN zone that bridge is in.
        // Physical wiring, per cluster node:
        //   port ─(slave)─→ bridge          (PortState.master)
        //   vlan ─(child)──→ parent port     (VlanState.parent)
        //   port ─────────→ zone             (role/zone, when unbridged)
        //   bridge ──────→ zone              (BridgeState.zone)
        //   vm/ct ───────→ attached bridge   (attached_to)
        for (const n of (wrState.topology?.nodes || [])) {
            if (selNode && n.node_id !== selNode) continue;
            const portId = (name) => `port:${n.node_id}:${name}`;
            const brId   = (name) => `br:${n.node_id}:${name}`;
            const vlanId = (name) => `vlan:${n.node_id}:${name}`;

            for (const p of (n.interfaces || [])) {
                if (p.master && nodes.has(brId(p.master))) {
                    implicitEdge(portId(p.name), brId(p.master), '');
                } else if (p.zone) {
                    const zid = p.zone.kind === 'lan'
                        ? `zone:lan${p.zone.id ?? 0}`
                        : `zone:${p.zone.kind}`;
                    implicitEdge(portId(p.name), zid, p.role || '');
                } else if (p.role && p.role !== 'unused') {
                    const zid = p.role === 'wan' ? 'zone:wan'
                              : p.role === 'management' ? 'zone:management'
                              : p.role === 'wolfnet' ? 'zone:wolfnet'
                              : p.role === 'lan' ? 'zone:lan0'
                              : null;
                    if (zid) implicitEdge(portId(p.name), zid, p.role);
                }
            }
            for (const v of (n.vlans || [])) {
                if (v.parent && nodes.has(portId(v.parent))) {
                    implicitEdge(vlanId(v.name), portId(v.parent), `vlan ${v.vlan_id}`);
                }
            }
            for (const b of (n.bridges || [])) {
                if (b.zone) {
                    const zid = b.zone.kind === 'lan'
                        ? `zone:lan${b.zone.id ?? 0}`
                        : `zone:${b.zone.kind}`;
                    implicitEdge(brId(b.name), zid, '');
                }
            }
            for (const vm of (n.vms || [])) {
                const toBr = vm.attached_to && nodes.has(brId(vm.attached_to))
                    ? brId(vm.attached_to) : null;
                if (toBr) {
                    implicitEdge(`vm:${vm.name}`, toBr, '');
                } else if (vm.attached_to === 'wolfnet' || vm.ip) {
                    implicitEdge(`vm:${vm.name}`, 'zone:wolfnet', '');
                }
            }
            for (const ct of (n.containers || [])) {
                const toBr = ct.attached_to && nodes.has(brId(ct.attached_to))
                    ? brId(ct.attached_to) : null;
                if (toBr) {
                    implicitEdge(`ct:${ct.name}`, toBr, '');
                } else {
                    implicitEdge(`ct:${ct.name}`, 'zone:lan0', '');
                }
            }
        }

        // Edges from firewall rules. An Any source/dest is rendered
        // as an edge to/from Internet (visual shorthand — a rule
        // with from=Any means "anywhere, including the internet").
        const actionColour = {
            allow:  '#22c55e',
            deny:   '#ef4444',
            reject: '#f97316',
            log:    '#60a5fa',
        };
        for (const rule of (wrState.rules || [])) {
            const fromId = wrEndpointNodeId(rule.from);
            const toId   = wrEndpointNodeId(rule.to);
            if (!fromId || !toId) continue;
            // Ensure endpoint-derived nodes exist (e.g. rule references
            // an IP/interface we don't have a node for yet).
            if (!nodes.has(fromId)) {
                addNode(fromId, fromId.split(':').slice(1).join(':') || fromId, '•', 2, 'dynamic');
            }
            if (!nodes.has(toId)) {
                addNode(toId, toId.split(':').slice(1).join(':') || toId, '•', 2, 'dynamic');
            }
            edges.push({
                id: 'rule:' + rule.id,
                from: fromId, to: toId,
                kind: 'rule',
                action: rule.action,
                colour: actionColour[rule.action] || '#94a3b8',
                enabled: rule.enabled !== false,
                label: `${rule.protocol || 'any'}${rule.ports?.length ? ':' + rule.ports.map(p=>p.port).join(',') : ''}`,
                rule,
            });
        }

        // Edges from IP mappings (DNAT): Internet → target WolfNet IP
        // / VM. These are port forwards.
        for (const m of (wrState.managed?.ip_mappings || [])) {
            const toName = (wrState.topology?.nodes || []).flatMap(n => n.vms || [])
                .find(v => v.ip === m.wolfnet_ip)?.name;
            const toId = toName ? `vm:${toName}` : `ip:${m.wolfnet_ip}/32`;
            if (!nodes.has(toId)) addNode(toId, m.wolfnet_ip, '', 4, 'dynamic');
            edges.push({
                id: 'mapping:' + m.id,
                from: 'internet', to: toId,
                kind: 'dnat',
                action: 'dnat',
                colour: '#a855f7',
                enabled: m.enabled !== false,
                label: `${(m.protocol || 'all').toUpperCase()}${m.ports ? ' :' + m.ports : ''}`,
                mapping: m,
            });
        }

        return { nodes: Array.from(nodes.values()), edges };
    }

    /// Hierarchical layout: group nodes by tier, space them evenly
    /// across the canvas width. Returns a map of node id → {x, y}.
    function wrLayoutPolicyGraph(graph, width, height) {
        const layout = new Map();
        const tiers = {};
        for (const n of graph.nodes) {
            if (!tiers[n.tier]) tiers[n.tier] = [];
            tiers[n.tier].push(n);
        }
        const tierKeys = Object.keys(tiers).map(n => parseInt(n, 10)).sort((a, b) => a - b);
        const tierCount = tierKeys.length;
        const rowH = Math.max(110, height / Math.max(tierCount, 1));
        for (let i = 0; i < tierKeys.length; i++) {
            const row = tiers[tierKeys[i]];
            const y = rowH * (i + 0.5);
            const spacing = width / (row.length + 1);
            row.forEach((n, idx) => {
                layout.set(n.id, { x: spacing * (idx + 1), y, node: n });
            });
        }
        return layout;
    }

    /// Per-view UI state for the policy map. Survives across renders
    /// so filters / traced-node / sim path don't reset on topology
    /// refresh.
    let wrPolicyUi = {
        filters: { allow: true, deny: true, reject: true, log: true, dnat: true, disabled: false },
        search: '',
        selectedNode: '',   // cluster node_id to limit VMs/containers to (empty = all)
        tracedNode: null,   // node id currently in "trace mode" (null = off)
        simPath: null,      // { edgeIds: [...], verdict: 'allow' | 'deny' | ... }
        zoom: 1,            // 1.0 = fit to window; <1 zooms out; >1 zooms in
    };

    /// Traffic rates per node id (in bps rx + tx). Computed once per
    /// render from topology.nodes[].interfaces[].{rx_bps,tx_bps}
    /// joined with the per-node zone assignments so we can total up
    /// "how much traffic is flowing across WAN right now" etc.
    function wrComputeNodeTraffic(fullGraph) {
        const bps = new Map();  // node-id → { rx, tx, speedMbps }
        const topo = wrState.topology;
        if (!topo) return bps;

        // Iterate every cluster node's interfaces and bucket the
        // traffic by which policy-map node each iface rolls up into.
        for (const node of (topo.nodes || [])) {
            const asg = wrState.zones?.assignments?.[node.node_id] || {};
            for (const iface of (node.interfaces || [])) {
                const rx = iface.rx_bps || 0, tx = iface.tx_bps || 0;
                const sp = iface.speed_mbps || 0;
                const addTo = (id) => {
                    const cur = bps.get(id) || { rx: 0, tx: 0, speedMbps: 0 };
                    cur.rx += rx; cur.tx += tx;
                    cur.speedMbps = Math.max(cur.speedMbps, sp);
                    bps.set(id, cur);
                };
                // Per-port bucket — makes the port node in the policy
                // map show its own BPS tag and heats up the edges it
                // sits on, so bottlenecks are obvious.
                addTo(`port:${node.node_id}:${iface.name}`);
                // Always add to the role-derived zone if assigned.
                const assigned = asg[iface.name];
                if (assigned) {
                    const zid = assigned.kind === 'lan'
                        ? `zone:lan${assigned.id ?? 0}`
                        : `zone:${assigned.kind}`;
                    addTo(zid);
                } else if (iface.role) {
                    const zid = iface.role === 'wan' ? 'zone:wan'
                              : iface.role === 'management' ? 'zone:management'
                              : iface.role === 'lan' ? 'zone:lan0'
                              : iface.role === 'wolfnet' ? 'zone:wolfnet'
                              : null;
                    if (zid) addTo(zid);
                }
                // WAN role also counts toward Internet.
                if (iface.role === 'wan') addTo('internet');
            }
        }
        return bps;
    }

    /// Format bps into a short humanised string. Used on edge labels
    /// and the summary bar so operators can read them at a glance.
    function wrFmtBps(bps) {
        if (!bps || bps < 1) return '—';
        if (bps < 1024) return bps.toFixed(0) + ' bps';
        if (bps < 1024*1024) return (bps/1024).toFixed(1) + ' Kbps';
        if (bps < 1024*1024*1024) return (bps/1048576).toFixed(1) + ' Mbps';
        return (bps/1073741824).toFixed(2) + ' Gbps';
    }

    /// Pick a heat colour for a link given its utilisation as a
    /// fraction of link speed. Used to tint edges so a saturated
    /// link goes red on the policy map.
    function wrHeatColour(utilFrac) {
        if (utilFrac >= 0.70) return '#ef4444';  // red
        if (utilFrac >= 0.30) return '#fbbf24';  // amber
        return null;  // no override — use the rule's action colour
    }

    /// Walk every node in the graph and flag it with a warning level
    /// when something's wrong:
    ///   danger  — down links, crash-looping containers, orphan VMs
    ///   warn    — unassigned ports, ports with no zone, link saturated
    /// Returns Map<nodeId, { level, reasons }>. The render loop uses
    /// this to paint a red/amber glow + tooltip so problems jump out.
    function wrComputeNodeWarnings(fullGraph) {
        const out = new Map();
        const add = (id, level, reason) => {
            const cur = out.get(id) || { level: 'warn', reasons: [] };
            // Promote to danger if any reason is danger-level.
            if (level === 'danger') cur.level = 'danger';
            cur.reasons.push(reason);
            out.set(id, cur);
        };
        // Port-level checks from topology.
        for (const n of (wrState.topology?.nodes || [])) {
            for (const p of (n.interfaces || [])) {
                const pid = `port:${n.node_id}:${p.name}`;
                if (!fullGraph.nodes.some(x => x.id === pid)) continue;
                if (p.link_up === false) {
                    // WAN down is catastrophic; any other port down is
                    // merely a warning (could be a spare).
                    const isWan = p.role === 'wan';
                    add(pid, isWan ? 'danger' : 'warn',
                        isWan ? 'WAN link is down' : 'link down');
                }
                const hasAddr = (p.addresses && p.addresses.length) ||
                                (p.master); // slave port inherits from bridge
                if (p.role && p.role !== 'unused' && !hasAddr) {
                    add(pid, 'warn', `role=${p.role} but no IP configured`);
                }
            }
            for (const vm of (n.vms || [])) {
                const vid = `vm:${vm.name}`;
                if (!fullGraph.nodes.some(x => x.id === vid)) continue;
                if (!vm.ip && !vm.attached_to) {
                    add(vid, 'warn', 'VM has no network attachment');
                }
            }
            for (const ct of (n.containers || [])) {
                const cid = `ct:${ct.name}`;
                if (!fullGraph.nodes.some(x => x.id === cid)) continue;
                if (!ct.ip && !ct.attached_to) {
                    add(cid, 'warn', 'container has no network attachment');
                }
                // Restart-loop / stopped-but-should-be-running signals
                // come from the `state` field on the topology-supplied
                // container record (present for docker).
                if (ct.state === 'restarting') {
                    add(cid, 'danger', 'container is restart-looping');
                } else if (ct.state === 'exited' || ct.state === 'dead') {
                    add(cid, 'warn', `container is ${ct.state}`);
                }
            }
        }
        // WAN node + uplink edge: flag the zone:wan node when every
        // configured/enabled WAN is down. This drives the danger
        // glow on the WAN zone in the policy graph so a dropped
        // PPPoE link is impossible to miss. Skipped when nothing is
        // configured (the user is on the host's pre-existing DHCP
        // and WolfRouter has nothing to report).
        {
            const wans = (wrState.wan || []).filter(w => w.enabled);
            const wanStatus = wrState.wanStatus || [];
            const liveById = new Set(wanStatus.filter(s => s.live_iface).map(s => s.id));
            if (wans.length > 0 && wans.every(w => !liveById.has(w.id))) {
                const detail = wans.length === 1
                    ? `${(wans[0].mode?.mode || 'WAN').toUpperCase()} on ${wans[0].interface} is not connected`
                    : `${wans.length} WAN connections configured, none are up`;
                if (fullGraph.nodes.some(x => x.id === 'zone:wan')) {
                    add('zone:wan', 'danger', detail);
                }
            }
        }
        // LAN segments without a DHCP range — boots-from-zero install
        // would give zero leases. Easy mistake, easy to flag.
        for (const lan of (wrState.lans || [])) {
            if (lan.dhcp && lan.dhcp.enabled) {
                if (!lan.dhcp.range_start || !lan.dhcp.range_end) {
                    add(`lan:${lan.id}`, 'warn', 'DHCP enabled but range is empty');
                }
            }
        }
        // Zones referenced by rules but with no interface assignment
        // in this cluster — rules can't fire if nothing's in the zone.
        const assignedZones = new Set();
        const asgAll = wrState.zones?.assignments || {};
        for (const nodeId of Object.keys(asgAll)) {
            for (const iface of Object.keys(asgAll[nodeId] || {})) {
                const z = asgAll[nodeId][iface];
                if (!z) continue;
                assignedZones.add(z.kind === 'lan' ? `zone:lan${z.id ?? 0}` : `zone:${z.kind}`);
            }
        }
        for (const zn of fullGraph.nodes.filter(n => n.kind === 'zone')) {
            if (zn.id === 'zone:wan' || zn.id === 'zone:management' || zn.id === 'zone:trusted') {
                // WAN/Mgmt/Trusted: no assignment is fine if no rules
                // reference them — only warn if the zone's in a rule.
                const referenced = (wrState.rules || []).some(r =>
                    wrEndpointNodeId(r.from) === zn.id || wrEndpointNodeId(r.to) === zn.id);
                if (referenced && !assignedZones.has(zn.id)) {
                    add(zn.id, 'warn', 'rules reference this zone but no interface is assigned to it');
                }
            }
        }
        return out;
    }

    /// Render the canvas from scratch. Safe to call on every poll —
    /// cheap because graphs stay small (dozens of nodes, not
    /// thousands).
    function wrRenderPolicyMap() {
        const host = document.getElementById('wr-policy-canvas');
        if (!host) return;
        const fullGraph = wrBuildPolicyGraph();
        if (!fullGraph.nodes.length) {
            host.innerHTML = '<div style="color:var(--text-muted); text-align:center; padding:60px;">No data yet.</div>';
            return;
        }

        // Apply filters: action-type toggles + node-name search.
        // Edges are filtered by their action; nodes are filtered by
        // text match, but we keep every node that's still referenced
        // by a visible edge so the graph stays connected.
        const f = wrPolicyUi.filters;
        const searchText = (wrPolicyUi.search || '').toLowerCase().trim();
        const edgeVisible = (e) => {
            if (!e.enabled && !f.disabled) return false;
            if (e.kind === 'dnat') return f.dnat;
            return f[e.action] !== false;
        };
        const edges = fullGraph.edges.filter(edgeVisible);
        let nodes = fullGraph.nodes;
        if (searchText) {
            const hit = new Set(nodes.filter(n => n.label.toLowerCase().includes(searchText)).map(n => n.id));
            // Include the other end of any edge touching a matching node.
            for (const e of edges) {
                if (hit.has(e.from)) hit.add(e.to);
                if (hit.has(e.to))   hit.add(e.from);
            }
            nodes = nodes.filter(n => hit.has(n.id));
        }
        const graph = { nodes, edges };

        // Group edges by unordered-pair for fan-out rendering — many
        // rules between the same pair used to stack on one path.
        const bundleKey = (from, to) => [from, to].sort().join(' | ');
        const bundles = new Map();
        for (const e of edges) {
            const k = bundleKey(e.from, e.to);
            if (!bundles.has(k)) bundles.set(k, []);
            bundles.get(k).push(e);
        }

        // Per-node throughput map — used by the edge renderer to
        // show live BPS and colour saturated links red.
        const nodeBps = wrComputeNodeTraffic(fullGraph);

        // Render the per-cluster-node throughput strip. Each cluster
        // node gets one badge: hostname + rx/tx summed across its
        // interfaces. Drops immediately show up as tiny bars.
        const nodeBwStrip = document.getElementById('wr-policy-node-bw');
        if (nodeBwStrip) {
            const cluster = wrState.topology?.nodes || [];
            if (!cluster.length) {
                nodeBwStrip.innerHTML = '';
            } else {
                // Find the max aggregate across cluster nodes so we
                // can scale the little inline bar consistently.
                const aggregates = cluster.map(n => {
                    let rx = 0, tx = 0, speedMbps = 0;
                    for (const i of (n.interfaces || [])) {
                        rx += i.rx_bps || 0; tx += i.tx_bps || 0;
                        speedMbps = Math.max(speedMbps, i.speed_mbps || 0);
                    }
                    return { name: n.node_name, rx, tx, speedMbps };
                });
                const maxRx = Math.max(1, ...aggregates.map(a => a.rx));
                const maxTx = Math.max(1, ...aggregates.map(a => a.tx));
                nodeBwStrip.innerHTML = `<span style="color:var(--text);">Cluster throughput:</span> ` +
                    aggregates.map(a => {
                        const rxPct = (a.rx / maxRx) * 100;
                        const txPct = (a.tx / maxTx) * 100;
                        const linkBps = (a.speedMbps || 1000) * 1e6;
                        const util = (a.rx + a.tx) / linkBps;
                        const colour = util >= 0.7 ? '#ef4444' : util >= 0.3 ? '#fbbf24' : '#22c55e';
                        return `<span style="display:inline-flex; align-items:center; gap:4px; padding:3px 8px; background:var(--bg-card); border:1px solid var(--border); border-radius:4px;">
                            <span style="font-weight:600; color:var(--text);">${escHtml(a.name)}</span>
                            <span style="color:${colour};">⬇${wrFmtBps(a.rx)}</span>
                            <span style="color:${colour};">⬆${wrFmtBps(a.tx)}</span>
                            <span style="display:inline-block; width:40px; height:4px; background:var(--bg-secondary); border-radius:2px; position:relative;">
                                <span style="position:absolute; left:0; top:0; height:100%; width:${Math.min(100, rxPct)}%; background:${colour}; border-radius:2px;"></span>
                            </span>
                        </span>`;
                    }).join('');
            }
        }

        const wrap = document.getElementById('wr-policy-canvas-wrap');
        const wrapW = wrap?.clientWidth || 1000;
        // Canvas grows to fit the widest row (210px per node) so ports
        // on a big cluster don't end up a crammed ribbon across the
        // middle; wrap has overflow:auto so users pan horizontally.
        // Vertical space is a generous 190px per tier.
        const tierCounts = {};
        for (const n of graph.nodes) {
            tierCounts[n.tier] = (tierCounts[n.tier] || 0) + 1;
        }
        const maxRow = Math.max(1, ...Object.values(tierCounts));
        const tierCount = Object.keys(tierCounts).length || 1;
        const baseW = Math.max(wrapW, maxRow * 210);
        const baseH = Math.max(680, tierCount * 190);
        const layout = wrLayoutPolicyGraph(graph, baseW - 60, baseH);

        const zoom = Math.max(0.3, Math.min(2.5, wrPolicyUi.zoom || 1));
        const W = baseW * zoom, H = baseH * zoom;
        const ns = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('width', W);
        svg.setAttribute('height', H);
        svg.setAttribute('viewBox', `0 0 ${baseW} ${baseH}`);
        svg.setAttribute('xmlns', ns);
        svg.style.display = 'block';

        svg.insertAdjacentHTML('afterbegin', `
            <defs>
                <marker id="wr-policy-arrow" viewBox="0 -5 10 10" refX="10" refY="0" markerWidth="6" markerHeight="6" orient="auto">
                    <path d="M0,-5L10,0L0,5" fill="currentColor"/>
                </marker>
                <filter id="wr-policy-glow" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="3" result="b"/>
                    <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
                <filter id="wr-policy-warn-glow" x="-80%" y="-80%" width="260%" height="260%">
                    <feGaussianBlur stdDeviation="5" result="b"/>
                    <feFlood flood-color="#ef4444" flood-opacity="0.9" result="c"/>
                    <feComposite in="c" in2="b" operator="in" result="cb"/>
                    <feMerge><feMergeNode in="cb"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
                <filter id="wr-policy-amber-glow" x="-80%" y="-80%" width="260%" height="260%">
                    <feGaussianBlur stdDeviation="4" result="b"/>
                    <feFlood flood-color="#fbbf24" flood-opacity="0.85" result="c"/>
                    <feComposite in="c" in2="b" operator="in" result="cb"/>
                    <feMerge><feMergeNode in="cb"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
                <radialGradient id="wr-sim-packet">
                    <stop offset="0" stop-color="#fde68a"/>
                    <stop offset="0.5" stop-color="#f59e0b"/>
                    <stop offset="1" stop-color="#92400e" stop-opacity="0"/>
                </radialGradient>
            </defs>
        `);

        // Compute which nodes + edges are "live" for the trace/sim
        // highlight, so we can dim the rest.
        const tracedEdgeIds = new Set();
        const tracedNodeIds = new Set();
        if (wrPolicyUi.tracedNode) {
            tracedNodeIds.add(wrPolicyUi.tracedNode);
            for (const e of edges) {
                if (e.from === wrPolicyUi.tracedNode || e.to === wrPolicyUi.tracedNode) {
                    tracedEdgeIds.add(e.id);
                    tracedNodeIds.add(e.from);
                    tracedNodeIds.add(e.to);
                }
            }
        }
        if (wrPolicyUi.simPath) {
            for (const id of wrPolicyUi.simPath.edgeIds) tracedEdgeIds.add(id);
        }
        const dimMode = wrPolicyUi.tracedNode != null;

        // Edges with fan-out offsets so parallel rules don't stack.
        // Edges tinted by utilisation when both endpoints have a BPS
        // reading — saturated links go red so bottlenecks jump out.
        for (const [, bundle] of bundles) {
            const n = bundle.length;
            bundle.forEach((e, idx) => {
                const a = layout.get(e.from), b = layout.get(e.to);
                if (!a || !b) return;
                const t = n === 1 ? 0 : (idx - (n - 1) / 2);
                const spread = 28;
                const dx = b.x - a.x, dy = b.y - a.y;
                const len = Math.hypot(dx, dy) || 1;
                const nx = -dy / len, ny = dx / len;
                const cx = (a.x + b.x) / 2 + nx * t * spread;
                const cy = (a.y + b.y) / 2 + ny * t * spread;
                const path = `M ${a.x},${a.y} Q ${cx},${cy} ${b.x},${b.y}`;
                const dim = dimMode && !tracedEdgeIds.has(e.id);
                const opacity = (e.enabled ? 0.85 : 0.35) * (dim ? 0.18 : 1);

                // Bottleneck analysis: the edge's effective throughput
                // is the minimum of the traffic measured at the two
                // endpoints that ACTUALLY have a measurement. An edge
                // from "zone that's measured" to "VM that isn't" uses
                // the measured side straight — don't silently zero it
                // out with Math.min(measured, 0).
                const fromBps = nodeBps.get(e.from);
                const toBps   = nodeBps.get(e.to);
                let edgeRx = 0, edgeTx = 0, edgeSpeedMbps = 0, util = 0;
                if (fromBps && toBps) {
                    edgeRx = Math.min(fromBps.rx, toBps.rx);
                    edgeTx = Math.min(fromBps.tx, toBps.tx);
                    const speeds = [fromBps.speedMbps, toBps.speedMbps].filter(Boolean);
                    edgeSpeedMbps = speeds.length ? Math.min(...speeds) : 1000;
                    const avgTotal = ((fromBps.rx + fromBps.tx) + (toBps.rx + toBps.tx)) / 2;
                    util = avgTotal / Math.max(1, edgeSpeedMbps * 1e6);
                } else if (fromBps) {
                    edgeRx = fromBps.rx; edgeTx = fromBps.tx;
                    edgeSpeedMbps = fromBps.speedMbps || 1000;
                    util = (fromBps.rx + fromBps.tx) / Math.max(1, edgeSpeedMbps * 1e6);
                } else if (toBps) {
                    edgeRx = toBps.rx; edgeTx = toBps.tx;
                    edgeSpeedMbps = toBps.speedMbps || 1000;
                    util = (toBps.rx + toBps.tx) / Math.max(1, edgeSpeedMbps * 1e6);
                }
                const heat = wrHeatColour(util);
                const strokeColour = heat || e.colour;
                // Scale stroke width by traffic so a fat cable = busy.
                const bpsTotal = edgeRx + edgeTx;
                const trafficBoost = bpsTotal > 0
                    ? Math.min(4, Math.log10(Math.max(1, bpsTotal / 1000)))
                    : 0;
                const baseW = e.enabled ? 2.5 : 1.5;
                const isTraced = tracedEdgeIds.has(e.id);
                const strokeW = baseW + trafficBoost + (isTraced ? 1.5 : 0);
                const bpsLabel = bpsTotal > 0
                    ? ` · ${wrFmtBps(bpsTotal)}${util >= 0.7 ? ' ' : ''}`
                    : '';
                svg.insertAdjacentHTML('beforeend', `
                    <g class="wr-policy-edge" data-edge="${escHtml(e.id)}" style="cursor:pointer; color:${strokeColour};">
                        <path d="${path}" fill="none" stroke="${strokeColour}"
                              stroke-width="${strokeW.toFixed(2)}"
                              opacity="${opacity}"
                              stroke-dasharray="${e.enabled ? (bpsTotal > 0 ? '10 6' : 'none') : '4 3'}"
                              marker-end="url(#wr-policy-arrow)"
                              ${bpsTotal > 0 ? 'class="wr-wire-active"' : ''}
                              ${isTraced ? 'filter="url(#wr-policy-glow)"' : ''}/>
                        <path d="${path}" fill="none" stroke="transparent" stroke-width="14"/>
                        <text x="${cx}" y="${cy - 6}" text-anchor="middle"
                              style="fill:${strokeColour}; font-size:10px; font-family:var(--font-mono,monospace); pointer-events:none; opacity:${opacity};">${escHtml(e.label || '')}${escHtml(bpsLabel)}</text>
                    </g>
                `);
            });
        }

        // Nodes on top. Dim when trace mode is active and we're not
        // on the traced graph. Nodes with a meta.ip get a taller rect
        // so we can show the IP/subnet on a second line. Nodes that
        // fail a health check get a red or amber glow + tooltip so
        // problems are spottable at a glance.
        const warnings = wrComputeNodeWarnings(fullGraph);
        const nodeW = 160, nodeH = 38, nodeHip = 56;
        for (const n of graph.nodes) {
            const p = layout.get(n.id);
            if (!p) continue;
            const ipText = (n.meta && n.meta.ip) ? String(n.meta.ip) : '';
            const h = ipText ? nodeHip : nodeH;
            const x = p.x - nodeW/2, y = p.y - h/2;
            const warn = warnings.get(n.id);
            const fill = {
                internet: 'rgba(96,165,250,0.18)', zone: 'rgba(168,85,247,0.18)',
                lan: 'rgba(34,197,94,0.15)', vm: 'rgba(59,130,246,0.12)',
                container:'rgba(168,85,247,0.12)',
                port: 'rgba(250,204,21,0.14)', bridge: 'rgba(45,212,191,0.14)',
                vlan: 'rgba(244,114,182,0.14)',
            }[n.kind] || 'rgba(148,163,184,0.12)';
            const stroke = {
                internet: '#60a5fa', zone: '#a855f7', lan: '#22c55e',
                vm: '#60a5fa', container:'#a855f7',
                port: '#facc15', bridge: '#2dd4bf', vlan: '#f472b6',
            }[n.kind] || '#94a3b8';
            const dim = dimMode && !tracedNodeIds.has(n.id);
            const opacity = dim ? 0.25 : 1;
            const isTraced = tracedNodeIds.has(n.id);
            // Per-node traffic readout — tiny BPS tag above the rect
            // so users can see which hubs (WAN, WolfNet, a busy zone)
            // are pushing the most bytes. Only shown when > 0.
            const nbps = nodeBps.get(n.id);
            const nodeTotalBps = nbps ? (nbps.rx + nbps.tx) : 0;
            const nodeUtil = nbps && nbps.speedMbps
                ? nodeTotalBps / (nbps.speedMbps * 1e6) : 0;
            const bpsTagColour = nodeUtil >= 0.7 ? '#ef4444'
                : nodeUtil >= 0.3 ? '#fbbf24'
                : '#4ade80';
            const bpsTag = nodeTotalBps > 0
                ? `<text x="${p.x}" y="${y-6}" text-anchor="middle"
                        style="fill:${bpsTagColour}; font-size:10px; font-family:var(--font-mono,monospace); pointer-events:none;">${escHtml(wrFmtBps(nodeTotalBps))}</text>`
                : '';
            const labelY = ipText ? (p.y - 4) : (p.y + 4);
            const ipLine = ipText
                ? `<text x="${p.x}" y="${p.y+12}" text-anchor="middle"
                        style="fill:var(--text-muted); font-size:10px; font-family:var(--font-mono,monospace); pointer-events:none;">${escHtml(ipText.slice(0,22))}</text>`
                : '';
            // Warning glow: down-ports/unconfigured things glow red,
            // things that are merely "needs attention" glow amber.
            // Trace highlight wins over warning so the traced path is
            // never obscured.
            const warnFilter = isTraced ? 'url(#wr-policy-glow)'
                             : warn?.level === 'danger' ? 'url(#wr-policy-warn-glow)'
                             : warn?.level === 'warn'   ? 'url(#wr-policy-amber-glow)'
                             : '';
            const warnStroke = warn?.level === 'danger' ? '#ef4444'
                             : warn?.level === 'warn'   ? '#fbbf24'
                             : stroke;
            const warnStrokeW = warn ? 2.5 : (isTraced ? 2.5 : 1.5);
            const tooltip = warn ? `<title>${escHtml(n.label)}\n${escHtml(warn.reasons.join('\n'))}</title>` : '';
            svg.insertAdjacentHTML('beforeend', `
                <g class="wr-policy-node" data-node="${escHtml(n.id)}" style="cursor:crosshair; opacity:${opacity};">
                    ${tooltip}
                    <rect x="${x}" y="${y}" width="${nodeW}" height="${h}" rx="8"
                          fill="${fill}" stroke="${warnStroke}" stroke-width="${warnStrokeW}"
                          ${warnFilter ? `filter="${warnFilter}"` : ''}/>
                    <text x="${p.x}" y="${labelY}" text-anchor="middle"
                          style="fill:var(--text); font-size:12px; font-weight:600; pointer-events:none;">${escHtml(n.icon)} ${escHtml(n.label.slice(0,18))}</text>
                    ${ipLine}
                    ${bpsTag}
                    ${warn ? `<text x="${x + nodeW - 8}" y="${y + 14}" text-anchor="end" style="fill:${warn.level === 'danger' ? '#ef4444' : '#fbbf24'}; font-size:14px; pointer-events:none;"></text>` : ''}
                </g>
            `);
        }

        // Live drag + drop-target highlight rings. Hidden until
        // mousedown picks a source node.
        svg.insertAdjacentHTML('beforeend', `
            <g id="wr-drag-layer" style="pointer-events:none;">
                <path id="wr-policy-drag-ghost" d="" fill="none" stroke="#fbbf24" stroke-width="3" stroke-dasharray="6 4" opacity="0.8" style="display:none;" marker-end="url(#wr-policy-arrow)"/>
                <circle id="wr-drag-source-ring" r="32" fill="none" stroke="#fbbf24" stroke-width="3" style="display:none;" filter="url(#wr-policy-glow)"/>
                <circle id="wr-drag-target-ring" r="32" fill="none" stroke="#22c55e" stroke-width="3" style="display:none;" filter="url(#wr-policy-glow)"/>
            </g>
        `);

        // Simulator: animated packet glow that travels along the
        // highlighted path. Rendered only when a sim path is set.
        if (wrPolicyUi.simPath?.edgeIds?.length) {
            const firstEdge = edges.find(e => e.id === wrPolicyUi.simPath.edgeIds[0]);
            if (firstEdge) {
                const a = layout.get(firstEdge.from), b = layout.get(firstEdge.to);
                if (a && b) {
                    svg.insertAdjacentHTML('beforeend', `
                        <circle r="12" fill="url(#wr-sim-packet)">
                            <animateMotion dur="1.2s" repeatCount="indefinite"
                                path="M ${a.x},${a.y} L ${b.x},${b.y}"/>
                        </circle>
                    `);
                }
            }
        }

        host.innerHTML = '';
        host.appendChild(svg);

        // Legend.
        const legend = document.getElementById('wr-policy-legend');
        if (legend) {
            const sw = (c, l) => `<div style="display:flex; align-items:center; gap:4px;"><span style="display:inline-block; width:14px; height:3px; background:${c}; border-radius:2px;"></span>${l}</div>`;
            legend.innerHTML = [
                sw('#22c55e', 'allow'), sw('#ef4444', 'deny'), sw('#f97316', 'reject'),
                sw('#60a5fa', 'log'),   sw('#a855f7', 'DNAT'), sw('#64748b', 'implicit'),
            ].join('');
        }

        wrWirePolicyInteractions(svg, graph, layout, nodeW, nodeH, fullGraph);
        wrWirePolicyFilters();
        wrWirePolicySimulator(fullGraph);
    }

    /// Drag-to-create + click-to-edit + click-to-trace handlers.
    /// Drag distance threshold separates "click" (trace a node / edit
    /// an edge) from "drag" (create a rule) so simple clicks don't
    /// accidentally open the rule editor.
    function wrWirePolicyInteractions(svg, graph, layout, nodeW, nodeH, fullGraph) {
        let dragFrom = null;
        let dragStart = null;
        let dragMoved = false;
        const CLICK_THRESHOLD = 6;  // px — anything less than this is a click
        const ghost = svg.querySelector('#wr-policy-drag-ghost');
        const sourceRing = svg.querySelector('#wr-drag-source-ring');
        const targetRing = svg.querySelector('#wr-drag-target-ring');

        const getMousePos = (evt) => {
            const rect = svg.getBoundingClientRect();
            return {
                x: (evt.clientX - rect.left) * (svg.viewBox.baseVal.width / rect.width),
                y: (evt.clientY - rect.top)  * (svg.viewBox.baseVal.height / rect.height),
            };
        };

        // Pan state — dragging on empty space scrolls the canvas wrap
        // instead of creating a rule.
        let panning = false;
        let panStart = { x: 0, y: 0 };
        let panScrollStart = { x: 0, y: 0 };
        const wrap = document.getElementById('wr-policy-canvas-wrap');

        svg.addEventListener('mousedown', (evt) => {
            const nodeEl = evt.target.closest('[data-node]');
            if (nodeEl) {
                // Node drag — create rule.
                dragFrom = nodeEl.dataset.node;
                const p = layout.get(dragFrom);
                if (!p) return;
                dragStart = { x: p.x, y: p.y };
                dragMoved = false;
                sourceRing.setAttribute('cx', p.x);
                sourceRing.setAttribute('cy', p.y);
                sourceRing.style.display = 'block';
                ghost.setAttribute('d', `M ${p.x},${p.y} L ${p.x},${p.y}`);
                evt.preventDefault();
                return;
            }
            // Edge click is handled on mouseup via .closest('[data-edge]')
            // — for now start panning.
            if (evt.target.closest('[data-edge]')) return;
            panning = true;
            panStart = { x: evt.clientX, y: evt.clientY };
            panScrollStart = { x: wrap?.scrollLeft || 0, y: wrap?.scrollTop || 0 };
            svg.style.cursor = 'grabbing';
            evt.preventDefault();
        });

        svg.addEventListener('mousemove', (evt) => {
            if (panning && wrap) {
                wrap.scrollLeft = panScrollStart.x - (evt.clientX - panStart.x);
                wrap.scrollTop  = panScrollStart.y - (evt.clientY - panStart.y);
                return;
            }
            if (!dragFrom) return;
            const m = getMousePos(evt);
            const dx = m.x - dragStart.x, dy = m.y - dragStart.y;
            if (Math.hypot(dx, dy) > CLICK_THRESHOLD) {
                dragMoved = true;
                ghost.style.display = 'block';
            }
            ghost.setAttribute('d', `M ${dragStart.x},${dragStart.y} L ${m.x},${m.y}`);
            const overEl = evt.target.closest('[data-node]');
            const overId = overEl?.dataset?.node;
            if (overId && overId !== dragFrom) {
                const q = layout.get(overId);
                if (q) {
                    targetRing.setAttribute('cx', q.x);
                    targetRing.setAttribute('cy', q.y);
                    targetRing.style.display = 'block';
                    return;
                }
            }
            targetRing.style.display = 'none';
        });

        const clearDrag = () => {
            ghost.style.display = 'none';
            ghost.setAttribute('d', '');
            sourceRing.style.display = 'none';
            targetRing.style.display = 'none';
            dragFrom = null; dragStart = null; dragMoved = false;
        };

        svg.addEventListener('mouseup', (evt) => {
            if (panning) {
                panning = false;
                svg.style.cursor = '';
                return;
            }
            if (!dragFrom) return;
            const fromId = dragFrom;
            const wasClick = !dragMoved;
            const targetEl = evt.target.closest('[data-node]');
            const toId = targetEl?.dataset?.node;
            clearDrag();

            if (wasClick) {
                // Click — enter trace mode for this node.
                wrPolicyUi.tracedNode = (wrPolicyUi.tracedNode === fromId) ? null : fromId;
                wrPolicyUi.simPath = null;
                const clearTraceBtn = document.getElementById('wr-policy-clear-trace');
                if (clearTraceBtn) {
                    clearTraceBtn.style.display = wrPolicyUi.tracedNode ? 'inline-block' : 'none';
                }
                wrRenderPolicyMap();
                return;
            }
            // Drag complete.
            if (!toId || toId === fromId) return;
            const fromEp = wrNodeIdToEndpoint(fromId, fullGraph);
            const toEp   = wrNodeIdToEndpoint(toId,   fullGraph);
            if (!fromEp || !toEp) {
                alert('One of those nodes isn\'t addressable as a firewall endpoint yet — try a zone or a named VM/container.');
                return;
            }
            wrShowRuleEditorPrefilled({
                action: 'allow', direction: 'forward',
                from: fromEp, to: toEp,
                protocol: 'any', ports: [], state_track: true,
                log_match: false,
                comment: `drag-created: ${fromId} → ${toId}`,
                enabled: true,
            });
        });
        svg.addEventListener('mouseleave', () => { if (dragFrom) clearDrag(); });

        // Click on an edge opens the edit popover.
        svg.querySelectorAll('[data-edge]').forEach(el => {
            el.addEventListener('click', (evt) => {
                const edgeId = el.dataset.edge;
                const edge = graph.edges.find(e => e.id === edgeId);
                if (!edge) return;
                wrShowEdgePopover(edge, evt.clientX, evt.clientY);
                evt.stopPropagation();
            });
        });

        // Clear-trace button — visible only while a trace is active.
        const clearBtn = document.getElementById('wr-policy-clear-trace');
        if (clearBtn) {
            clearBtn.onclick = () => {
                wrPolicyUi.tracedNode = null;
                wrPolicyUi.simPath = null;
                clearBtn.style.display = 'none';
                wrRenderPolicyMap();
            };
        }
    }

    /// Wire the filter toolbar checkboxes + search input once per
    /// render. Re-renders the canvas on every change.
    function wrWirePolicyFilters() {
        document.querySelectorAll('[data-wr-filter]').forEach(cb => {
            cb.onchange = () => {
                wrPolicyUi.filters[cb.dataset.wrFilter] = cb.checked;
                wrRenderPolicyMap();
            };
            // Re-sync DOM state with stored UI state (after a full re-render).
            cb.checked = !!wrPolicyUi.filters[cb.dataset.wrFilter];
        });
        const searchEl = document.getElementById('wr-policy-search');
        if (searchEl) {
            searchEl.value = wrPolicyUi.search;
            searchEl.oninput = () => {
                wrPolicyUi.search = searchEl.value;
                wrRenderPolicyMap();
            };
        }
        // Zoom controls — buttons + ctrl-scroll on the canvas.
        const zIn  = document.getElementById('wr-policy-zoom-in');
        const zOut = document.getElementById('wr-policy-zoom-out');
        const zFit = document.getElementById('wr-policy-zoom-fit');
        const zPct = document.getElementById('wr-policy-zoom-pct');
        const setZoom = (z) => {
            wrPolicyUi.zoom = Math.max(0.3, Math.min(2.5, z));
            wrRenderPolicyMap();
        };
        if (zPct) zPct.textContent = Math.round((wrPolicyUi.zoom || 1) * 100) + '%';
        if (zIn)  zIn.onclick  = () => setZoom((wrPolicyUi.zoom || 1) * 1.25);
        if (zOut) zOut.onclick = () => setZoom((wrPolicyUi.zoom || 1) / 1.25);
        if (zFit) zFit.onclick = () => setZoom(1);
        const wrap = document.getElementById('wr-policy-canvas-wrap');
        if (wrap && !wrap._wrZoomWired) {
            wrap.addEventListener('wheel', (evt) => {
                if (!evt.ctrlKey && !evt.metaKey) return;
                evt.preventDefault();
                const factor = evt.deltaY < 0 ? 1.1 : 1/1.1;
                setZoom((wrPolicyUi.zoom || 1) * factor);
            }, { passive: false });
            wrap._wrZoomWired = true;
        }

        // Cluster-node selector — populates from topology on every
        // render so newly-joined nodes show up without a page reload.
        const nodeSel = document.getElementById('wr-policy-node-select');
        if (nodeSel) {
            const clusterNodes = wrState.topology?.nodes || [];
            const prev = wrPolicyUi.selectedNode || '';
            nodeSel.innerHTML = '<option value="">All cluster nodes</option>' +
                clusterNodes.map(n =>
                    `<option value="${escHtml(n.node_id)}">${escHtml(n.node_name || n.node_id)}</option>`
                ).join('');
            // Preserve selection across re-renders if the node still exists.
            if (prev && clusterNodes.some(n => n.node_id === prev)) {
                nodeSel.value = prev;
            } else if (prev) {
                wrPolicyUi.selectedNode = '';
            }
            nodeSel.onchange = () => {
                wrPolicyUi.selectedNode = nodeSel.value;
                wrRenderPolicyMap();
            };
        }
    }

    /// Wire the traffic simulator toolbar. Populates the src/dst
    /// dropdowns with every node on the graph, then evaluates the
    /// proposed packet against the rule list in order and shows the
    /// verdict + which rule matched. Animates a packet along the
    /// matched edge.
    function wrWirePolicySimulator(fullGraph) {
        const fromSel = document.getElementById('wr-sim-from');
        const toSel = document.getElementById('wr-sim-to');
        const protoSel = document.getElementById('wr-sim-proto');
        const portIn = document.getElementById('wr-sim-port');
        const goBtn = document.getElementById('wr-sim-go');
        const result = document.getElementById('wr-sim-result');
        if (!fromSel || !toSel || !goBtn || !result) return;

        const opts = fullGraph.nodes.map(n =>
            `<option value="${escHtml(n.id)}">${escHtml(n.icon)} ${escHtml(n.label)}</option>`
        ).join('');
        const prevFrom = fromSel.value;
        const prevTo = toSel.value;
        fromSel.innerHTML = opts;
        toSel.innerHTML = opts;
        if (prevFrom && fullGraph.nodes.some(n => n.id === prevFrom)) fromSel.value = prevFrom;
        if (prevTo && fullGraph.nodes.some(n => n.id === prevTo)) toSel.value = prevTo;

        goBtn.onclick = () => {
            const fromEp = wrNodeIdToEndpoint(fromSel.value, fullGraph);
            const toEp   = wrNodeIdToEndpoint(toSel.value,   fullGraph);
            if (!fromEp || !toEp) {
                result.innerHTML = '<span style="color:#ef4444;">src or dst can\'t be translated</span>';
                return;
            }
            const proto = protoSel.value;
            const port = portIn.value.trim();
            const verdict = wrSimulateTraffic(fromEp, toEp, proto, port);
            wrPolicyUi.simPath = verdict.matchedEdgeId
                ? { edgeIds: [verdict.matchedEdgeId], verdict: verdict.action }
                : null;
            const colour = {
                allow:  '#22c55e', deny:   '#ef4444',
                reject: '#f97316', log:    '#60a5fa',
                implicit_allow: '#94a3b8',
            }[verdict.action] || '#94a3b8';
            result.innerHTML = `
                <span style="color:${colour}; font-weight:600;">${verdict.action.toUpperCase()}</span>
                ${verdict.matchedRuleId ? ` via rule <code style="color:var(--text);">${escHtml(verdict.matchedRuleId.slice(0, 8))}</code>` : ''}
                ${verdict.note ? `<span style="color:var(--text-muted); margin-left:6px;">${escHtml(verdict.note)}</span>` : ''}
            `;
            wrRenderPolicyMap();
        };
    }

    /// Evaluate a proposed packet against the current rule list in
    /// order. Returns { action, matchedRuleId, matchedEdgeId, note }.
    /// Mirrors the backend's rule-matching for the common cases —
    /// this is a client-side approximation, not an exact iptables
    /// walk, but close enough to answer "will this go through?".
    function wrSimulateTraffic(fromEp, toEp, protocol, port) {
        // Endpoint match logic: an endpoint in the rule matches the
        // proposed endpoint iff rule endpoint is Any OR same kind+id.
        const matchEp = (ruleEp, proposed) => {
            if (!ruleEp) return true;
            if (ruleEp.kind === 'any') return true;
            if (!proposed) return false;  // guard against null proposed endpoint
            if (ruleEp.kind !== proposed.kind) return false;
            if (ruleEp.kind === 'zone') {
                return ruleEp.zone?.kind === proposed.zone?.kind
                    && (ruleEp.zone?.id ?? 0) === (proposed.zone?.id ?? 0);
            }
            if (ruleEp.kind === 'lan')       return ruleEp.id === proposed.id;
            if (ruleEp.kind === 'vm'
             || ruleEp.kind === 'container'
             || ruleEp.kind === 'interface') return ruleEp.name === proposed.name;
            if (ruleEp.kind === 'ip')        return ruleEp.cidr === proposed.cidr;
            return true;
        };
        const protoMatches = (rp) => {
            // Rule with proto=any matches every proposed packet.
            if (rp === 'any') return true;
            // Proposed packet with proto=any means "any/unknown" — we
            // interpret this as "match rules regardless of proto" so
            // users can simulate without committing to a layer-4
            // protocol (e.g. "can X talk to Y at all?").
            if (protocol === 'any') return true;
            if (rp === 'tcpudp') return protocol === 'tcp' || protocol === 'udp';
            return rp === protocol;
        };
        const portMatches = (rulePorts) => {
            if (!rulePorts?.length) return true;
            if (!port) return false;
            const n = parseInt(port, 10);
            if (isNaN(n)) return false;
            return rulePorts.some(p => {
                const s = p.port;
                if (s.includes('-')) {
                    const [lo, hi] = s.split('-').map(x => parseInt(x, 10));
                    return n >= lo && n <= hi;
                }
                return parseInt(s, 10) === n;
            });
        };
        // .slice() before sort — otherwise the sort mutates the live
        // wrState.rules order and other tabs that iterate it see the
        // shuffled-by-order sequence (caught in review).
        const rules = (wrState.rules || []).slice()
            .filter(r => r.enabled !== false)
            .sort((a, b) => (a.order || 0) - (b.order || 0));
        for (const r of rules) {
            if (!matchEp(r.from, fromEp)) continue;
            if (!matchEp(r.to,   toEp))   continue;
            if (!protoMatches(r.protocol)) continue;
            if (!portMatches(r.ports))    continue;
            return {
                action: r.action,
                matchedRuleId: r.id,
                matchedEdgeId: 'rule:' + r.id,
                note: `${r.action === 'allow' ? 'permitted' : 'blocked'} — ${r.comment || '(no comment)'}`,
            };
        }
        return {
            action: 'implicit_allow',
            matchedRuleId: null,
            matchedEdgeId: null,
            note: 'no rule matched — kernel default (ACCEPT) applies',
        };
    }

    /// Translate a policy-map node id back to a firewall Endpoint
    /// suitable for wrSaveRule. Mirrors wrEndpointNodeId() in reverse.
    function wrNodeIdToEndpoint(id, graph) {
        const node = graph?.nodes?.find(n => n.id === id);
        if (id === 'internet') return { kind: 'any' };
        if (id.startsWith('zone:')) {
            // Prefer the node's stashed zone meta (exact round-trip)…
            if (node?.meta?.zone) return { kind: 'zone', zone: node.meta.zone };
            // …but fall back to reconstructing from the id so dynamic
            // custom-zone nodes (added by the unknown-endpoint fallback)
            // still translate to a usable endpoint instead of silently
            // returning null and confusing the user.
            const slug = id.slice(5);
            const m = slug.match(/^lan(\d+)$/);
            if (m) return { kind: 'zone', zone: { kind: 'lan', id: parseInt(m[1], 10) } };
            if (slug.startsWith('custom:')) {
                return { kind: 'zone', zone: { kind: 'custom', id: slug.slice(7) } };
            }
            return { kind: 'zone', zone: { kind: slug } };
        }
        if (id.startsWith('lan:')) return { kind: 'lan', id: id.slice(4) };
        if (id.startsWith('vm:'))  return { kind: 'vm',  name: id.slice(3) };
        if (id.startsWith('ct:'))  return { kind: 'container', name: id.slice(3) };
        if (id.startsWith('ip:'))  return { kind: 'ip', cidr: id.slice(3) };
        if (id.startsWith('iface:')) return { kind: 'interface', name: id.slice(6) };
        return null;
    }

    /// Open the existing rule editor modal with fields pre-populated
    /// from a drag-to-create action. Reuses wrShowRuleEditor's DOM.
    function wrShowRuleEditorPrefilled(rule) {
        wrShowRuleEditor(null);  // fresh modal
        // Populate synchronously — the modal was just appended.
        const byId = (id) => document.getElementById(id);
        if (!byId('wr-f-action')) return;
        byId('wr-f-action').value = rule.action;
        byId('wr-f-dir').value = rule.direction;
        byId('wr-f-from').value = endpointToPrefillText(rule.from);
        byId('wr-f-to').value   = endpointToPrefillText(rule.to);
        byId('wr-f-proto').value = rule.protocol;
        byId('wr-f-ports').value = (rule.ports || []).map(p => p.port).join(', ');
        byId('wr-f-comment').value = rule.comment || '';
        byId('wr-f-log').checked = !!rule.log_match;
        byId('wr-f-enabled').checked = rule.enabled !== false;
        // Call the analyser explicitly once the pre-fill is written —
        // don't race the 50ms timer that wrShowRuleEditor scheduled.
        wrRenderRuleWarnings();
    }
    function endpointToPrefillText(ep) {
        if (!ep || ep.kind === 'any') return 'any';
        if (ep.kind === 'zone') {
            if (ep.zone?.kind === 'lan') return 'zone:lan' + (ep.zone.id ?? 0);
            return 'zone:' + ep.zone?.kind;
        }
        if (ep.kind === 'interface') return 'iface:' + ep.name;
        if (ep.kind === 'ip')        return 'ip:' + ep.cidr;
        if (ep.kind === 'lan')       return 'lan:' + ep.id;
        if (ep.kind === 'vm')        return 'vm:' + ep.name;
        if (ep.kind === 'container') return 'ct:' + ep.name;
        return 'any';
    }

    /// Click-to-edit popover for an existing edge. Shows edit +
    /// delete buttons + a compact rule summary.
    function wrShowEdgePopover(edge, clientX, clientY) {
        const pop = document.getElementById('wr-policy-edge-popover');
        if (!pop) return;
        const wrap = document.getElementById('wr-policy-canvas-wrap');
        const rect = wrap.getBoundingClientRect();
        pop.style.left = (clientX - rect.left + 8) + 'px';
        pop.style.top  = (clientY - rect.top + 8) + 'px';
        pop.style.display = 'block';
        if (edge.kind === 'rule') {
            const r = edge.rule;
            pop.innerHTML = `
                <div style="margin-bottom:6px;"><strong style="color:${edge.colour};">${escHtml(r.action.toUpperCase())}</strong> ${escHtml(r.protocol||'any')}${r.ports?.length ? ' ports ' + r.ports.map(p=>p.port).join(',') : ''}</div>
                ${r.comment ? `<div style="color:var(--text-muted); font-size:11px; margin-bottom:6px;">${escHtml(r.comment)}</div>` : ''}
                <div style="display:flex; gap:6px;">
                    <button class="btn btn-sm" onclick="wrShowRuleEditor('${escHtml(r.id)}'); document.getElementById('wr-policy-edge-popover').style.display='none';">Edit</button>
                    <button class="btn btn-sm" onclick="(async()=>{await wrDeleteRule('${escHtml(r.id)}'); wrRenderPolicyMap();})(); document.getElementById('wr-policy-edge-popover').style.display='none';">Delete</button>
                    <button class="btn btn-sm" onclick="document.getElementById('wr-policy-edge-popover').style.display='none';">Close</button>
                </div>`;
        } else if (edge.kind === 'dnat') {
            const m = edge.mapping;
            pop.innerHTML = `
                <div style="margin-bottom:6px;"><strong style="color:${edge.colour};">DNAT</strong> port forward</div>
                <div style="font-size:11px;">${escHtml(m.public_ip)} → <code>${escHtml(m.wolfnet_ip)}</code>${m.ports ? ' :' + escHtml(m.ports) : ''}</div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Managed on the per-server Networking page.</div>
                <div style="margin-top:6px;"><button class="btn btn-sm" onclick="document.getElementById('wr-policy-edge-popover').style.display='none';">Close</button></div>`;
        }
    }
    // Expose for inline onclick handlers.
    window.wrRenderPolicyMap = wrRenderPolicyMap;

    // Fullscreen toggle — requests the Fullscreen API on the policy tab
    // panel so the whole tab (canvas + toolbar + simulator) fills the
    // screen. A second click (or Escape) exits fullscreen.
    window.wrToggleFullscreen = function () {
        const panel = document.getElementById('wr-tab-policy');
        if (!panel) return;
        if (document.fullscreenElement) {
            document.exitFullscreen().catch(() => {});
        } else {
            panel.requestFullscreen().catch(() => {});
            // Set a bg so the panel isn't transparent over the page.
            panel.style.background = 'var(--bg-primary, #0a0e1a)';
        }
    };
    // Re-render on fullscreen change so the canvas fills the new size.
    document.addEventListener('fullscreenchange', () => {
        const panel = document.getElementById('wr-tab-policy');
        if (panel && !document.fullscreenElement) {
            panel.style.background = '';
        }
        if (wrState.activeTab === 'policy') wrRenderPolicyMap();
    });
    // Escape dismisses the help modal.
    document.addEventListener('keydown', (evt) => {
        if (evt.key === 'Escape') {
            const modal = document.getElementById('wr-policy-help-modal');
            if (modal && modal.style.display !== 'none') {
                modal.style.display = 'none';
                evt.stopPropagation();
            }
        }
    });

    // Dismiss popover on outside click.
    document.addEventListener('click', (evt) => {
        const pop = document.getElementById('wr-policy-edge-popover');
        if (!pop || pop.style.display === 'none') return;
        if (evt.target.closest('#wr-policy-edge-popover')) return;
        if (evt.target.closest('[data-edge]')) return;
        pop.style.display = 'none';
    });

    // ─── Packets (tcpdump) tab ───────────────────────────────

    function wrRenderPackets() {
        // Populate node + interface dropdowns from the live topology.
        // Only show interfaces that are link-up — capturing on a down
        // interface is just dead time waiting for the timeout.
        const nodeSel = document.getElementById('wr-pcap-node');
        const ifSel = document.getElementById('wr-pcap-iface');
        if (!nodeSel || !ifSel) return;

        const nodes = (wrState.topology?.nodes || []).filter(n => n.status !== 'unreachable');
        const currentNode = nodeSel.value;
        nodeSel.innerHTML = nodes.map(n =>
            `<option value="${escHtml(n.node_id)}">${escHtml(n.node_name)}</option>`
        ).join('') || '<option value="">(no nodes)</option>';
        if (currentNode && nodes.some(n => n.node_id === currentNode)) {
            nodeSel.value = currentNode;
        }

        const selectedNode = nodes.find(n => n.node_id === nodeSel.value) || nodes[0];
        const ifaces = new Set();
        if (selectedNode) {
            for (const i of (selectedNode.interfaces || [])) {
                if (i.link_up) ifaces.add(i.name);
            }
            for (const b of (selectedNode.bridges || [])) {
                ifaces.add(b.name);  // bridges always shown — they
                                     // don't have an operstate concept
            }
        }
        const list = ['any', ...Array.from(ifaces).sort()];
        const currentIf = ifSel.value;
        ifSel.innerHTML = list.map(i => `<option value="${escHtml(i)}">${escHtml(i)}</option>`).join('');
        if (currentIf && list.includes(currentIf)) ifSel.value = currentIf;
    }

    /// Parse a single tcpdump line (with -tttt timestamp) into a row:
    ///   "2026-04-15 11:37:34.107236 IP 100.96.0.2.45413 > 100.95.0.254.53: 32916+ A? discord.com. (29)"
    /// Returns { time, proto, src, dst, info, length } — best-effort;
    /// non-matching lines are passed through verbatim in the info col.
    function wrParsePacketLine(line) {
        const out = { time: '', proto: '', src: '', dst: '', info: line, length: '' };
        // Timestamp: "YYYY-MM-DD HH:MM:SS.frac"
        const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(.*)$/);
        if (!tsMatch) return out;
        out.time = tsMatch[2].slice(0, 12);  // HH:MM:SS.frac3
        const rest = tsMatch[3];
        // L3 family + src > dst:
        const headerMatch = rest.match(/^(IP6?|ARP|STP|PPP|RARP)\s+(\S+)\s+>\s+(\S+):\s*(.*)$/);
        if (!headerMatch) {
            out.info = rest;
            return out;
        }
        const family = headerMatch[1];
        const srcRaw = headerMatch[2];
        const dstRaw = headerMatch[3].replace(/[:,]+$/, '');
        out.info = headerMatch[4] || '';
        // src/dst may have a port appended via dot for IPv4 or .NNN for IPv6
        const splitHostPort = (s) => {
            // IPv4: a.b.c.d.PORT — last segment is port if all-digits
            const lastDot = s.lastIndexOf('.');
            if (lastDot > -1) {
                const tail = s.slice(lastDot + 1);
                if (/^\d+$/.test(tail) && s.slice(0, lastDot).split('.').length === 4) {
                    return s.slice(0, lastDot) + ':' + tail;
                }
            }
            return s;
        };
        out.src = splitHostPort(srcRaw);
        out.dst = splitHostPort(dstRaw);
        // Protocol: sniff from info or family.
        if (/^ICMP\b/i.test(out.info)) out.proto = 'ICMP';
        else if (/^Flags\s+\[/.test(out.info)) out.proto = 'TCP';
        else if (/^UDP[, ]/.test(out.info)) out.proto = 'UDP';
        else if (/^\d+\+\s+/.test(out.info)) out.proto = 'DNS';
        else if (family === 'ARP') out.proto = 'ARP';
        else if (family === 'IP6') out.proto = 'IPv6';
        else out.proto = family;
        // Length: "length N" anywhere
        const lenMatch = out.info.match(/length\s+(\d+)/);
        if (lenMatch) out.length = lenMatch[1];
        return out;
    }

    async function wrStartCapture() {
        const node_id = document.getElementById('wr-pcap-node').value.trim();
        const iface = document.getElementById('wr-pcap-iface').value.trim();
        const filter = document.getElementById('wr-pcap-filter').value.trim();
        const count = parseInt(document.getElementById('wr-pcap-count').value, 10) || 100;
        const timeoutSeconds = parseInt(document.getElementById('wr-pcap-timeout').value, 10) || 30;
        const tbody = document.getElementById('wr-pcap-tbody');
        const status = document.getElementById('wr-pcap-status');
        const btn = document.getElementById('wr-pcap-go');
        if (!iface) { alert('Pick an interface first'); return; }

        const setBtn = (disabled, label) => { btn.disabled = disabled; btn.textContent = label; };
        const showStatus = (msg) => { status.innerHTML = msg; };
        const showPlaceholder = (msg) => {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:24px;">${msg}</td></tr>`;
        };

        showStatus(`Capturing on <code>${escHtml(iface)}</code>${filter ? ' [filter: <code>' + escHtml(filter) + '</code>]' : ''}… max ${count} packets / ${timeoutSeconds}s timeout`);
        showPlaceholder('Waiting for packets…');
        setBtn(true, 'Capturing…');

        const runCapture = async () => {
            const r = await fetch(wrUrl('/api/router/capture'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ iface, filter, count, timeout_seconds: timeoutSeconds, node_id }),
            });
            const data = await r.json();
            return { ok: r.ok, status: r.status, data };
        };

        try {
            let result = await runCapture();
            // Auto-install tcpdump if the backend tagged the response
            // with `missing_tool: "tcpdump"`, then retry once. Backend
            // and frontend ship in the same binary so we always get
            // the structured key — no legacy regex fallback needed.
            if (result.data?.missing_tool === 'tcpdump') {
                const manualCmd = result.data.install_command;
                const manualHelp = manualCmd
                    ? `Try manually: <code>${escHtml(manualCmd)}</code>`
                    : `Install <code>tcpdump</code> with your distro's package manager and try again.`;
                showStatus('Installing tcpdump on this host (one-time)…');
                setBtn(true, 'Installing tcpdump…');
                const inst = await fetch(wrUrl('/api/router/install-tool'), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tool: 'tcpdump' }),
                });
                const instData = await inst.json();
                if (!instData.success) {
                    showStatus(`Couldn't install tcpdump automatically: ${escHtml(instData.error || 'unknown error')}. ${manualHelp}`);
                    showPlaceholder('Install tcpdump manually with your package manager and try again.');
                    return;
                }
                showStatus(`tcpdump installed. Now capturing…`);
                setBtn(true, 'Capturing…');
                result = await runCapture();
            }

            if (!result.ok) {
                showStatus(`HTTP ${result.status}: ${escHtml(result.data.error || JSON.stringify(result.data))}`);
                showPlaceholder('Capture failed.');
                return;
            }
            const lines = result.data.lines || [];
            const rows = lines.map(wrParsePacketLine);
            showStatus(`${lines.length} packet${lines.length === 1 ? '' : 's'} on <code>${escHtml(result.data.iface || iface)}</code>${result.data.filter ? ' [filter: <code>' + escHtml(result.data.filter) + '</code>]' : ''}${result.data.error ? ' — ' + escHtml(result.data.error) : ''}`);

            if (!rows.length) {
                showPlaceholder('No packets captured (the timeout fired before any matched).');
                return;
            }

            const protoColor = {
                TCP: '#60a5fa', UDP: '#22c55e', ICMP: '#fbbf24',
                DNS: '#a855f7', ARP: '#fb923c', IPv6: '#f472b6',
            };
            tbody.innerHTML = rows.map(p => {
                const c = protoColor[p.proto] || '#94a3b8';
                return `<tr>
                    <td style="font-family:var(--font-mono); color:var(--text-muted);">${escHtml(p.time)}</td>
                    <td><span class="badge" style="background:${c}22; color:${c}; font-size:10px; padding:1px 6px;">${escHtml(p.proto || '?')}</span></td>
                    <td><code>${escHtml(p.src)}</code></td>
                    <td><code>${escHtml(p.dst)}</code></td>
                    <td style="color:var(--text-muted); font-family:var(--font-mono); font-size:10px;">${escHtml(p.info.slice(0, 200))}</td>
                    <td style="text-align:right; color:var(--text-muted); font-family:var(--font-mono);">${escHtml(p.length)}</td>
                </tr>`;
            }).join('');
        } catch (e) {
            showStatus('' + escHtml(e.message || e));
            showPlaceholder('Network error.');
        } finally {
            setBtn(false, '▶ Capture');
        }
    }
    window.wrStartCapture = wrStartCapture;

    async function wrRenderLogs() {
        const pre = document.getElementById('wr-logs-pre');
        if (!pre) return;
        try {
            const r = await fetch(wrUrl('/api/router/logs'));
            const lines = r.ok ? await r.json() : [];
            pre.textContent = lines.length ? lines.join('\n') : '(no firewall log lines — enable "Log this match" on a rule to populate)';
        } catch (e) {}
    }

    // ─── Visual TraceRoute ───
    //
    // GET /api/traceroute?target=… returns the parsed hops (ip, rtt_ms),
    // we then geolocate each non-private hop via /api/geolocate (already
    // used by the home-page world map), and render a Leaflet map with a
    // marker per hop and a polyline tying them together. RFC1918 and
    // loopback IPs are kept in the table but not plotted (no useful
    // geolocation — they're the user's LAN / the ISP's near edge).
    let wrTrMap = null;
    let wrTrLayer = null;

    function wrIsPrivateIp(ip) {
        if (!ip) return true;
        return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1$|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|fe80:)/i.test(ip);
    }

    // Escape user-influenced text before embedding in innerHTML / Leaflet
    // popups. ip-api.com is third-party data we proxy through — a spoofed
    // reverse-DNS / WHOIS field would otherwise XSS into the dashboard.
    function wrEsc(s) {
        if (s == null) return '';
        return String(s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function wrEnsureTracerouteMap() {
        const el = document.getElementById('wr-tr-map');
        if (!el) return null;
        if (!wrTrMap) {
            wrTrMap = L.map(el, { worldCopyJump: true, zoomControl: true })
                .setView([20, 0], 2);
            // Same OpenStreetMap tiles + theme darkening as the home-page
            // world map (app.js OSM_TILE_URL / refreshMapTheme), so the
            // traceroute view feels like part of the same UI.
            wrTrMap.attributionControl.setPrefix(false);
            L.tileLayer(OSM_TILE_URL, {
                attribution: OSM_ATTRIBUTION,
                maxZoom: 19,
            }).addTo(wrTrMap);
            refreshMapTheme();
            wrTrLayer = L.layerGroup().addTo(wrTrMap);
        }
        // Fix sizing in case the tab was display:none when the map was created.
        setTimeout(() => { try { wrTrMap.invalidateSize(); } catch (_) {} }, 50);
        return wrTrMap;
    }

    async function wrRenderTraceroute() {
        // Just init the map. Real work happens on click of Trace.
        wrEnsureTracerouteMap();
    }

    async function wrTracerouteGo() {
        const input = document.getElementById('wr-tr-target');
        const status = document.getElementById('wr-tr-status');
        const tbody = document.getElementById('wr-tr-hops');
        const goBtn = document.getElementById('wr-tr-go');
        const target = (input?.value || '').trim();
        if (!target) {
            status.textContent = 'Enter an IP address or hostname.';
            input?.focus();
            return;
        }
        if (tbody) tbody.innerHTML = '';
        if (status) status.textContent = 'Tracing route to ' + target + '… (up to ~30s)';
        if (goBtn) { goBtn.disabled = true; goBtn.textContent = 'Tracing…'; }

        const map = wrEnsureTracerouteMap();
        if (wrTrLayer) wrTrLayer.clearLayers();

        let resp, data;
        try {
            resp = await fetch(apiUrl('/api/traceroute?target=' + encodeURIComponent(target)));
            data = await resp.json();
        } catch (e) {
            if (status) status.textContent = 'Trace failed: ' + e.message;
            if (goBtn) { goBtn.disabled = false; goBtn.textContent = 'Trace'; }
            return;
        }
        if (!resp.ok) {
            // When traceroute itself isn't installed the backend tags
            // the response with `missing_tool`. Surface an inline
            // install button instead of a dead-end error so the user
            // doesn't have to leave the tab to fix it.
            // Adam Cogswell 2026-04-30: Ubuntu minimal ships without
            // traceroute; previous flow had no in-app remedy.
            if (data && data.missing_tool === 'traceroute') {
                const pkg = data.install_package || 'traceroute';
                // Distro-aware manual-install command from the backend.
                // null when the host's distro couldn't be identified —
                // we then show a generic "use your package manager"
                // message rather than guessing at a wrong shell.
                const manualCmd = data.install_command;
                const manualHelp = manualCmd
                    ? `Try the package manager directly: <code>${wrEsc(manualCmd)}</code>.`
                    : `Install <code>${wrEsc(pkg)}</code> with your distro's package manager and try again.`;
                if (status) {
                    status.innerHTML = `${wrEsc(data.error || 'traceroute is not installed')} ` +
                        `<button id="wr-tr-install" class="btn btn-sm btn-primary" style="margin-left:8px;">Install ${wrEsc(pkg)}</button>`;
                    const btn = document.getElementById('wr-tr-install');
                    if (btn) btn.onclick = async () => {
                        btn.disabled = true;
                        btn.textContent = 'Installing…';
                        try {
                            const ir = await fetch('/api/system/install-package', {
                                method: 'POST', headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ package: pkg }),
                            });
                            const idata = await ir.json().catch(() => ({}));
                            if (!ir.ok || idata.success === false) {
                                status.innerHTML = `Install failed: ${wrEsc(idata.error || ir.statusText || 'unknown')}. ${manualHelp}`;
                                return;
                            }
                            status.textContent = 'Installed — re-running trace…';
                            // Re-fire the original Trace flow so the user
                            // doesn't have to click again.
                            wrTracerouteGo();
                        } catch (e) {
                            status.innerHTML = `Install errored: ${wrEsc(e.message || String(e))}. ${manualHelp}`;
                        }
                    };
                }
                if (goBtn) { goBtn.disabled = false; goBtn.textContent = 'Trace'; }
                return;
            }
            if (status) status.textContent = '' + (data.error || resp.statusText);
            if (goBtn) { goBtn.disabled = false; goBtn.textContent = 'Trace'; }
            return;
        }
        const hops = data.hops || [];
        if (!hops.length) {
            if (status) status.textContent = 'traceroute returned no hops' + (data.error ? ' — ' + data.error : '');
            if (goBtn) { goBtn.disabled = false; goBtn.textContent = 'Trace'; }
            return;
        }

        if (status) status.textContent = `${hops.length} hops to ${target}${data.resolved_ip && data.resolved_ip !== target ? ' (' + data.resolved_ip + ')' : ''} — geolocating…`;

        // Render the table immediately; fill location cells as geo lookups complete.
        if (tbody) {
            tbody.innerHTML = hops.map(h => {
                const ip = h.ip ? wrEsc(h.ip) : '*';
                const rtt = (h.rtt_ms != null) ? `${h.rtt_ms.toFixed(1)} ms` : '<span style="color:var(--text-muted);">timeout</span>';
                const isPriv = wrIsPrivateIp(h.ip);
                const locId = `wr-tr-loc-${h.hop}`;
                const placeholder = h.ip
                    ? (isPriv ? '<span style="color:var(--text-muted);">private</span>' : '<span style="color:var(--text-muted);">…</span>')
                    : '';
                return `<tr><td>${h.hop}</td><td style="font-family:var(--font-mono);">${ip}</td><td>${rtt}</td><td id="${locId}">${placeholder}</td></tr>`;
            }).join('');
        }

        // Sequentially geolocate each public hop. Sequential (not parallel)
        // because ip-api.com's free tier throttles to ~45 req/min and
        // bursting all hops at once gets rate-limited; we'd rather take a
        // few seconds longer than show "*" for hops we could have plotted.
        const points = [];
        for (const h of hops) {
            if (!h.ip || wrIsPrivateIp(h.ip)) continue;
            try {
                const gr = await fetch(apiUrl('/api/geolocate?ip=' + encodeURIComponent(h.ip)));
                const gd = await gr.json();
                if (gd.status === 'success' && gd.lat != null && gd.lon != null) {
                    points.push({ hop: h.hop, ip: h.ip, lat: gd.lat, lon: gd.lon, rtt_ms: h.rtt_ms, label: gd });
                    const cell = document.getElementById('wr-tr-loc-' + h.hop);
                    if (cell) {
                        const place = wrEsc([gd.city, gd.country].filter(Boolean).join(', ') || gd.regionName || '');
                        const isp = wrEsc(gd.isp || gd.as || '');
                        cell.innerHTML = `${place}${isp ? ' <span style="color:var(--text-muted);font-size:11px;">(' + isp + ')</span>' : ''}`;
                    }
                } else {
                    const cell = document.getElementById('wr-tr-loc-' + h.hop);
                    if (cell) cell.innerHTML = '<span style="color:var(--text-muted);">unknown</span>';
                }
            } catch (e) {
                const cell = document.getElementById('wr-tr-loc-' + h.hop);
                if (cell) cell.innerHTML = '<span style="color:var(--text-muted);">lookup failed</span>';
            }
        }

        // Plot. Each hop = a circle marker, polyline ties the path
        // together. Final hop in red so the destination is visible.
        if (wrTrLayer) wrTrLayer.clearLayers();
        const latlngs = points.map(p => [p.lat, p.lon]);
        points.forEach((p, idx) => {
            const isFinal = idx === points.length - 1;
            const colour = isFinal ? '#ef4444' : '#3b82f6';
            const radius = isFinal ? 8 : 5;
            const m = L.circleMarker([p.lat, p.lon], {
                radius, color: '#fff', weight: 2, fillColor: colour, fillOpacity: 0.9,
            }).addTo(wrTrLayer);
            const place = wrEsc([p.label.city, p.label.country].filter(Boolean).join(', '));
            const isp = wrEsc(p.label.isp || p.label.as || '');
            const rtt = (p.rtt_ms != null) ? `${p.rtt_ms.toFixed(1)} ms` : '?';
            m.bindPopup(`<strong>Hop ${p.hop}</strong> — ${wrEsc(p.ip)}<br>${place}<br>${isp}<br>RTT: ${rtt}`);
        });
        if (latlngs.length >= 2) {
            L.polyline(latlngs, { color: '#3b82f6', weight: 2, opacity: 0.7, dashArray: '4 4' })
                .addTo(wrTrLayer);
        }
        if (latlngs.length === 1) {
            wrTrMap.setView(latlngs[0], 5);
        } else if (latlngs.length > 1) {
            wrTrMap.fitBounds(latlngs, { padding: [30, 30] });
        }
        if (status) {
            const plotted = points.length;
            status.textContent = `${hops.length} hops — ${plotted} plotted (private/unresolved hops are listed but not on the map).`;
        }
        if (goBtn) { goBtn.disabled = false; goBtn.textContent = 'Trace'; }
    }
    window.wrRenderTraceroute = wrRenderTraceroute;
    window.wrTracerouteGo = wrTracerouteGo;

    // ─── Rack view SVG (the real-rack version) ───
    //
    // Renders a server-room scene: Internet cloud at top, vertical rack
    // with mounting rails on either side, 2U appliances stacked inside,
    // each with a brand strip + LCD label + a row of RJ45-style port
    // jacks (with link/activity LEDs), and thick coloured patch cables
    // routed from each WAN port up to the cloud and from each LAN/etc
    // port down to a "device shelf" at the bottom.
    //
    // Cable colour code:
    //   yellow  = WAN (internet uplink)
    //   blue    = LAN (general user network)
    //   green   = WolfNet overlay
    //   purple  = Management
    //   grey    = unassigned / trunk

    /// Hash the topology's structural fingerprint — the stuff that
    /// affects what the rack LOOKS like. Deliberately excludes anything
    /// that changes every poll (rx_bps, tx_bps) so the common case
    /// ("3-second tick, nothing structural changed, just traffic
    /// counters updated") skips the expensive full re-render.
    function wrRackStructureHash(topo) {
        if (!topo || !topo.nodes) return '';
        const bits = [];
        for (const n of topo.nodes) {
            bits.push('N:' + n.node_id + '|' + n.node_name + '|' + (n.status || 'live'));
            for (const i of (n.interfaces || [])) {
                bits.push('I:' + i.name + '|' + (i.zone ? (i.zone.kind + (i.zone.id != null ? ':' + i.zone.id : '')) : '') + '|' + (i.role || '') + '|' + (i.link_up ? 1 : 0) + '|' + (i.addresses || []).join(','));
            }
            for (const b of (n.bridges || [])) bits.push('B:' + b.name + '|' + (b.members || []).join(','));
            for (const v of (n.vms || [])) bits.push('V:' + v.name + '|' + (v.attached_to || '') + '|' + (v.ip || ''));
            for (const c of (n.containers || [])) bits.push('C:' + c.name + '|' + (c.kind || '') + '|' + (c.attached_to || '') + '|' + (c.ip || ''));
        }
        for (const d of (topo.peer_diagnostics || [])) {
            bits.push('P:' + d.node_id + '|' + d.result + '|' + (d.reason || ''));
        }
        for (const r of (topo.routers || [])) {
            bits.push('R:' + r.ip + '|' + (r.name || '') + '|' + (r.vendor || '') + '|' + (r.reachable ? '1' : '0'));
        }
        return bits.join(';');
    }

    /// Soft-update the rack view: patch BPS labels, LED colours, pin
    /// opacity on every port in place. Assumes the structural skeleton
    /// is unchanged (caller has already verified via wrRackStructureHash).
    /// Runs in <1ms for typical clusters. No SVG rebuild, no flash.
    function wrSoftUpdateRack(topo) {
        const canvas = document.getElementById('wr-rack-canvas');
        if (!canvas) return false;
        // Build a quick lookup of the current port state.
        const byKey = new Map();
        for (const n of topo.nodes || []) {
            for (const i of n.interfaces || []) {
                byKey.set(n.node_id + '::' + i.name, i);
            }
        }
        const ports = canvas.querySelectorAll('.wr-port[data-node][data-iface]');
        if (!ports.length) return false;  // nothing to patch — force full render
        for (const g of ports) {
            const key = g.dataset.node + '::' + g.dataset.iface;
            const port = byKey.get(key);
            if (!port) continue;
            const bps = (port.rx_bps || 0) + (port.tx_bps || 0);

            // Activity LED + glow.
            const actLed = g.querySelector('[data-wr-role="led-act"]');
            if (actLed) {
                actLed.setAttribute('fill', bps > 0 ? 'url(#wr-led-amber)' : 'url(#wr-led-off)');
                if (bps > 0) actLed.setAttribute('filter', 'url(#wr-glow)');
                else actLed.removeAttribute('filter');
            }

            // Link LED (changes rarely but cheap to patch when it does).
            const linkLed = g.querySelector('[data-wr-role="led-link"]');
            if (linkLed) {
                linkLed.setAttribute('fill', port.link_up ? 'url(#wr-led-green)' : 'url(#wr-led-off)');
            }

            // Pin opacity tracks link_up.
            const pinOpacity = port.link_up ? '0.75' : '0.25';
            g.querySelectorAll('[data-wr-role="pin"]').forEach(p => {
                if (p.getAttribute('opacity') !== pinOpacity) p.setAttribute('opacity', pinOpacity);
            });

            // BPS label — patch text + visibility without adding/removing nodes.
            const bpsLabel = g.querySelector('[data-wr-role="bps"]');
            if (bpsLabel) {
                if (bps > 0) {
                    const newText = fmtBpsShort(bps);
                    if (bpsLabel.textContent !== newText) bpsLabel.textContent = newText;
                    bpsLabel.setAttribute('visibility', 'visible');
                } else {
                    bpsLabel.setAttribute('visibility', 'hidden');
                }
            }
        }
        // Cable active/idle styling — WAN cables change look when their
        // source port goes from idle to flowing. Patch in place so the
        // user sees the wire light up without a whole-rack repaint.
        const cables = canvas.querySelectorAll('[data-wr-cable]');
        for (const cable of cables) {
            const key = cable.dataset.wrCable;
            if (!key) continue;
            const port = byKey.get(key);
            if (!port) continue;
            const bps = (port.rx_bps || 0) + (port.tx_bps || 0);
            const active = bps > 0;
            cable.setAttribute('stroke-width', active ? '5' : '4');
            cable.setAttribute('opacity', active ? '0.95' : '0.7');
            if (active) {
                cable.classList.add('wr-wire-active');
                cable.setAttribute('stroke-dasharray', '10 6');
            } else {
                cable.classList.remove('wr-wire-active');
                cable.removeAttribute('stroke-dasharray');
            }
        }
        return true;
    }

    function wrRenderRack() {
        const canvas = document.getElementById('wr-rack-canvas');
        if (!canvas) return;
        const topo = wrState.topology;
        if (!topo || !topo.nodes || topo.nodes.length === 0) {
            canvas.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:60px;">
                No nodes in topology. <br>
                ${wrState.cluster ? `Cluster <code>${escHtml(wrState.cluster)}</code> may have no online WolfStack nodes.` : 'No cluster selected.'}
            </div>`;
            wrState.lastRackHash = '';
            return;
        }

        // Structural-change gate: if the rack's skeleton is identical
        // to the last render, skip the full SVG rebuild and just patch
        // the live values. This is what kills the 3-second flash the
        // user was seeing — 95% of polls only see BPS deltas, nothing
        // structural, so most ticks are now no-op paints.
        const structureHash = wrRackStructureHash(topo);
        if (wrState.lastRackHash === structureHash) {
            if (wrSoftUpdateRack(topo)) return;
            // Fall through to full render if soft-update can't find the
            // tagged elements (first paint after a navigation, DOM reset).
        }
        wrState.lastRackHash = structureHash;
        // Render a header describing the cluster + node count so the
        // rack view feels like a real cluster overview, not just a
        // diagram floating in space.
        const header = document.createElement('div');
        header.style.cssText = 'margin-bottom:12px; padding:10px 14px; background:rgba(168,85,247,0.08); border:1px solid rgba(168,85,247,0.25); border-radius:6px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; font-size:13px;';
        const totalPorts = topo.nodes.reduce((s, n) => s + (n.interfaces?.length || 0), 0);
        const totalUp = topo.nodes.reduce((s, n) => s + (n.interfaces || []).filter(i => i.link_up).length, 0);
        const totalVms = topo.nodes.reduce((s, n) => s + (n.vms?.length || 0), 0);
        const totalCt = topo.nodes.reduce((s, n) => s + (n.containers?.length || 0), 0);
        // Per-peer diagnostics surface "why is this node missing?" right
        // on the cluster header — no need to dig into server logs to
        // debug fan-out failures.
        // WolfRouter is cluster-scoped — peers from OTHER clusters are
        // supposed to be absent from this view. Only surface "failed"
        // peers (couldn't reach a cluster-mate) as warnings.
        //   • failed  → real problem: a same-cluster peer isn't answering
        //   • skipped → intentional: peer belongs to a different cluster
        //     or isn't a wolfstack node at all
        // Skipped entries stay available behind a quieter "hidden peers"
        // disclosure for debugging, but don't amber-flag them.
        const diag = topo.peer_diagnostics || [];
        const diagFailed  = diag.filter(d => d.result === 'failed');
        const diagSkipped = diag.filter(d => d.result === 'skipped');
        const failedBanner = diagFailed.length
            ? `<details style="margin-top:6px; font-size:11px;">
                <summary style="cursor:pointer; color:#fbbf24;">${diagFailed.length} cluster peer${diagFailed.length===1?'':'s'} unreachable — click to see why</summary>
                <div style="margin-top:6px; padding:6px 10px; background:rgba(0,0,0,0.3); border-radius:4px;">
                    ${diagFailed.map(d => `<div style="color:var(--text-muted);"><strong>${escHtml(d.hostname || d.node_id)}</strong>: ${escHtml(d.reason || d.result)}</div>`).join('')}
                </div>
            </details>` : '';
        const skippedInfo = diagSkipped.length
            ? `<details style="margin-top:4px; font-size:10px; color:var(--text-muted);">
                <summary style="cursor:pointer; opacity:0.7;">${diagSkipped.length} node${diagSkipped.length===1?'':'s'} hidden (different cluster / not WolfStack)</summary>
                <div style="margin-top:4px; padding:6px 10px; background:rgba(0,0,0,0.15); border-radius:4px;">
                    ${diagSkipped.map(d => `<div><strong>${escHtml(d.hostname || d.node_id)}</strong>: ${escHtml(d.reason || '')}</div>`).join('')}
                </div>
            </details>` : '';
        const diagBanner = failedBanner + skippedInfo;

        header.innerHTML = `
            <div style="flex:1; min-width:240px;">
                <div><strong>Cluster: ${escHtml(wrState.cluster || 'unnamed')}</strong>
                    <span style="color:var(--text-muted); margin-left:8px;">${topo.nodes.length} node${topo.nodes.length===1?'':'s'} · ${totalUp}/${totalPorts} ports up · ${totalVms} VMs · ${totalCt} containers</span>
                </div>
                ${diagBanner}
            </div>
            <div style="color:var(--text-muted); font-size:11px;">live topology refreshes every 3s</div>
        `;

        const W = Math.max(canvas.clientWidth || 1000, 720);
        const ns = 'http://www.w3.org/2000/svg';

        // Layout dimensions ─────────────────────────────────────────
        const padX = 20;
        const cloudH = 90;
        const cloudGap = 30;
        const railW = 22;          // vertical rail width on each side
        const rackInnerPad = 8;    // gap between rail and appliance
        const baseUnitH = 116;     // 2U baseline — taller now to fit
                                   // the bigger port labels + IP line
        const oneUH = 22;          // each "rack unit" of growth = one device row
        const unitGap = 24;
        const deviceRowH = 22;     // pixel pitch for each device badge

        // ─── Gateway-grouped layout ───
        //
        // Group servers by their primary default gateway. Each group
        // becomes a vertical stack in the rack: router chassis (1U)
        // followed by its servers (2U+). Servers with no detected
        // gateway go at the bottom with a direct cable to the cloud.
        //
        // This produces an accurate "trace the cable" view:
        //   Server WAN port → router LAN port → router WAN port → cloud
        const discoveredRouters = topo.routers || [];
        const routerUnitH = 56;  // 1U router chassis — tall enough for RJ45 jacks + LEDs + labels
        const nodeCount = topo.nodes.length;

        // Per-node heights (unchanged formula, just computed up front).
        const nodeHeights = topo.nodes.map(n => {
            const devCount = (n.vms?.length || 0) + (n.containers?.length || 0);
            if (devCount <= 6) return baseUnitH;
            const extraRows = Math.ceil((devCount - 6) / 2);
            return baseUnitH + extraRows * oneUH;
        });

        // Group nodes by their default gateway. Two-phase approach:
        //
        // Phase 1: if there's only ONE unique router in the deduped
        // list, ALL servers share that gateway. Don't bother matching
        // per-node — just assign every server to it. This covers the
        // Hetzner / OVH / any-VLAN pattern where multiple servers sit
        // behind the same upstream gateway and is impossible to break.
        //
        // Phase 2: if there are MULTIPLE unique routers, try to match
        // each node to its gateway by checking the node's own
        // routers[] array. Nodes that don't match anything go
        // ungrouped (direct cable to cloud).
        const gwGroups = new Map();   // gateway_ip → { router, nodeIndices: [] }
        const noGwNodes = [];         // indices of nodes with no gateway

        if (discoveredRouters.length === 1) {
            // Single gateway — every server uses it.
            const r = discoveredRouters[0];
            gwGroups.set(r.ip, {
                router: r,
                nodeIndices: topo.nodes.map((_, i) => i),
            });
        } else if (discoveredRouters.length > 1) {
            // Multiple gateways — seed groups then match per-node.
            for (const r of discoveredRouters) {
                if (r.ip && !gwGroups.has(r.ip)) {
                    gwGroups.set(r.ip, { router: r, nodeIndices: [] });
                }
            }
            topo.nodes.forEach((node, idx) => {
                const gw = (node.routers || []).find(r => r.ip && !r.ip.startsWith('fe80'));
                if (gw && gwGroups.has(gw.ip)) {
                    gwGroups.get(gw.ip).nodeIndices.push(idx);
                } else {
                    noGwNodes.push(idx);
                }
            });
        } else {
            // No routers discovered — all nodes ungrouped.
            topo.nodes.forEach((_, idx) => noGwNodes.push(idx));
        }

        // Build the rack item sequence: [router, server, server, …, router, server, …, ungrouped servers].
        // Skip gateway groups with no servers (e.g. IPv6-only gateways
        // that no node matched to after the fe80 filter above).
        const rackItems = [];
        for (const [, grp] of gwGroups) {
            if (!grp.nodeIndices.length) continue;
            rackItems.push({ type: 'router', router: grp.router, height: routerUnitH, serverIndices: grp.nodeIndices });
            for (const idx of grp.nodeIndices) {
                rackItems.push({ type: 'server', nodeIdx: idx, height: nodeHeights[idx], gatewayIp: grp.router.ip });
            }
        }
        for (const idx of noGwNodes) {
            rackItems.push({ type: 'server', nodeIdx: idx, height: nodeHeights[idx], gatewayIp: null });
        }

        // Compute Y positions for every rack item (routers + servers
        // interleaved). Also build nodeYs[] indexed by topo.nodes position
        // so the existing per-node rendering code (which indexes by
        // nodeIdx) still works without rewrite.
        const nodeYs = new Array(nodeCount).fill(0);
        const itemYs = [];
        const routerItems = [];   // { rackItemIdx, y, router, serverIndices }
        let yAcc = rackInnerPad;
        for (let i = 0; i < rackItems.length; i++) {
            itemYs.push(yAcc);
            const item = rackItems[i];
            if (item.type === 'router') {
                routerItems.push({ idx: i, y: yAcc, router: item.router, serverIndices: item.serverIndices });
            } else {
                nodeYs[item.nodeIdx] = yAcc;
            }
            yAcc += item.height + unitGap;
        }
        const innerContent = yAcc - unitGap + rackInnerPad;

        const rackY = cloudH + cloudGap;
        const rackInnerH = innerContent;
        const H = rackY + rackInnerH + 60;

        const rackX = padX;
        const rackW = Math.max(W - padX*2 - 220, 600);  // reserve right-side strip for devices
        const apX = rackX + railW + rackInnerPad;
        const apW = rackW - railW*2 - rackInnerPad*2;

        // SVG root + defs ──────────────────────────────────────────
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('width', W); svg.setAttribute('height', H);
        svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
        svg.setAttribute('xmlns', ns);
        svg.style.fontFamily = 'system-ui, sans-serif';

        svg.insertAdjacentHTML('afterbegin', `
            <defs>
                <radialGradient id="wr-cloud" cx="50%" cy="40%" r="55%">
                    <stop offset="0" stop-color="rgba(96,165,250,0.65)"/>
                    <stop offset="0.7" stop-color="rgba(59,130,246,0.25)"/>
                    <stop offset="1" stop-color="rgba(30,58,138,0.05)"/>
                </radialGradient>
                <linearGradient id="wr-rail" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0" stop-color="#1f2937"/>
                    <stop offset="0.5" stop-color="#374151"/>
                    <stop offset="1" stop-color="#1f2937"/>
                </linearGradient>
                <linearGradient id="wr-chassis" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stop-color="#2c3a4f"/>
                    <stop offset="0.5" stop-color="#1f2a3d"/>
                    <stop offset="1" stop-color="#141d2c"/>
                </linearGradient>
                <linearGradient id="wr-brand" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stop-color="#7c3aed"/>
                    <stop offset="1" stop-color="#4c1d95"/>
                </linearGradient>
                <radialGradient id="wr-led-green" cx="50%" cy="50%" r="50%">
                    <stop offset="0" stop-color="#bbf7d0"/>
                    <stop offset="0.5" stop-color="#22c55e"/>
                    <stop offset="1" stop-color="#15803d"/>
                </radialGradient>
                <radialGradient id="wr-led-amber" cx="50%" cy="50%" r="50%">
                    <stop offset="0" stop-color="#fde68a"/>
                    <stop offset="0.5" stop-color="#f59e0b"/>
                    <stop offset="1" stop-color="#92400e"/>
                </radialGradient>
                <radialGradient id="wr-led-off" cx="50%" cy="50%" r="50%">
                    <stop offset="0" stop-color="#1e293b"/>
                    <stop offset="1" stop-color="#0f172a"/>
                </radialGradient>
                <linearGradient id="wr-jack" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stop-color="#0a0f18"/>
                    <stop offset="1" stop-color="#1e293b"/>
                </linearGradient>
                <filter id="wr-glow" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="2" result="b"/>
                    <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
            </defs>
        `);

        // Internet cloud ──────────────────────────────────────────
        const cloudCX = W/2, cloudCY = cloudH/2 + 6;
        svg.insertAdjacentHTML('beforeend', `
            <g class="wr-cloud-group">
                <path d="M ${cloudCX-160},${cloudCY+12}
                         C ${cloudCX-180},${cloudCY-20} ${cloudCX-110},${cloudCY-50} ${cloudCX-70},${cloudCY-30}
                         C ${cloudCX-50},${cloudCY-55} ${cloudCX+10},${cloudCY-55} ${cloudCX+30},${cloudCY-30}
                         C ${cloudCX+80},${cloudCY-55} ${cloudCX+150},${cloudCY-25} ${cloudCX+140},${cloudCY+5}
                         C ${cloudCX+180},${cloudCY+15} ${cloudCX+170},${cloudCY+45} ${cloudCX+120},${cloudCY+40}
                         L ${cloudCX-130},${cloudCY+40}
                         C ${cloudCX-180},${cloudCY+45} ${cloudCX-185},${cloudCY+15} ${cloudCX-160},${cloudCY+12} Z"
                      fill="url(#wr-cloud)" stroke="rgba(96,165,250,0.5)" stroke-width="1.5"/>
                <text x="${cloudCX}" y="${cloudCY-2}" text-anchor="middle"
                      style="fill:#bfdbfe; font-size:14px; font-weight:600;">Internet</text>
                <text x="${cloudCX}" y="${cloudCY+18}" text-anchor="middle"
                      style="fill:#93c5fd; font-size:10px;">WAN uplink</text>
            </g>
        `);

        const vendorEmoji = {
            'mikrotik': '', 'ubiquiti': '⬛', 'avm': '', 'openwrt': '',
            'opnsense': '', 'pfsense': '', 'tp-link': '', 'netgear': '',
            'asus': '📶', 'linksys': '📶', 'cisco': '🔷', 'draytek': '📶',
        };

        // Rack frame ──────────────────────────────────────────────
        // Outer rack background panel
        svg.insertAdjacentHTML('beforeend', `
            <rect x="${rackX}" y="${rackY}" width="${rackW}" height="${rackInnerH}" rx="6"
                  fill="rgba(15,23,42,0.65)" stroke="#1e293b" stroke-width="2"/>
        `);
        // Left + right rails with mounting holes
        for (const railX of [rackX, rackX + rackW - railW]) {
            svg.insertAdjacentHTML('beforeend', `
                <rect x="${railX}" y="${rackY}" width="${railW}" height="${rackInnerH}"
                      fill="url(#wr-rail)" stroke="#0a0f18" stroke-width="0.5"/>
            `);
            // Mounting holes — one every ~22px
            for (let yy = rackY + 12; yy < rackY + rackInnerH - 6; yy += 22) {
                svg.insertAdjacentHTML('beforeend', `
                    <ellipse cx="${railX + railW/2}" cy="${yy}" rx="3" ry="4.5"
                             fill="#0a0f18" stroke="#374151" stroke-width="0.4"/>
                `);
            }
        }

        // Router chassis (1U, inside the rack) ─────────────────────
        // Each gateway gets a full-width amber chassis with a WAN port
        // (top-left, cable goes to cloud) and LAN ports (bottom edge,
        // one per server, cables come from server WAN ports below).
        const routerPortPositions = {}; // gwIp → { wanPortCx, wanPortCy, lanPorts: [{cx,cy}] }
        for (const ri of routerItems) {
            const r = ri.router;
            const uy = rackY + ri.y;
            const emoji = vendorEmoji[(r.vendor || '').toLowerCase()] || '';
            const label = r.name || r.ip;
            const sublabel = r.vendor ? `${r.vendor}${r.model && r.model !== r.vendor ? ' · ' + r.model : ''}` : r.ip;

            // ─── Router chassis: rack-mount network appliance ───
            // Layout: brand panel left, 8 RJ45 ports center-right,
            // power button far right (click → opens admin web UI).
            const brandW = 130;
            const pwrBtnX = apX + apW - 36;
            const pwrBtnCY = uy + routerUnitH / 2;
            const adminUrl = escHtml(r.web_url || `http://${r.ip}`);

            const chassisHtml = `
                <rect x="${apX}" y="${uy}" width="${apW}" height="${routerUnitH}" rx="4"
                      fill="rgba(251,191,36,0.06)" stroke="rgba(251,191,36,0.35)" stroke-width="1.5"/>
            `;

            // Brand panel (left strip) — vendor emoji + name + IP + model
            const brandHtml = `
                <rect x="${apX}" y="${uy}" width="${brandW}" height="${routerUnitH}" rx="4"
                      fill="rgba(251,191,36,0.12)"/>
                <text x="${apX + 10}" y="${uy + 18}" style="fill:#fbbf24; font-size:12px; font-weight:700;">${emoji}</text>
                <text x="${apX + 28}" y="${uy + 18}" style="fill:#fbbf24; font-size:11px; font-weight:600;">${escHtml((r.vendor || r.name || 'Router').slice(0,12))}</text>
                <text x="${apX + 10}" y="${uy + 32}" style="fill:#94a3b8; font-size:9px;">${escHtml(r.ip)}</text>
                <text x="${apX + 10}" y="${uy + 44}" style="fill:#64748b; font-size:8px;">${escHtml((r.model || '').slice(0,16))}</text>
                ${r.reachable ? '' : '<circle cx="' + (apX + brandW - 10) + '" cy="' + (uy + 12) + '" r="3" fill="#ef4444"/>'}
                <title>${escHtml([r.name || 'Router', 'IP: ' + r.ip, r.vendor ? 'Vendor: ' + r.vendor : '', r.model ? 'Model: ' + r.model : '', r.web_url ? 'Admin: ' + r.web_url : ''].filter(Boolean).join('\n'))}</title>
            `;

            // Power switch — realistic rocker-style with a red glow.
            // SVG <a> wraps the whole switch so clicking anywhere on
            // it opens the router's admin UI in a new tab.
            const swX = apX + apW - 42;
            const swY = uy + 8;
            const swH = routerUnitH - 16;
            const swW = 28;
            const glowOn = r.reachable;
            const pwrBtnHtml = `
                <a href="${adminUrl}" target="_blank" style="cursor:pointer;">
                    <!-- Glow halo behind the switch when router is up -->
                    ${glowOn ? `<ellipse cx="${swX + swW/2}" cy="${swY + swH/2}" rx="${swW/2 + 6}" ry="${swH/2 + 4}"
                                  fill="rgba(239,68,68,0.15)"/>
                               <ellipse cx="${swX + swW/2}" cy="${swY + swH/2}" rx="${swW/2 + 3}" ry="${swH/2 + 2}"
                                  fill="rgba(239,68,68,0.08)"/>` : ''}
                    <!-- Switch housing (recessed dark bezel) -->
                    <rect x="${swX - 2}" y="${swY - 2}" width="${swW + 4}" height="${swH + 4}" rx="4"
                          fill="#0a0f18" stroke="#1e293b" stroke-width="1"/>
                    <!-- Rocker body — red when on, dark grey when off -->
                    <rect x="${swX}" y="${swY}" width="${swW}" height="${swH}" rx="3"
                          fill="${glowOn ? '#dc2626' : '#374151'}"
                          stroke="${glowOn ? '#ef4444' : '#4b5563'}" stroke-width="0.8"/>
                    <!-- Top highlight (3D bevel effect) -->
                    <rect x="${swX + 2}" y="${swY + 1}" width="${swW - 4}" height="${swH/2 - 2}" rx="2"
                          fill="${glowOn ? 'rgba(248,113,113,0.4)' : 'rgba(255,255,255,0.06)'}"/>
                    <!-- Center line (rocker seam) -->
                    <line x1="${swX + 4}" y1="${swY + swH/2}" x2="${swX + swW - 4}" y2="${swY + swH/2}"
                          stroke="${glowOn ? 'rgba(0,0,0,0.3)' : 'rgba(0,0,0,0.2)'}" stroke-width="0.8"/>
                    <!-- Power LED dot -->
                    <circle cx="${swX + swW/2}" cy="${swY + swH/2 - 5}" r="2.5"
                            fill="${glowOn ? '#fca5a5' : '#1f2937'}"
                            ${glowOn ? 'filter="url(#wr-glow)"' : ''}/>
                    <!-- I/O label -->
                    <text x="${swX + swW/2}" y="${swY + swH - 4}" text-anchor="middle"
                          style="fill:${glowOn ? 'rgba(255,255,255,0.7)' : 'rgba(255,255,255,0.2)'}; font-size:6px; font-weight:700;">I / O</text>
                    <title>Open ${escHtml(r.vendor || 'router')} admin UI at ${adminUrl}</title>
                </a>
            `;

            // Ports — 8 total, right of the brand panel. WAN first, then
            // LAN (one per connected server), then empty jacks to fill.
            const totalPorts = 8;
            const serverCount = ri.serverIndices.length;
            const jackW = 32, jackH = routerUnitH - 18;
            const portStartX = apX + brandW + 16;
            const jackGap = 6;
            const portsCY = uy + routerUnitH / 2 + 2;
            const lanPorts = [];
            let portsHtml = '';

            for (let pi = 0; pi < totalPorts; pi++) {
                const px = portStartX + pi * (jackW + jackGap);
                const py = portsCY - jackH / 2;
                const jackPath = `M ${px+2},${py+jackH-2} L ${px+2},${py+5} L ${px+5},${py+2} L ${px+jackW-5},${py+2} L ${px+jackW-2},${py+5} L ${px+jackW-2},${py+jackH-2} Z`;

                if (pi === 0) {
                    // WAN port — gold pins, cable goes to cloud.
                    portsHtml += `
                        <path d="${jackPath}" fill="url(#wr-jack)" stroke="#000" stroke-width="0.6"/>
                        ${Array.from({length:8}).map((_,j) =>
                            `<line x1="${px+5+j*((jackW-10)/7)}" y1="${py+5}" x2="${px+5+j*((jackW-10)/7)}" y2="${py+jackH-3}" stroke="#fbbf24" stroke-width="0.7" opacity="0.8"/>`
                        ).join('')}
                        <circle cx="${px+8}" cy="${py-2}" r="2" fill="url(#wr-led-green)"/>
                        <circle cx="${px+jackW-8}" cy="${py-2}" r="2" fill="${r.reachable ? 'url(#wr-led-amber)' : 'url(#wr-led-off)'}"/>
                        <text x="${px+jackW/2}" y="${py+jackH+9}" text-anchor="middle" style="fill:#fbbf24; font-size:8px; font-weight:600;">WAN</text>
                    `;
                } else if (pi - 1 < serverCount) {
                    // LAN port — blue pins, cable from a server's WAN port.
                    const si = pi - 1;
                    lanPorts.push({ cx: px + jackW / 2, cy: uy + routerUnitH, nodeIdx: ri.serverIndices[si] });
                    portsHtml += `
                        <path d="${jackPath}" fill="url(#wr-jack)" stroke="#000" stroke-width="0.6"/>
                        ${Array.from({length:8}).map((_,j) =>
                            `<line x1="${px+5+j*((jackW-10)/7)}" y1="${py+5}" x2="${px+5+j*((jackW-10)/7)}" y2="${py+jackH-3}" stroke="#3b82f6" stroke-width="0.7" opacity="0.7"/>`
                        ).join('')}
                        <circle cx="${px+8}" cy="${py-2}" r="2" fill="url(#wr-led-green)"/>
                        <circle cx="${px+jackW-8}" cy="${py-2}" r="2" fill="url(#wr-led-amber)"/>
                        <text x="${px+jackW/2}" y="${py+jackH+9}" text-anchor="middle" style="fill:#94a3b8; font-size:8px;">LAN${si}</text>
                    `;
                } else {
                    // Empty port — dark, no LEDs, no label. Looks like an
                    // unused jack on the back of real network gear.
                    portsHtml += `
                        <path d="${jackPath}" fill="rgba(15,23,42,0.7)" stroke="#1e293b" stroke-width="0.5"/>
                    `;
                }
            }

            svg.insertAdjacentHTML('beforeend', chassisHtml + brandHtml + portsHtml + pwrBtnHtml);
            const wanPortCx = portStartX + jackW / 2;
            routerPortPositions[r.ip] = { wanCx: wanPortCx, wanCy: uy, lanPorts };
        }

        // Rack appliances + ports ─────────────────────────────────
        const portsByNode = {};
        for (let nodeIdx = 0; nodeIdx < topo.nodes.length; nodeIdx++) {
            const node = topo.nodes[nodeIdx];
            // Per-node height grows with device count (3U/4U/5U as needed).
            const uh = nodeHeights[nodeIdx];
            const ux = apX, uy = rackY + nodeYs[nodeIdx], uw = apW;
            const brandW = 120;
            const portsZoneX = ux + brandW + 14;
            const portsZoneW = uw - brandW - 28 - 100;  // leave room for stats panel
            const statsX = ux + uw - 96;

            // Chassis
            const chassis = document.createElementNS(ns, 'g');
            svg.appendChild(chassis);
            chassis.insertAdjacentHTML('beforeend', `
                <rect x="${ux}" y="${uy}" width="${uw}" height="${uh}" rx="6"
                      fill="url(#wr-chassis)" stroke="#0a0f18" stroke-width="1.5"/>
                <!-- Top venting strip -->
                ${Array.from({length: 24}).map((_,i) =>
                    `<line x1="${ux+10+i*8}" y1="${uy+5}" x2="${ux+14+i*8}" y2="${uy+5}" stroke="#0a0f18" stroke-width="1.2"/>`
                ).join('')}
                <!-- Brand panel (left) -->
                <rect x="${ux+8}" y="${uy+10}" width="${brandW}" height="${uh-20}" rx="3"
                      fill="url(#wr-brand)" opacity="0.85"/>
                <text x="${ux+18}" y="${uy+34}" style="fill:#fff; font-size:14px; font-weight:700; letter-spacing:0.5px;">WOLF</text>
                <text x="${ux+18}" y="${uy+50}" style="fill:rgba(255,255,255,0.7); font-size:10px; letter-spacing:1px;">STACK</text>
                <text x="${ux+18}" y="${uy+72}" style="fill:#fde68a; font-size:11px; font-weight:600; font-family:monospace;">${escHtml(node.node_name.slice(0,14))}</text>
                <!-- Power LED (always on if responsive) -->
                <circle cx="${ux+brandW-8}" cy="${uy+18}" r="3.5" fill="url(#wr-led-green)" filter="url(#wr-glow)"/>
                <!-- Activity LED (any port up) -->
                <circle cx="${ux+brandW-8}" cy="${uy+34}" r="3.5"
                        fill="${node.interfaces.some(i=>i.link_up) ? 'url(#wr-led-amber)' : 'url(#wr-led-off)'}"
                        ${node.interfaces.some(i=>i.link_up) ? 'filter="url(#wr-glow)"' : ''}/>
                <!-- Stats panel (right) -->
                <rect x="${statsX}" y="${uy+10}" width="88" height="${uh-20}" rx="3"
                      fill="rgba(0,0,0,0.4)" stroke="#0a0f18"/>
                <text x="${statsX+8}" y="${uy+24}" style="fill:#22c55e; font-size:9px; font-family:monospace;">PORTS ${node.interfaces.length}</text>
                <text x="${statsX+8}" y="${uy+38}" style="fill:#60a5fa; font-size:9px; font-family:monospace;">VMS   ${node.vms.length}</text>
                <text x="${statsX+8}" y="${uy+52}" style="fill:#a855f7; font-size:9px; font-family:monospace;">CTRS  ${node.containers.length}</text>
                ${node.lan_segments?.length ? `<text x="${statsX+8}" y="${uy+72}" style="fill:#94a3b8; font-size:8px;">${node.lan_segments.length} WR LAN</text>` : ''}
                <!-- Rack-unit size badge so taller nodes are explained -->
                <text x="${statsX+80}" y="${uy+24}" text-anchor="end" style="fill:#fde68a; font-size:11px; font-weight:700; font-family:monospace;">${Math.max(2, Math.round(uh / 44))}U</text>
            `);

            // Ports — bigger jacks, left-aligned starting at the brand
            // panel edge so layout is consistent across nodes. Each
            // port shows iface name AND its IP address(es) underneath
            // so the user can read what's what at a glance.
            portsByNode[node.node_id] = [];
            const jackW = 44, jackH = 32, jackGap = 22;  // wider gap so iface labels don't collide
            const maxPorts = Math.min(node.interfaces.length, Math.floor((portsZoneW + jackGap) / (jackW + jackGap)));
            const startPx = portsZoneX;  // left-align (was centered)
            const portsCY = uy + uh/2 - 2;

            node.interfaces.slice(0, maxPorts).forEach((port, idx) => {
                const px = startPx + idx * (jackW + jackGap);
                const py = portsCY - jackH/2;
                const cableColor = port.link_up
                    ? (port.role === 'wan' ? '#fbbf24' :
                       port.role === 'lan' ? '#3b82f6' :
                       port.role === 'wolfnet' ? '#22c55e' :
                       port.role === 'management' ? '#a855f7' : '#94a3b8')
                    : '#475569';
                const linkLed = port.link_up ? 'url(#wr-led-green)' : 'url(#wr-led-off)';
                const actLed = (port.rx_bps + port.tx_bps) > 0 ? 'url(#wr-led-amber)' : 'url(#wr-led-off)';
                // First IPv4 address for inline display under the port
                const ipv4 = (port.addresses || []).find(a => a.includes('.') && !a.startsWith('fe80'));
                const ipDisplay = ipv4 ? ipv4.split('/')[0] : '';
                // RJ45 jack: trapezoidal shape with 8 contact pins inside.
                const jackPath = `M ${px+3},${py+jackH-3}
                                  L ${px+3},${py+8}
                                  L ${px+8},${py+3}
                                  L ${px+jackW-8},${py+3}
                                  L ${px+jackW-3},${py+8}
                                  L ${px+jackW-3},${py+jackH-3} Z`;
                // Tag every dynamic element (LEDs, pin lines, BPS text,
                // tooltip) with data-wr-role="…" so the soft-update pass
                // can patch them in place without re-rendering the whole
                // rack. The BPS text is always emitted — hidden when
                // zero — so we never have to add/remove nodes on update.
                const actBps = port.rx_bps + port.tx_bps;
                chassis.insertAdjacentHTML('beforeend', `
                    <g class="wr-port" data-node="${escHtml(node.node_id)}" data-iface="${escHtml(port.name)}">
                        <!-- LEDs above the jack: link (left) + activity (right) -->
                        <circle cx="${px+10}" cy="${py-4}" r="2.5" fill="${linkLed}" data-wr-role="led-link"/>
                        <circle cx="${px+jackW-10}" cy="${py-4}" r="2.5" fill="${actLed}" data-wr-role="led-act"
                                ${actBps > 0 ? 'filter="url(#wr-glow)"' : ''}/>
                        <!-- The jack itself -->
                        <path d="${jackPath}" fill="url(#wr-jack)" stroke="#000" stroke-width="0.8"/>
                        <!-- 8 contact pins -->
                        ${Array.from({length: 8}).map((_,j) =>
                            `<line data-wr-role="pin" x1="${px+8+j*((jackW-16)/7)}" y1="${py+8}" x2="${px+8+j*((jackW-16)/7)}" y2="${py+jackH-5}" stroke="#fbbf24" stroke-width="0.8" opacity="${port.link_up ? 0.75 : 0.25}"/>`
                        ).join('')}
                        <!-- Iface name below (bigger, readable) -->
                        <text x="${px+jackW/2}" y="${py+jackH+12}" text-anchor="middle"
                              style="fill:#f1f5f9; font-size:11px; font-weight:600; font-family:monospace;">${escHtml(port.name.slice(0,10))}</text>
                        <!-- Live BPS above LEDs. Always rendered so soft
                             update can patch text + visibility without
                             adding/removing DOM nodes (which triggers
                             the flash the user hated). -->
                        <text data-wr-role="bps" x="${px+jackW/2}" y="${py-9}" text-anchor="middle"
                              style="fill:#fde68a; font-size:8px; font-family:monospace;"
                              visibility="${actBps > 0 ? 'visible' : 'hidden'}">${actBps > 0 ? fmtBpsShort(actBps) : ''}</text>
                        <!-- Multi-line tooltip — browsers honour
                             newlines inside SVG <title>. -->
                        <title data-wr-role="tooltip">${escHtml([
                            `Interface: ${port.name}`,
                            `State: ${port.link_up ? 'UP' : 'DOWN'}`,
                            `Role: ${port.role}`,
                            ...(port.addresses && port.addresses.length ? port.addresses.map(a => `IP: ${a}`) : []),
                        ].join('\n'))}</title>
                    </g>
                `);
                portsByNode[node.node_id].push({
                    name: port.name, cx: px + jackW/2, cy: py + jackH/2,
                    portTop: py - 8, portBottom: py + jackH + 4,
                    chassisTop: uy,
                    role: port.role, link_up: port.link_up,
                    bps: port.rx_bps + port.tx_bps, color: cableColor,
                });
            });

        }

        // Patch cables ────────────────────────────────────────────
        // WolfNet mesh: when there are multiple nodes, draw a thick
        // green cable along the right side of the rack connecting every
        // appliance — visualises the L3 overlay that ties the cluster
        // together. The "spine" runs vertically; each node taps off it.
        const wolfnetSpineX = rackX + rackW - railW + 6;
        if (topo.nodes.length > 1) {
            const firstY = rackY + nodeYs[0] + nodeHeights[0]/2;
            const lastY = rackY + nodeYs[topo.nodes.length-1] + nodeHeights[topo.nodes.length-1]/2;
            // Spine
            svg.insertAdjacentHTML('beforeend', `
                <line x1="${wolfnetSpineX}" y1="${firstY}" x2="${wolfnetSpineX}" y2="${lastY}"
                      stroke="#22c55e" stroke-width="4" stroke-linecap="round" opacity="0.6"
                      stroke-dasharray="6 4" class="wr-wire-active"/>
                <text x="${wolfnetSpineX + 8}" y="${(firstY+lastY)/2}" transform="rotate(90 ${wolfnetSpineX+8} ${(firstY+lastY)/2})"
                      text-anchor="middle" style="fill:#22c55e; font-size:10px; font-weight:600;">WolfNet mesh</text>
            `);
            // Per-node tap from the spine into the back of each appliance
            for (let n = 0; n < topo.nodes.length; n++) {
                const ny = rackY + nodeYs[n] + nodeHeights[n]/2;
                const nx = apX + apW - 100;  // right edge of the stats panel
                svg.insertAdjacentHTML('beforeend', `
                    <path d="M ${nx},${ny} H ${wolfnetSpineX}"
                          fill="none" stroke="#22c55e" stroke-width="3" stroke-linecap="square" opacity="0.7"/>
                    <circle cx="${wolfnetSpineX}" cy="${ny}" r="4" fill="#22c55e" opacity="0.9"/>
                `);
            }
        }

        // WAN cables — spine routing pattern for clean large installs.
        //
        // Every cable runs: port → UP → LEFT to the rack rail → UP
        // along the rail to the target. This collects all cables on
        // the left edge so they don't cross each other horizontally
        // in the middle of the rack. On a 4-server setup the
        // difference is dramatic — no spaghetti.
        //
        // Three cable types:
        //   1. Router WAN port → cloud (uplink)
        //   2. Server WAN port → router LAN port (through the rack)
        //   3. Server WAN port → cloud (direct, no gateway)
        const cables = [];
        const spineX = rackX + 8;  // left rack rail inner edge
        let spineSlot = 0;         // stagger each cable 3px apart on the spine

        // Router WAN port → cloud.
        for (const ri of routerItems) {
            const rp = routerPortPositions[ri.router.ip];
            if (!rp) continue;
            const x1 = rp.wanCx, y1 = rp.wanCy;
            const sx = spineX + spineSlot * 3;
            // UP from WAN port to just above the chassis, LEFT to
            // spine, UP along spine to rack exit, RIGHT to cloud
            // center, UP to cloud bottom. Previous version went DOWN
            // first then UP, creating a U-bend that crossed itself.
            const clearY = rackY + ri.y - 6;  // just above this router's top edge
            const path = `M ${x1},${y1} V ${clearY} H ${sx} V ${rackY - 6} H ${cloudCX} V ${cloudCY + 30}`;
            cables.push({ path, color: '#fbbf24', bps: 1, kind: 'wan-uplink', cableKey: 'gw::' + ri.router.ip });
            spineSlot++;
        }

        // Server WAN ports.
        for (const node of topo.nodes) {
            for (const port of (portsByNode[node.node_id] || [])) {
                if (port.role !== 'wan' || !port.link_up) continue;
                const x1 = port.cx, y1 = port.portTop;
                const chassisTop = port.chassisTop ?? (port.portTop - 30);
                const sx = spineX + spineSlot * 3;
                const cableKey = node.node_id + '::' + port.name;

                // Find the server's gateway group.
                const gwIp = rackItems.find(ri => ri.type === 'server' && topo.nodes[ri.nodeIdx]?.node_id === node.node_id)?.gatewayIp;
                const rp = gwIp ? routerPortPositions[gwIp] : null;
                const lanPort = rp?.lanPorts?.find(lp => lp.nodeIdx === topo.nodes.findIndex(n => n.node_id === node.node_id));

                if (lanPort) {
                    // Server → LEFT to spine → UP to router LAN port row → RIGHT to port.
                    const path = `M ${x1},${y1} V ${chassisTop - 6} H ${sx} V ${lanPort.cy + 4} H ${lanPort.cx} V ${lanPort.cy}`;
                    cables.push({ path, color: port.color, bps: port.bps, kind: 'wan', cableKey });
                } else {
                    // No gateway — spine route direct to cloud.
                    const path = `M ${x1},${y1} V ${chassisTop - 6} H ${sx} V ${rackY - 6} H ${cloudCX} V ${cloudCY + 30}`;
                    cables.push({ path, color: port.color, bps: port.bps, kind: 'wan', cableKey });
                }
                spineSlot++;
            }
        }
        // (No more port "patch tails" — they overlapped the iface name
        // and IP address text underneath the jacks.)

        // Render cables behind the chassis but above the rack panel —
        // we already drew the rack/appliances first, so cables now go on
        // top, which actually reads better in this metaphor (cables in
        // front of equipment is what you see in a real rack from the
        // patch-panel side).
        for (const c of cables) {
            const active = c.bps > 0;
            // The outer path carries the activity styling; the inner
            // path is a static highlight. Only the outer needs a data
            // attribute for soft updates.
            svg.insertAdjacentHTML('beforeend', `
                <path data-wr-cable="${escHtml(c.cableKey || '')}" d="${c.path}" fill="none" stroke-linecap="round"
                      stroke="${c.color}" stroke-width="${active ? 5 : 4}"
                      opacity="${active ? 0.95 : 0.7}"
                      ${active ? 'class="wr-wire-active" stroke-dasharray="10 6"' : ''}/>
                <path d="${c.path}" fill="none" stroke-linecap="round"
                      stroke="rgba(255,255,255,0.18)" stroke-width="1"/>
            `);
        }

        // Per-node device clusters — instead of a flat shelf, hang each
        // node's VMs/containers directly under that node so the wiring
        // is unambiguous: device → server → port → cable → cloud.
        // Each device gets its own row; the node's appliance height was
        // grown above to accommodate them, so devices line up vertically
        // within their owning node's vertical band.
        for (let nIdx = 0; nIdx < topo.nodes.length; nIdx++) {
            const node = topo.nodes[nIdx];
            const nodeY = rackY + nodeYs[nIdx];
            const nodeHeightPx = nodeHeights[nIdx];
            const devicesForNode = (node.vms || []).concat(node.containers || []);
            if (!devicesForNode.length) continue;

            // Anchor on the node's right side, wired to all devices.
            const anchorX = apX + apW;
            const anchorY = nodeY + nodeHeightPx / 2;
            const colX = anchorX + 40 + nIdx * 4;  // staggered to avoid overlap
            // Centre the device column on the node so taller appliances
            // host their devices symmetrically rather than top-aligned.
            const totalDeviceH = devicesForNode.length * deviceRowH;
            const startY = nodeY + (nodeHeightPx - totalDeviceH) / 2;
            devicesForNode.forEach((dev, i) => {
                const isVm = dev.kind === 'vm';
                const accent = isVm ? '#60a5fa' : '#a855f7';
                const icon = isVm ? '' : '';
                const dy = startY + i * deviceRowH;
                const cableColor = accent;
                // Manhattan H-V-H: out the chassis right, down/up to
                // the device row, into the device left edge.
                const midX = anchorX + 18;
                svg.insertAdjacentHTML('beforeend', `
                    <path d="M ${anchorX},${anchorY} H ${midX} V ${dy+10} H ${colX}"
                          fill="none" stroke="${cableColor}" stroke-width="2" stroke-linecap="square" opacity="0.55"
                          ${i % 2 === 0 ? 'stroke-dasharray="6 4" class="wr-wire-active"' : ''}/>
                    <g>
                        <rect x="${colX}" y="${dy}" width="200" height="20" rx="5"
                              fill="rgba(15,23,42,0.95)" stroke="${accent}" stroke-width="1"/>
                        <text x="${colX+8}" y="${dy+14}" style="fill:#f1f5f9; font-size:11px;">${icon} ${escHtml(dev.name.slice(0,16))}</text>
                        <text x="${colX+195}" y="${dy+14}" text-anchor="end" style="fill:${accent}; font-size:10px; font-family:monospace;">${escHtml(dev.ip || dev.attached_to || '')}</text>
                    </g>
                `);
            });
        }

        // Inter-node WolfNet mesh — each pair of nodes connected by a
        // curved green cable to visualise the L3 overlay holding the
        // cluster together. Drawn behind everything else for depth.
        if (topo.nodes.length > 1) {
            for (let i = 0; i < topo.nodes.length; i++) {
                for (let j = i + 1; j < topo.nodes.length; j++) {
                    const yi = rackY + nodeYs[i] + nodeHeights[i]/2;
                    const yj = rackY + nodeYs[j] + nodeHeights[j]/2;
                    const xLeft = apX + 8;
                    // Manhattan C-shape to the left of the rack: out,
                    // along, back. Right-angle bends, no curves.
                    const railX = xLeft - 30 - ((i + j) % 3) * 8;
                    svg.insertAdjacentHTML('beforeend', `
                        <path d="M ${xLeft},${yi} H ${railX} V ${yj} H ${xLeft}"
                              fill="none" stroke="#22c55e" stroke-width="2.5" stroke-linecap="square"
                              opacity="0.5" stroke-dasharray="8 5" class="wr-wire-active"/>
                    `);
                }
            }
        }

        canvas.innerHTML = '';
        canvas.appendChild(header);
        canvas.appendChild(svg);

        // Legend + integration badges
        const legend = document.getElementById('wr-rack-legend');
        if (legend) {
            const sw = (color, label) =>
                `<div style="display:flex; align-items:center; gap:6px;"><span style="display:inline-block; width:18px; height:4px; background:${color}; border-radius:2px;"></span> ${label}</div>`;

            // Surface live integration state — what WolfStack already
            // runs that WolfRouter is now showing alongside its own.
            const wn = wrState.managed?.wolfnet_status;
            const peerCount = (wn?.peers || []).length;
            const wnBadge = wn
                ? `<div style="display:flex; align-items:center; gap:6px;"><span style="color:#22c55e;"></span> WolfNet: ${peerCount} peer${peerCount===1?'':'s'}${wn.running===false ? ' <span style="color:#ef4444;">(daemon down)</span>' : ''}</div>`
                : '';
            const mappingCount = (wrState.managed?.ip_mappings || []).length;
            const mapBadge = mappingCount
                ? `<div style="display:flex; align-items:center; gap:6px;"><span style="color:#60a5fa;"></span> ${mappingCount} port forward${mappingCount===1?'':'s'} (DNAT)</div>`
                : '';

            legend.innerHTML = [
                sw('#fbbf24', 'WAN cable'),
                sw('#3b82f6', 'LAN cable'),
                sw('#22c55e', 'WolfNet'),
                sw('#a855f7', 'Management'),
                sw('#94a3b8', 'Unassigned'),
                wnBadge,
                mapBadge,
                `<div style="margin-left:auto; color:var(--text-muted);">Click a port to assign a zone · cables animate when traffic flows</div>`
            ].filter(Boolean).join('');
        }

        // Click handler for ports → open zone assignment
        canvas.querySelectorAll('.wr-port').forEach(el => {
            el.addEventListener('click', () => {
                const node = el.dataset.node;
                const iface = el.dataset.iface;
                wrShowPortPanel(node, iface);
            });
        });
    }

    // Compact "5K" "120M" formatter for the LED-style port readouts.
    function fmtBpsShort(bps) {
        if (bps < 1024) return bps + 'b';
        if (bps < 1024*1024) return Math.round(bps / 1024) + 'K';
        if (bps < 1024*1024*1024) return Math.round(bps / 1048576) + 'M';
        return (bps / 1073741824).toFixed(1) + 'G';
    }

    function wrShowPortPanel(nodeId, ifaceName) {
        const topo = wrState.topology;
        const node = topo?.nodes?.find(n => n.node_id === nodeId);
        const port = node?.interfaces?.find(i => i.name === ifaceName);
        if (!port) return;
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:500px;">
                <div class="modal-header">
                    <h3>${escHtml(ifaceName)} on ${escHtml(node.node_name)}</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="display:grid; grid-template-columns:1fr 2fr; gap:6px 12px;">
                        <div style="color:var(--text-muted);">State</div><div>${port.link_up ? 'UP' : 'DOWN'}</div>
                        <div style="color:var(--text-muted);">MAC</div><div><code>${escHtml(port.mac)}</code></div>
                        <div style="color:var(--text-muted);">Speed</div><div>${port.speed_mbps ? port.speed_mbps + ' Mbps' : '—'}</div>
                        <div style="color:var(--text-muted);">Addresses</div><div>${(port.addresses||[]).map(a => `<code>${escHtml(a)}</code>`).join(', ') || '—'}</div>
                        <div style="color:var(--text-muted);">Live</div><div>⬇ ${fmtBps(port.rx_bps)} · ⬆ ${fmtBps(port.tx_bps)}</div>
                        <div style="color:var(--text-muted);">Role</div><div>${port.role.toUpperCase()}</div>
                        <div style="color:var(--text-muted);">Zone</div><div>
                            <select class="form-control" style="font-size:12px; padding:3px 6px; width:auto;" id="wr-port-zone">
                                <option value="">(unassigned)</option>
                                <option value="wan">WAN</option>
                                <option value="lan0">LAN 0</option>
                                <option value="lan1">LAN 1</option>
                                <option value="dmz">DMZ</option>
                                <option value="wolfnet">WolfNet</option>
                                <option value="trusted">Trusted</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Close</button>
                    ${!port.link_up ? `<button class="btn" style="background:rgba(34,197,94,0.15); color:#22c55e;" onclick="wrBringUpPort('${escHtml(nodeId)}', '${escHtml(ifaceName)}', this)">⬆ Bring Up</button>` : ''}
                    <button class="btn btn-primary" onclick="(async()=>{await wrAssignZone('${nodeId}','${ifaceName}',document.getElementById('wr-port-zone').value); this.closest('.modal-overlay').remove();})()">Apply zone</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        const cur = port.zone?.kind === 'lan' ? `lan${port.zone.id}` : (port.zone?.kind || '');
        if (cur) document.getElementById('wr-port-zone').value = cur;
    }

    /// Runs `ip link set <iface> up` on the owning node (via cluster
    /// RPC if remote). Intentionally one-way — no "Bring Down"
    /// companion, because clicking that over a remote session is a
    /// good way to take yourself offline.
    async function wrBringUpPort(nodeId, iface, btn) {
        const orig = btn.textContent;
        btn.disabled = true; btn.textContent = 'Bringing up…';
        try {
            const r = await fetch(wrUrl('/api/router/interface-up'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ iface, node_id: nodeId }),
            });
            const data = await r.json();
            if (!r.ok || data.success === false) {
                btn.textContent = 'failed';
                alert('Bring up failed: ' + (data.error || 'HTTP ' + r.status));
                btn.disabled = false; btn.textContent = orig;
                return;
            }
            btn.textContent = 'up';
            // Refresh topology so the rack view redraws the port as UP.
            setTimeout(async () => {
                await wrLoadAll();
                btn.closest('.modal-overlay')?.remove();
            }, 500);
        } catch (e) {
            btn.disabled = false; btn.textContent = orig;
            alert('Error: ' + e.message);
        }
    }
    window.wrBringUpPort = wrBringUpPort;

    // ─── Helpers ───

    function escHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function fmtBps(bps) {
        if (bps < 1024) return bps + ' bps';
        if (bps < 1024 * 1024) return (bps / 1024).toFixed(1) + ' Kbps';
        if (bps < 1024 * 1024 * 1024) return (bps / 1048576).toFixed(1) + ' Mbps';
        return (bps / 1073741824).toFixed(2) + ' Gbps';
    }

    // ─── Picker helpers (Zones / Interfaces / LANs / VMs / Containers) ───
    //
    // Replace the old "type it yourself" UX with dropdowns sourced from
    // the live topology. Frees users from remembering interface names
    // like enp3s0 and from typing zone slugs like "zone:lan0" correctly.

    async function wrLocalNodeId() {
        // Cached hit only when lookup previously succeeded. Use `undefined`
        // as the "never looked up" sentinel so lookups can retry after a
        // transient failure (the cluster-info endpoint can be briefly
        // unavailable during startup).
        if (typeof wrState.localNodeId === 'string') return wrState.localNodeId;
        try {
            const r = await fetch('/api/nodes');
            if (r.ok) {
                const j = await r.json();
                const self = (j.nodes || []).find(n => n.is_self);
                if (self?.id) {
                    wrState.localNodeId = self.id;
                    return self.id;
                }
            }
        } catch {}
        // Leave cache unset so a subsequent call retries — this matters
        // because without a known local id every IP-assignment attempt
        // would go through node_proxy and fail with "Use local API for
        // self node" against the local node.
        return '';
    }

    // Build a URL for a non-wolfrouter endpoint (e.g. /api/networking/…)
    // that may need to execute on a remote cluster node. Returns the
    // local path when nodeId is blank or matches self; otherwise the
    // node_proxy wrapper.
    //
    // If we can't resolve the local node id (startup race, auth edge
    // case), default to the direct path rather than the proxy: the
    // browser is already talking to a specific node, and the proxy
    // refuses self-targets with HTTP 400. Wrong-proxying is the worse
    // failure mode because it's silent until someone investigates the
    // 400 response.
    async function wrNodeUrl(nodeId, path) {
        if (!nodeId) return path;
        const local = await wrLocalNodeId();
        if (!local) return path;                      // unknown self → default to direct
        if (nodeId === local) return path;
        const stripped = path.replace(/^\/api\//, '');
        return `/api/nodes/${encodeURIComponent(nodeId)}/proxy/${stripped}`;
    }

    // Zone options used in every picker. Standard zones + any custom
    // zones already in play on the cluster so the set stays coherent.
    function wrZoneOptions() {
        const base = [
            { value: 'wan',      label: 'WAN — outside world',       zone: { kind: 'wan' } },
            { value: 'lan0',     label: 'LAN 0 — primary LAN',       zone: { kind: 'lan', id: 0 } },
            { value: 'lan1',     label: 'LAN 1',                      zone: { kind: 'lan', id: 1 } },
            { value: 'lan2',     label: 'LAN 2',                      zone: { kind: 'lan', id: 2 } },
            { value: 'lan3',     label: 'LAN 3',                      zone: { kind: 'lan', id: 3 } },
            { value: 'dmz',      label: 'DMZ — public-facing hosts', zone: { kind: 'dmz' } },
            { value: 'wolfnet',  label: 'WolfNet — cluster mesh',    zone: { kind: 'wolfnet' } },
            { value: 'trusted',  label: 'Trusted — admins only',     zone: { kind: 'trusted' } },
        ];
        const custom = new Set();
        for (const n of (wrState.topology?.nodes || [])) {
            for (const ifc of (n.interfaces || [])) {
                if (ifc.zone?.kind === 'custom' && ifc.zone.id) custom.add(ifc.zone.id);
            }
            for (const b of (n.bridges || [])) {
                if (b.zone?.kind === 'custom' && b.zone.id) custom.add(b.zone.id);
            }
        }
        for (const c of custom) {
            base.push({ value: 'custom:' + c, label: 'Custom — ' + c, zone: { kind: 'custom', id: c } });
        }
        return base;
    }

    // Flat list of every interface + bridge on every node.
    function wrInterfaceOptions() {
        const out = [];
        for (const n of (wrState.topology?.nodes || [])) {
            for (const ifc of (n.interfaces || [])) {
                out.push({
                    node_id: n.node_id, node_name: n.node_name,
                    name: ifc.name, kind: 'iface',
                    zone: ifc.zone, addresses: ifc.addresses || [], up: !!ifc.link_up,
                });
            }
            for (const b of (n.bridges || [])) {
                out.push({
                    node_id: n.node_id, node_name: n.node_name,
                    name: b.name, kind: 'bridge',
                    zone: b.zone, addresses: b.addresses || [], up: true,
                });
            }
        }
        return out;
    }

    function wrVmOptions() {
        const out = [];
        for (const n of (wrState.topology?.nodes || [])) {
            for (const v of (n.vms || [])) {
                out.push({ node_id: n.node_id, node_name: n.node_name, name: v.name, ip: v.ip || null });
            }
        }
        return out;
    }

    function wrContainerOptions() {
        const out = [];
        for (const n of (wrState.topology?.nodes || [])) {
            for (const c of (n.containers || [])) {
                out.push({ node_id: n.node_id, node_name: n.node_name, name: c.name, kind: c.kind, ip: c.ip || null });
            }
        }
        return out;
    }

    function wrZoneToValue(z) {
        if (!z) return '';
        if (z.kind === 'lan') return 'lan' + (z.id ?? 0);
        if (z.kind === 'custom') return 'custom:' + (z.id || '');
        return z.kind;
    }

    function wrValueToZone(v) {
        if (!v) return null;
        if (v.startsWith('custom:')) return { kind: 'custom', id: v.slice(7) };
        const m = v.match(/^lan(\d+)$/);
        if (m) return { kind: 'lan', id: parseInt(m[1], 10) };
        return { kind: v };
    }

    // Suggest a /24 subnet that doesn't collide with existing LAN
    // segments. Uses 192.168.<10+preferredLanIdx*10>.0/24 as the seed.
    function wrSuggestSubnet(preferredLanIdx) {
        const used = new Set((wrState.lans || []).map(l => l.subnet_cidr));
        const seed = ((preferredLanIdx || 0) + 1) * 10;
        for (let offset = 0; offset < 244; offset++) {
            const thirdOct = seed + offset;
            if (thirdOct >= 255) break;
            const cidr = `192.168.${thirdOct}.0/24`;
            if (!used.has(cidr)) {
                return {
                    cidr, router_ip: `192.168.${thirdOct}.1`,
                    pool_start: `192.168.${thirdOct}.100`,
                    pool_end: `192.168.${thirdOct}.250`,
                };
            }
        }
        return { cidr: '192.168.99.0/24', router_ip: '192.168.99.1',
                 pool_start: '192.168.99.100', pool_end: '192.168.99.250' };
    }

    // Parse prefix length out of a CIDR string. Returns null on malformed input.
    function wrPrefixFromCidr(cidr) {
        const m = (cidr || '').match(/\/(\d+)\s*$/);
        if (!m) return null;
        const p = parseInt(m[1], 10);
        return (p >= 0 && p <= 32) ? p : null;
    }

    // Ensure a backend tool (dnsmasq, iptables, tcpdump, conntrack) is
    // installed on the local node — hit /api/router/install-tool which
    // short-circuits when already installed or spawns apt/dnf/pacman
    // otherwise. Returns { success, message, alreadyInstalled }.
    //
    // We call this as a preflight so users never hit the "dnsmasq is
    // not installed" error buried inside dhcp::start. The wait (30-60s
    // on a first-time install) is shown explicitly in the UI.
    async function wrEnsureTool(tool) {
        try {
            const r = await fetch(wrUrl('/api/router/install-tool'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tool }),
            });
            const j = await r.json();
            return {
                success: !!j.success,
                message: j.message || j.error || '',
                alreadyInstalled: (j.message || '').includes('already installed'),
            };
        } catch (e) {
            return { success: false, message: 'request failed: ' + (e.message || e), alreadyInstalled: false };
        }
    }

    // DNS forwarder presets. Keyed so the LAN editor + Quick Setup wizard
    // can switch forwarders with a single select change. "custom" keeps
    // whatever the user typed.
    const WR_DNS_PRESETS = [
        { id: 'cloudflare', label: 'Cloudflare (1.1.1.1)',         servers: ['1.1.1.1', '1.0.0.1'] },
        { id: 'google',     label: 'Google (8.8.8.8)',             servers: ['8.8.8.8', '8.8.4.4'] },
        { id: 'quad9',      label: 'Quad9 (9.9.9.9, filters malware)', servers: ['9.9.9.9', '149.112.112.112'] },
        { id: 'opendns',    label: 'OpenDNS (Cisco)',              servers: ['208.67.222.222', '208.67.220.220'] },
        { id: 'adguard',    label: 'AdGuard (blocks ads/trackers)', servers: ['94.140.14.14', '94.140.15.15'] },
        { id: 'custom',     label: 'Custom — enter below',          servers: null },
    ];

    function wrDnsPresetOptionsHtml() {
        return WR_DNS_PRESETS.map(p =>
            `<option value="${p.id}">${p.label}</option>`).join('');
    }

    // Look up which preset a list of forwarders matches (if any).
    function wrDnsPresetFromServers(servers) {
        const s = (servers || []).slice().sort().join(',');
        for (const p of WR_DNS_PRESETS) {
            if (!p.servers) continue;
            if (p.servers.slice().sort().join(',') === s) return p.id;
        }
        return 'custom';
    }

    // ─── Quick Setup wizard ───
    //
    // One click on the Zones tab → WAN + LAN records auto-created with
    // sensible defaults, derived from the zones the user already
    // assigned. Transparent: the user sees exactly what will happen
    // before they click the go button, and each step reports success
    // or failure inline so they never wonder why internet isn't
    // working.

    async function wrShowQuickSetup() {
        if (!wrState.topology?.nodes?.length) {
            alert('Topology is still loading — try again in a moment.');
            return;
        }
        const ifaces = wrInterfaceOptions();
        const wanIfaces = ifaces.filter(i => i.zone?.kind === 'wan');
        const lanIfaces = ifaces.filter(i => i.zone?.kind === 'lan');

        let existingWans = [];
        try {
            const r = await fetch(wrUrl('/api/router/wan'));
            if (r.ok) existingWans = await r.json();
        } catch {}
        const existingLans = wrState.lans || [];

        const wanPlan = wanIfaces.map(i => {
            const already = existingWans.find(w => w.node_id === i.node_id && w.interface === i.name);
            return { iface: i, already };
        });
        // Two interfaces sharing the same LAN zone id would otherwise collide
        // on the default subnet. Track what we've handed out in this pass so
        // each iface gets a unique /24.
        const consumed = new Set((wrState.lans || []).map(l => l.subnet_cidr));
        const lanPlan = lanIfaces.map((i, idx) => {
            const already = existingLans.find(l => l.node_id === i.node_id && l.interface === i.name);
            const zoneId = i.zone?.id ?? 0;
            let subnet;
            if (already) {
                subnet = {
                    cidr: already.subnet_cidr, router_ip: already.router_ip,
                    pool_start: already.dhcp?.pool_start || '',
                    pool_end: already.dhcp?.pool_end || '',
                };
            } else {
                // Offset by both the zone id AND the iface iteration index
                // so two ifaces in the same zone still get distinct /24s.
                let offset = zoneId + idx;
                do {
                    subnet = wrSuggestSubnet(offset);
                    offset++;
                } while (consumed.has(subnet.cidr) && offset < zoneId + idx + 24);
                consumed.add(subnet.cidr);
            }
            const ipAlready = (i.addresses || []).some(a => a.startsWith(subnet.router_ip + '/'));
            const otherIps = (i.addresses || []).filter(a => !a.startsWith(subnet.router_ip + '/'));
            return { iface: i, already, subnet, ipAlready, otherIps };
        });

        const hasAnything = wanPlan.length + lanPlan.length > 0;

        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:720px;">
                <div class="modal-header">
                    <h3>Quick Setup — turn this host into a router</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    ${!hasAnything ? `
                    <div style="padding:16px; background:rgba(251,191,36,0.1); border:1px solid rgba(251,191,36,0.35); border-radius:6px;">
                        <strong>Assign zones first.</strong> Give at least one interface the <code>WAN</code> zone (your internet-facing NIC) and one or more the <code>LAN</code> zone (your home network side). Then come back here.
                    </div>` : `
                    <div style="padding:10px 12px; margin-bottom:12px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.35); border-radius:6px; font-size:12px;">
                        <strong style="color:#fca5a5;">Shut down any other DHCP server on this LAN first.</strong>
                        <div style="margin-top:3px; color:var(--text-muted);">If OPNsense, pfSense, your ISP router, a pi-hole, or another WolfRouter instance is still handing out leases on the same physical network, clients will get random leases from whichever server answered first — you'll see half the devices online and half unable to reach anything. One DHCP per broadcast domain.</div>
                    </div>
                    <p style="color:var(--text-muted); margin:0 0 12px;">Based on your zone assignments, WolfRouter will create the missing WAN + LAN records, assign the router IP to each LAN interface, apply the firewall, and verify DNS resolution end-to-end. Review below and edit any defaults, then click <strong>Run setup</strong>.</p>

                    <label style="display:block; margin-bottom:10px;">DNS provider for every new LAN
                        <select id="wr-qs-dns-preset" class="form-control" style="max-width:360px;">${wrDnsPresetOptionsHtml()}</select>
                    </label>

                    ${wanPlan.length ? `
                    <h4 style="font-size:13px; margin:14px 0 6px;">WAN (internet uplink)</h4>
                    <div id="wr-qs-wan" style="display:grid; gap:8px;">
                        ${wanPlan.map((p, i) => `
                        <div style="padding:10px; border:1px solid var(--border); border-radius:6px; background:var(--bg-card);">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <div><code>${escHtml(p.iface.name)}</code> on <code>${escHtml(p.iface.node_name)}</code>
                                ${p.iface.up ? '<span style="color:#22c55e;">● up</span>' : '<span style="color:var(--text-muted);">○ down</span>'}</div>
                                <span class="badge" style="background:${p.already ? 'rgba(96,165,250,0.15)' : 'rgba(34,197,94,0.15)'}; color:${p.already ? '#60a5fa' : '#22c55e'}; font-size:10px;">${p.already ? 'exists — will skip' : 'will create DHCP uplink'}</span>
                            </div>
                            ${p.already ? '' : `
                            <div style="margin-top:6px; font-size:11px; color:var(--text-muted);">
                                Mode: DHCP (the interface's existing DHCP client keeps running; WolfRouter just installs MASQUERADE on <code>${escHtml(p.iface.name)}</code>).
                            </div>`}
                            <input type="hidden" data-wan-idx="${i}" data-node="${escHtml(p.iface.node_id)}" data-iface="${escHtml(p.iface.name)}" data-skip="${p.already ? '1' : '0'}"/>
                        </div>`).join('')}
                    </div>` : '<div style="color:#f87171; font-size:12px;">No interface has the WAN zone. Without WAN, LAN clients have no internet uplink.</div>'}

                    ${lanPlan.length ? `
                    <h4 style="font-size:13px; margin:14px 0 6px;">LAN (your home network)</h4>
                    <div id="wr-qs-lan" style="display:grid; gap:8px;">
                        ${lanPlan.map((p, i) => `
                        <div style="padding:10px; border:1px solid var(--border); border-radius:6px; background:var(--bg-card);">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                                <div><code>${escHtml(p.iface.name)}</code> on <code>${escHtml(p.iface.node_name)}</code>
                                <span class="badge" style="background:rgba(168,85,247,0.15); color:#a855f7; font-size:10px; margin-left:4px;">${zoneHuman(p.iface.zone)}</span></div>
                                <span class="badge" style="background:${p.already ? 'rgba(96,165,250,0.15)' : 'rgba(34,197,94,0.15)'}; color:${p.already ? '#60a5fa' : '#22c55e'}; font-size:10px;">${p.already ? 'exists — will reconfigure IP only' : 'will create segment'}</span>
                            </div>
                            <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px; font-size:12px;">
                                <label>Subnet <input class="form-control wr-qs-cidr" value="${escHtml(p.subnet.cidr)}" ${p.already ? 'disabled' : ''}/></label>
                                <label>Router IP <input class="form-control wr-qs-router" value="${escHtml(p.subnet.router_ip)}" ${p.already ? 'disabled' : ''}/></label>
                                <label>DHCP pool start <input class="form-control wr-qs-pool-start" value="${escHtml(p.subnet.pool_start)}" ${p.already ? 'disabled' : ''}/></label>
                                <label>DHCP pool end <input class="form-control wr-qs-pool-end" value="${escHtml(p.subnet.pool_end)}" ${p.already ? 'disabled' : ''}/></label>
                            </div>
                            ${p.otherIps.length ? `
                            <div style="margin-top:6px; padding:6px 8px; background:rgba(251,191,36,0.1); border:1px solid rgba(251,191,36,0.35); border-radius:4px; font-size:11px;">
                                Interface already has address(es): ${p.otherIps.map(a => `<code>${escHtml(a)}</code>`).join(', ')}. WolfRouter will add the router IP alongside — the existing IPs stay.
                            </div>` : ''}
                            ${p.ipAlready ? `<div style="margin-top:6px; font-size:11px; color:var(--text-muted);"><code>${escHtml(p.subnet.router_ip)}</code> already assigned to this interface.</div>` : ''}
                            <input type="hidden" data-lan-idx="${i}" data-node="${escHtml(p.iface.node_id)}" data-iface="${escHtml(p.iface.name)}" data-zone="${escHtml(wrZoneToValue(p.iface.zone))}" data-skip="${p.already ? '1' : '0'}"/>
                        </div>`).join('')}
                    </div>` : '<div style="color:var(--text-muted); font-size:12px;">No interface has a LAN zone — nothing to serve DHCP on.</div>'}

                    <div id="wr-qs-status" style="margin-top:14px; display:none;"></div>
                    `}
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Close</button>
                    ${hasAnything ? `<button id="wr-qs-run" class="btn btn-primary" onclick="wrRunQuickSetup()">Run setup</button>` : ''}
                </div>
            </div>`;
        document.body.appendChild(overlay);
    }
    window.wrShowQuickSetup = wrShowQuickSetup;

    async function wrRunQuickSetup() {
        const runBtn = document.getElementById('wr-qs-run');
        const statusBox = document.getElementById('wr-qs-status');
        if (!runBtn || !statusBox) return;
        runBtn.disabled = true;
        runBtn.textContent = 'Running…';
        statusBox.style.display = 'block';
        statusBox.innerHTML = '';
        const log = (emoji, msg, colour = 'var(--text)') => {
            statusBox.innerHTML += `<div style="padding:4px 0; font-size:12px; color:${colour};">${emoji} ${msg}</div>`;
            statusBox.scrollTop = statusBox.scrollHeight;
        };

        // 0. Preflight — make sure dnsmasq and iptables are installed BEFORE
        // trying to use them. Without this, users hit a cryptic "dnsmasq is
        // not installed" error inside dhcp::start after all the setup ran.
        // install-tool no-ops (returns "already installed") when present, so
        // calling blind is safe.
        log('', 'Preflight: checking dnsmasq + iptables are installed on the host…', 'var(--text-muted)');
        for (const tool of ['iptables', 'dnsmasq']) {
            const res = await wrEnsureTool(tool);
            if (res.alreadyInstalled) {
                log('', `<code>${escHtml(tool)}</code> already installed.`, '#22c55e');
            } else if (res.success) {
                log('', `<code>${escHtml(tool)}</code> installed: ${escHtml(res.message)}`, '#22c55e');
            } else {
                log('', `<code>${escHtml(tool)}</code> install failed: ${escHtml(res.message)}. Fix that first (try <code>apt install ${escHtml(tool)}</code>) then re-run Quick Setup.`, '#ef4444');
                // Abort — every subsequent step depends on these tools.
                runBtn.textContent = 'Aborted';
                return;
            }
        }

        // 1. Create WAN connections for any WAN-zoned iface without one.
        const wanHiddens = Array.from(document.querySelectorAll('#wr-qs-wan input[type="hidden"]'));
        for (const h of wanHiddens) {
            if (h.dataset.skip === '1') continue;
            const node = h.dataset.node, iface = h.dataset.iface;
            const body = {
                id: '', name: `WAN on ${iface}`,
                node_id: node, interface: iface,
                mode: { mode: 'dhcp' },
                enabled: true, description: 'Created by Quick Setup',
            };
            try {
                const r = await fetch(wrUrl('/api/router/wan'), {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                });
                if (r.ok) log('', `WAN connection on <code>${escHtml(iface)}</code> created. MASQUERADE installed.`, '#22c55e');
                else log('', `WAN create on <code>${escHtml(iface)}</code> failed: ${escHtml(await r.text())}`, '#ef4444');
            } catch (e) {
                log('', `WAN create on <code>${escHtml(iface)}</code> errored: ${escHtml(e.message || e)}`, '#ef4444');
            }
        }

        // Resolve the DNS provider once — applied to every LAN we create.
        const dnsPresetId = document.getElementById('wr-qs-dns-preset')?.value || 'cloudflare';
        const dnsPreset = WR_DNS_PRESETS.find(p => p.id === dnsPresetId);
        const forwarders = (dnsPreset?.servers) || ['1.1.1.1', '1.0.0.1'];

        // 2. For each LAN-zoned iface: assign router IP to interface, bring up, create LanSegment.
        const lanHiddens = Array.from(document.querySelectorAll('#wr-qs-lan input[type="hidden"]'));
        const createdLans = [];  // for the post-setup DNS validation pass
        for (const h of lanHiddens) {
            const node = h.dataset.node, iface = h.dataset.iface, zoneVal = h.dataset.zone;
            const card = h.closest('div');
            const cidr = card.querySelector('.wr-qs-cidr').value.trim();
            const routerIp = card.querySelector('.wr-qs-router').value.trim();
            const poolStart = card.querySelector('.wr-qs-pool-start').value.trim();
            const poolEnd = card.querySelector('.wr-qs-pool-end').value.trim();
            const prefix = wrPrefixFromCidr(cidr);
            if (prefix == null) { log('', `LAN <code>${escHtml(iface)}</code>: bad CIDR <code>${escHtml(cidr)}</code>`, '#ef4444'); continue; }

            // 2a. Assign router IP to the interface (idempotent — ignore "File exists").
            try {
                const url = await wrNodeUrl(node, '/api/networking/interfaces/' + encodeURIComponent(iface) + '/ip');
                const r = await fetch(url, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ address: routerIp, prefix }),
                });
                const txt = await r.text();
                if (r.ok) log('', `<code>${escHtml(routerIp)}/${prefix}</code> assigned to <code>${escHtml(iface)}</code>.`, '#22c55e');
                else if (/file exists|already assigned|RTNETLINK.*File exists/i.test(txt)) log('ℹ', `<code>${escHtml(routerIp)}/${prefix}</code> already on <code>${escHtml(iface)}</code>.`, 'var(--text-muted)');
                else log('', `IP assign on <code>${escHtml(iface)}</code> failed: ${escHtml(txt)}`, '#ef4444');
            } catch (e) {
                log('', `IP assign on <code>${escHtml(iface)}</code> errored: ${escHtml(e.message || e)}`, '#ef4444');
            }

            // 2b. Bring interface up.
            try {
                const url = await wrNodeUrl(node, '/api/networking/interfaces/' + encodeURIComponent(iface) + '/state');
                await fetch(url, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ up: true }),
                });
            } catch {}

            // 2c. Create the LAN segment (skip if already exists).
            if (h.dataset.skip === '1') {
                log('ℹ', `LAN segment on <code>${escHtml(iface)}</code> already exists — IP re-confirmed only.`, 'var(--text-muted)');
                // Still include in the DNS-validation pass so an existing-but-broken LAN gets flagged.
                createdLans.push({ iface, routerIp });
                continue;
            }
            const zoneObj = wrValueToZone(zoneVal);
            const body = {
                id: '', name: `LAN on ${iface}`,
                node_id: node, interface: iface, zone: zoneObj,
                subnet_cidr: cidr, router_ip: routerIp,
                dhcp: { enabled: true, pool_start: poolStart, pool_end: poolEnd,
                        lease_time: '12h', reservations: [], extra_options: [] },
                dns: { forwarders, local_records: [], wildcard_domains: [],
                       cache_enabled: true, block_ads: false },
                description: 'Created by Quick Setup',
            };
            try {
                const r = await fetch(wrUrl('/api/router/segments'), {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                });
                if (r.ok) {
                    log('', `LAN segment on <code>${escHtml(iface)}</code> created — dnsmasq serving DHCP+DNS on <code>${escHtml(cidr)}</code> (forwarders: ${escHtml(forwarders.join(', '))}).`, '#22c55e');
                    createdLans.push({ iface, routerIp });
                } else log('', `LAN segment on <code>${escHtml(iface)}</code> failed: ${escHtml(await r.text())}`, '#ef4444');
            } catch (e) {
                log('', `LAN segment on <code>${escHtml(iface)}</code> errored: ${escHtml(e.message || e)}`, '#ef4444');
            }
        }

        // 3. Apply firewall so the new rules/MASQUERADE go live.
        try {
            const r = await fetch(wrUrl('/api/router/rules/apply'), { method: 'POST' });
            if (r.ok) log('', 'Firewall ruleset applied.', '#22c55e');
            else log('', `Firewall apply failed: ${escHtml(await r.text())}`, '#ef4444');
        } catch (e) {
            log('', `Firewall apply errored: ${escHtml(e.message || e)}`, '#ef4444');
        }

        // 4. Host-side DNS bind check for each created LAN. This only
        // confirms dnsmasq is bound on the router IP (the query routes
        // via lo from the host) — it does NOT prove LAN clients can
        // reach it. For that, point the user at the DNS Tools tab's
        // LAN-side health section.
        if (createdLans.length) {
            log('', 'Running host-side dnsmasq bind check on each LAN…', 'var(--text-muted)');
            // Give dnsmasq a moment to finish binding after segment create.
            await new Promise(r => setTimeout(r, 800));
            let anyFailed = false;
            for (const cl of createdLans) {
                try {
                    // Pass the LAN's actual listen_port so we don't hit
                    // the misleading "Connection refused on :53" error
                    // when the LAN is on a non-standard port (5353
                    // etc., when AdGuard/Pi-hole takes :53). Default
                    // to 53 when not set.
                    const probePort = (cl.listenPort && cl.listenPort > 0) ? cl.listenPort : 53;
                    const r = await fetch(wrUrl('/api/router/test-dns'), {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ router_ip: cl.routerIp, hostname: 'cloudflare.com', port: probePort }),
                    });
                    const j = await r.json();
                    if (j.success) {
                        log('', `dnsmasq on <code>${escHtml(cl.iface)}</code> (<code>${escHtml(cl.routerIp)}</code>) is bound and answering host-side — resolved cloudflare.com → <code>${escHtml((j.answer || '').split('\n')[0])}</code> in ${j.duration_ms}ms. (Host-side only — doesn't prove LAN clients can reach it.)`, '#22c55e');
                    } else {
                        anyFailed = true;
                        log('', `dnsmasq bind check on <code>${escHtml(cl.iface)}</code> (<code>${escHtml(cl.routerIp)}</code>): ${escHtml(j.error || 'failed')}`, '#ef4444');
                    }
                } catch (e) {
                    anyFailed = true;
                    log('', `DNS bind check on <code>${escHtml(cl.iface)}</code> errored (dig not installed?): ${escHtml(e.message || e)}`, '#fbbf24');
                }
            }
            if (anyFailed) {
                log('ℹ', 'Open the <strong>DNS Tools</strong> tab → "LAN-side DNS health" section to see if LAN clients are actually reaching dnsmasq.', '#60a5fa');
            } else {
                log('ℹ', 'Next step: verify from a LAN client. If a client can\'t resolve, open the <strong>DNS Tools</strong> tab → "LAN-side DNS health" section — it tails dnsmasq\'s query log so you can see in real time whether client queries are arriving.', '#60a5fa');
            }
        }

        log('', '<strong>Setup complete.</strong> Plug a client into the LAN interface — it should get a DHCP lease and reach the internet.', '#a855f7');
        runBtn.textContent = 'Done';
        if (typeof showToast === 'function') showToast('Quick Setup complete — WAN + LAN + firewall applied', 'success');
        await wrLoadAll();
        // Auto-close after a few seconds so user doesn't have to hunt
        // for the Close button. Long enough to read the final "setup
        // complete" line; short enough that they don't wonder if it's
        // stuck. Close manually is still available via the × / Close
        // button for users who want to copy the log.
        setTimeout(() => {
            runBtn.closest('.modal-overlay')?.remove();
        }, 4000);
    }
    window.wrRunQuickSetup = wrRunQuickSetup;

    // ─── DNS Tools tab — ping / traceroute / nslookup / whois ─────────
    //
    // Every interaction pushes status/feedback into the visible panel —
    // spinners for in-flight, coloured results, explanatory messages on
    // failure. Nothing goes only to the console.

    async function wrRenderDnsTools() {
        const root = document.getElementById('wr-tools-root');
        if (!root) return;

        // Lane-side LAN picker options — only LANs with DHCP/DNS matter
        // for the "is a client reaching our dnsmasq?" question.
        const lanOpts = (wrState.lans || []).map(l =>
            `<option value="${escHtml(l.id)}">${escHtml(l.name)} — ${escHtml(l.interface)} (${escHtml(l.subnet_cidr)})</option>`).join('');

        // Node picker for the per-node panels (host-DNS + deps check).
        // Build from the LANs that actually have a node_id, falling
        // back to the cluster's topology nodes so even a fresh cluster
        // with no LANs defined yet still gets a usable selector.
        const _lanNodes = new Map();
        for (const l of (wrState.lans || [])) {
            if (l.node_id) _lanNodes.set(l.node_id, l.node_id);
        }
        for (const n of (wrState.topology?.nodes || [])) {
            if (n.node_id && !_lanNodes.has(n.node_id)) {
                _lanNodes.set(n.node_id, n.node_name || n.node_id);
            }
        }
        // If a LAN contributed an ID but topology has the nicer name, prefer the name.
        for (const n of (wrState.topology?.nodes || [])) {
            if (n.node_id && _lanNodes.has(n.node_id)) _lanNodes.set(n.node_id, n.node_name || n.node_id);
        }
        const nodeOpts = Array.from(_lanNodes.entries())
            .map(([id, name]) => `<option value="${escHtml(id)}">${escHtml(name)}</option>`).join('');

        root.innerHTML = `
            <!-- PER-NODE scope picker. Host DNS / deps are node-local;
                 we surface the choice explicitly so operators on a
                 multi-node cluster know exactly which box they're
                 inspecting. Defaults to the first LAN's node so the
                 common "one LAN on one node" case needs zero clicks. -->
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px; padding:8px 12px; background:var(--bg-secondary); border:1px solid var(--border); border-radius:6px;">
                <strong style="font-size:12px;">Node:</strong>
                <select id="wr-tools-node" class="form-control" style="max-width:280px; font-size:12px;" onchange="wrToolsOnNodeChange()">${nodeOpts || '<option value="">(no nodes)</option>'}</select>
                <span style="font-size:11px; color:var(--text-muted);">Host DNS + dependency checks below run against this node.</span>
            </div>

            <!-- DEPENDENCY CHECK — lists what's installed / missing on
                 the selected node, shows the exact pkg-mgr command we
                 would run, lets the operator click Install or copy it
                 to run by hand. Distro-aware (apt/dnf/pacman/apk/zypper). -->
            <div id="wr-deps-card" style="padding:14px; border:1px solid rgba(34,197,94,0.35); border-radius:8px; background:rgba(34,197,94,0.06); margin-bottom:16px;">
                <div style="display:flex; align-items:baseline; gap:8px; margin-bottom:6px;">
                    <strong style="font-size:14px; color:#22c55e;">DNS tooling on this node</strong>
                    <span style="font-size:11px; color:var(--text-muted);">— what's installed vs. what we need, with a one-click installer matched to your distro</span>
                </div>
                <div id="wr-deps-body" style="font-size:12px; color:var(--text-muted);">Checking…</div>
            </div>

            <!-- HOST DNS RESOLVER — who owns port 53 on this node,
                 release it to a containerised resolver, restore when
                 done. One-click alternative to editing resolved.conf
                 by hand for the "AdGuard in Docker wants port 53"
                 scenario. -->
            <div id="wr-host-dns-card" style="padding:14px; border:1px solid rgba(59,130,246,0.35); border-radius:8px; background:rgba(59,130,246,0.06); margin-bottom:16px;">
                <div style="display:flex; align-items:baseline; gap:8px; margin-bottom:6px;">
                    <strong style="font-size:14px; color:#3b82f6;">Host DNS resolver — port 53</strong>
                    <span style="font-size:11px; color:var(--text-muted);">— who owns port 53 on this node, and how to free it for a containerised DNS server</span>
                </div>
                <div id="wr-host-dns-body" style="font-size:12px; color:var(--text-muted);">Checking…</div>
            </div>
            <!-- LAN-SIDE DIAGNOSTICS — the section that actually answers
                 "why can't my client resolve?" by watching real client
                 traffic, not by running dig from the host. -->
            <div style="padding:14px; border:1px solid rgba(168,85,247,0.35); border-radius:8px; background:rgba(168,85,247,0.06); margin-bottom:16px;">
                <div style="display:flex; align-items:baseline; gap:8px; margin-bottom:6px;">
                    <strong style="font-size:14px; color:#a855f7;">LAN-side DNS health</strong>
                    <span style="font-size:11px; color:var(--text-muted);">— shows whether LAN clients can actually reach dnsmasq</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px;">
                    Host-side tests (dig, nslookup) reach dnsmasq via <code>lo</code> and mislead if the issue is LAN routing or firewall. These two tools watch the LAN interface and dnsmasq's own query log to show what clients are (or aren't) doing.
                </div>

                ${lanOpts ? `
                <label style="display:block; margin-bottom:10px;">LAN to diagnose
                    <select id="wr-lside-lan" class="form-control" style="max-width:480px;" onchange="wrLSideRefreshLog()">${lanOpts}</select>
                </label>

                <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                    <!-- dnsmasq query log — definitive evidence of whether clients arrive. -->
                    <div style="padding:12px; border:1px solid var(--border); border-radius:6px; background:var(--bg-card); display:flex; flex-direction:column; gap:8px;">
                        <div style="display:flex; align-items:center; justify-content:space-between;">
                            <strong style="font-size:13px;">dnsmasq query log</strong>
                            <span id="wr-lside-log-badge" class="badge" style="font-size:10px; padding:2px 6px;">checking…</span>
                        </div>
                        <div style="font-size:11px; color:var(--text-muted);">Tail the per-LAN dnsmasq log. Enable to capture every query from LAN clients — no query in here after a client tries to resolve = packet never reached dnsmasq.</div>
                        <div style="display:flex; gap:6px;">
                            <button id="wr-lside-log-on" class="btn btn-sm btn-primary" onclick="wrLSideSetQueryLog(true)">Enable logging</button>
                            <button id="wr-lside-log-off" class="btn btn-sm" onclick="wrLSideSetQueryLog(false)">Disable</button>
                            <button class="btn btn-sm" onclick="wrLSideRefreshLog()">Refresh</button>
                            <label style="font-size:11px; display:flex; align-items:center; gap:4px; margin-left:auto;">
                                <input type="checkbox" id="wr-lside-log-auto" checked/> auto-refresh
                            </label>
                        </div>
                        <div id="wr-lside-log-meta" style="font-size:11px; color:var(--text-muted);"></div>
                        <pre id="wr-lside-log-tail" style="font-family:var(--font-mono); font-size:11px; background:var(--bg-secondary); padding:8px; border-radius:4px; max-height:280px; overflow:auto; white-space:pre-wrap; margin:0; min-height:80px;">(Enable logging then try DNS from a LAN client — queries will appear here as they arrive.)</pre>
                    </div>

                    <!-- Packet capture on the LAN interface. Independent check
                         that sees arriving packets even if dnsmasq rejected them. -->
                    <div style="padding:12px; border:1px solid var(--border); border-radius:6px; background:var(--bg-card); display:flex; flex-direction:column; gap:8px;">
                        <div style="display:flex; align-items:center; justify-content:space-between;">
                            <strong style="font-size:13px;">Capture UDP 53 on LAN interface</strong>
                            <span id="wr-lside-cap-badge" class="badge" style="font-size:10px; padding:2px 6px; background:rgba(148,163,184,0.15); color:var(--text-muted);">idle</span>
                        </div>
                        <div style="font-size:11px; color:var(--text-muted);">Runs <code>tcpdump -i &lt;iface&gt; udp port 53</code> for 10 seconds. Shows packets reaching the NIC even if dnsmasq isn't answering them.</div>
                        <div style="display:flex; gap:6px;">
                            <button id="wr-lside-cap-btn" class="btn btn-sm btn-primary" onclick="wrLSideCapture()">▶ Capture 10s</button>
                        </div>
                        <div id="wr-lside-cap-meta" style="font-size:11px; color:var(--text-muted);"></div>
                        <pre id="wr-lside-cap-out" style="font-family:var(--font-mono); font-size:11px; background:var(--bg-secondary); padding:8px; border-radius:4px; max-height:280px; overflow:auto; white-space:pre-wrap; margin:0; min-height:80px;">(Click Capture 10s, then generate DNS traffic from a LAN client.)</pre>
                    </div>
                </div>` : `
                <div style="padding:10px; color:var(--text-muted); font-size:12px;">
                    No LAN segments defined yet — create one in the DHCP/LANs tab first, then come back.
                </div>`}
            </div>

            <!-- HOST-SIDE TOOLS — useful for upstream checks (is 1.1.1.1
                 reachable from this host? is a public domain resolving?),
                 but NOT for "can my LAN client resolve" — the section
                 above is the right place for that. -->
            <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
                <strong>Host-side tools</strong> below run from the WolfStack host, not from a client machine. Use them for upstream reachability checks. For LAN-client diagnostics, use the section above.
            </div>
            <div id="wr-tools-status" style="margin-bottom:12px;"></div>

            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                ${wrToolCardHtml('ping', 'Ping', 'Four ICMP echo packets with 1s timeout. Shows round-trip latency and packet loss.', 'cloudflare.com', false)}
                ${wrToolCardHtml('traceroute', 'Traceroute', 'Map each router hop to the target. Capped at 20 hops, 2s per probe.', 'cloudflare.com', false)}
                ${wrToolCardHtml('nslookup', 'nslookup', 'Resolve a name against the system (or an explicit) DNS server. Runs from the host — for LAN-client issues use the section above.', 'cloudflare.com', true)}
                ${wrToolCardHtml('whois', 'whois', 'WHOIS registry lookup for a domain or IP. Takes up to 30 seconds.', 'cloudflare.com', false)}
            </div>
        `;

        // Surface per-tool availability so users know if "Run" will work
        // BEFORE they click it (no silent confusion on missing dig).
        await wrRenderToolsStatus();

        // Kick off the LAN-side log tail + auto-refresh loop (if any LAN exists).
        if (lanOpts) {
            wrLSideRefreshLog();
            wrLSideStartAutoRefresh();
        }

        // Pre-select the first node (or whatever the operator had
        // selected previously, preserved across re-renders).
        const nodeSel = document.getElementById('wr-tools-node');
        if (nodeSel) {
            if (wrState.toolsNodeId && Array.from(nodeSel.options).some(o => o.value === wrState.toolsNodeId)) {
                nodeSel.value = wrState.toolsNodeId;
            } else if (nodeSel.options.length) {
                wrState.toolsNodeId = nodeSel.value;
            }
        }

        // Load host-DNS + deps for the selected node. Both are strictly
        // node-local — we use wrNodeUrl so remote nodes go through the
        // /api/nodes/{id}/proxy route instead of querying the dashboard
        // node by mistake.
        wrHostDnsRefresh();
        wrDepsRefresh();
    }

    /// Selected node for the DNS Tools per-node panels. Memoised on
    /// wrState so switching tabs and coming back preserves the choice.
    function wrToolsSelectedNodeId() {
        const sel = document.getElementById('wr-tools-node');
        return sel?.value || wrState.toolsNodeId || '';
    }

    /// Handler on the node-picker — refresh both panels against the
    /// newly-selected node.
    function wrToolsOnNodeChange() {
        wrState.toolsNodeId = wrToolsSelectedNodeId();
        wrHostDnsRefresh();
        wrDepsRefresh();
    }
    window.wrToolsOnNodeChange = wrToolsOnNodeChange;

    /// Fetch /api/router/host-dns and render the card. Called on DNS
    /// Tools tab load, after each Release/Restore, and when the node
    /// picker changes. Uses wrNodeUrl so the call lands on the node
    /// the operator actually picked, not the dashboard host.
    async function wrHostDnsRefresh() {
        const body = document.getElementById('wr-host-dns-body');
        if (!body) return;
        body.innerHTML = 'Checking what owns port 53 on this node…';
        const nodeId = wrToolsSelectedNodeId();
        const url = await wrNodeUrl(nodeId, '/api/router/host-dns');
        let status;
        try {
            const r = await fetch(url);
            if (!r.ok) {
                body.innerHTML = `<span style="color:#ef4444;">Status check failed: HTTP ${r.status}</span>`;
                return;
            }
            status = await r.json();
        } catch (e) {
            body.innerHTML = `<span style="color:#ef4444;">Status check errored: ${escHtml(e.message || String(e))}</span>`;
            return;
        }
        const servers = (status.resolv_conf_servers || []);
        // Stub release is independent of WolfRouter dnsmasq — both can
        // hold :53 at once (127.0.0.53 for the stub, LAN bridge IP for
        // dnsmasq). The old guard that also required !wolfrouter_owns_53
        // left mixed-state hosts with no way forward.
        const canRelease = status.stub_listener && !status.release_applied;
        const canRestore = status.release_applied;

        // Full bindings list — "first owner wins" before v18.7.26 hid
        // stub behind dnsmasq (or vice versa) depending on `ss` output
        // order. Show all of them.
        const bindings = Array.isArray(status.port_53_bindings) ? status.port_53_bindings : [];
        const bindingsHtml = bindings.length
            ? bindings.map(b => `<code>${escHtml(b.owner)}</code> <span style="color:var(--text-muted);">@ ${escHtml(b.local_addr)}</span>`).join('<br>')
            : '<span style="color:var(--text-muted);">nothing listening</span>';

        // Per-LAN WolfRouter DNS rows. Only LANs owned by this node
        // come through (the backend filters) so operators don't see
        // remote LANs they can't reach from this panel.
        const lans = Array.isArray(status.wolfrouter_lans) ? status.wolfrouter_lans : [];
        const lansHtml = wrHostDnsLansHtml(lans);

        body.innerHTML = `
            <div style="display:grid; grid-template-columns:auto 1fr; gap:4px 14px; margin-bottom:10px; font-size:12px;">
                <span style="color:var(--text-muted);">Resolver:</span>
                <span><strong>${escHtml(status.resolver)}</strong></span>
                <span style="color:var(--text-muted);">:53 bindings:</span>
                <span>${bindingsHtml}</span>
                <span style="color:var(--text-muted);">Stub listener:</span>
                <span>${status.stub_listener ? '<span style="color:#f59e0b;">on (holding 127.0.0.53:53)</span>' : '<span style="color:var(--text-muted);">off</span>'}</span>
                <span style="color:var(--text-muted);">Release applied:</span>
                <span>${status.release_applied ? '<span style="color:#10b981;">yes (WolfStack drop-in present)</span>' : '<span style="color:var(--text-muted);">no</span>'}</span>
                <span style="color:var(--text-muted);">/etc/resolv.conf:</span>
                <span>${servers.length ? servers.map(s => `<code>${escHtml(s)}</code>`).join(', ') : '<span style="color:var(--text-muted);">(empty)</span>'}</span>
            </div>
            <div style="font-size:12px; color:var(--text,#fff); margin-bottom:10px;">${escHtml(status.message || '')}</div>

            <div style="border:1px solid var(--border); border-radius:6px; padding:10px; margin-bottom:10px;">
                <div style="font-weight:600; font-size:12px; margin-bottom:6px;">systemd-resolved stub (127.0.0.53:53)</div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">
                    Releasing disables the stub and points /etc/resolv.conf at an upstream you pick. Affects host DNS only; LAN DNS served by WolfRouter is untouched.
                </div>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    ${canRelease ? `
                        <label style="font-size:12px; color:var(--text-muted); display:flex; gap:6px; align-items:center;">
                            Host DNS upstream:
                            <input id="wr-host-dns-upstream" placeholder="1.1.1.1" value="1.1.1.1"
                                style="width:120px; padding:4px 8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:4px; color:var(--text);"/>
                        </label>
                        <button class="btn btn-sm btn-primary" onclick="wrHostDnsRelease()">Release stub</button>
                    ` : ''}
                    ${canRestore ? `<button class="btn btn-sm" onclick="wrHostDnsRestore()">Restore stub</button>` : ''}
                    ${!canRelease && !canRestore ? `<span style="font-size:12px; color:var(--text-muted);">Stub already off — no action needed.</span>` : ''}
                </div>
            </div>

            ${lansHtml}

            <div style="display:flex; gap:8px; align-items:center; margin-top:6px;">
                <button class="btn btn-sm" onclick="wrHostDnsRefresh()">Refresh</button>
            </div>
            <div id="wr-host-dns-result" style="font-size:12px; margin-top:10px;"></div>
        `;
    }
    window.wrHostDnsRefresh = wrHostDnsRefresh;

    /// Render the per-LAN WolfRouter DNS rows. Each row shows the
    /// LAN's current dnsmasq DNS port and offers:
    ///   • if mode=wolf_router && port==53 — "Move off :53" form
    ///     (port input defaults to 5353, external_server required)
    ///   • if mode=wolf_router && port!=53 — "Move back to :53" button
    ///     plus an inline "Change port" editor
    ///   • if mode=external — read-only note (DNS off entirely)
    function wrHostDnsLansHtml(lans) {
        if (!lans.length) {
            return `<div style="font-size:12px; color:var(--text-muted); padding:6px 0;">
                This node doesn't serve any WolfRouter LANs, so there's no per-LAN dnsmasq DNS to move.
            </div>`;
        }
        const rows = lans.map(lan => wrHostDnsLanRowHtml(lan)).join('');
        return `
            <div style="border:1px solid var(--border); border-radius:6px; padding:10px; margin-bottom:10px;">
                <div style="font-weight:600; font-size:12px; margin-bottom:6px;">WolfRouter LANs on this node</div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">
                    Each LAN runs its own dnsmasq on its bridge interface. To let a containerised resolver (AdGuard Home, Pi-hole) bind :53 on a LAN, move that LAN's dnsmasq to a non-standard port and point DHCP option 6 at the container.
                </div>
                ${rows}
            </div>
        `;
    }

    function wrHostDnsLanRowHtml(lan) {
        const safeId = escHtml(lan.id);
        const head = `
            <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
                <div>
                    <strong>${escHtml(lan.name)}</strong>
                    <span style="color:var(--text-muted); font-size:11px;"> — ${escHtml(lan.interface)} @ ${escHtml(lan.router_ip)}</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted);">
                    mode: <code>${escHtml(lan.mode)}</code> · dnsmasq port: <code>${lan.listen_port}</code>
                </div>
            </div>
        `;

        if (lan.mode === 'external') {
            return `<div style="padding:8px; border-top:1px solid var(--border);">
                ${head}
                <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">
                    DNS mode is External — dnsmasq runs DHCP-only (port=0), so :53 on this LAN is already free. Change the mode on the LAN editor if you want WolfRouter to serve DNS again.
                </div>
            </div>`;
        }

        // WolfRouter mode: port is the axis of control.
        if (lan.listen_port === 53) {
            // On :53 — the common "standing in AdGuard's way" case.
            return `<div style="padding:8px; border-top:1px solid var(--border);">
                ${head}
                <div style="font-size:12px; margin-top:6px;">
                    dnsmasq is on :53 for this LAN. Move it off to let a container own :53 on <code>${escHtml(lan.interface)}</code>.
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px; line-height:1.5;">
                    The "Advertise DNS" IP doesn't need to be running yet — it's just a future reference DHCP will hand out to clients. Set it to your AdGuard/Pi-hole container's planned IP, click Apply, and dnsmasq will move off :53 — freeing it for AdGuard to bind. <strong>Then</strong> start AdGuard on that IP.
                </div>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:6px;">
                    <label style="font-size:12px; color:var(--text-muted); display:flex; gap:6px; align-items:center;">
                        New port:
                        <input id="wr-lan-port-${safeId}" type="number" min="1" max="65535" value="5353"
                            style="width:90px; padding:4px 8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:4px; color:var(--text);"/>
                    </label>
                    <label style="font-size:12px; color:var(--text-muted); display:flex; gap:6px; align-items:center;">
                        Advertise DNS (DHCP opt 6):
                        <input id="wr-lan-extdns-${safeId}" placeholder="e.g. ${escHtml(lan.router_ip)}"
                            style="width:160px; padding:4px 8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:4px; color:var(--text);"/>
                    </label>
                    <button class="btn btn-sm btn-primary" onclick="wrSetLanDnsPort('${safeId}')">Apply</button>
                </div>
            </div>`;
        }

        // WolfRouter mode on a non-53 port — offer "back to :53" plus
        // an inline port editor so the operator can tune it without
        // digging into the LAN editor.
        return `<div style="padding:8px; border-top:1px solid var(--border);">
            ${head}
            <div style="font-size:12px; margin-top:6px;">
                dnsmasq is on :${lan.listen_port} for this LAN — :53 on <code>${escHtml(lan.interface)}</code> is free for a container.
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:6px;">
                <label style="font-size:12px; color:var(--text-muted); display:flex; gap:6px; align-items:center;">
                    Change port:
                    <input id="wr-lan-port-${safeId}" type="number" min="1" max="65535" value="${lan.listen_port}"
                        style="width:90px; padding:4px 8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:4px; color:var(--text);"/>
                </label>
                <label style="font-size:12px; color:var(--text-muted); display:flex; gap:6px; align-items:center;">
                    Advertise DNS (DHCP opt 6):
                    <input id="wr-lan-extdns-${safeId}" placeholder="required when port ≠ 53"
                        style="width:160px; padding:4px 8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:4px; color:var(--text);"/>
                </label>
                <button class="btn btn-sm" onclick="wrSetLanDnsPort('${safeId}')">Apply</button>
                <button class="btn btn-sm" onclick="wrSetLanDnsPortTo53('${safeId}')">Back to :53</button>
            </div>
        </div>`;
    }

    /// Apply the new dnsmasq DNS port for one LAN. Reads the per-LAN
    /// port + external_server inputs, posts to the new backend
    /// endpoint, surfaces the result in the shared status line, then
    /// re-polls to show the new state.
    async function wrSetLanDnsPort(lanId) {
        const portEl = document.getElementById(`wr-lan-port-${lanId}`);
        const extEl = document.getElementById(`wr-lan-extdns-${lanId}`);
        const out = document.getElementById('wr-host-dns-result');
        const port = parseInt(portEl?.value || '0', 10);
        const externalServer = (extEl?.value || '').trim();
        if (!port || port < 1 || port > 65535) {
            if (out) out.innerHTML = `<span style="color:#ef4444;">Port must be a number between 1 and 65535.</span>`;
            return;
        }
        if (port !== 53 && !externalServer) {
            if (out) out.innerHTML = `<span style="color:#ef4444;">When port isn't 53, a DHCP option-6 DNS server is required (typically your AdGuard/Pi-hole container IP).</span>`;
            return;
        }
        const confirmMsg = port === 53
            ? `Move this LAN's dnsmasq back to port 53? Any container currently bound to :53 on this LAN's interface will conflict.`
            : `Move this LAN's dnsmasq to :${port} and advertise ${externalServer} via DHCP option 6? dnsmasq will restart.`;
        if (!(await showConfirm(confirmMsg))) return;
        const nodeId = wrToolsSelectedNodeId();
        const url = await wrNodeUrl(nodeId, '/api/router/host-dns/lan-dns-port');
        if (out) out.innerHTML = '<span style="color:var(--text-muted);">Applying…</span>';
        try {
            const r = await fetch(url, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ lan_id: lanId, new_port: port, external_server: externalServer || null }),
            });
            const data = await r.json().catch(() => ({}));
            if (!r.ok || data.ok === false) {
                if (out) out.innerHTML = `<span style="color:#ef4444;">Failed: ${escHtml(data.error || ('HTTP ' + r.status))}</span>`;
                return;
            }
            if (out) out.innerHTML = `<span style="color:#10b981;">${escHtml(data.message || 'Applied')}</span>`;
        } catch (e) {
            if (out) out.innerHTML = `<span style="color:#ef4444;">Error: ${escHtml(e.message || String(e))}</span>`;
        }
        setTimeout(wrHostDnsRefresh, 400);
    }
    window.wrSetLanDnsPort = wrSetLanDnsPort;

    /// Convenience helper: move a LAN's dnsmasq DNS back to :53. No
    /// external_server needed (DHCP opt 6 on :53 is implicit).
    async function wrSetLanDnsPortTo53(lanId) {
        const out = document.getElementById('wr-host-dns-result');
        if (!(await showConfirm(`Move this LAN's dnsmasq back to port 53? Any container currently bound to :53 on this LAN's interface will conflict.`))) return;
        const nodeId = wrToolsSelectedNodeId();
        const url = await wrNodeUrl(nodeId, '/api/router/host-dns/lan-dns-port');
        if (out) out.innerHTML = '<span style="color:var(--text-muted);">Applying…</span>';
        try {
            const r = await fetch(url, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ lan_id: lanId, new_port: 53 }),
            });
            const data = await r.json().catch(() => ({}));
            if (!r.ok || data.ok === false) {
                if (out) out.innerHTML = `<span style="color:#ef4444;">Failed: ${escHtml(data.error || ('HTTP ' + r.status))}</span>`;
                return;
            }
            if (out) out.innerHTML = `<span style="color:#10b981;">${escHtml(data.message || 'Applied')}</span>`;
        } catch (e) {
            if (out) out.innerHTML = `<span style="color:#ef4444;">Error: ${escHtml(e.message || String(e))}</span>`;
        }
        setTimeout(wrHostDnsRefresh, 400);
    }
    window.wrSetLanDnsPortTo53 = wrSetLanDnsPortTo53;

    /// Disable systemd-resolved's stub listener and redirect
    /// /etc/resolv.conf at the chosen upstream on the currently
    /// selected node, then re-poll status.
    async function wrHostDnsRelease() {
        const input = document.getElementById('wr-host-dns-upstream');
        const upstream = (input?.value || '').trim() || '1.1.1.1';
        const out = document.getElementById('wr-host-dns-result');
        const nodeId = wrToolsSelectedNodeId();
        const url = await wrNodeUrl(nodeId, '/api/router/host-dns/release');
        const confirmed = (typeof showDangerConfirm === 'function')
            ? await showDangerConfirm({
                title: 'Release systemd-resolved stub listener?',
                danger: 'This rewrites /etc/resolv.conf and restarts systemd-resolved. If the new upstream (' + upstream + ') is unreachable from this node, host DNS will stop resolving until you click Restore.',
                detail: 'Browser sessions already open stay usable; new lookups on the host may fail until the resolver comes back. Do not do this if you are SSHed in via hostname rather than IP.',
                countdown: 6,
                confirmLabel: 'Release stub',
            })
            : await showConfirm(`Disable systemd-resolved's stub listener on this node and point host DNS at ${upstream}? This is undoable via Restore.`);
        if (!confirmed) return;
        if (out) out.innerHTML = '<span style="color:var(--text-muted);">Applying…</span>';
        try {
            const r = await fetch(url, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ upstream }),
            });
            const data = await r.json().catch(() => ({}));
            if (!r.ok || data.ok === false) {
                if (out) out.innerHTML = `<span style="color:#ef4444;">Failed: ${escHtml(data.error || ('HTTP ' + r.status))}</span>`;
                return;
            }
            if (out) out.innerHTML = `<span style="color:#10b981;">${escHtml(data.message || 'Released')}</span>`;
        } catch (e) {
            if (out) out.innerHTML = `<span style="color:#ef4444;">Error: ${escHtml(e.message || String(e))}</span>`;
        }
        setTimeout(wrHostDnsRefresh, 400);
    }
    window.wrHostDnsRelease = wrHostDnsRelease;

    /// Undo a prior Release on the selected node: delete the drop-in,
    /// restore the saved /etc/resolv.conf, restart systemd-resolved.
    async function wrHostDnsRestore() {
        const out = document.getElementById('wr-host-dns-result');
        const nodeId = wrToolsSelectedNodeId();
        const url = await wrNodeUrl(nodeId, '/api/router/host-dns/restore');
        const confirmed = (typeof showDangerConfirm === 'function')
            ? await showDangerConfirm({
                title: 'Restore systemd-resolved stub?',
                danger: 'Any container currently bound to :53 on 127.0.0.53 will conflict with the returning stub listener and fail.',
                detail: 'Stop your containerised resolver (AdGuard Home, Pi-hole) BEFORE clicking Restore, or docker/systemd will bind the stub into an error loop.',
                countdown: 5,
                confirmLabel: 'Restore stub',
            })
            : await showConfirm('Restore the host DNS resolver? systemd-resolved\'s stub listener will come back on 127.0.0.53:53 — any containerised resolver currently bound to port 53 on this host will need to be stopped first.');
        if (!confirmed) return;
        if (out) out.innerHTML = '<span style="color:var(--text-muted);">Restoring…</span>';
        try {
            const r = await fetch(url, { method: 'POST' });
            const data = await r.json().catch(() => ({}));
            if (!r.ok || data.ok === false) {
                if (out) out.innerHTML = `<span style="color:#ef4444;">Failed: ${escHtml(data.error || ('HTTP ' + r.status))}</span>`;
                return;
            }
            if (out) out.innerHTML = `<span style="color:#10b981;">${escHtml(data.message || 'Restored')}</span>`;
        } catch (e) {
            if (out) out.innerHTML = `<span style="color:#ef4444;">Error: ${escHtml(e.message || String(e))}</span>`;
        }
        setTimeout(wrHostDnsRefresh, 400);
    }
    window.wrHostDnsRestore = wrHostDnsRestore;

    // ─── Dependency check / install (distro-aware, per-node) ────────
    //
    // `/api/system/deps/check?group=dns` tells us what's installed on
    // the selected node, what's missing, and the exact command we'd
    // run on its package manager. The operator always gets a choice:
    // click Install to run it directly, or copy the command and run
    // it by hand via their own sudo/terminal. We never silently run
    // anything — install needs an explicit click.

    async function wrDepsRefresh() {
        const body = document.getElementById('wr-deps-body');
        if (!body) return;
        body.innerHTML = 'Checking installed tools on this node…';
        const nodeId = wrToolsSelectedNodeId();
        const url = await wrNodeUrl(nodeId, '/api/system/deps/check?group=dns');
        let data;
        try {
            const r = await fetch(url);
            if (!r.ok) {
                // Degrade gracefully — the dep check is a nice-to-have, not
                // a blocker. The Host DNS panel above this one is fully
                // independent and still works. Two common 404 causes worth
                // calling out explicitly so the operator knows what to do:
                //   - 404 with `{"error":"Node not found"}`: the proxy
                //     couldn't resolve the picked node's id (cluster state
                //     out of sync).
                //   - 404 from the remote with no body: the remote is on
                //     an older WolfStack that lacks /api/system/deps/check
                //     (added v18.7.25). Tell the operator to upgrade.
                let detail = `HTTP ${r.status}`;
                try {
                    const errBody = await r.clone().json();
                    if (errBody?.error) detail += ` — ${errBody.error}`;
                } catch (_) { /* not JSON, leave the status alone */ }
                let hint = '';
                if (r.status === 404) {
                    hint = ' This usually means the selected node is on a WolfStack version older than v18.7.25 (which added the dep check), or its id is no longer in the cluster state. The Host DNS panel above still works regardless.';
                }
                body.innerHTML = `
                    <div style="color:#f59e0b; font-size:12px;">
                        Dependency check unavailable on this node (${escHtml(detail)}).${escHtml(hint)}
                    </div>`;
                return;
            }
            data = await r.json();
        } catch (e) {
            // Network-level failure (proxy died, TLS handshake failed,
            // etc.). Same graceful-degradation principle — the dep check
            // is independent from the Host DNS panel and should never
            // hide it behind a red error.
            body.innerHTML = `
                <div style="color:#f59e0b; font-size:12px;">
                    Dependency check unreachable: ${escHtml(e.message || String(e))}. The Host DNS panel above still works.
                </div>`;
            return;
        }

        const depRows = (data.deps || []).map(d => {
            const mark = d.installed
                ? '<span style="color:#22c55e;">installed</span>'
                : (d.package
                    ? '<span style="color:#f59e0b;">◯ missing</span>'
                    : '<span style="color:var(--text-muted);">— not packaged on this distro</span>');
            const pkg = d.package ? `<code>${escHtml(d.package)}</code>` : '<span style="color:var(--text-muted);">n/a</span>';
            const where = d.found_binaries?.length
                ? `<span style="color:var(--text-muted);">at <code>${escHtml(d.found_binaries[0])}</code></span>`
                : '';
            return `
                <tr>
                    <td style="padding:4px 8px;">${escHtml(d.label)}</td>
                    <td style="padding:4px 8px;">${pkg}</td>
                    <td style="padding:4px 8px;">${mark} ${where}</td>
                </tr>
                <tr><td colspan="3" style="padding:0 8px 8px 8px; font-size:11px; color:var(--text-muted);">${escHtml(d.rationale || '')}</td></tr>
            `;
        }).join('');

        const missingAny = (data.deps || []).some(d => !d.installed && !!d.package);
        const cmd = data.install_cmd || '';
        body.innerHTML = `
            <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">
                Distro: <strong>${escHtml(data.distro)}</strong> · Package manager: <strong>${escHtml(data.pkg_mgr)}</strong> ${data.is_root ? '' : '<span style="color:#f59e0b;">· not running as root — install will refuse, copy the command and run it via sudo instead</span>'}
            </div>
            <table style="width:100%; border-collapse:collapse; font-size:12px; margin-bottom:8px;">
                <thead><tr style="color:var(--text-muted); text-align:left;">
                    <th style="padding:4px 8px; font-weight:500;">Tool</th>
                    <th style="padding:4px 8px; font-weight:500;">Package</th>
                    <th style="padding:4px 8px; font-weight:500;">Status</th>
                </tr></thead>
                <tbody>${depRows}</tbody>
            </table>
            ${missingAny ? `
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:4px;">Command we'd run on your behalf:</div>
                <pre style="font-family:var(--font-mono); font-size:11px; background:var(--bg-secondary); padding:8px; border-radius:4px; margin:0 0 8px 0; white-space:pre-wrap; overflow-x:auto;">${escHtml(cmd)}</pre>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    <button class="btn btn-sm btn-primary" onclick="wrDepsInstall()" ${data.is_root ? '' : 'disabled title="Install needs root — copy the command and run it manually."'}>Install on this node</button>
                    <button class="btn btn-sm" onclick="wrDepsCopy()">Copy command</button>
                    <button class="btn btn-sm" onclick="wrDepsRefresh()">Refresh</button>
                </div>
                <div id="wr-deps-result" style="font-size:12px; margin-top:10px;"></div>
            ` : `
                <div style="color:#22c55e; font-size:12px;">All DNS-area tooling is already installed on this node.</div>
                <div style="margin-top:6px;"><button class="btn btn-sm" onclick="wrDepsRefresh()">Refresh</button></div>
            `}
        `;
        // Stash the command on the card so copy button can grab it
        // without re-fetching / re-parsing.
        const card = document.getElementById('wr-deps-card');
        if (card) card.dataset.installCmd = cmd;
    }
    window.wrDepsRefresh = wrDepsRefresh;

    async function wrDepsInstall() {
        const out = document.getElementById('wr-deps-result');
        const nodeId = wrToolsSelectedNodeId();
        const url = await wrNodeUrl(nodeId, '/api/system/deps/install');
        if (!(await showConfirm('Run the package-manager install on this node now? WolfStack will execute the command shown above as root.'))) return;
        if (out) out.innerHTML = '<span style="color:var(--text-muted);">Installing… (first run can take 30-60 s while the package index refreshes)</span>';
        try {
            const r = await fetch(url, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ group: 'dns' }),
            });
            const data = await r.json().catch(() => ({}));
            if (!r.ok) {
                if (out) out.innerHTML = `<span style="color:#ef4444;">Install failed: ${escHtml(data.error || ('HTTP ' + r.status))}</span>`;
                return;
            }
            const ok = (data.exit_code || 0) === 0;
            if (out) {
                out.innerHTML = `
                    <div style="color:${ok ? '#22c55e' : '#ef4444'}; margin-bottom:4px;">
                        ${ok ? 'Install finished (exit 0).' : `Install exited with code ${escHtml(String(data.exit_code))}.`}
                    </div>
                    <details ${ok ? '' : 'open'}><summary style="cursor:pointer; font-size:11px; color:var(--text-muted);">package manager output</summary>
                        <pre style="font-family:var(--font-mono); font-size:11px; background:var(--bg-secondary); padding:8px; border-radius:4px; max-height:280px; overflow:auto; white-space:pre-wrap; margin:6px 0 0 0;">${escHtml(data.output || '(no output)')}</pre>
                    </details>
                `;
            }
        } catch (e) {
            if (out) out.innerHTML = `<span style="color:#ef4444;">Install errored: ${escHtml(e.message || String(e))}</span>`;
        }
        setTimeout(wrDepsRefresh, 400);
    }
    window.wrDepsInstall = wrDepsInstall;

    function wrDepsCopy() {
        const card = document.getElementById('wr-deps-card');
        const cmd = card?.dataset?.installCmd || '';
        if (!cmd) return;
        navigator.clipboard?.writeText(cmd).then(() => {
            const out = document.getElementById('wr-deps-result');
            if (out) out.innerHTML = '<span style="color:#10b981;">Command copied. Paste into a terminal with sudo if needed.</span>';
        }).catch(() => {
            // Fallback for older browsers that don't grant clipboard access.
            window.prompt('Copy this command:', cmd);
        });
    }
    window.wrDepsCopy = wrDepsCopy;

    // ─── LAN-side diagnostics helpers ─────────────────────────────

    function wrLSideLanId() {
        return document.getElementById('wr-lside-lan')?.value || '';
    }

    function wrLSideLan() {
        const id = wrLSideLanId();
        return (wrState.lans || []).find(l => l.id === id);
    }

    async function wrLSideSetQueryLog(enable) {
        const id = wrLSideLanId();
        if (!id) return;
        const btnOn = document.getElementById('wr-lside-log-on');
        const btnOff = document.getElementById('wr-lside-log-off');
        const meta = document.getElementById('wr-lside-log-meta');
        if (btnOn) btnOn.disabled = true;
        if (btnOff) btnOff.disabled = true;
        if (meta) meta.innerHTML = `<span style="color:var(--text-muted);">${enable ? 'Enabling' : 'Disabling'} query logging — dnsmasq will restart (~1s)…</span>`;
        try {
            const r = await fetch(wrUrl(`/api/router/segments/${encodeURIComponent(id)}/query-log`), {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enable }),
            });
            const j = await r.json();
            if (j.success) {
                if (meta) meta.innerHTML = `<span style="color:#22c55e;">${escHtml(j.message || '')}</span>`;
            } else {
                if (meta) meta.innerHTML = `<span style="color:#ef4444;">${escHtml(j.error || 'Failed')}</span>`;
            }
        } catch (e) {
            if (meta) meta.innerHTML = `<span style="color:#ef4444;">Request failed: ${escHtml(e.message || e)}</span>`;
        } finally {
            if (btnOn) btnOn.disabled = false;
            if (btnOff) btnOff.disabled = false;
            wrLSideRefreshLog();
        }
    }
    window.wrLSideSetQueryLog = wrLSideSetQueryLog;

    async function wrLSideRefreshLog() {
        const id = wrLSideLanId();
        const tail = document.getElementById('wr-lside-log-tail');
        const meta = document.getElementById('wr-lside-log-meta');
        const badge = document.getElementById('wr-lside-log-badge');
        if (!id || !tail) return;
        try {
            const r = await fetch(wrUrl(`/api/router/segments/${encodeURIComponent(id)}/query-log?lines=200`));
            if (!r.ok) {
                tail.textContent = 'Fetch failed: HTTP ' + r.status;
                if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; badge.style.background = 'rgba(239,68,68,0.15)'; }
                return;
            }
            const j = await r.json();
            if (badge) {
                if (j.enabled) {
                    badge.textContent = 'logging ON';
                    badge.style.color = '#22c55e';
                    badge.style.background = 'rgba(34,197,94,0.15)';
                } else {
                    badge.textContent = 'logging OFF';
                    badge.style.color = 'var(--text-muted)';
                    badge.style.background = 'rgba(148,163,184,0.15)';
                }
            }
            const lines = j.lines || [];
            const clients = j.unique_clients || [];
            if (!j.enabled && !lines.length) {
                tail.textContent = '(Query logging is OFF. Click "Enable logging" — dnsmasq will restart. Then try DNS from a LAN client; entries will appear here.)';
            } else if (!lines.length) {
                tail.textContent = '(Logging is ON but no entries yet. Try `nslookup cloudflare.com ' + (wrLSideLan()?.router_ip || '<router-ip>') + '` from a LAN client.)';
            } else {
                tail.textContent = lines.join('\n');
                tail.scrollTop = tail.scrollHeight;
            }
            if (meta) {
                const parts = [`${j.total_entries || 0} total entries`];
                if (clients.length) parts.push(`clients seen: ${clients.join(', ')}`);
                else if (j.enabled) parts.push('<span style="color:#fbbf24;">no LAN clients have queried yet</span>');
                meta.innerHTML = parts.join(' · ');
            }
        } catch (e) {
            tail.textContent = 'Fetch errored: ' + (e.message || e);
        }
    }
    window.wrLSideRefreshLog = wrLSideRefreshLog;

    // Auto-refresh loop — only fires while the DNS Tools tab is visible
    // and auto-refresh is ticked. Reuses the existing wrState timer slot
    // pattern so switching tabs / pages doesn't leave stale intervals.
    function wrLSideStartAutoRefresh() {
        if (wrState.lsideTimer) { clearInterval(wrState.lsideTimer); wrState.lsideTimer = null; }
        wrState.lsideTimer = setInterval(() => {
            const auto = document.getElementById('wr-lside-log-auto');
            const panel = document.getElementById('wr-tab-tools');
            if (!auto || !auto.checked) return;
            if (!panel || panel.style.display === 'none') {
                clearInterval(wrState.lsideTimer); wrState.lsideTimer = null;
                return;
            }
            wrLSideRefreshLog();
        }, 2000);
    }

    async function wrLSideCapture() {
        const lan = wrLSideLan();
        const btn = document.getElementById('wr-lside-cap-btn');
        const badge = document.getElementById('wr-lside-cap-badge');
        const meta = document.getElementById('wr-lside-cap-meta');
        const out = document.getElementById('wr-lside-cap-out');
        if (!lan || !btn || !out) return;
        btn.disabled = true;
        btn.textContent = 'Capturing 10s…';
        if (badge) { badge.textContent = 'capturing…'; badge.style.background = 'rgba(251,191,36,0.15)'; badge.style.color = '#fbbf24'; }
        if (meta) meta.innerHTML = `<span style="color:var(--text-muted);">Watching <code>${escHtml(lan.interface)}</code> for UDP/53 traffic. Try DNS from a LAN client NOW — you have 10 seconds.</span>`;
        out.textContent = '(waiting for packets…)';
        try {
            const r = await fetch(wrUrl('/api/router/capture'), {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    iface: lan.interface,
                    filter: 'udp port 53',
                    count: 500,
                    timeout_seconds: 10,
                    node_id: lan.node_id,
                }),
            });
            const j = await r.json();
            const lines = j.lines || [];
            if (lines.length) {
                out.textContent = lines.join('\n');
                if (badge) { badge.textContent = `${lines.length} packets`; badge.style.background = 'rgba(34,197,94,0.15)'; badge.style.color = '#22c55e'; }
                if (meta) meta.innerHTML = `<span style="color:#22c55e;">${lines.length} packet(s) captured on <code>${escHtml(lan.interface)}</code>. DNS traffic IS reaching the interface.</span>`;
            } else if (j.error) {
                out.textContent = '' + j.error;
                if (badge) { badge.textContent = 'error'; badge.style.background = 'rgba(239,68,68,0.15)'; badge.style.color = '#ef4444'; }
                if (meta) meta.innerHTML = `<span style="color:#ef4444;">${escHtml(j.error)}</span>`;
            } else {
                out.textContent = '(nothing captured in 10 seconds)';
                if (badge) { badge.textContent = 'nothing seen'; badge.style.background = 'rgba(251,191,36,0.15)'; badge.style.color = '#fbbf24'; }
                if (meta) meta.innerHTML = `<span style="color:#fbbf24;">No DNS packets reached <code>${escHtml(lan.interface)}</code>. If you tried to resolve from a client during the capture, the packet never made it here — check client's default gateway, ARP (<code>ip neigh</code>), and upstream switches.</span>`;
            }
        } catch (e) {
            out.textContent = 'Capture failed: ' + (e.message || e);
            if (badge) { badge.textContent = 'failed'; badge.style.background = 'rgba(239,68,68,0.15)'; badge.style.color = '#ef4444'; }
        } finally {
            btn.disabled = false;
            btn.textContent = '▶ Capture 10s';
        }
    }
    window.wrLSideCapture = wrLSideCapture;

    function wrToolCardHtml(tool, heading, desc, placeholder, hasServer) {
        const sfx = tool;
        return `
            <div style="padding:14px; border:1px solid var(--border); border-radius:8px; background:var(--bg-card); display:flex; flex-direction:column; gap:8px;">
                <div style="display:flex; align-items:baseline; gap:8px;">
                    <strong style="font-size:14px;">${heading}</strong>
                    <span id="wr-tool-badge-${sfx}" class="badge" style="font-size:10px; padding:2px 6px; background:rgba(148,163,184,0.15); color:var(--text-muted);">checking…</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted);">${desc}</div>
                <div style="display:flex; gap:6px;">
                    <input id="wr-tool-target-${sfx}" class="form-control" placeholder="${escHtml(placeholder)}" style="flex:1; font-size:12px;"/>
                    ${hasServer ? `<input id="wr-tool-server-${sfx}" class="form-control" placeholder="DNS server (optional)" style="flex:1; font-size:12px;"/>` : ''}
                    <button id="wr-tool-btn-${sfx}" class="btn btn-sm btn-primary" onclick="wrRunTool('${sfx}')">Run</button>
                </div>
                <pre id="wr-tool-out-${sfx}" style="display:none; font-family:var(--font-mono); font-size:11px; background:var(--bg-secondary); padding:8px; border-radius:4px; max-height:260px; overflow:auto; white-space:pre-wrap; margin:0;"></pre>
            </div>
        `;
    }

    // Fetch the tool-installed status from the backend and annotate each
    // card. If anything is missing, surface a prominent "Install diag tools"
    // button so the user isn't left wondering why "Run" is silently broken.
    async function wrRenderToolsStatus() {
        const statusBox = document.getElementById('wr-tools-status');
        if (!statusBox) return;
        statusBox.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">Checking which diagnostic tools are installed on this host…</span>';
        let status;
        try {
            const r = await fetch(wrUrl('/api/router/tools/status'));
            if (!r.ok) throw new Error('HTTP ' + r.status);
            status = await r.json();
        } catch (e) {
            statusBox.innerHTML = `<div style="padding:10px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.35); border-radius:6px; font-size:12px; color:#fca5a5;">Could not check tool status: ${escHtml(e.message || e)}</div>`;
            return;
        }
        const tools = [
            { key: 'ping',       card: 'ping' },
            { key: 'traceroute', card: 'traceroute' },
            { key: 'nslookup',   card: 'nslookup' },
            { key: 'whois',      card: 'whois' },
        ];
        for (const t of tools) {
            const badge = document.getElementById('wr-tool-badge-' + t.card);
            if (!badge) continue;
            if (status[t.key]) {
                badge.textContent = 'installed';
                badge.style.background = 'rgba(34,197,94,0.15)';
                badge.style.color = '#22c55e';
            } else {
                badge.textContent = 'NOT installed';
                badge.style.background = 'rgba(239,68,68,0.15)';
                badge.style.color = '#ef4444';
            }
        }
        const missing = tools.filter(t => !status[t.key]).map(t => t.key);
        const digMissing = !status.dig;
        if (missing.length || digMissing) {
            const parts = [...missing];
            if (digMissing && !parts.includes('nslookup')) parts.push('dig');
            statusBox.innerHTML = `
                <div style="padding:12px 14px; background:rgba(251,191,36,0.1); border:1px solid rgba(251,191,36,0.35); border-radius:6px; font-size:13px;">
                    <strong style="color:#fbbf24;">Missing tools:</strong> <code>${parts.join(', ')}</code>
                    <div style="color:var(--text-muted); font-size:11px; margin-top:3px;">
                        Click the button to install them automatically — WolfStack detects your distro's package manager (apt, dnf, yum, pacman, zypper) and uses the right package name for each.
                    </div>
                    <button id="wr-tools-install-btn" class="btn btn-primary btn-sm" style="margin-top:8px;" onclick="wrInstallDiagTools()">Install missing tools</button>
                    <div id="wr-tools-install-status" style="margin-top:6px; font-size:11px; color:var(--text-muted);"></div>
                </div>
            `;
        } else {
            statusBox.innerHTML = `<div style="padding:10px 12px; background:rgba(34,197,94,0.08); border:1px solid rgba(34,197,94,0.3); border-radius:6px; font-size:12px; color:#4ade80;">All diagnostic tools are installed on this host.</div>`;
        }
    }

    async function wrInstallDiagTools() {
        const btn = document.getElementById('wr-tools-install-btn');
        const statusEl = document.getElementById('wr-tools-install-status');
        if (!btn || !statusEl) return;
        btn.disabled = true;
        btn.textContent = 'Installing…';
        statusEl.textContent = 'Running the package manager. On a first-time install this can take 10–60 seconds depending on your distro.';
        try {
            const r = await fetch(wrUrl('/api/router/tools/install'), {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
            });
            const j = await r.json();
            if (j.success) {
                statusEl.innerHTML = `<span style="color:#22c55e;">${escHtml(j.message || 'Installed.')}</span>`;
                btn.textContent = 'Installed';
                // Refresh status so the per-card badges flip to "installed".
                setTimeout(() => wrRenderToolsStatus(), 400);
            } else {
                statusEl.innerHTML = `<span style="color:#ef4444;">${escHtml(j.error || 'Install failed.')}</span>`;
                btn.disabled = false;
                btn.textContent = 'Retry install';
            }
        } catch (e) {
            statusEl.innerHTML = `<span style="color:#ef4444;">Install request failed: ${escHtml(e.message || e)}</span>`;
            btn.disabled = false;
            btn.textContent = 'Retry install';
        }
    }
    window.wrInstallDiagTools = wrInstallDiagTools;

    async function wrRunTool(tool) {
        const targetEl = document.getElementById('wr-tool-target-' + tool);
        const serverEl = document.getElementById('wr-tool-server-' + tool);
        const btn = document.getElementById('wr-tool-btn-' + tool);
        const out = document.getElementById('wr-tool-out-' + tool);
        if (!targetEl || !btn || !out) return;
        const target = targetEl.value.trim();
        if (!target) {
            out.style.display = 'block';
            out.style.color = '#ef4444';
            out.textContent = 'Enter a target hostname or IP first.';
            return;
        }
        btn.disabled = true;
        const origLabel = btn.textContent;
        btn.textContent = 'Running…';
        out.style.display = 'block';
        out.style.color = 'var(--text-muted)';
        // Per-tool "this may take a while" hint so the user doesn't wonder
        // if the page is stuck. Traceroute in particular can take 30–60s.
        const waits = {
            ping: 'Sending 4 ICMP echo packets (up to ~15 seconds)…',
            traceroute: 'Tracing each hop up to 20 routers — this can take up to 60 seconds…',
            nslookup: 'Querying DNS server (up to 10 seconds)…',
            whois: 'Looking up WHOIS registry (up to 30 seconds)…',
        };
        out.textContent = waits[tool] || 'Running…';

        const body = { target };
        if (tool === 'nslookup' && serverEl?.value.trim()) body.server = serverEl.value.trim();

        try {
            const r = await fetch(wrUrl('/api/router/tools/' + tool), {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const j = await r.json();
            if (r.status === 400) {
                out.style.color = '#ef4444';
                out.textContent = '' + (j.error || 'Invalid input');
            } else if (j.success) {
                out.style.color = 'var(--text)';
                const tail = `\n\n──\nCompleted in ${j.duration_ms}ms.`;
                out.textContent = (j.output || '(no output)') + tail;
            } else {
                out.style.color = '#f87171';
                const parts = [];
                if (j.output) parts.push(j.output);
                if (j.error) parts.push('' + j.error);
                parts.push(`Completed in ${j.duration_ms}ms.`);
                out.textContent = parts.join('\n');
            }
        } catch (e) {
            out.style.color = '#ef4444';
            out.textContent = 'Request failed: ' + (e.message || e);
        } finally {
            btn.disabled = false;
            btn.textContent = origLabel;
        }
    }
    window.wrRunTool = wrRunTool;
    window.wrRenderDnsTools = wrRenderDnsTools;

    // ─── Config export / import ───
    //
    // Back up the entire WolfRouter state (zones, LANs, WAN, rules,
    // global toggles) to a JSON file the user can re-upload later.
    // Useful before experimenting, for rebuild-after-reinstall, and
    // for cloning a known-good config between clusters.

    async function wrExportConfig() {
        // Toast feedback is subtle — the browser's download indicator is
        // the primary signal. We also show a short-lived banner so the
        // user sees "yes, it's done" without having to notice the file.
        try {
            const r = await fetch(wrUrl('/api/router/export'));
            if (!r.ok) {
                alert('Export failed: HTTP ' + r.status + ' ' + await r.text());
                return;
            }
            // Pull the filename out of Content-Disposition so the file
            // lands with the server-supplied timestamp.
            const disp = r.headers.get('Content-Disposition') || '';
            const m = disp.match(/filename="([^"]+)"/);
            const filename = m ? m[1] : 'wolfrouter-config.json';
            const blob = await r.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
            if (typeof showToast === 'function') {
                showToast(`Exported ${filename}. PPPoE passwords masked.`, 'success');
            } else {
                alert(`Exported ${filename}.\n\nNote: PPPoE passwords are masked as "***" in the export — safe to share, but you'll keep passwords if you re-import back onto this node.`);
            }
        } catch (e) {
            alert('Export errored: ' + (e.message || e));
        }
    }
    window.wrExportConfig = wrExportConfig;

    function wrShowImportConfig() {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:560px;">
                <div class="modal-header">
                    <h3>Import WolfRouter config</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="padding:10px 12px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.35); border-radius:6px; margin-bottom:12px;">
                        <strong style="color:#fca5a5;">Replaces your entire config.</strong>
                        <div style="color:var(--text-muted); font-size:12px; margin-top:3px;">
                            All zones, LANs, WAN connections, and firewall rules will be overwritten by the uploaded file. Export your current config first (Export) if you want a rollback.
                        </div>
                    </div>
                    <label style="display:block; margin-bottom:10px;">Config file (JSON from Export)
                        <input id="wr-imp-file" type="file" accept=".json,application/json" class="form-control"/>
                    </label>
                    <label style="display:flex; gap:8px; align-items:center; padding:8px 10px; background:rgba(34,197,94,0.08); border:1px solid rgba(34,197,94,0.3); border-radius:6px;">
                        <input type="checkbox" id="wr-imp-apply" checked/>
                        <div>
                            <strong style="color:#4ade80;">Apply immediately after import</strong>
                            <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                                Restarts dnsmasq for every LAN, re-dials PPPoE, re-applies the firewall. Uncheck to stage the config and apply manually.
                            </div>
                        </div>
                    </label>
                    <div id="wr-imp-status" style="margin-top:12px; font-size:12px;"></div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button id="wr-imp-btn" class="btn btn-primary" onclick="wrRunImportConfig()">Import</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
    }
    window.wrShowImportConfig = wrShowImportConfig;

    async function wrRunImportConfig() {
        const fileEl = document.getElementById('wr-imp-file');
        const applyEl = document.getElementById('wr-imp-apply');
        const btn = document.getElementById('wr-imp-btn');
        const statusEl = document.getElementById('wr-imp-status');
        if (!fileEl || !btn || !statusEl) return;
        const file = fileEl.files && fileEl.files[0];
        if (!file) {
            statusEl.innerHTML = '<span style="color:#ef4444;">Pick a JSON file first.</span>';
            return;
        }
        btn.disabled = true;
        btn.textContent = 'Importing…';
        statusEl.innerHTML = '<span style="color:var(--text-muted);">Reading file…</span>';

        let parsed;
        try {
            const text = await file.text();
            parsed = JSON.parse(text);
        } catch (e) {
            statusEl.innerHTML = `<span style="color:#ef4444;">Could not parse JSON: ${escHtml(e.message || e)}</span>`;
            btn.disabled = false;
            btn.textContent = 'Import';
            return;
        }

        statusEl.innerHTML = '<span style="color:var(--text-muted);">Uploading + applying…</span>';
        try {
            const r = await fetch(wrUrl('/api/router/import'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ config: parsed, apply: !!applyEl.checked }),
            });
            const j = await r.json();
            if (j.success) {
                const s = j.summary || {};
                const a = j.applied || {};
                const parts = [`${escHtml(j.message || 'Imported.')}`];
                parts.push(`<div style="margin-top:6px; font-size:11px; color:var(--text-muted);">Summary: ${s.lans || 0} LAN(s), ${s.wan_connections || 0} WAN, ${s.rules || 0} rules, ${s.zones || 0} zone assignments.</div>`);
                if (applyEl.checked) {
                    const applyBits = [];
                    if (a.wan_applied != null)        applyBits.push(`${a.wan_applied} WAN dialers started`);
                    if (a.dnsmasq_restarted != null)  applyBits.push(`${a.dnsmasq_restarted} dnsmasq instance(s) restarted`);
                    if (a.firewall)                   applyBits.push(`firewall: ${escHtml(a.firewall)}`);
                    if ((a.wan_errors || []).length)  applyBits.push(`<span style="color:#ef4444;">WAN errors: ${(a.wan_errors).map(escHtml).join('; ')}</span>`);
                    if (applyBits.length) parts.push(`<div style="margin-top:4px; font-size:11px;">Applied: ${applyBits.join(' · ')}</div>`);
                }
                statusEl.innerHTML = `<div style="padding:8px 10px; background:rgba(34,197,94,0.1); border:1px solid rgba(34,197,94,0.35); border-radius:4px; color:#4ade80;">${parts.join('')}</div>`;
                btn.textContent = 'Imported';
                // Delay close so user reads the summary.
                setTimeout(() => {
                    document.querySelector('.modal-overlay')?.remove();
                    wrLoadAll();
                }, 2000);
            } else {
                statusEl.innerHTML = `<div style="padding:8px 10px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.35); border-radius:4px; color:#fca5a5;">${escHtml(j.error || 'Import failed.')}</div>`;
                btn.disabled = false;
                btn.textContent = 'Import';
            }
        } catch (e) {
            statusEl.innerHTML = `<span style="color:#ef4444;">Request failed: ${escHtml(e.message || e)}</span>`;
            btn.disabled = false;
            btn.textContent = 'Import';
        }
    }
    window.wrRunImportConfig = wrRunImportConfig;

    // ─── Reverse proxy (domain → backend, all ports + all protocols) ───

    function wrRenderProxies() {
        const list = document.getElementById('wr-proxy-list');
        if (!list) return;
        const items = wrState.proxies || [];
        if (!items.length) {
            list.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:40px; font-size:13px; border:1px dashed var(--border); border-radius:8px;">
                No domain forwards yet. Click <strong>+ Domain forward</strong> to create one.
            </div>`;
            return;
        }
        // Sort: enabled first, then alphabetical by domain.
        const sorted = [...items].sort((a, b) => {
            if (a.enabled !== b.enabled) return a.enabled ? -1 : 1;
            return (a.domain || '').localeCompare(b.domain || '');
        });
        list.innerHTML = sorted.map(p => proxyCardHtml(p)).join('');
    }

    function proxyBackendLabel(b) {
        if (!b || !b.kind) return '<span style="color:var(--text-muted);">no backend</span>';
        if (b.kind === 'custom') {
            return `<code>${escHtml(b.host || '?')}</code>`;
        }
        if (b.kind === 'vm') {
            const typeIcon = b.vm_type === 'proxmox' ? '' : '';
            return `${typeIcon} ${escHtml(b.vm_name || b.vm_id)} <span style="color:var(--text-muted); font-size:11px;">(${escHtml(b.vm_type || 'vm')} — <code>${escHtml(b.host || '?')}</code>)</span>`;
        }
        if (b.kind === 'container') {
            const icon = b.container_type === 'lxc' ? '' : '';
            return `${icon} ${escHtml(b.container_name || b.container_id)} <span style="color:var(--text-muted); font-size:11px;">(${escHtml(b.container_type || 'container')} — <code>${escHtml(b.host || '?')}</code>)</span>`;
        }
        return escHtml(JSON.stringify(b));
    }

    function proxyLbLabel(policy, count) {
        if (count <= 1) return '';
        const label = policy === 'ip_hash' ? 'weighted random' : 'round-robin';
        return `<span class="badge" style="background:rgba(168,85,247,0.12); color:#a855f7; font-size:10px; margin-left:8px;">${label}</span>`;
    }

    function proxyCardHtml(p) {
        const disabled = !p.enabled;
        const backends = Array.isArray(p.backends) ? p.backends : [];
        const backendsHtml = backends.length
            ? backends.map(b => `<div style="font-size:13px; padding:2px 0;">→ ${proxyBackendLabel(b)}</div>`).join('')
            : '<div style="font-size:13px; color:var(--text-muted);">→ (no backends)</div>';
        return `<div style="border:1px solid var(--border); border-radius:8px; padding:12px 16px; background:var(--bg-card); ${disabled ? 'opacity:0.55;' : ''}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap;">
                <div style="flex:1; min-width:260px;">
                    <div style="font-size:15px; font-weight:600; margin-bottom:4px;">
                        ${escHtml(p.domain || '(no domain)')}
                        ${proxyLbLabel(p.lb_policy, backends.length)}
                        ${disabled ? '<span class="badge" style="background:rgba(148,163,184,0.15); color:#94a3b8; font-size:10px; margin-left:8px;">disabled</span>' : ''}
                    </div>
                    <div style="font-size:12px; color:var(--text-muted); margin-bottom:6px;">
                        Public IP <code>${escHtml(p.resolved_public_ip || '(unresolved)')}</code>
                        ${p.description ? ` · ${escHtml(p.description)}` : ''}
                    </div>
                    ${backendsHtml}
                </div>
                <div style="display:flex; gap:6px;">
                    <button class="btn btn-sm" onclick="wrToggleProxy('${escHtml(p.id)}')" title="${disabled ? 'Enable' : 'Disable'}">${disabled ? '▶' : ''}</button>
                    <button class="btn btn-sm" onclick="wrShowProxyEditor('${escHtml(p.id)}')" title="Edit"><span class="ws-icon-clean-wrap" data-icon="edit"></span></button>
                    <button class="btn btn-sm" onclick="wrDeleteProxy('${escHtml(p.id)}')" title="Delete"><span class="ws-icon-clean-wrap" data-icon="trash"></span></button>
                </div>
            </div>
        </div>`;
    }

    // Cache for the backend picker — /api/router/proxy-backends is cheap
    // but we fetch it every modal open since VMs/containers come and go.
    async function loadProxyBackends() {
        try {
            const r = await fetch(wrUrl('/api/router/proxy-backends'));
            if (!r.ok) return { vms: { libvirt: [], proxmox: [] }, containers: { docker: [], lxc: [] } };
            return await r.json();
        } catch (e) {
            return { vms: { libvirt: [], proxmox: [] }, containers: { docker: [], lxc: [] } };
        }
    }

    // State for the editor — we rebuild the backend rows in place so
    // this persists across "Add backend" clicks. Cleared on modal close.
    let wrProxyEditorState = null;

    function proxyPickerOptionsHtml(picks, selectedRaw) {
        const out = [];
        if (picks.vms?.libvirt?.length) {
            out.push(`<optgroup label="WolfStack / libvirt VMs">`);
            for (const v of picks.vms.libvirt) {
                const val = `vm::libvirt::${v.id}::${v.host || ''}::${v.name}`;
                out.push(`<option value="${escHtml(val)}" ${val === selectedRaw ? 'selected' : ''}>${escHtml(v.name)} — ${escHtml(v.host || 'no IP')}</option>`);
            }
            out.push(`</optgroup>`);
        }
        if (picks.vms?.proxmox?.length) {
            out.push(`<optgroup label="Proxmox VE VMs">`);
            for (const v of picks.vms.proxmox) {
                const val = `vm::proxmox::${v.id}::${v.host || ''}::${v.name}`;
                out.push(`<option value="${escHtml(val)}" ${val === selectedRaw ? 'selected' : ''}>${escHtml(v.name)} — ${escHtml(v.host || 'no IP')}</option>`);
            }
            out.push(`</optgroup>`);
        }
        if (picks.containers?.docker?.length) {
            out.push(`<optgroup label="Docker containers">`);
            for (const c of picks.containers.docker) {
                const val = `container::docker::${c.id}::${c.host || ''}::${c.name}`;
                out.push(`<option value="${escHtml(val)}" ${val === selectedRaw ? 'selected' : ''}>${escHtml(c.name)} — ${escHtml(c.host || 'no IP')}</option>`);
            }
            out.push(`</optgroup>`);
        }
        if (picks.containers?.lxc?.length) {
            out.push(`<optgroup label="LXC containers">`);
            for (const c of picks.containers.lxc) {
                const val = `container::lxc::${c.id}::${c.host || ''}::${c.name}`;
                out.push(`<option value="${escHtml(val)}" ${val === selectedRaw ? 'selected' : ''}>${escHtml(c.name)} — ${escHtml(c.host || 'no IP')}</option>`);
            }
            out.push(`</optgroup>`);
        }
        if (!out.length) return '<option value="">(no running VMs or containers with an IP)</option>';
        return `<option value="">— Pick a VM or container —</option>${out.join('')}`;
    }

    /// Render one row of the backends list. `idx` is the array index
    /// used for event routing; `backend` is the current shape.
    function proxyBackendRowHtml(idx, backend, picks) {
        const kindIsCustom = backend.kind === 'custom';
        let selectedRaw = '';
        if (backend.kind === 'vm') {
            selectedRaw = `vm::${backend.vm_type || 'libvirt'}::${backend.vm_id || ''}::${backend.host || ''}::${backend.vm_name || ''}`;
        } else if (backend.kind === 'container') {
            selectedRaw = `container::${backend.container_type || 'docker'}::${backend.container_id || ''}::${backend.host || ''}::${backend.container_name || ''}`;
        }
        const pickerOpts = proxyPickerOptionsHtml(picks, selectedRaw);
        const weight = (backend.weight === 0 || backend.weight) ? backend.weight : 1;
        return `<div class="wr-proxy-backend-row" data-idx="${idx}" style="border:1px solid var(--border); border-radius:6px; padding:10px 12px; display:grid; gap:8px; background:var(--bg-secondary);">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
                <div style="font-size:12px; color:var(--text-muted);">Backend #${idx + 1}</div>
                <div style="display:flex; gap:16px; font-size:12px; align-items:center;">
                    <label style="font-weight:normal;"><input type="radio" name="wr-proxy-kind-${idx}" value="picker" ${!kindIsCustom ? 'checked' : ''} onchange="wrProxyBackendKindChanged(${idx})" /> VM / container</label>
                    <label style="font-weight:normal;"><input type="radio" name="wr-proxy-kind-${idx}" value="custom" ${kindIsCustom ? 'checked' : ''} onchange="wrProxyBackendKindChanged(${idx})" /> Custom IP</label>
                    <label style="font-weight:normal; display:flex; align-items:center; gap:4px;" title="Relative weight — 2 gets twice as many connections as 1">
                        Weight
                        <input type="number" class="form-control wr-proxy-weight" data-idx="${idx}" value="${weight}" min="1" max="100" style="width:64px; padding:2px 6px; font-size:12px;" />
                    </label>
                    <button class="btn btn-sm" type="button" onclick="wrProxyRemoveBackend(${idx})" title="Remove this backend"><span class="ws-icon-clean-wrap" data-icon="trash"></span></button>
                </div>
            </div>
            <div class="wr-proxy-picker-row" data-idx="${idx}" style="${kindIsCustom ? 'display:none;' : ''}">
                <select class="form-control wr-proxy-picker" data-idx="${idx}">${pickerOpts}</select>
            </div>
            <div class="wr-proxy-custom-row" data-idx="${idx}" style="${!kindIsCustom ? 'display:none;' : ''}">
                <input class="form-control wr-proxy-custom-host" data-idx="${idx}" value="${escHtml(kindIsCustom ? (backend.host || '') : '')}" placeholder="10.10.10.5 or backend.internal" />
            </div>
        </div>`;
    }

    function rerenderBackendRows() {
        const wrap = document.getElementById('wr-proxy-backends-wrap');
        if (!wrap || !wrProxyEditorState) return;
        const { backends, picks } = wrProxyEditorState;
        wrap.innerHTML = backends.map((b, i) => proxyBackendRowHtml(i, b, picks)).join('');
        // Show/hide the lb policy selector based on count.
        const lbRow = document.getElementById('wr-proxy-lb-row');
        if (lbRow) lbRow.style.display = backends.length > 1 ? '' : 'none';
    }

    /// Collect current form state of the N backend rows into the
    /// editor state array before we rebuild the DOM (otherwise adding
    /// a row blows away any unsaved picker selections in the other
    /// rows).
    function snapshotBackendRows() {
        if (!wrProxyEditorState) return;
        const rows = document.querySelectorAll('.wr-proxy-backend-row');
        const collected = [];
        rows.forEach((row) => {
            const idx = parseInt(row.dataset.idx, 10);
            const kindRadio = row.querySelector(`input[name="wr-proxy-kind-${idx}"]:checked`);
            const kind = kindRadio ? kindRadio.value : 'picker';
            // Clamp weight to [1, 100] — backend coerces 0 to 1 but we
            // prefer to prevent the user from entering nonsense at source.
            const rawWeight = parseInt(row.querySelector('.wr-proxy-weight')?.value, 10);
            const weight = (Number.isFinite(rawWeight) && rawWeight > 0) ? Math.min(rawWeight, 100) : 1;
            if (kind === 'custom') {
                const host = row.querySelector('.wr-proxy-custom-host')?.value.trim() || '';
                collected.push({ kind: 'custom', host, weight });
            } else {
                const raw = row.querySelector('.wr-proxy-picker')?.value || '';
                if (!raw) { collected.push({ kind: 'custom', host: '', weight }); return; }
                const parts = raw.split('::');
                if (parts[0] === 'vm') {
                    collected.push({
                        kind: 'vm', vm_type: parts[1], vm_id: parts[2],
                        host: parts[3], vm_name: parts[4], weight,
                    });
                } else {
                    collected.push({
                        kind: 'container', container_type: parts[1], container_id: parts[2],
                        host: parts[3], container_name: parts[4], weight,
                    });
                }
            }
        });
        wrProxyEditorState.backends = collected;
    }

    function wrProxyBackendKindChanged(idx) {
        const pickerRow = document.querySelector(`.wr-proxy-picker-row[data-idx="${idx}"]`);
        const customRow = document.querySelector(`.wr-proxy-custom-row[data-idx="${idx}"]`);
        const kind = document.querySelector(`input[name="wr-proxy-kind-${idx}"]:checked`)?.value || 'picker';
        if (pickerRow) pickerRow.style.display = kind === 'picker' ? '' : 'none';
        if (customRow) customRow.style.display = kind === 'custom' ? '' : 'none';
    }

    function wrProxyAddBackend() {
        if (!wrProxyEditorState) return;
        snapshotBackendRows();
        wrProxyEditorState.backends.push({ kind: 'custom', host: '', weight: 1 });
        rerenderBackendRows();
    }

    function wrProxyRemoveBackend(idx) {
        if (!wrProxyEditorState) return;
        snapshotBackendRows();
        wrProxyEditorState.backends.splice(idx, 1);
        if (wrProxyEditorState.backends.length === 0) {
            wrProxyEditorState.backends.push({ kind: 'custom', host: '', weight: 1 });
        }
        rerenderBackendRows();
    }

    async function wrShowProxyEditor(id) {
        const existing = id ? (wrState.proxies || []).find(p => p.id === id) : null;
        const entry = existing || {
            id: '', domain: '', node_id: '',
            resolved_public_ip: '',
            backends: [{ kind: 'custom', host: '', weight: 1 }],
            lb_policy: 'round_robin',
            enabled: true,
            failover: false,
            description: '',
        };
        // Back-compat: older configs may have `backend` (singular). Coerce.
        if (!Array.isArray(entry.backends) || !entry.backends.length) {
            entry.backends = entry.backend ? [entry.backend] : [{ kind: 'custom', host: '', weight: 1 }];
        }

        const nodes = (wrState.topology?.nodes) || [];
        const nodeOptionsHtml = nodes.map(n =>
            `<option value="${escHtml(n.node_id)}" ${entry.node_id === n.node_id ? 'selected' : ''}>${escHtml(n.node_name || n.node_id)}</option>`
        ).join('') || '<option value="">(no nodes discovered)</option>';

        const picks = await loadProxyBackends();
        wrProxyEditorState = {
            picks,
            backends: entry.backends.map(b => ({ ...b })),
        };

        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.id = 'wr-proxy-editor-overlay';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:720px;">
                <div class="modal-header">
                    <h3>${existing ? 'Edit' : 'New'} domain forward</h3>
                    <button class="modal-close" onclick="document.getElementById('wr-proxy-editor-overlay').remove(); wrProxyEditorState=null;">×</button>
                </div>
                <div class="modal-body">
                    <div style="display:grid; gap:12px;">
                        <label>Domain
                            <input id="wr-proxy-domain" class="form-control" value="${escHtml(entry.domain || '')}" placeholder="e.g. pbs.home.example.com" />
                            <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Must already resolve to a public IP on the selected node. If you haven't set up DNS, enter the public IP manually below.</div>
                        </label>
                        <label>Public IP <span style="color:var(--text-muted); font-weight:normal;">(optional — auto-resolved from the domain if blank)</span>
                            <input id="wr-proxy-public-ip" class="form-control" value="${escHtml(entry.resolved_public_ip || '')}" placeholder="auto" />
                        </label>
                        <label>Owning node
                            <select id="wr-proxy-node" class="form-control">${nodeOptionsHtml}</select>
                            <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">iptables rules are installed only on this node — it must be the one the public IP actually lives on.</div>
                        </label>
                        <div>
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                                <label style="margin:0;">Backends</label>
                                <button class="btn btn-sm" type="button" onclick="wrProxyAddBackend()">+ Add backend</button>
                            </div>
                            <div id="wr-proxy-backends-wrap" style="display:grid; gap:8px;"></div>
                        </div>
                        <div id="wr-proxy-lb-row" style="display:${entry.backends.length > 1 ? '' : 'none'};">
                            <label>Load balancing
                                <select id="wr-proxy-lb" class="form-control">
                                    <option value="round_robin" ${entry.lb_policy === 'round_robin' ? 'selected' : ''}>Round-robin (weighted cycle)</option>
                                    <option value="ip_hash" ${entry.lb_policy === 'ip_hash' ? 'selected' : ''}>Random per connection</option>
                                    <option value="source_hash" ${entry.lb_policy === 'source_hash' ? 'selected' : ''}>Sticky by source IP (nftables)</option>
                                </select>
                                <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">
                                    <b>Round-robin</b> cycles through backends in order; per-backend weight controls how many consecutive slots each one gets.<br>
                                    <b>Random per connection</b> picks a backend at random for each new TCP connection (weighted). Connections stay on their first pick for the life of the stream — not across reconnects.<br>
                                    <b>Sticky by source IP</b> hashes the client IP so the same client always lands on the same backend. Requires <code>nftables</code> installed on every forwarding node; falls back to random if not.
                                </div>
                            </label>
                        </div>
                        <label>Description <span style="color:var(--text-muted); font-weight:normal;">(optional)</span>
                            <input id="wr-proxy-description" class="form-control" value="${escHtml(entry.description || '')}" placeholder="e.g. PBS backup server" maxlength="120" />
                        </label>
                        <label style="display:flex; align-items:center; gap:8px;">
                            <input type="checkbox" id="wr-proxy-enabled" ${entry.enabled !== false ? 'checked' : ''} />
                            Enabled
                        </label>
                        <label style="display:flex; align-items:flex-start; gap:8px;" title="Install rules on every cluster node — lets a peer take over if the owning node goes down.">
                            <input type="checkbox" id="wr-proxy-failover" ${entry.failover ? 'checked' : ''} style="margin-top:3px;" />
                            <div>
                                <div>Cluster failover</div>
                                <div style="font-size:11px; color:var(--text-muted); font-weight:normal;">Install the forward on every online WolfStack node, not just the owner. Any peer receiving traffic (via DNS, a floating public IP, or manual takeover) can then serve it. Pin the public IP above so every node binds to the same address.</div>
                            </div>
                        </label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="document.getElementById('wr-proxy-editor-overlay').remove(); wrProxyEditorState=null;">Cancel</button>
                    <button class="btn btn-primary" onclick="wrSaveProxy('${escHtml(entry.id || '')}')">Save</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);
        rerenderBackendRows();
    }

    async function wrSaveProxy(existingId) {
        const domain = document.getElementById('wr-proxy-domain').value.trim();
        if (!domain) {
            showProxyWarning('Domain is required.');
            return;
        }
        const node_id = document.getElementById('wr-proxy-node').value;
        const resolved_public_ip = document.getElementById('wr-proxy-public-ip').value.trim();
        const description = document.getElementById('wr-proxy-description').value.trim();
        const enabled = document.getElementById('wr-proxy-enabled').checked;
        const failover = document.getElementById('wr-proxy-failover')?.checked || false;
        const lb_policy = document.getElementById('wr-proxy-lb')?.value || 'round_robin';

        snapshotBackendRows();
        const backends = (wrProxyEditorState?.backends || []).filter(b => (b.host || '').trim() !== '');
        if (!backends.length) {
            showProxyWarning('At least one backend with an IP or hostname is required.');
            return;
        }

        const body = {
            id: existingId || '',
            domain,
            node_id,
            resolved_public_ip,
            backends,
            lb_policy,
            enabled,
            failover,
            description,
        };

        const url = existingId
            ? wrUrl('/api/router/proxies/' + encodeURIComponent(existingId))
            : wrUrl('/api/router/proxies');
        const method = existingId ? 'PUT' : 'POST';
        try {
            const resp = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            if (!resp.ok) {
                const text = await resp.text();
                showProxyWarning('Save failed: ' + text);
                return;
            }
            const data = await resp.json();
            document.getElementById('wr-proxy-editor-overlay')?.remove();
            wrProxyEditorState = null;
            if (Array.isArray(data.warnings) && data.warnings.length) {
                showProxyWarning(data.warnings.join('\n'));
            } else {
                hideProxyWarning();
            }
            await wrLoadAll();
        } catch (e) {
            showProxyWarning('Save failed: ' + (e.message || e));
        }
    }

    async function wrDeleteProxy(id) {
        if (!confirm('Delete this domain forward? iptables rules will be removed immediately.')) return;
        try {
            const resp = await fetch(wrUrl('/api/router/proxies/' + encodeURIComponent(id)), { method: 'DELETE' });
            if (!resp.ok) {
                const text = await resp.text();
                showProxyWarning('Delete failed: ' + text);
                return;
            }
            hideProxyWarning();
            await wrLoadAll();
        } catch (e) {
            showProxyWarning('Delete failed: ' + (e.message || e));
        }
    }

    async function wrToggleProxy(id) {
        const entry = (wrState.proxies || []).find(p => p.id === id);
        if (!entry) return;
        const updated = { ...entry, enabled: !entry.enabled };
        try {
            const resp = await fetch(wrUrl('/api/router/proxies/' + encodeURIComponent(id)), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updated),
            });
            if (!resp.ok) {
                const text = await resp.text();
                showProxyWarning('Toggle failed: ' + text);
                return;
            }
            const data = await resp.json();
            if (Array.isArray(data.warnings) && data.warnings.length) {
                showProxyWarning(data.warnings.join('\n'));
            } else {
                hideProxyWarning();
            }
            await wrLoadAll();
        } catch (e) {
            showProxyWarning('Toggle failed: ' + (e.message || e));
        }
    }

    function showProxyWarning(msg) {
        const el = document.getElementById('wr-proxy-warnings');
        if (!el) return;
        el.textContent = msg;
        el.style.display = 'block';
    }

    function hideProxyWarning() {
        const el = document.getElementById('wr-proxy-warnings');
        if (el) el.style.display = 'none';
    }

    // ─── Subnet Routes ───

    async function wrLoadSubnetRoutes() {
        try {
            const resp = await fetch(wrUrl('/api/router/subnet-routes'));
            if (!resp.ok) {
                console.error('Failed to load subnet routes');
                wrState.subnet_routes = [];
                return;
            }
            wrState.subnet_routes = await resp.json() || [];
        } catch (e) {
            console.error('Error loading subnet routes:', e);
            wrState.subnet_routes = [];
        }
        wrRenderSubnetRoutes();
    }

    function wrRenderSubnetRoutes() {
        // Refresh the IPv6 opt-in banner whenever the tab renders (fire and
        // forget — it only updates its own element, never re-enters render).
        wrLoadIpv6SubnetSetting();
        const routes = wrState.subnet_routes || [];
        const el = document.getElementById('wr-subnet-routes-list');
        if (!el) return;

        if (routes.length === 0) {
            el.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-muted); background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px;">No subnet routes configured.</div>';
            return;
        }

        // Pre-compute the set of node_ids the cluster currently knows
        // about so we can flag any route whose Node Assignment doesn't
        // match a real cluster member — that makes the route silently
        // unreachable (no node ever runs the apply path) and is the
        // single most common configuration mistake.
        const knownNodeIds = new Set(
            (wrState.topology?.nodes || []).map(n => n.node_id).filter(Boolean)
        );
        const nodeNameById = new Map(
            (wrState.topology?.nodes || []).map(n => [n.node_id, n.node_name || n.node_id])
        );

        el.innerHTML = routes.map(r => {
            // Node line: cluster-wide, real-node-with-friendly-name, or
            // a red "not in cluster" warning that points the user at
            // the fix.
            let nodeLine;
            if (!r.node_id) {
                nodeLine = `<span style="color:var(--text-muted);">Cluster-wide (every node)</span>`;
            } else if (knownNodeIds.size === 0) {
                // Topology not loaded yet — don't false-alarm. Just show the id.
                nodeLine = `<span style="color:var(--text-muted);">Node: ${escHtml(r.node_id)}</span>`;
            } else if (knownNodeIds.has(r.node_id)) {
                const friendly = nodeNameById.get(r.node_id) || r.node_id;
                nodeLine = `<span style="color:var(--text-muted);">Node: <strong style="color:var(--text);">${escHtml(friendly)}</strong> <code style="font-size:10px;">(${escHtml(r.node_id)})</code></span>`;
            } else {
                nodeLine = `<span style="color:#fca5a5;">Assigned to <code>${escHtml(r.node_id)}</code> — no such node in this cluster. Click Edit and pick a node from the dropdown to fix.</span>`;
            }
            return `
            <div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px; padding:14px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                <div>
                    <div style="font-weight:600; color:var(--text); font-size:14px; font-family:monospace;">
                        ${escHtml(r.subnet_cidr)} <span style="color:var(--text-muted);">→</span> ${escHtml(r.gateway)}
                    </div>
                    <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">
                        ${r.description ? escHtml(r.description) : '<em>(no description)</em>'}
                    </div>
                    <div style="font-size:11px; margin-top:4px;">
                        ${nodeLine}
                    </div>
                </div>
                <div style="display:flex; gap:6px; flex-wrap:wrap;">
                    <button class="btn btn-sm" onclick="wrToggleSubnetRoute('${escHtml(r.id)}')" title="${r.enabled ? 'Disable this route' : 'Enable this route'}" style="font-size:11px;">
                        ${r.enabled ? 'Enabled' : '⊘ Disabled'}
                    </button>
                    <button class="btn btn-sm" onclick="wrEditSubnetRoute('${escHtml(r.id)}')" title="Edit route" style="font-size:11px;">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="wrDeleteSubnetRoute('${escHtml(r.id)}')" title="Delete route" style="font-size:11px;">Delete</button>
                </div>
            </div>
            `;
        }).join('');
    }

    // ─── IPv6 subnet routing opt-in (default OFF) ───
    // Reflects RouterConfig.ipv6_subnet_routing and whether the host has a
    // working v6 stack. Until enabled, the backend rejects IPv6 routes and
    // no IPv6 code path runs on any node — IPv4 routing is untouched.
    async function wrLoadIpv6SubnetSetting() {
        const el = document.getElementById('wr-ipv6-subnet-banner');
        if (!el) return;
        let enabled = false, available = false, ok = false;
        try {
            const resp = await fetch(wrUrl('/api/router/subnet-routes/ipv6'));
            if (resp.ok) {
                const j = await resp.json();
                enabled = !!j.ipv6_subnet_routing;
                available = !!j.ipv6_available;
                ok = true;
            }
        } catch (e) {
            console.error('Failed to load IPv6 subnet setting:', e);
        }
        if (!ok) { el.innerHTML = ''; return; }

        const hostWarn = (enabled && !available)
            ? `<div style="margin-top:6px; color:#fca5a5; font-size:11px;">⚠ IPv6 is disabled on this host (<code>net.ipv6.conf.all.disable_ipv6=1</code>). Enable IPv6 and forwarding before routes can pass traffic.</div>`
            : '';
        const btnLabel = enabled ? 'Disable IPv6 subnet routing' : 'Enable IPv6 subnet routing';
        const stateText = enabled
            ? `<strong style="color:var(--text);">On</strong> — IPv6 destination subnets can be routed over the WolfNet overlay.`
            : `<strong style="color:var(--text);">Off</strong> (default) — turn on to route IPv6 workload subnets across peers. IPv4 routing is unaffected either way.`;
        el.innerHTML = `
            <div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px; padding:12px 14px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                <div style="font-size:12px; color:var(--text-muted); max-width:720px;">
                    <span style="font-weight:600; color:var(--text);">IPv6 subnet routing:</span> ${stateText}
                    The gateway stays the peer's IPv4 WolfNet IP; only the destination subnet is IPv6.
                    ${hostWarn}
                </div>
                <button class="btn btn-sm ${enabled ? '' : 'btn-primary'}" onclick="wrSetIpv6SubnetRouting(${enabled ? 'false' : 'true'})">${btnLabel}</button>
            </div>`;
    }

    async function wrSetIpv6SubnetRouting(enabled) {
        if (enabled && !confirm('Enable IPv6 subnet routing?\n\nThis lets WolfStack route IPv6 workload subnets across WolfNet peers. It only affects nodes that have IPv6 enabled; IPv4 routing is unchanged. You can turn it off again at any time.')) return;
        if (!enabled && !confirm('Disable IPv6 subnet routing?\n\nAny IPv6 subnet routes stop being applied and their kernel routes / ip6tables rules are removed on this node. IPv4 routes are unaffected.')) return;
        try {
            const resp = await fetch(wrUrl('/api/router/subnet-routes/ipv6'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: !!enabled }),
            });
            const j = await resp.json().catch(() => ({}));
            if (!resp.ok || j.ok === false) {
                if (typeof showToast === 'function') showToast('Failed to update IPv6 subnet routing: ' + (j.error || `HTTP ${resp.status}`), 'error');
                return;
            }
            if (typeof showToast === 'function') showToast('IPv6 subnet routing ' + (enabled ? 'enabled' : 'disabled'), 'success');
            if (Array.isArray(j.warnings) && j.warnings.length) {
                alert('IPv6 subnet routing updated, with warnings:\n\n' + j.warnings.join('\n'));
            }
            await wrLoadAll();
        } catch (e) {
            if (typeof showToast === 'function') showToast('Failed to update IPv6 subnet routing: ' + (e.message || e), 'error');
        }
    }

    function wrShowSubnetRouteEditor(routeId) {
        const route = routeId ? (wrState.subnet_routes || []).find(r => r.id === routeId) : null;

        // Build a node-id dropdown from live topology — same pattern as the
        // LAN segment editor. Free-text used to be the input here, which let
        // operators type a hostname or display name (e.g. "klnet-12gb"). The
        // backend stores `node_id` as `ws-<hex>` (see src/main.rs node_id
        // generation), so a hostname-typed value matched NO node in the
        // cluster and `route_targets_self()` returned false everywhere —
        // resulting in the route being saved + replicated but never applied
        // to any kernel routing table. (Sponsor report 2026-04-27.)
        const nodes = wrState.topology?.nodes || [];
        const currentNodeId = route && route.node_id ? route.node_id : '';
        // Show node_name to humans, store node_id. If editing a route whose
        // node_id no longer matches any topology entry, surface that as a
        // tagged "not in cluster" option so the operator can SEE the
        // mismatch and pick a real node.
        // <option> renders content as plain text in every browser, so we
        // build the label as a single text string ("name — id") rather
        // than nesting a <span>.
        const nodeOptionsHtml = (() => {
            const opts = [`<option value="">Cluster-wide (install on every node)</option>`];
            for (const n of nodes) {
                const sel = n.node_id === currentNodeId ? 'selected' : '';
                const friendly = n.node_name || n.node_id;
                const label = friendly === n.node_id ? n.node_id : `${friendly} — ${n.node_id}`;
                opts.push(`<option value="${escHtml(n.node_id)}" ${sel}>${escHtml(label)}</option>`);
            }
            const inCluster = nodes.some(n => n.node_id === currentNodeId);
            if (currentNodeId && !inCluster) {
                opts.push(`<option value="${escHtml(currentNodeId)}" selected>${escHtml(currentNodeId)} (NOT in this cluster — pick a real node)</option>`);
            }
            return opts.join('');
        })();

        const dlg = showDialog({
            title: routeId ? 'Edit Subnet Route' : 'Add Subnet Route',
            html: `
                <div style="display:grid; gap:14px; color:var(--text);">
                    <div>
                        <label style="display:block; font-size:13px; font-weight:600; margin-bottom:6px; color:var(--text);">Destination Subnet</label>
                        <input id="wr-sr-cidr" class="form-control" value="${route ? escHtml(route.subnet_cidr) : ''}" placeholder="e.g. 10.20.0.0/16 or fc00:abcd::/48" style="padding:10px 12px;" />
                        <small style="color:var(--text-muted); display:block; margin-top:4px;">Remote subnet you want to reach, IPv4 or IPv6 (CIDR). IPv6 requires the IPv6 subnet routing toggle above to be on.</small>
                    </div>
                    <div>
                        <label style="display:block; font-size:13px; font-weight:600; margin-bottom:6px; color:var(--text);">Gateway IP</label>
                        <input id="wr-sr-gateway" class="form-control" value="${route ? escHtml(route.gateway) : ''}" placeholder="e.g. 10.100.10.30" style="padding:10px 12px;" />
                        <small style="color:var(--text-muted); display:block; margin-top:4px;">Next-hop — the WolfNet peer's IPv4 WolfNet IP. Always IPv4, even when the destination subnet is IPv6.</small>
                    </div>
                    <div>
                        <label style="display:block; font-size:13px; font-weight:600; margin-bottom:6px; color:var(--text);">Description</label>
                        <input id="wr-sr-desc" class="form-control" value="${route ? escHtml(route.description) : ''}" placeholder="e.g. WolfNet peer datacenter A" style="padding:10px 12px;" />
                        <small style="color:var(--text-muted); display:block; margin-top:4px;">Optional label for reference</small>
                    </div>
                    <div>
                        <label style="display:block; font-size:13px; font-weight:600; margin-bottom:6px; color:var(--text);">Node Assignment</label>
                        <select id="wr-sr-node" class="form-control" style="padding:10px 12px;">${nodeOptionsHtml}</select>
                        <small style="color:var(--text-muted); display:block; margin-top:4px;">Pick the node that should hold the kernel route. Cluster-wide installs the route on every node.</small>
                    </div>
                </div>
            `,
            buttons: [
                {
                    label: 'Cancel',
                    onclick: (dlg) => dlg.close(),
                },
                {
                    label: routeId ? 'Save Changes' : 'Create Route',
                    onclick: (dlg) => wrSaveSubnetRoute(dlg, routeId),
                },
            ],
        });
    }

    function wrEditSubnetRoute(id) {
        wrShowSubnetRouteEditor(id);
    }

    async function wrSaveSubnetRoute(dlg, routeId) {
        const cidr = (document.getElementById('wr-sr-cidr') || {}).value.trim();
        const gateway = (document.getElementById('wr-sr-gateway') || {}).value.trim();
        const desc = (document.getElementById('wr-sr-desc') || {}).value.trim();
        const node = (document.getElementById('wr-sr-node') || {}).value.trim();

        if (!cidr) {
            alert('Destination subnet is required');
            return;
        }
        if (!gateway) {
            alert('Gateway IP is required');
            return;
        }

        // Preserve the existing enabled state on edit. Hardcoding true meant
        // opening a disabled route and pressing Save silently re-enabled it —
        // including the ones WolfRouter auto-disables (locally-owned subnet,
        // duplicate of an operator route), which would then start failing to
        // apply every tick again. New routes still default to enabled.
        const existing = routeId
            ? (wrState.subnet_routes || []).find(r => r.id === routeId)
            : null;

        const route = {
            id: routeId || '',
            subnet_cidr: cidr,
            gateway: gateway,
            description: desc,
            node_id: node || null,
            enabled: existing ? existing.enabled !== false : true,
        };

        try {
            const method = routeId ? 'PUT' : 'POST';
            const url = routeId
                ? wrUrl('/api/router/subnet-routes/' + encodeURIComponent(routeId))
                : wrUrl('/api/router/subnet-routes');

            const resp = await fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(route),
            });

            const j = await resp.json().catch(() => null);
            if (!resp.ok || (j && j.ok === false)) {
                // Parse the structured error (e.g. the IPv6-disabled
                // rejection) so the operator sees a readable message, not
                // raw JSON.
                const msg = (j && j.error) ? j.error : `HTTP ${resp.status}`;
                alert('Error: ' + msg);
                return;
            }

            dlg.close();
            // Surface a non-fatal apply warning (e.g. IPv6 enabled but the
            // host has v6 disabled) — the route saved but won't pass traffic.
            if (j && j.apply_warning && typeof showToast === 'function') {
                showToast('Saved, but: ' + j.apply_warning, 'warning');
            }
            await wrLoadAll();
        } catch (e) {
            alert('Error: ' + (e.message || e));
        }
    }

    async function wrDeleteSubnetRoute(id) {
        if (!confirm('Delete this subnet route?')) return;

        try {
            const resp = await fetch(wrUrl('/api/router/subnet-routes/' + encodeURIComponent(id)), {
                method: 'DELETE',
            });

            if (!resp.ok) {
                const text = await resp.text();
                alert('Delete failed: ' + text);
                return;
            }

            await wrLoadAll();
        } catch (e) {
            alert('Delete failed: ' + (e.message || e));
        }
    }

    async function wrToggleSubnetRoute(id) {
        const route = (wrState.subnet_routes || []).find(r => r.id === id);
        if (!route) return;
        const updated = { ...route, enabled: !route.enabled };
        try {
            const resp = await fetch(wrUrl('/api/router/subnet-routes/' + encodeURIComponent(id)), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updated),
            });
            if (!resp.ok) {
                const text = await resp.text();
                alert('Toggle failed: ' + text);
                return;
            }
            await wrLoadAll();
        } catch (e) {
            alert('Toggle failed: ' + (e.message || e));
        }
    }

    // ─── Subnet Route Diagnostics ───
    //
    // Sponsor report 2026-04-27: a configured route was reported missing
    // from `ip route` on the targeted VPS. Operator had no way to tell
    // whether the config didn't replicate, the apply silently failed, or
    // the config targets a different node than they expected. Diagnostics
    // calls /api/router/subnet-routes/diagnostics on every cluster node
    // and lays the kernel state side-by-side with the configured intent.

    async function wrRunSubnetRouteDiagnostics() {
        const panel = document.getElementById('wr-subnet-routes-diagnostics');
        if (!panel) return;
        panel.style.display = 'block';
        panel.innerHTML = `
            <div style="padding:14px; background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px; font-size:12px; color:var(--text-muted);">
                Querying every cluster node for kernel routing state…
            </div>
        `;

        // Walk the topology so we cover every node — routes can target
        // any node, not just the one the browser is connected to.
        const topoNodes = (wrState.topology?.nodes || [])
            .filter(n => n && n.node_id);

        // Cross-cluster nodes used as subnet-route targets.
        //
        // Sponsor report 2026-05-27: a VPS that lives in a different
        // cluster (after the WolfNet cluster merge) hosted a working
        // subnet route — confirmed by manual test — but never appeared
        // in the diagnostics rack because `wrState.topology.nodes` is
        // scoped to the cluster being viewed. The route showed up
        // (every local responder has it in its config) but with no
        // row for the VPS, so the operator couldn't tell whether the
        // VPS had installed it or not.
        //
        // Pull /api/nodes (admins see EVERY cluster) and add any node
        // referenced as a route target whose id we don't already have
        // in topology. Each extra node gets queried via the standard
        // wrNodeUrl proxy path — the backend accepts proxy requests
        // for any registered node regardless of cluster scope.
        const knownIds = new Set(topoNodes.map(n => n.node_id));
        const referencedIds = new Set(
            (wrState.subnet_routes || [])
                .filter(r => r && r.enabled && r.node_id)
                .map(r => r.node_id)
        );
        const missingIds = [...referencedIds].filter(id => !knownIds.has(id));
        if (missingIds.length) {
            try {
                const r = await fetch('/api/nodes');
                if (r.ok) {
                    const j = await r.json();
                    const allNodes = (j.nodes || []);
                    for (const id of missingIds) {
                        const n = allNodes.find(x => x.id === id);
                        const label = n
                            ? (n.hostname || n.address || id.slice(0, 8))
                            : id.slice(0, 8);
                        topoNodes.push({
                            node_id: id,
                            node_name: label + ' (other cluster)',
                        });
                    }
                } else {
                    // /api/nodes failed — best-effort: still query the
                    // missing IDs by id alone. wrNodeUrl works on id
                    // and we'll surface "(other cluster)" without a
                    // friendly hostname.
                    for (const id of missingIds) {
                        topoNodes.push({
                            node_id: id,
                            node_name: id.slice(0, 8) + ' (other cluster)',
                        });
                    }
                }
            } catch (e) {
                for (const id of missingIds) {
                    topoNodes.push({
                        node_id: id,
                        node_name: id.slice(0, 8) + ' (other cluster)',
                    });
                }
            }
        }

        if (topoNodes.length === 0) {
            // Fall back to a single self-call when topology hasn't loaded
            // (can happen if preflight failed). Better than no answer.
            topoNodes.push({ node_id: '', node_name: 'this node' });
        }

        const results = await Promise.all(topoNodes.map(async (n) => {
            try {
                // wrNodeUrl picks the local path (current node) or the
                // /api/nodes/<id>/proxy/... wrapper (remote node). We do
                // NOT wrap with wrUrl: the cluster query param is only
                // used by topology/preflight filtering and would just be
                // passed through to a node that knows its own cluster.
                const url = await wrNodeUrl(n.node_id, '/api/router/subnet-routes/diagnostics');
                const r = await fetch(url);
                if (!r.ok) {
                    return { node: n, error: `HTTP ${r.status}: ${(await r.text()).slice(0, 200)}` };
                }
                const j = await r.json();
                return { node: n, data: j };
            } catch (e) {
                return { node: n, error: (e && e.message) || String(e) };
            }
        }));

        wrRenderSubnetRouteDiagnostics(results);
    }

    function wrRenderSubnetRouteDiagnostics(results) {
        const panel = document.getElementById('wr-subnet-routes-diagnostics');
        if (!panel) return;

        // Aggregate every (node, route) pair so we can group by route id
        // and show per-node status side-by-side. A route entry on a node
        // that doesn't host it is informational ("not_targeted_here") but
        // still useful — it confirms the config replicated.
        const routeIndex = new Map(); // route_id -> { config, byNode: Map<node_id, entry> }
        const nodeErrors = []; // { node, error }
        for (const r of results) {
            if (r.error) {
                nodeErrors.push({ node: r.node, error: r.error });
                continue;
            }
            const data = r.data || {};
            const responderId = data.node_id || r.node?.node_id || '(unknown)';
            for (const e of (data.routes || [])) {
                if (!routeIndex.has(e.id)) {
                    routeIndex.set(e.id, {
                        config: {
                            id: e.id,
                            subnet_cidr: e.subnet_cidr,
                            gateway: e.configured_gateway,
                            node_id: e.configured_node_id,
                            enabled: e.enabled,
                            description: e.description,
                        },
                        byNode: new Map(),
                    });
                }
                routeIndex.get(e.id).byNode.set(responderId, {
                    ...e,
                    ip_forward: data.ip_forward,
                });
            }
        }

        const sevColour = {
            ok:                      { bg: 'rgba(34,197,94,0.15)',  fg: '#4ade80', border: 'rgba(34,197,94,0.5)',  label: 'Working' },
            gateway_ok:              { bg: 'rgba(34,197,94,0.15)',  fg: '#4ade80', border: 'rgba(34,197,94,0.5)',  label: 'Working (gateway)' },
            missing:                 { bg: 'rgba(239,68,68,0.15)',  fg: '#fca5a5', border: 'rgba(239,68,68,0.5)',  label: 'Broken — route not in Linux' },
            wrong_gateway:           { bg: 'rgba(234,179,8,0.15)',  fg: '#fde047', border: 'rgba(234,179,8,0.5)',  label: 'Conflict — different route already there' },
            unsupported_form:        { bg: 'rgba(234,179,8,0.15)',  fg: '#fde047', border: 'rgba(234,179,8,0.5)',  label: 'Special route — needs manual fix' },
            gateway_misconfigured:   { bg: 'rgba(239,68,68,0.15)',  fg: '#fca5a5', border: 'rgba(239,68,68,0.5)',  label: 'Gateway plumbing missing' },
            forwarding_misconfigured:{ bg: 'rgba(234,179,8,0.15)',  fg: '#fde047', border: 'rgba(234,179,8,0.5)',  label: 'Half-broken — forwarding missing' },
            kernel_query_failed:     { bg: 'rgba(239,68,68,0.15)',  fg: '#fca5a5', border: 'rgba(239,68,68,0.5)',  label: 'Could not check' },
            disabled:                { bg: 'rgba(148,163,184,0.15)',fg: '#94a3b8', border: 'rgba(148,163,184,0.5)',label: '⊘ Switched off' },
            not_targeted_here:       { bg: 'rgba(148,163,184,0.15)',fg: '#94a3b8', border: 'rgba(148,163,184,0.5)',label: '— Not for this node' },
        };

        // Pre-flight: detect routes whose Node Assignment matches NO node
        // in the cluster. This is the sponsor's actual case (typed a
        // hostname like "klnet-12gb" into a free-text field that wanted
        // a node_id like "ws-1a2b3c4d"). When this happens, every node
        // says "not for this node" — looks deceptively like the route is
        // just configured for a different node, but really it's
        // configured for a node that doesn't exist.
        //
        // klasSponsor 2026-05-13: a node that has just restarted WolfStack
        // briefly disappears from `wrState.topology.nodes` while it
        // re-registers. Routes targeting it would then look orphaned
        // here even though they're perfectly valid. Two extra guards:
        //   1. Only run orphan detection when EVERY topology node
        //      responded to its diagnostics call. If any node failed,
        //      we don't yet know which IDs the cluster actually has.
        //   2. A node ID that we DID receive a diagnostics response from
        //      (via its `node_id` field in the response) is, by
        //      definition, a real node — accept it even if topology
        //      hasn't caught up yet.
        const knownNodeIds = new Set(
            (wrState.topology?.nodes || []).map(n => n.node_id).filter(Boolean)
        );
        // Add every node ID that actually answered diagnostics — covers
        // the restarting-node case where topology lags.
        for (const r of results) {
            if (r.error) continue;
            const responderId = r.data?.node_id;
            if (responderId) knownNodeIds.add(responderId);
        }
        const orphanedRoutes = [];
        const orphanDetectionRan = knownNodeIds.size > 0 && nodeErrors.length === 0;
        if (orphanDetectionRan) {
            for (const r of routeIndex.values()) {
                const c = r.config;
                if (!c.enabled || !c.node_id) continue; // disabled or cluster-wide → can't be orphaned
                if (!knownNodeIds.has(c.node_id)) orphanedRoutes.push(c);
            }
        }

        const parts = [];
        parts.push(`
            <div style="padding:14px; background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
                    <div style="font-weight:600; font-size:13px; color:var(--text);">Subnet route diagnostics</div>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-sm" onclick="wrResyncContainerRoutes(this)" title="Force every node to recompute its /var/run/wolfnet/routes.json from cluster state and reload wolfnetd. Fixes the case where container/VM WolfNet IPs are unreachable from a peer even though wolfnet peers themselves work.">Re-sync container routes</button>
                        <button class="btn btn-sm" onclick="wrRunSubnetRouteDiagnostics()">Re-run</button>
                        <button class="btn btn-sm" onclick="document.getElementById('wr-subnet-routes-diagnostics').style.display='none'">Close</button>
                    </div>
                </div>
                <div style="padding:10px 12px; background:var(--bg); border:1px solid var(--border); border-radius:6px; margin-bottom:10px; font-size:12px; color:var(--text-muted); line-height:1.6;">
                    <strong style="color:var(--text);">What this does:</strong> for every subnet route you've configured, we go to the node that's supposed to host it and look at Linux's actual routing table. Then we tell you whether the route is actually there, and if not, why.
                    <br><br>
                    <strong style="color:var(--text);">How to read it:</strong> each route gets its own block below. Each row inside the block is one node. Look for the "target node" star — that's the node that <em>must</em> have the route installed. If the star says <span style="color:#4ade80;">Working</span> you're good. Anything red or yellow needs your attention; the explanation tells you exactly what to do.
                </div>
        `);

        if (orphanedRoutes.length) {
            parts.push(`
                <div style="margin-bottom:14px; padding:14px; background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.5); border-radius:8px; color:var(--text);">
                    <div style="font-weight:600; font-size:13px; color:#fca5a5; margin-bottom:6px;">Found ${orphanedRoutes.length} route${orphanedRoutes.length === 1 ? '' : 's'} pointing at a node that doesn't exist in this cluster</div>
                    <div style="font-size:12px; color:var(--text-muted); line-height:1.6;">
                        These routes have a Node Assignment that doesn't match any of the <code>ws-…</code> node IDs your cluster knows about. That means <strong>no node ever installs the route</strong> — it just sits in config doing nothing. This usually happens when the route was created with a hostname (e.g. <code>klnet-12gb</code>) typed into the Node Assignment field instead of being picked from the dropdown.
                        <br><br>
                        <strong style="color:var(--text);">Fix:</strong> click Edit on each route below, then pick the right node from the <strong>Node Assignment</strong> dropdown (which now shows the friendly name plus the <code>ws-…</code> ID), then Save.
                    </div>
                    <ul style="margin:10px 0 0; padding-left:20px; font-size:12px; font-family:monospace;">
                        ${orphanedRoutes.map(c => `<li><strong>${escHtml(c.subnet_cidr)} → ${escHtml(c.gateway)}</strong> — assigned to <code>${escHtml(c.node_id)}</code> (no such node)</li>`).join('')}
                    </ul>
                </div>
            `);
        }

        if (nodeErrors.length) {
            parts.push(`
                <div style="margin-bottom:10px; padding:10px 12px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.4); border-radius:6px; font-size:12px; color:#fca5a5;">
                    Could not collect diagnostics from <strong>${nodeErrors.length}</strong> node(s):
                    <ul style="margin:6px 0 0; padding-left:18px;">
                        ${nodeErrors.map(e => `<li><code>${escHtml(e.node?.node_name || e.node?.node_id || 'node')}</code>: ${escHtml(e.error)}</li>`).join('')}
                    </ul>
                </div>
            `);
        }

        // ─── Orphaned KERNEL routes (klas, 2026-05-04) ───
        //
        // Each per-node response carries an `orphans` array — kernel
        // routes via the WolfNet interface that don't match ANY
        // configured route. These are unreachable via the regular
        // route list (the config has nothing to delete) so we render
        // a dedicated section with a one-click "Remove from kernel"
        // action that calls /api/router/subnet-routes/orphan/remove
        // on the originating node.
        const kernelOrphans = []; // { nodeId, nodeName, cidr, gateway, iface, raw }
        for (const r of results) {
            if (r.error) continue;
            const data = r.data || {};
            const responderId = data.node_id || r.node?.node_id || '';
            const responderName = topoNodeName(responderId) || responderId || 'this node';
            for (const o of (data.orphans || [])) {
                kernelOrphans.push({
                    nodeId: responderId,
                    nodeName: responderName,
                    cidr: o.cidr,
                    gateway: o.gateway,
                    iface: o.iface,
                    raw: o.raw,
                });
            }
        }
        if (kernelOrphans.length) {
            parts.push(`
                <div style="margin-bottom:14px; padding:14px; background:rgba(234,179,8,0.10); border:1px solid rgba(234,179,8,0.45); border-radius:8px; color:var(--text);">
                    <div style="font-weight:600; font-size:13px; color:#fde047; margin-bottom:6px;">Found ${kernelOrphans.length} kernel route${kernelOrphans.length === 1 ? '' : 's'} with no matching configuration row</div>
                    <div style="font-size:12px; color:var(--text-muted); line-height:1.6;">
                        These routes go via the WolfNet interface but aren't in WolfStack's subnet-route list. They were likely installed by an older WolfStack version and never cleaned up, or by a manual <code>ip route add</code>. Click <strong>Remove from kernel</strong> to drop the entry — WolfStack will refuse if the kernel's gateway has changed since this scan, so it can't accidentally undo another tool's route.
                    </div>
                    <table style="width:100%; margin-top:10px; border-collapse:collapse; font-size:12px;">
                        <thead>
                            <tr style="text-align:left; color:var(--text-muted); font-size:11px;">
                                <th style="padding:6px 8px; border-bottom:1px solid var(--border);">Node</th>
                                <th style="padding:6px 8px; border-bottom:1px solid var(--border);">Destination</th>
                                <th style="padding:6px 8px; border-bottom:1px solid var(--border);">Gateway</th>
                                <th style="padding:6px 8px; border-bottom:1px solid var(--border);">Interface</th>
                                <th style="padding:6px 8px; border-bottom:1px solid var(--border);"></th>
                            </tr>
                        </thead>
                        <tbody>
                            ${kernelOrphans.map((o, idx) => `
                                <tr>
                                    <td style="padding:6px 8px; border-bottom:1px solid var(--border);">${escHtml(o.nodeName)}</td>
                                    <td style="padding:6px 8px; border-bottom:1px solid var(--border); font-family:monospace;">${escHtml(o.cidr)}</td>
                                    <td style="padding:6px 8px; border-bottom:1px solid var(--border); font-family:monospace;">${escHtml(o.gateway)}</td>
                                    <td style="padding:6px 8px; border-bottom:1px solid var(--border); font-family:monospace;">${escHtml(o.iface || '?')}</td>
                                    <td style="padding:6px 8px; border-bottom:1px solid var(--border);">
                                        <button class="btn btn-sm" data-orphan-idx="${idx}" onclick="wrRemoveOrphanRoute('${escHtml(o.nodeId)}','${escHtml(o.cidr)}','${escHtml(o.gateway)}', this)">Remove from kernel</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `);
        }

        if (routeIndex.size === 0 && nodeErrors.length === 0) {
            parts.push(`<div style="padding:10px 12px; color:var(--text-muted); font-size:12px;">No subnet routes configured.</div>`);
        }

        // Per-route block: configured intent on the left, per-node kernel
        // state on the right. We sort target node first (so the targeted
        // node — where it MUST be in the kernel — leads).
        const routes = Array.from(routeIndex.values()).sort((a, b) =>
            (a.config.subnet_cidr || '').localeCompare(b.config.subnet_cidr || ''));

        const nodeNameById = new Map(
            (wrState.topology?.nodes || []).map(n => [n.node_id, n.node_name || n.node_id])
        );

        for (const r of routes) {
            const c = r.config;
            // Match the global orphan-detection guard above: only call a
            // route "orphaned" when EVERY node responded AND the target
            // ID isn't a node we either know via topology or just got a
            // diagnostics response from. Otherwise routes briefly look
            // orphaned during a restart of the target node.
            const isOrphan = !!c.node_id && orphanDetectionRan && !knownNodeIds.has(c.node_id);
            // Friendly target label: show the node's hostname plus its
            // node_id when we can resolve it; show the cluster-wide
            // marker for cluster-scoped routes; flag orphans loudly so
            // beginners aren't fooled by per-row "Not for this node"
            // messages further down (orphans are NOT fine).
            let targetLabel;
            if (isOrphan) {
                targetLabel = `<code>${escHtml(c.node_id)}</code> — not a real node in this cluster`;
            } else if (c.node_id) {
                const friendly = nodeNameById.get(c.node_id);
                targetLabel = friendly && friendly !== c.node_id
                    ? `<strong>${escHtml(friendly)}</strong> <code style="font-size:10px;">(${escHtml(c.node_id)})</code>`
                    : `<code>${escHtml(c.node_id)}</code>`;
            } else {
                targetLabel = 'Cluster-wide (every node)';
            }
            // The "target" node is the one that MUST hold the kernel
            // entry. For cluster-wide routes, every node is a target.
            // For orphaned routes, no node is a target.
            const isTarget = (nodeId) => !isOrphan && (!c.node_id || c.node_id === nodeId);

            const nodeRows = [];
            const sortedEntries = Array.from(r.byNode.entries()).sort(([a], [b]) => {
                const at = isTarget(a) ? 0 : 1;
                const bt = isTarget(b) ? 0 : 1;
                if (at !== bt) return at - bt;
                return a.localeCompare(b);
            });
            for (const [nodeId, e] of sortedEntries) {
                const sev = sevColour[e.status] || sevColour.unsupported_form;
                const nodeName = (topoNodeName(nodeId)) || nodeId;
                // Gateway nodes deliberately don't install a kernel route
                // for the CIDR they own — they reach it directly via their
                // wolfnet0 interface and forward peer traffic in via
                // iptables. Saying "no entry — kernel does not have this
                // CIDR" on the gateway is misleading; show the gateway
                // role instead so the row reads coherently.
                const kernelLine = e.kernel_present
                    ? `<code style="font-size:11px;">${escHtml((e.kernel_raw || '').trim().split('\n')[0] || '(empty)')}</code>`
                    : (e.is_gateway_here
                        ? '<span style="color:var(--text-muted); font-size:11px;">(gateway role — no kernel route expected; forwarding handled via iptables)</span>'
                        : '<span style="color:var(--text-muted); font-size:11px;">(no entry — kernel does not have this CIDR)</span>');
                const fwd = e.ip_forward;
                const fwdHint = (isTarget(nodeId) && fwd === '0' && e.enabled)
                    ? `<div style="margin-top:6px; font-size:11px; color:#fde047;"><code>net.ipv4.ip_forward = 0</code> on this node — packets that need to traverse this route will be dropped. Enable forwarding with <code>sysctl -w net.ipv4.ip_forward=1</code> and persist via <code>/etc/sysctl.conf</code>.</div>`
                    : '';
                // Surface a re-apply button on rows where the node has a
                // role to play in this route (target/gateway) AND the
                // status is something the operator can plausibly fix
                // with a re-apply. klasSponsor 2026-05-13: "gateway
                // plumbing missing, edit+save does nothing" — silent
                // apply failure inside config_receive. The new POST
                // /api/router/subnet-routes/{id}/reapply endpoint runs
                // synchronously and returns the underlying iptables /
                // sysctl error so the operator can see what broke.
                const repairable = new Set([
                    'gateway_misconfigured',
                    'gateway_no_lan_path',
                    'gateway_egress_unknown',
                    'missing',
                    'wrong_gateway',
                    'unsupported_form',
                    'forwarding_misconfigured',
                    'kernel_query_failed',
                ]);
                const showReapply = e.enabled
                    && (isTarget(nodeId) || e.is_gateway_here)
                    && repairable.has(e.status);
                const reapplyBtn = showReapply
                    ? `<div style="margin-top:6px;"><button class="btn btn-sm" onclick="wrReapplySubnetRoute('${escHtml(nodeId)}','${escHtml(c.id)}', this)">Re-apply on this node</button></div>`
                    : '';
                nodeRows.push(`
                    <tr>
                        <td style="padding:8px; border-bottom:1px solid var(--border); vertical-align:top;">
                            <div style="font-weight:600; font-size:12px;">${escHtml(nodeName)}</div>
                            <div style="font-size:11px; color:var(--text-muted); font-family:monospace;">${escHtml(nodeId)}</div>
                            ${isTarget(nodeId) ? '<div style="font-size:10px; color:var(--success); margin-top:2px;">target node</div>' : ''}
                        </td>
                        <td style="padding:8px; border-bottom:1px solid var(--border); vertical-align:top;">
                            <span style="display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; background:${sev.bg}; color:${sev.fg}; border:1px solid ${sev.border};">${sev.label}</span>
                        </td>
                        <td style="padding:8px; border-bottom:1px solid var(--border); vertical-align:top;">
                            ${kernelLine}
                            <div style="margin-top:4px; font-size:11px; color:var(--text-muted);">${escHtml(e.status_detail || '')}</div>
                            ${fwdHint}
                            ${reapplyBtn}
                        </td>
                    </tr>
                `);
            }

            parts.push(`
                <div style="margin-bottom:14px; border:1px solid var(--border); border-radius:8px; overflow:hidden;">
                    <div style="padding:10px 12px; background:var(--bg);">
                        <div style="font-size:13px; font-weight:600; font-family:monospace;">
                            ${escHtml(c.subnet_cidr)} <span style="color:var(--text-muted);">→</span> ${escHtml(c.gateway)}
                            ${c.enabled ? '' : '<span style="margin-left:8px; padding:1px 6px; background:rgba(148,163,184,0.2); color:#94a3b8; font-size:10px; border-radius:8px; font-family:inherit;">disabled</span>'}
                        </div>
                        <div style="font-size:11px; color:var(--text-muted); margin-top:3px;">
                            Target: ${targetLabel}${c.description ? ' · ' + escHtml(c.description) : ''}
                        </div>
                    </div>
                    <table style="width:100%; border-collapse:collapse; font-size:12px;">
                        <thead>
                            <tr style="background:var(--bg-secondary);">
                                <th style="padding:6px 8px; text-align:left; font-size:11px; color:var(--text-muted); border-bottom:1px solid var(--border);">Node</th>
                                <th style="padding:6px 8px; text-align:left; font-size:11px; color:var(--text-muted); border-bottom:1px solid var(--border);">Status</th>
                                <th style="padding:6px 8px; text-align:left; font-size:11px; color:var(--text-muted); border-bottom:1px solid var(--border);">Kernel state on that node · explanation</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${nodeRows.join('')}
                        </tbody>
                    </table>
                </div>
            `);
        }

        parts.push(`</div>`);
        panel.innerHTML = parts.join('');
    }

    function topoNodeName(nodeId) {
        const n = (wrState.topology?.nodes || []).find(x => x.node_id === nodeId);
        return n ? n.node_name : '';
    }

    /// Remove a kernel route that has no matching configuration row.
    /// Calls /api/router/subnet-routes/orphan/remove on the originating
    /// node (the one whose diagnostics surfaced the orphan). The
    /// backend re-validates the (cidr, gateway) pair against the
    /// kernel and refuses if anything's changed since the operator
    /// clicked, so the worst-case is "Refuse — kernel state changed,
    /// re-run diagnostics".
    async function wrRemoveOrphanRoute(nodeId, cidr, gateway, btn) {
        if (!confirm(`Remove kernel route ${cidr} via ${gateway} from this node?\n\nThis runs \`ip route del ${cidr}\` on the host. WolfStack will refuse if the kernel's gateway has changed since the scan, so it can't accidentally delete a route managed by something else.`)) {
            return;
        }
        if (btn) { btn.disabled = true; btn.textContent = 'Removing…'; }
        try {
            const url = await wrNodeUrl(nodeId, '/api/router/subnet-routes/orphan/remove');
            const resp = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cidr, gateway }),
            });
            const j = await resp.json().catch(() => ({}));
            if (!resp.ok || j.ok === false) {
                if (btn) { btn.disabled = false; btn.textContent = 'Remove from kernel'; }
                alert('Could not remove orphan route:\n\n' + (j.error || `HTTP ${resp.status}`));
                return;
            }
            // Re-run diagnostics so the page reflects post-delete state.
            await wrRunSubnetRouteDiagnostics();
        } catch (e) {
            if (btn) { btn.disabled = false; btn.textContent = 'Remove from kernel'; }
            alert('Could not remove orphan route: ' + ((e && e.message) || String(e)));
        }
    }

    /// Force `apply_subnet_route` to run synchronously for one route on
    /// one specific node and surface the result (success or kernel/
    /// iptables error). Drives the "Re-apply on this node" button shown
    /// on diagnostic rows whose status is something the operator can
    /// plausibly fix that way.
    ///
    /// Sponsor klasSponsor 2026-05-13: gateway diagnostics said "gateway
    /// plumbing missing" and edit+save did nothing — silent apply
    /// failure inside config_receive. This surfaces the underlying
    /// error so the operator can see whether iptables is missing, the
    /// FORWARD chain rejected the rule, etc.
    async function wrReapplySubnetRoute(nodeId, routeId, btn) {
        if (btn) { btn.disabled = true; btn.textContent = 'Re-applying…'; }
        try {
            const url = await wrNodeUrl(nodeId, '/api/router/subnet-routes/' + encodeURIComponent(routeId) + '/reapply');
            const resp = await fetch(url, { method: 'POST' });
            const j = await resp.json().catch(() => ({}));
            if (!resp.ok || j.ok === false) {
                if (btn) { btn.disabled = false; btn.textContent = 'Re-apply on this node'; }
                showToast('Re-apply failed: ' + (j.error || `HTTP ${resp.status}`), 'error');
                return;
            }
            showToast(`Re-applied on ${j.role || 'node'} — re-running diagnostics`, 'success');
            await wrRunSubnetRouteDiagnostics();
        } catch (e) {
            if (btn) { btn.disabled = false; btn.textContent = 'Re-apply on this node'; }
            showToast('Re-apply failed: ' + ((e && e.message) || String(e)), 'error');
        }
    }

    /// Force every cluster node to recompute its `/var/run/wolfnet/routes.json`
    /// from the current cluster state and SIGHUP wolfnetd. Used when
    /// container/VM WolfNet IPs are unreachable from a peer even though
    /// peer-to-peer WolfNet pings work — symptom of a stale or missing
    /// route table on the peer (klasSponsor 2026-05-13).
    ///
    /// Renders a non-blocking result panel above the diagnostics list
    /// rather than calling `alert()` — matches the "visible feedback,
    /// no blocking dialogs" rule the rest of WolfRouter follows.
    async function wrResyncContainerRoutes(btn) {
        if (btn) { btn.disabled = true; btn.textContent = 'Re-syncing…'; }
        const topoNodes = (wrState.topology?.nodes || [])
            .filter(n => n && n.node_id);
        if (topoNodes.length === 0) topoNodes.push({ node_id: '', node_name: 'this node' });
        const results = await Promise.all(topoNodes.map(async (n) => {
            try {
                const url = await wrNodeUrl(n.node_id, '/api/router/wolfnet/routes/resync');
                const r = await fetch(url, { method: 'POST' });
                if (!r.ok) return { node: n, error: `HTTP ${r.status}: ${(await r.text()).slice(0, 200)}` };
                return { node: n, data: await r.json() };
            } catch (e) {
                return { node: n, error: (e && e.message) || String(e) };
            }
        }));
        if (btn) { btn.disabled = false; btn.textContent = 'Re-sync container routes'; }

        const okResults = results.filter(r => !r.error && r.data?.ok);
        const failedResults = results.filter(r => r.error || r.data?.ok === false);
        const heading = `Re-synced container routes on ${okResults.length} of ${results.length} node${results.length === 1 ? '' : 's'}.`;
        const okRows = okResults.map(r => {
            const name = r.node?.node_name || r.data?.node_id || 'node';
            const rc = r.data?.route_count ?? 0;
            const pp = r.data?.polled_peers ?? 0;
            return `<li><code>${escHtml(name)}</code>: ${rc} route${rc === 1 ? '' : 's'} after polling ${pp} peer${pp === 1 ? '' : 's'}</li>`;
        }).join('');
        const failedRows = failedResults.map(r => {
            const name = r.node?.node_name || r.node?.node_id || 'node';
            const msg = r.error || r.data?.error || 'unknown error';
            return `<li><code>${escHtml(name)}</code>: ${escHtml(msg)}</li>`;
        }).join('');

        const panel = document.getElementById('wr-subnet-routes-diagnostics');
        const banner = `
            <div id="wr-resync-result" style="margin-bottom:14px; padding:12px 14px; background:${failedResults.length ? 'rgba(234,179,8,0.10)' : 'rgba(34,197,94,0.10)'}; border:1px solid ${failedResults.length ? 'rgba(234,179,8,0.45)' : 'rgba(34,197,94,0.45)'}; border-radius:8px;">
                <div style="display:flex; justify-content:space-between; gap:8px; align-items:center;">
                    <div style="font-weight:600; font-size:13px; color:var(--text);">${escHtml(heading)}</div>
                    <button class="btn btn-sm" onclick="document.getElementById('wr-resync-result')?.remove()">Dismiss</button>
                </div>
                ${okRows ? `<div style="margin-top:8px; font-size:12px; color:var(--text-muted);">Succeeded:<ul style="margin:4px 0 0; padding-left:20px;">${okRows}</ul></div>` : ''}
                ${failedRows ? `<div style="margin-top:8px; font-size:12px; color:#fca5a5;">Failed:<ul style="margin:4px 0 0; padding-left:20px;">${failedRows}</ul></div>` : ''}
            </div>
        `;
        if (panel) {
            const existing = document.getElementById('wr-resync-result');
            if (existing) existing.remove();
            // Insert just inside the diagnostics container, before the
            // first child block, so the operator sees it immediately
            // without scrolling.
            const inner = panel.firstElementChild;
            if (inner) inner.insertAdjacentHTML('afterbegin', banner);
            else panel.insertAdjacentHTML('afterbegin', banner);
        }

        if (failedResults.length === 0) {
            showToast('Container routes re-synced — wolfnetd reloaded on every node.', 'success');
        } else {
            showToast(`Re-sync had ${failedResults.length} failure${failedResults.length === 1 ? '' : 's'} — see details above.`, 'error');
        }
    }

    // Expose subnet route functions
    window.wrShowSubnetRouteEditor = wrShowSubnetRouteEditor;
    window.wrEditSubnetRoute = wrEditSubnetRoute;
    window.wrDeleteSubnetRoute = wrDeleteSubnetRoute;
    window.wrToggleSubnetRoute = wrToggleSubnetRoute;
    window.wrRunSubnetRouteDiagnostics = wrRunSubnetRouteDiagnostics;
    window.wrSetIpv6SubnetRouting = wrSetIpv6SubnetRouting;
    window.wrRemoveOrphanRoute = wrRemoveOrphanRoute;
    window.wrReapplySubnetRoute = wrReapplySubnetRoute;
    window.wrResyncContainerRoutes = wrResyncContainerRoutes;

    // ─── HTTP (L7) proxies — v23.2 multi-target + edge ─────────────────
    //
    // The list view + editor for the new HTTP proxies tab. Render is
    // driven by `hpState`; every save round-trips through the backend
    // CRUD + apply pipeline, and the response carries any per-target
    // render warnings (e.g. "nginx not installed on node-c") so the
    // operator sees what actually went out to disk.

    let hpState = {
        proxies: [],
        topology: [],        // cluster nodes for the targets picker
        availableCerts: [],  // local-node Let's Encrypt certs (DNS-01 cluster-wide flow lives later)
        cloudProviders: [],  // CloudProvider entries for the Edge dropdown
        dnsProviders: [],    // DnsProvider entries — both Cloudflare and others
        runtime: null,       // detect_runtime() snapshot for the install banner
        editing: null,
        draft: null,
    };

    async function hpLoad() {
        const listEl = document.getElementById('hp-list');
        if (listEl) listEl.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:20px;">Loading…</div>';
        try {
            const [proxiesR, topoR, certsR, runtimeR, cloudR, dnsR] = await Promise.all([
                fetch(wrUrl('/api/router/http-proxies')),
                fetch(wrUrl('/api/router/topology')),
                fetch('/api/configurator/nginx/available-certs'),
                fetch(wrUrl('/api/router/http-proxies/runtime', {local:true})),
                fetch('/api/edge/cloud-providers'),
                fetch('/api/dns-providers'),
            ]);
            hpState.proxies = proxiesR.ok ? await proxiesR.json() : [];
            const topoJson = topoR.ok ? await topoR.json() : {};
            hpState.topology = (topoJson && topoJson.nodes) || [];
            const certsJson = certsR.ok ? await certsR.json() : {};
            hpState.availableCerts = certsJson.certs || [];
            hpState.runtime = runtimeR.ok ? await runtimeR.json() : null;
            const cloudJson = cloudR.ok ? await cloudR.json() : {};
            hpState.cloudProviders = cloudJson.providers || [];
            const dnsJson = dnsR.ok ? await dnsR.json() : {};
            hpState.dnsProviders = dnsJson.providers || [];
            hpRenderRuntimeBanner();
            hpRenderList();
        } catch (e) {
            if (listEl) listEl.innerHTML = '<div style="color:var(--danger);padding:12px;">Load failed: ' + escHtml(e.message) + '</div>';
        }
    }

    function hpRenderRuntimeBanner() {
        const el = document.getElementById('hp-runtime-banner');
        if (!el) return;
        const r = hpState.runtime;
        if (!r) { el.innerHTML = ''; return; }
        if (!r.any_installed) {
            el.innerHTML =
                '<div style="background:rgba(234,179,8,0.10);border:1px solid rgba(234,179,8,0.4);border-radius:8px;padding:12px 14px;margin-bottom:12px;">' +
                    '<div style="font-weight:600;margin-bottom:6px;">No reverse-proxy software installed on this node.</div>' +
                    '<div style="font-size:12px;color:var(--text-secondary);margin-bottom:10px;">' +
                        'Saving an HTTP proxy renders the config to <code>/etc/nginx/conf.d/</code>, but nothing will serve it until you install a reverse proxy. Both choices consume the same files.' +
                    '</div>' +
                    '<button class="btn btn-primary btn-sm" onclick="hpOpenInstallPicker()">Install a reverse proxy…</button>' +
                '</div>';
            return;
        }
        const colour = r.active ? 'rgba(34,197,94,0.10)' : 'rgba(234,179,8,0.10)';
        const border = r.active ? 'rgba(34,197,94,0.4)' : 'rgba(234,179,8,0.4)';
        const statusLine = r.active
            ? 'Active runtime on this node: <strong>' + escHtml(r.active) + '</strong>'
            : 'Installed but not running. Start with <code>sudo systemctl start ' + (r.wolfproxy_installed ? 'wolfproxy' : 'nginx') + '</code>.';
        el.innerHTML =
            '<div style="background:' + colour + ';border:1px solid ' + border + ';border-radius:6px;padding:6px 12px;margin-bottom:12px;font-size:12px;">' +
                statusLine +
            '</div>';
    }

    function hpRenderList() {
        const el = document.getElementById('hp-list');
        if (!el) return;
        if (!hpState.proxies.length) {
            el.innerHTML = '<div style="background:var(--bg-input);border:1px dashed var(--border);border-radius:10px;padding:24px;text-align:center;color:var(--text-muted);font-size:13px;">' +
                'No HTTP proxies yet. Click <strong>+ HTTP proxy</strong> to add one. Tick "Replicate to every node" on the editor for resilient multi-node setups.' +
                '</div>';
            return;
        }
        const nodeName = (id) => {
            const n = hpState.topology.find(t => t.node_id === id);
            return n ? (n.node_name || n.node_id) : id;
        };
        let html = '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:13px;">';
        html += '<thead><tr style="text-align:left;border-bottom:1px solid var(--border);color:var(--text-muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;">' +
            '<th style="padding:8px 12px;">ID</th>' +
            '<th style="padding:8px 12px;">Domains</th>' +
            '<th style="padding:8px 12px;">Targets</th>' +
            '<th style="padding:8px 12px;">Edge</th>' +
            '<th style="padding:8px 12px;">TLS</th>' +
            '<th style="padding:8px 12px;text-align:right;">Actions</th></tr></thead><tbody>';
        hpState.proxies.forEach(p => {
            const targets = (p.targets || []).map(t => {
                const n = nodeName(t.node_id);
                const r = t.runtime && t.runtime.kind !== 'host' ? ' (' + t.runtime.kind + ')' : '';
                return escHtml(n + r);
            }).join(', ') || '— none —';
            const edgeKind = (p.edge && p.edge.kind) || 'local';
            const edgeLabel = edgeKind === 'local' ? 'local (manual DNS)'
                            : edgeKind === 'dns_round_robin' ? 'DNS round-robin'
                            : edgeKind === 'cloudflare_dns' ? 'Cloudflare DNS'
                            : edgeKind === 'hetzner_lb' ? 'Hetzner LB'
                            : edgeKind === 'digitalocean_lb' ? 'DigitalOcean LB'
                            : edgeKind === 'cloudflare_tunnel' ? 'Cloudflare Tunnel'
                            : edgeKind;
            // Tunnel proxies get an extra "Install cloudflared" button
            // — without it the tunnel exists in Cloudflare but no
            // connector is running, so requests would hang at the edge.
            const tunnelInstallBtn = edgeKind === 'cloudflare_tunnel'
                ? '<button class="btn btn-sm" onclick="hpInstallCloudflared(\'' + escHtml(p.id) + '\')" title="Install cloudflared on every target node" style="background:rgba(244,128,32,0.15);border:1px solid rgba(244,128,32,0.5);color:#f48020;">Install cloudflared</button> '
                : '';
            html += '<tr style="border-bottom:1px solid var(--border);">' +
                '<td style="padding:10px 12px;"><strong>' + escHtml(p.id) + '</strong></td>' +
                '<td style="padding:10px 12px;color:var(--text-muted);">' + escHtml((p.server_names || []).join(', ')) + '</td>' +
                '<td style="padding:10px 12px;color:var(--text-muted);">' + targets + '</td>' +
                '<td style="padding:10px 12px;color:var(--text-muted);">' + escHtml(edgeLabel) + '</td>' +
                '<td style="padding:10px 12px;text-align:center;">' + (p.tls ? '✓' : '—') + '</td>' +
                '<td style="padding:10px 12px;text-align:right;">' +
                    tunnelInstallBtn +
                    '<button class="btn btn-sm" onclick="hpOpenEditor(\'' + escHtml(p.id) + '\')">Edit</button> ' +
                    '<button class="btn btn-sm" onclick="hpDelete(\'' + escHtml(p.id) + '\')" style="background:var(--danger);color:#fff;border:1px solid var(--danger);">Delete</button>' +
                '</td></tr>';
        });
        html += '</tbody></table></div>';
        el.innerHTML = html;
    }

    function hpDefaultDraft() {
        // Default: replicate to every wolfstack node visible in
        // topology. Single-host is one click ("uncheck Replicate" or
        // remove targets in the picker).
        const targets = hpState.topology
            .filter(n => n.node_id)
            .map(n => ({ node_id: n.node_id, runtime: { kind: 'host' } }));
        // If we have ≥1 Cloudflare DNS provider, default the Edge
        // strategy to CloudflareDns proxied. Otherwise Local.
        const cfDns = (hpState.dnsProviders || []).find(p => p.plugin === 'cloudflare');
        const edge = cfDns ? { kind: 'cloudflare_dns', dns_provider_id: cfDns.id, ttl_seconds: 60 }
                           : { kind: 'local' };
        return {
            id: '',
            server_names: [],
            enabled: true,
            listen_ports: [],
            targets: targets.length ? targets : [],
            edge: edge,
            upstreams: [],
            lb_strategy: 'round_robin',
            tls: null,
            force_https: false,
            hsts: false,
            http2: false,
            websocket: false,
            upstream_headers: [],
            response_headers: [],
            connect_timeout_s: 0,
            send_timeout_s: 0,
            read_timeout_s: 0,
            error_pages: [],
            access: { rules: [], basic_auth_file: '', basic_auth_realm: '', rate_limit_rps: 0, rate_limit_burst: 0, conn_limit_per_ip: 0, block_threat_intel: false, country_block: [] },
            description: '',
            updated_at: '',
        };
    }

    async function hpOpenEditor(id) {
        await hpLoad();
        if (id) {
            const found = hpState.proxies.find(p => p.id === id);
            if (!found) { alert('Proxy not found'); return; }
            hpState.editing = found;
            hpState.draft = JSON.parse(JSON.stringify(found));
        } else {
            hpState.editing = null;
            hpState.draft = hpDefaultDraft();
        }
        hpRenderEditor();
    }

    function hpCloseEditor() {
        hpState.editing = null;
        hpState.draft = null;
        const m = document.getElementById('hp-editor-mount');
        if (m) m.remove();
    }

    function hpRenderEditor() {
        let mount = document.getElementById('hp-editor-mount');
        if (!mount) {
            mount = document.createElement('div');
            mount.id = 'hp-editor-mount';
            document.body.appendChild(mount);
        }
        const d = hpState.draft;
        if (!d) { mount.innerHTML = ''; return; }

        // Single-form editor (skipping tabs for v23.2 — minimum
        // viable; tabs can come back when there's a real need). Each
        // section is collapsible-looking via h4 headers + spacing.

        const nodeOpts = hpState.topology.map(n =>
            '<label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;padding:4px 0;">' +
                '<input type="checkbox" data-hp-target value="' + escHtml(n.node_id) + '" ' +
                    (d.targets.some(t => t.node_id === n.node_id) ? 'checked' : '') + '> ' +
                '<span>' + escHtml(n.node_name || n.node_id) + ' ' +
                    '<span style="color:var(--text-muted);font-size:11px;">(' + escHtml(n.node_id) + ')</span>' +
                '</span>' +
            '</label>'
        ).join('');

        const certOpts = ['<option value="">— enter paths manually —</option>'].concat(
            hpState.availableCerts.map(c => {
                const tag = c.is_wildcard ? ' (wildcard)' : '';
                return '<option value="' + escHtml(c.cert_path) + '|' + escHtml(c.key_path) + '">' +
                    escHtml(c.name + tag) + '</option>';
            })
        ).join('');

        // Edge strategy options + which provider field(s) to render
        // based on the current draft. Each strategy has its own field
        // shape — DNS strategies want a DNS-provider id; LB/tunnel
        // strategies want a cloud-provider id + an LB/tunnel name.
        const edgeKind = (d.edge && d.edge.kind) || 'local';

        const dnsOptsForPlugin = (plugin) =>
            hpState.dnsProviders.filter(p => p.plugin === plugin).map(p =>
                '<option value="' + escHtml(p.id) + '" ' +
                ((d.edge && d.edge.dns_provider_id === p.id) ? 'selected' : '') + '>' +
                escHtml(p.name) + ' (' + escHtml(plugin) + ')</option>'
            ).join('');
        const dnsOptsForRoundRobin = ['cloudflare','hetzner','digitalocean'].map(plugin =>
            hpState.dnsProviders.filter(p => p.plugin === plugin).map(p =>
                '<option value="' + escHtml(p.id) + '" ' +
                ((d.edge && d.edge.dns_provider_id === p.id) ? 'selected' : '') + '>' +
                escHtml(p.name) + ' (' + escHtml(plugin) + ')</option>'
            ).join('')
        ).join('');
        const cloudOptsForKind = (kind) =>
            hpState.cloudProviders.filter(p => p.kind === kind).map(p =>
                '<option value="' + escHtml(p.id) + '" ' +
                ((d.edge && d.edge.cloud_provider_id === p.id) ? 'selected' : '') + '>' +
                escHtml(p.name) + '</option>'
            ).join('');

        const noProviderWarn = (text) =>
            '<div style="background:rgba(234,179,8,0.10);border:1px solid rgba(234,179,8,0.4);border-radius:6px;padding:8px 12px;font-size:12px;">' +
            text + '</div>';

        const edgeFields = (() => {
            if (edgeKind === 'local') {
                return '<div style="font-size:12px;color:var(--text-muted);">No automation — point DNS at your target nodes manually.</div>';
            }
            if (edgeKind === 'dns_round_robin') {
                if (!dnsOptsForRoundRobin) {
                    return noProviderWarn('No DNS provider configured. Add one (Cloudflare/Hetzner/DigitalOcean) in <a href="#" onclick="selectView(\'settings\'); switchSettingsTab(\'dnsproviders\'); return false;">Settings → DNS Providers</a>.');
                }
                return '<div class="form-group" style="margin-top:8px;"><label>DNS provider</label>' +
                    '<select id="hp-edge-dnspid" class="form-control" style="max-width:380px;">' + dnsOptsForRoundRobin + '</select></div>' +
                    '<div class="form-group" style="margin-top:8px;"><label>TTL (seconds)</label>' +
                    '<input id="hp-edge-ttl" type="number" min="30" class="form-control" style="max-width:140px;" value="' + ((d.edge && d.edge.ttl_seconds) || 60) + '"></div>';
            }
            if (edgeKind === 'cloudflare_dns') {
                const opts = dnsOptsForPlugin('cloudflare');
                if (!opts) return noProviderWarn('No Cloudflare DNS provider configured.');
                return '<div class="form-group" style="margin-top:8px;"><label>Cloudflare DNS provider</label>' +
                    '<select id="hp-edge-dnspid" class="form-control" style="max-width:380px;">' + opts + '</select></div>' +
                    '<div class="form-group" style="margin-top:8px;"><label>TTL (seconds)</label>' +
                    '<input id="hp-edge-ttl" type="number" min="30" class="form-control" style="max-width:140px;" value="' + ((d.edge && d.edge.ttl_seconds) || 60) + '"></div>';
            }
            if (edgeKind === 'hetzner_lb') {
                const opts = cloudOptsForKind('hetzner');
                if (!opts) return noProviderWarn('No Hetzner cloud provider configured. Add one in Settings → Cloud Providers.');
                return '<div class="form-group" style="margin-top:8px;"><label>Hetzner cloud provider</label>' +
                    '<select id="hp-edge-cloudpid" class="form-control" style="max-width:380px;">' + opts + '</select></div>' +
                    '<div class="form-group" style="margin-top:8px;"><label>Load balancer name</label>' +
                    '<input id="hp-edge-lbname" class="form-control" style="max-width:380px;" value="' + escHtml((d.edge && d.edge.lb_name) || 'wolfstack-lb') + '"></div>' +
                    '<div class="form-group" style="margin-top:8px;"><label>Location</label>' +
                    '<select id="hp-edge-location" class="form-control" style="max-width:240px;">' +
                    ['fsn1','nbg1','hel1','ash','hil'].map(l =>
                        '<option value="' + l + '"' + (((d.edge && d.edge.location) || 'fsn1') === l ? ' selected' : '') + '>' + l + '</option>'
                    ).join('') + '</select></div>' +
                    '<div class="form-group" style="margin-top:6px;"><label style="display:flex;gap:8px;align-items:center;cursor:pointer;"><input id="hp-edge-https" type="checkbox" ' + (!(d.edge && d.edge.https_passthrough === false) ? 'checked' : '') + '> <span>HTTPS pass-through (TLS terminates on origin)</span></label></div>';
            }
            if (edgeKind === 'digitalocean_lb') {
                const opts = cloudOptsForKind('digitalocean');
                if (!opts) return noProviderWarn('No DigitalOcean cloud provider configured. Add one in Settings → Cloud Providers.');
                return '<div class="form-group" style="margin-top:8px;"><label>DigitalOcean cloud provider</label>' +
                    '<select id="hp-edge-cloudpid" class="form-control" style="max-width:380px;">' + opts + '</select></div>' +
                    '<div class="form-group" style="margin-top:8px;"><label>Load balancer name</label>' +
                    '<input id="hp-edge-lbname" class="form-control" style="max-width:380px;" value="' + escHtml((d.edge && d.edge.lb_name) || 'wolfstack-lb') + '"></div>' +
                    '<div class="form-group" style="margin-top:8px;"><label>Region</label>' +
                    '<select id="hp-edge-region" class="form-control" style="max-width:240px;">' +
                    ['nyc1','nyc3','sfo3','ams3','sgp1','lon1','fra1','tor1','blr1','syd1'].map(r =>
                        '<option value="' + r + '"' + (((d.edge && d.edge.region) || 'nyc3') === r ? ' selected' : '') + '>' + r + '</option>'
                    ).join('') + '</select></div>' +
                    '<div class="form-group" style="margin-top:6px;"><label style="display:flex;gap:8px;align-items:center;cursor:pointer;"><input id="hp-edge-https" type="checkbox" ' + (!(d.edge && d.edge.https_passthrough === false) ? 'checked' : '') + '> <span>HTTPS pass-through</span></label></div>' +
                    '<div style="font-size:11px;color:var(--text-muted);margin-top:6px;">Note: DigitalOcean LBs target droplets only. Each WolfStack node must be a droplet in this DO account or it can\'t be added.</div>';
            }
            if (edgeKind === 'cloudflare_tunnel') {
                const cloudOpts = cloudOptsForKind('cloudflare');
                const dnsOpts = dnsOptsForPlugin('cloudflare');
                if (!cloudOpts) return noProviderWarn('No Cloudflare cloud provider configured. Add one (account_id + tunnel API token) in Settings → Cloud Providers.');
                if (!dnsOpts) return noProviderWarn('No Cloudflare DNS provider configured for the CNAME.');
                return '<div class="form-group" style="margin-top:8px;"><label>Cloudflare cloud provider</label>' +
                    '<select id="hp-edge-cloudpid" class="form-control" style="max-width:380px;">' + cloudOpts + '</select></div>' +
                    '<div class="form-group" style="margin-top:8px;"><label>Cloudflare DNS provider (for the CNAME)</label>' +
                    '<select id="hp-edge-dnspid" class="form-control" style="max-width:380px;">' + dnsOpts + '</select></div>' +
                    '<div class="form-group" style="margin-top:8px;"><label>Tunnel name</label>' +
                    '<input id="hp-edge-tunnel" class="form-control" style="max-width:380px;" value="' + escHtml((d.edge && d.edge.tunnel_name) || 'wolfstack-tunnel') + '"></div>' +
                    '<div style="font-size:11px;color:var(--text-muted);margin-top:6px;">After saving, install <code>cloudflared</code> on each target node using the connector token (returned by the tunnel API).</div>';
            }
            return '';
        })();

        mount.innerHTML =
            '<div style="position:fixed;top:0;right:0;bottom:0;width:min(820px,100vw);background:var(--bg-card,#1e2028);border-left:1px solid var(--border);z-index:10000;display:flex;flex-direction:column;box-shadow:-8px 0 24px rgba(0,0,0,0.3);">' +
                '<div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">' +
                    '<h3 style="margin:0;font-size:16px;">' + escHtml(hpState.editing ? 'Edit HTTP proxy: ' + d.id : 'New HTTP proxy') + '</h3>' +
                    '<button class="btn btn-sm" onclick="hpCloseEditor()">Close</button>' +
                '</div>' +
                '<div style="flex:1;overflow:auto;padding:20px;">' +

                  '<h4 style="margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);">General</h4>' +
                  '<div class="form-group"><label>ID</label>' +
                  '<input id="hp-id" class="form-control" value="' + escHtml(d.id || '') + '" placeholder="mysite" ' + (hpState.editing ? 'readonly style="opacity:0.6;"' : '') + '>' +
                  '<small style="color:var(--text-muted);">Used as the nginx config filename. Lowercase a-z, 0-9, dot, dash, underscore. Cannot be renamed.</small></div>' +
                  '<div class="form-group" style="margin-top:10px;"><label>Server names</label>' +
                  '<input id="hp-snames" class="form-control" value="' + escHtml((d.server_names || []).join(' ')) + '" placeholder="app.example.com www.app.example.com">' +
                  '<small style="color:var(--text-muted);">Space or comma separated. First is canonical for redirect.</small></div>' +
                  '<div class="form-group" style="margin-top:10px;"><label style="display:flex;gap:8px;align-items:center;cursor:pointer;"><input id="hp-enabled" type="checkbox" ' + (d.enabled !== false ? 'checked' : '') + '> <span>Enabled</span></label></div>' +

                  '<h4 style="margin:20px 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);">Targets (where it runs)</h4>' +
                  '<div style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px 14px;max-width:560px;">' + (nodeOpts || '<div style="color:var(--text-muted);font-size:12px;">No nodes visible in topology.</div>') + '</div>' +
                  '<small style="color:var(--text-muted);">Pick one for single-node, or multiple to replicate across the cluster for HA. Each picked node renders identical nginx config. v23.2 supports Host runtime only — Docker/LXC per target coming in v23.3.</small>' +

                  '<h4 style="margin:20px 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);">Edge (public ingress)</h4>' +
                  '<div class="form-group"><label>Resilience strategy</label>' +
                  '<select id="hp-edge-kind" class="form-control" style="max-width:380px;" onchange="hpOnEdgeKindChange()">' +
                    '<option value="local"' + (edgeKind === 'local' ? ' selected' : '') + '>Local — operator manages DNS</option>' +
                    '<option value="dns_round_robin"' + (edgeKind === 'dns_round_robin' ? ' selected' : '') + '>DNS round-robin (Cloudflare / Hetzner / DigitalOcean)</option>' +
                    '<option value="cloudflare_dns"' + (edgeKind === 'cloudflare_dns' ? ' selected' : '') + '>Cloudflare DNS (orange cloud) — recommended, free</option>' +
                    '<option value="hetzner_lb"' + (edgeKind === 'hetzner_lb' ? ' selected' : '') + '>Hetzner Cloud Load Balancer (~€5/mo)</option>' +
                    '<option value="digitalocean_lb"' + (edgeKind === 'digitalocean_lb' ? ' selected' : '') + '>DigitalOcean Load Balancer (droplets only)</option>' +
                    '<option value="cloudflare_tunnel"' + (edgeKind === 'cloudflare_tunnel' ? ' selected' : '') + '>Cloudflare Tunnel — CGNAT-friendly, no public IP needed</option>' +
                  '</select></div>' +
                  edgeFields +

                  '<h4 style="margin:20px 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);">Backends</h4>' +
                  '<div id="hp-upstreams">' + hpUpstreamsHtml(d.upstreams || []) + '</div>' +
                  '<button class="btn btn-sm" onclick="hpAddUpstream()" style="margin-top:6px;">+ Backend</button>' +
                  '<div class="form-group" style="margin-top:10px;"><label>Load balancing</label>' +
                  '<select id="hp-lb" class="form-control" style="max-width:240px;">' +
                    '<option value="round_robin"' + (d.lb_strategy === 'round_robin' ? ' selected' : '') + '>Round robin</option>' +
                    '<option value="least_conn"' + (d.lb_strategy === 'least_conn' ? ' selected' : '') + '>Least connections</option>' +
                    '<option value="ip_hash"' + (d.lb_strategy === 'ip_hash' ? ' selected' : '') + '>IP hash (sticky)</option>' +
                  '</select></div>' +
                  '<div class="form-group" style="margin-top:6px;"><label style="display:flex;gap:8px;align-items:center;cursor:pointer;"><input id="hp-ws" type="checkbox" ' + (d.websocket ? 'checked' : '') + '> <span>WebSocket support</span></label></div>' +

                  '<h4 style="margin:20px 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);">TLS</h4>' +
                  '<div class="form-group"><label>Cert dropdown</label>' +
                  '<select id="hp-cert-picker" class="form-control" onchange="hpApplyCertPick()" style="max-width:380px;">' + certOpts + '</select>' +
                  '<small style="color:var(--text-muted);">Local-node certs only — cluster-wide cert distribution lands in v23.2.x.</small></div>' +
                  '<div class="form-group" style="margin-top:8px;"><button class="btn btn-sm" type="button" onclick="hpRequestCert()" title="Issue a free certificate for the domains above and wire it into this site"><span class="ws-icon-clean-wrap" data-icon="lock"></span> Get HTTPS certificate</button> <small style="color:var(--text-muted);">Issues a Let&rsquo;s Encrypt certificate for the domains above and fills these paths in. Save the site first.</small></div>' +
                  '<div class="form-group" style="margin-top:8px;"><label>Cert path</label>' +
                  '<input id="hp-tls-cert" class="form-control" value="' + escHtml((d.tls && d.tls.cert_path) || '') + '" placeholder="/etc/letsencrypt/live/zone/fullchain.pem"></div>' +
                  '<div class="form-group" style="margin-top:8px;"><label>Key path</label>' +
                  '<input id="hp-tls-key" class="form-control" value="' + escHtml((d.tls && d.tls.key_path) || '') + '" placeholder="/etc/letsencrypt/live/zone/privkey.pem">' +
                  '<small style="color:var(--text-muted);">Both blank = HTTP only. With Cloudflare orange-cloud, origin certs can be self-signed.</small></div>' +
                  '<div class="form-group" style="margin-top:8px;"><label style="display:flex;gap:8px;align-items:center;cursor:pointer;"><input id="hp-force-https" type="checkbox" ' + (d.force_https ? 'checked' : '') + '> <span>Force HTTPS (301 from :80)</span></label></div>' +
                  '<div class="form-group" style="margin-top:6px;"><label style="display:flex;gap:8px;align-items:center;cursor:pointer;"><input id="hp-hsts" type="checkbox" ' + (d.hsts ? 'checked' : '') + '> <span>HSTS</span></label></div>' +
                  '<div class="form-group" style="margin-top:6px;"><label style="display:flex;gap:8px;align-items:center;cursor:pointer;"><input id="hp-http2" type="checkbox" ' + (d.http2 ? 'checked' : '') + '> <span>HTTP/2</span></label></div>' +

                '</div>' +
                '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px;">' +
                    '<button class="btn" onclick="hpCloseEditor()">Cancel</button>' +
                    '<button class="btn btn-primary" onclick="hpSaveDraft()">Save &amp; apply</button>' +
                '</div>' +
            '</div>';
    }

    function hpUpstreamsHtml(ups) {
        if (!ups || !ups.length) {
            return hpUpstreamRowHtml({ url: '', weight: 1, max_conns: 0 });
        }
        return ups.map(hpUpstreamRowHtml).join('');
    }
    function hpUpstreamRowHtml(u) {
        return '<div data-hp-upstream style="display:grid;grid-template-columns:1fr 80px 100px auto;gap:8px;margin-bottom:6px;align-items:center;">' +
            '<input data-hp-up-url class="form-control" value="' + escHtml(u.url || '') + '" placeholder="http://10.0.0.5:3000">' +
            '<input data-hp-up-weight type="number" min="1" class="form-control" value="' + (u.weight || 1) + '" title="Weight">' +
            '<input data-hp-up-maxconns type="number" min="0" class="form-control" value="' + (u.max_conns || 0) + '" title="Max conns">' +
            '<button class="btn btn-sm" onclick="this.parentElement.remove()" style="background:var(--danger);color:#fff;border:1px solid var(--danger);">−</button>' +
            '</div>';
    }
    function hpAddUpstream() {
        const c = document.getElementById('hp-upstreams');
        if (c) c.insertAdjacentHTML('beforeend', hpUpstreamRowHtml({ url: '', weight: 1, max_conns: 0 }));
    }
    // Edge-strategy dropdown changed — reset d.edge to a sensible
    // default for the new kind so stale fields from the previous
    // strategy don't bleed through, then re-render so the per-strategy
    // fields appear. Doesn't read the rest of the form first — the user
    // can change kind back-and-forth without losing their server_names,
    // targets, etc. (those live elsewhere in the DOM).
    function hpOnEdgeKindChange() {
        const e = document.getElementById('hp-edge-kind');
        if (!e || !hpState.draft) return;
        const k = e.value;
        if (k === 'local') {
            hpState.draft.edge = { kind: 'local' };
        } else if (k === 'dns_round_robin' || k === 'cloudflare_dns') {
            const wantPlugin = k === 'cloudflare_dns' ? 'cloudflare' : null;
            const dp = (hpState.dnsProviders || []).find(p => !wantPlugin || p.plugin === wantPlugin);
            hpState.draft.edge = { kind: k, dns_provider_id: dp ? dp.id : '', ttl_seconds: 60 };
        } else if (k === 'hetzner_lb') {
            const cp = (hpState.cloudProviders || []).find(p => p.kind === 'hetzner');
            hpState.draft.edge = { kind: 'hetzner_lb', cloud_provider_id: cp ? cp.id : '', lb_name: 'wolfstack-lb', location: 'fsn1', https_passthrough: true };
        } else if (k === 'digitalocean_lb') {
            const cp = (hpState.cloudProviders || []).find(p => p.kind === 'digitalocean');
            hpState.draft.edge = { kind: 'digitalocean_lb', cloud_provider_id: cp ? cp.id : '', lb_name: 'wolfstack-lb', region: 'nyc3', https_passthrough: true };
        } else if (k === 'cloudflare_tunnel') {
            const cp = (hpState.cloudProviders || []).find(p => p.kind === 'cloudflare');
            const dp = (hpState.dnsProviders || []).find(p => p.plugin === 'cloudflare');
            hpState.draft.edge = { kind: 'cloudflare_tunnel', cloud_provider_id: cp ? cp.id : '', dns_provider_id: dp ? dp.id : '', tunnel_name: 'wolfstack-tunnel' };
        }
        hpRenderEditor();
    }
    window.hpOnEdgeKindChange = hpOnEdgeKindChange;
    function hpApplyCertPick() {
        const sel = document.getElementById('hp-cert-picker');
        if (!sel || !sel.value) return;
        const parts = sel.value.split('|');
        if (parts.length >= 2) {
            const ce = document.getElementById('hp-tls-cert');
            const ke = document.getElementById('hp-tls-key');
            if (ce) ce.value = parts[0];
            if (ke) ke.value = parts[1];
        }
    }

    function hpReadDraftFromForm() {
        const d = hpState.draft;
        if (!d) return;
        const gv = (id) => { const e = document.getElementById(id); return e ? e.value : null; };
        const gc = (id) => { const e = document.getElementById(id); return e ? !!e.checked : null; };

        if (gv('hp-id') !== null && !hpState.editing) d.id = gv('hp-id').trim();
        if (gv('hp-snames') !== null) d.server_names = gv('hp-snames').split(/[\s,]+/).filter(Boolean);
        if (gc('hp-enabled') !== null) d.enabled = gc('hp-enabled');

        // Targets — picked from checkboxes. Runtime is Host for v23.2.
        const checks = document.querySelectorAll('[data-hp-target]:checked');
        if (checks.length || document.querySelectorAll('[data-hp-target]').length) {
            d.targets = Array.from(checks).map(c => ({
                node_id: c.value,
                runtime: { kind: 'host' },
            }));
        }

        // Edge.
        const ek = gv('hp-edge-kind') || 'local';
        if (ek === 'local') {
            d.edge = { kind: 'local' };
        } else if (ek === 'dns_round_robin' || ek === 'cloudflare_dns') {
            const pid = gv('hp-edge-dnspid') || '';
            const ttl = parseInt(gv('hp-edge-ttl') || '60', 10) || 60;
            d.edge = { kind: ek, dns_provider_id: pid, ttl_seconds: ttl };
        } else if (ek === 'hetzner_lb') {
            d.edge = {
                kind: 'hetzner_lb',
                cloud_provider_id: gv('hp-edge-cloudpid') || '',
                lb_name: (gv('hp-edge-lbname') || 'wolfstack-lb').trim(),
                location: gv('hp-edge-location') || 'fsn1',
                https_passthrough: gc('hp-edge-https') !== false,
            };
        } else if (ek === 'digitalocean_lb') {
            d.edge = {
                kind: 'digitalocean_lb',
                cloud_provider_id: gv('hp-edge-cloudpid') || '',
                lb_name: (gv('hp-edge-lbname') || 'wolfstack-lb').trim(),
                region: gv('hp-edge-region') || 'nyc3',
                https_passthrough: gc('hp-edge-https') !== false,
            };
        } else if (ek === 'cloudflare_tunnel') {
            d.edge = {
                kind: 'cloudflare_tunnel',
                cloud_provider_id: gv('hp-edge-cloudpid') || '',
                dns_provider_id: gv('hp-edge-dnspid') || '',
                tunnel_name: (gv('hp-edge-tunnel') || 'wolfstack-tunnel').trim(),
            };
        }

        // Upstreams.
        const upRows = document.querySelectorAll('[data-hp-upstream]');
        if (upRows.length) {
            d.upstreams = [];
            upRows.forEach(r => {
                const u = r.querySelector('[data-hp-up-url]');
                const w = r.querySelector('[data-hp-up-weight]');
                const m = r.querySelector('[data-hp-up-maxconns]');
                if (u && u.value.trim()) {
                    d.upstreams.push({
                        url: u.value.trim(),
                        weight: parseInt((w && w.value) || '1', 10) || 1,
                        max_conns: parseInt((m && m.value) || '0', 10) || 0,
                    });
                }
            });
        }
        if (gv('hp-lb')) d.lb_strategy = gv('hp-lb');
        if (gc('hp-ws') !== null) d.websocket = gc('hp-ws');

        // TLS.
        const cert = gv('hp-tls-cert');
        const key = gv('hp-tls-key');
        if (cert !== null && key !== null) {
            if (cert.trim() && key.trim()) {
                d.tls = { cert_path: cert.trim(), key_path: key.trim(), cert_name: d.tls ? (d.tls.cert_name || '') : '' };
            } else {
                d.tls = null;
            }
        }
        if (gc('hp-force-https') !== null) d.force_https = gc('hp-force-https');
        if (gc('hp-hsts') !== null) d.hsts = gc('hp-hsts');
        if (gc('hp-http2') !== null) d.http2 = gc('hp-http2');
    }

    async function hpSaveDraft() {
        hpReadDraftFromForm();
        const d = hpState.draft;
        if (!d) return;
        if (!d.id) { alert('ID is required'); return; }
        if (!d.server_names || !d.server_names.length) { alert('At least one server name'); return; }
        if (!d.targets || !d.targets.length) { alert('Pick at least one target node'); return; }
        const isEdit = !!hpState.editing;
        const url = isEdit
            ? wrUrl('/api/router/http-proxies/' + encodeURIComponent(d.id))
            : wrUrl('/api/router/http-proxies');
        try {
            const resp = await fetch(url, {
                method: isEdit ? 'PUT' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(d),
            });
            const data = await resp.json().catch(() => ({}));
            if (resp.ok) {
                if (typeof showToast === 'function') {
                    showToast('Saved & applied' + ((data.apply_warnings || []).length ? ' (with warnings)' : ''), 'success');
                }
                if ((data.apply_warnings || []).length) {
                    // Show warnings in an alert so the operator can't
                    // miss them — covers things like "nginx not
                    // installed on node-c".
                    alert('Apply warnings:\n\n' + data.apply_warnings.join('\n'));
                }
                hpCloseEditor();
                hpLoad();
            } else {
                alert('Save failed: ' + (data.error || ('HTTP ' + resp.status)));
            }
        } catch (e) {
            alert('Save failed: ' + e.message);
        }
    }

    // Issue a Let's Encrypt cert for the site being edited and wire it in.
    // Requires the proxy to be saved first (the backend works by id).
    async function hpRequestCert() {
        hpReadDraftFromForm();
        const d = hpState.draft;
        if (!d) return;
        if (!hpState.editing) {
            if (typeof showToast === 'function') showToast('Save the site first, then click Get HTTPS certificate.', 'warning');
            else alert('Save the site first, then request a certificate.');
            return;
        }
        if (!d.server_names || !d.server_names.length) {
            if (typeof showToast === 'function') showToast('Add at least one domain (server name) first.', 'warning');
            return;
        }
        // Use DNS-01 automatically when this proxy's edge already carries a DNS
        // provider (works behind a firewall / for wildcards); else HTTP-01.
        let dnsPid = '';
        try {
            const e = d.edge || {};
            dnsPid = e.dns_provider_id
                || (e.CloudflareDns && e.CloudflareDns.dns_provider_id)
                || (e.DnsRoundRobin && e.DnsRoundRobin.dns_provider_id) || '';
        } catch (_) {}
        const how = dnsPid ? 'DNS-01 (via the configured DNS provider)' : 'HTTP-01 (port 80 must be reachable for these domains)';
        if (!confirm('Request a Let’s Encrypt certificate for:\n\n' + d.server_names.join('\n') + '\n\nChallenge: ' + how + '\n\nThis takes about a minute.')) return;
        const btn = document.querySelector('button[onclick="hpRequestCert()"]');
        const prev = btn ? btn.innerHTML : '';
        if (btn) { btn.disabled = true; btn.textContent = 'Requesting certificate…'; }
        try {
            const resp = await fetch(wrUrl('/api/router/http-proxies/' + encodeURIComponent(d.id) + '/certificate'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: '', challenge: 'webroot', dns_provider_id: dnsPid }),
            });
            const data = await resp.json().catch(() => ({}));
            if (resp.ok) {
                if (typeof showToast === 'function') showToast('Certificate issued & applied: ' + (data.cert_name || ''), 'success');
                // Surface any nginx-apply warnings so a half-applied cert isn't silent.
                if (data.apply_warnings && data.apply_warnings.length) {
                    alert('Certificate issued, but applying the nginx config produced warnings:\n\n' + data.apply_warnings.join('\n'));
                }
                hpCloseEditor();
                hpLoad();
            } else {
                const emailHint = (data.error && /email/i.test(data.error)) ? '\n\nTip: set a Let’s Encrypt email on the Certificates page first.' : '';
                alert('Certificate request failed:\n\n' + (data.error || ('HTTP ' + resp.status)) + emailHint);
                if (btn) { btn.disabled = false; btn.innerHTML = prev; }
            }
        } catch (e) {
            alert('Certificate request failed: ' + e.message);
            if (btn) { btn.disabled = false; btn.innerHTML = prev; }
        }
    }

    async function hpDelete(id) {
        if (!confirm('Delete HTTP proxy "' + id + '"?\n\nThe nginx config on every target node will be removed and the runtime reloaded. If the proxy uses a Hetzner/DigitalOcean Load Balancer or a Cloudflare Tunnel, those cloud resources will also be torn down.')) return;
        try {
            const resp = await fetch(wrUrl('/api/router/http-proxies/' + encodeURIComponent(id)), { method: 'DELETE' });
            const data = await resp.json().catch(() => ({}));
            if (resp.ok) {
                if (typeof showToast === 'function') showToast('Deleted & applied', 'success');
                if (data.apply_warnings && data.apply_warnings.length) {
                    // Surface any teardown warnings so the operator knows
                    // exactly what (if anything) was left dangling.
                    alert('Deleted, but with warnings:\n\n' + data.apply_warnings.join('\n'));
                }
                hpLoad();
            } else {
                alert('Delete failed: ' + (data.error || ('HTTP ' + resp.status)));
            }
        } catch (e) {
            alert('Delete failed: ' + e.message);
        }
    }

    // Fan out cloudflared install across every Host target of a tunnel
    // proxy. Each per-node install routes through the cluster proxy so
    // the master node makes one API call per target and serialises
    // the transcripts back to the operator.
    async function hpInstallCloudflared(proxyId) {
        const proxy = hpState.proxies.find(p => p.id === proxyId);
        if (!proxy) { alert('Proxy not found'); return; }
        if (!proxy.edge || proxy.edge.kind !== 'cloudflare_tunnel') {
            alert('Proxy is not a Cloudflare Tunnel.'); return;
        }
        const hostTargets = (proxy.targets || []).filter(t => !t.runtime || t.runtime.kind === 'host');
        if (!hostTargets.length) {
            alert('No Host-runtime targets — cloudflared install is host-level only for v23.2.');
            return;
        }
        // Identify self via the global `allNodes` array (every node row
        // has an `is_self` flag set by the master). Falls back to null
        // — in that case every target goes through the cluster proxy
        // (the master will 400 on self, so we always have at least one
        // route that works).
        const selfNode = (typeof allNodes !== 'undefined' && allNodes)
            ? allNodes.find(n => n.is_self) : null;
        const selfId = selfNode ? selfNode.id : null;
        const lines = ['Installing cloudflared on ' + hostTargets.length + ' node(s)…\n'];
        if (typeof showToast === 'function') showToast('Installing cloudflared on ' + hostTargets.length + ' node(s)…', 'info');
        for (const t of hostTargets) {
            // For the local node hit the endpoint directly; remote nodes
            // go through the cluster proxy.
            const isSelf = selfId && t.node_id === selfId;
            // node_proxy re-prepends /api/ to the captured path —
            // drop the leading /api/ when going via the cluster proxy.
            const url = isSelf
                ? '/api/edge/cloudflare-tunnel/install/' + encodeURIComponent(proxyId)
                : '/api/nodes/' + encodeURIComponent(t.node_id) + '/proxy/edge/cloudflare-tunnel/install/' + encodeURIComponent(proxyId);
            try {
                const resp = await fetch(url, { method: 'POST' });
                const data = await resp.json().catch(() => ({}));
                if (resp.ok) {
                    lines.push('✓ ' + t.node_id + ': ok');
                } else {
                    lines.push('✕ ' + t.node_id + ': ' + (data.error || ('HTTP ' + resp.status)));
                }
            } catch (e) {
                lines.push('✕ ' + t.node_id + ': ' + e.message);
            }
        }
        alert(lines.join('\n'));
    }
    window.hpInstallCloudflared = hpInstallCloudflared;

    // ─── Install picker ───────────────────────────────────────────────
    //
    // Styled modal — replaces the v23.1 browser confirm/alert pair.
    // Offers WolfProxy + nginx side-by-side; install runs synchronously
    // and the live stdout/stderr lands in the modal so the operator
    // sees what package manager actually said.

    function hpOpenInstallPicker() {
        const existing = document.getElementById('hp-install-picker');
        if (existing) existing.remove();
        const overlay = document.createElement('div');
        overlay.id = 'hp-install-picker';
        overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:100000;display:flex;align-items:center;justify-content:center;padding:20px;';
        const modal = document.createElement('div');
        modal.style.cssText = 'background:var(--bg-card,#1e2028);border:1px solid var(--border);border-radius:12px;padding:24px;max-width:760px;width:100%;max-height:90vh;overflow:auto;box-shadow:0 20px 60px rgba(0,0,0,0.5);';
        modal.innerHTML =
            '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:6px;">' +
                '<h3 style="margin:0;font-size:18px;">Install a reverse proxy</h3>' +
                '<button class="btn btn-sm" onclick="hpCloseInstallPicker()">Close</button>' +
            '</div>' +
            '<p style="font-size:13px;color:var(--text-muted);margin:0 0 16px;">Both consume identical nginx-format configs — pick on operational grounds.</p>' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">' +
                hpInstallCard({ which: 'wolfproxy', name: 'WolfProxy', tagline: 'IntelligentWolf\'s Rust-based reverse proxy.',
                    bullets: ['Drop-in nginx replacement.', 'Built-in TLS-abuse firewall.', 'Monitoring dashboard on :5001.'],
                    install_note: 'Downloads precompiled binary from github.com/intelligentwolf/wolfproxy.' }) +
                hpInstallCard({ which: 'nginx', name: 'nginx', tagline: 'The reference reverse proxy.',
                    bullets: ['Industry-standard, well-documented.', 'From your distro\'s package manager.', 'Mature ecosystem.'],
                    install_note: 'Installs via apt / dnf / pacman / zypper.' }) +
            '</div>' +
            '<div id="hp-install-output" style="display:none;margin-top:18px;"></div>';
        overlay.appendChild(modal);
        overlay.onclick = (e) => { if (e.target === overlay) hpCloseInstallPicker(); };
        document.body.appendChild(overlay);
    }
    function hpInstallCard(c) {
        const bullets = c.bullets.map(b => '<li>' + escHtml(b) + '</li>').join('');
        return '<div data-hp-install-card="' + escHtml(c.which) + '" style="background:var(--bg-input);border:1px solid var(--border);border-radius:10px;padding:16px;display:flex;flex-direction:column;">' +
            '<div style="font-weight:600;font-size:15px;margin-bottom:4px;">' + escHtml(c.name) + '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-bottom:10px;">' + escHtml(c.tagline) + '</div>' +
            '<ul style="font-size:12px;color:var(--text-secondary);margin:0 0 12px 18px;padding:0;line-height:1.6;">' + bullets + '</ul>' +
            '<div style="font-size:11px;color:var(--text-muted);margin-bottom:12px;flex:1;">' + escHtml(c.install_note) + '</div>' +
            '<button class="btn btn-primary btn-sm" onclick="hpInstallRuntime(\'' + escHtml(c.which) + '\', this)">Install ' + escHtml(c.name) + '</button>' +
        '</div>';
    }
    function hpCloseInstallPicker() {
        const m = document.getElementById('hp-install-picker');
        if (m) m.remove();
    }
    async function hpInstallRuntime(which, btn) {
        document.querySelectorAll('[data-hp-install-card] button').forEach(b => { b.disabled = true; });
        const origText = btn ? btn.textContent : '';
        if (btn) btn.textContent = 'Installing… (a few minutes)';
        const out = document.getElementById('hp-install-output');
        if (out) {
            out.style.display = 'block';
            out.innerHTML = '<div style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px 12px;font-size:12px;color:var(--text-muted);">Running install for <code>' + escHtml(which) + '</code>…</div>';
        }
        try {
            const resp = await fetch(wrUrl('/api/router/http-proxies/install/' + encodeURIComponent(which), {local:true}), { method: 'POST' });
            const data = await resp.json().catch(() => ({}));
            if (resp.ok && data.ok) {
                if (out) out.innerHTML =
                    '<div style="background:rgba(34,197,94,0.10);border:1px solid rgba(34,197,94,0.4);border-radius:6px;padding:10px 12px;font-size:12px;margin-bottom:8px;">✓ ' + escHtml(which) + ' installed.</div>' +
                    '<pre style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:monospace;font-size:11px;white-space:pre-wrap;max-height:240px;overflow:auto;margin:0;">' + escHtml(data.log || '(no log)') + '</pre>' +
                    '<div style="margin-top:10px;"><button class="btn btn-primary btn-sm" onclick="hpCloseInstallPicker(); hpLoad();">Done</button></div>';
            } else {
                if (out) out.innerHTML =
                    '<div style="background:rgba(239,68,68,0.10);border:1px solid var(--danger);border-radius:6px;padding:10px 12px;font-size:12px;color:var(--danger);font-weight:600;margin-bottom:8px;">Install failed.</div>' +
                    '<pre style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:monospace;font-size:11px;white-space:pre-wrap;max-height:240px;overflow:auto;margin:0;">' + escHtml(data.error || ('HTTP ' + resp.status)) + '</pre>' +
                    '<div style="margin-top:10px;display:flex;gap:8px;">' +
                        '<button class="btn btn-sm" onclick="hpCloseInstallPicker();">Close</button>' +
                        (which === 'nginx' ? '' : '<button class="btn btn-sm" onclick="hpInstallRuntime(\'nginx\', null);">Try nginx instead</button>') +
                    '</div>';
                document.querySelectorAll('[data-hp-install-card] button').forEach(b => { b.disabled = false; });
                if (btn) btn.textContent = origText;
            }
        } catch (e) {
            if (out) out.innerHTML = '<div style="color:var(--danger);">' + escHtml(e.message) + '</div>';
            document.querySelectorAll('[data-hp-install-card] button').forEach(b => { b.disabled = false; });
            if (btn) btn.textContent = origText;
        }
    }

    window.hpLoad = hpLoad;
    window.hpOpenEditor = hpOpenEditor;
    window.hpCloseEditor = hpCloseEditor;
    window.hpSaveDraft = hpSaveDraft;
    window.hpDelete = hpDelete;
    window.hpAddUpstream = hpAddUpstream;
    window.hpApplyCertPick = hpApplyCertPick;
    window.hpRequestCert = hpRequestCert;
    window.hpRenderEditor = hpRenderEditor;
    window.hpOpenInstallPicker = hpOpenInstallPicker;
    window.hpCloseInstallPicker = hpCloseInstallPicker;
    window.hpInstallRuntime = hpInstallRuntime;

})();
