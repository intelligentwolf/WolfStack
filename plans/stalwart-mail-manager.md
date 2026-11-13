# Stalwart Mail Manager — design plan

Status: LIVE-TESTED 2026-11-13 on dev (codewolf + wolf-server): new Galera (3 members, 2 hosts) + MaxScale master-only route :3307 + Keep (1 member, wolf-server) + 2 Stalwart nodes, both leases active; domains, mailbox create, app password, DNS tab verified in browser. UNCOMMITTED. Not yet exercised: Redis/Sentinel path, 3-member Keep, remove-cluster, password/2FA/suspend/quota/alias actions, ACME, real mail flow (needs port forwards + real domain).

## Goal

Install Stalwart Mail Server across one or more WolfStack nodes as a single
shared-data cluster, then manage domains, mailboxes, aliases, 2FA and DNS from
a WolfStack "Mail Manager" page.

Wizard: **Install Stalwart → choose servers → choose mailstore → coordinator → public name/certs → install**.

## Decisions (Paul, 2026-11-13)

| Decision | Choice |
|---|---|
| Mailstore (DataStore) options in v1 | **Galera/MariaDB only** — existing WolfStack Galera cluster (via MaxScale) or provision a new one with the existing provisioner |
| Coordinator / in-memory store | **Stalwart Keep**, with **Redis Sentinel fallback** for clusters where any node's kernel < 6.12 |
| Old-kernel UX | **Explain, don't silently fall back.** Show each node's kernel, why Keep needs ≥6.12, and offer *Upgrade kernel & re-check* or *Use Redis instead* (trade-off spelled out) |
| Existing `mail_tier` (Postfix/Dovecot config generator) + WolfHost mail | **Keep both untouched**; Stalwart is a new, separate path |

## Target versions (verified 2026-11-13)

- Stalwart **v1.1.0** (2026-11-09). Image `stalwartlabs/stalwart:v1` (docs: pin `v1`, avoid `latest` — install/upgrade#upgrading-a-container).
- Stalwart Keep **v1.0.1** (2026-11-09). Image `stalwartlabs/keep`, uid 2000, config `/etc/keep/keep.toml`, ports 7000 (client) / 7100 (peer, TCP+UDP) — keep README "Binaries and Docker".
- v0.16 removed TOML config and the `/api/*` REST management API; v1.0 changed the DB layout. **Design against v1.x only.** All management is JMAP at `POST /jmap/`.

## Stalwart cluster facts this design depends on (with sources)

Sources: github.com/stalwartlabs/website `src/content/docs/docs/<path>.md` (= stalw.art/docs/<path>), stalwart repo tag v1.1.0.

- Cluster = shared stores + a coordinator; nodes hold no data (cluster/index.md, cluster/configuration).
- Clustering is **AGPL / open source**; Enterprise only adds sharded stores, SQL read replicas, `metricsCalculate` (server/enterprise).
- Per-node local config is only `config.json` = the DataStore object (cluster/index.md). Everything else is a JMAP object in the shared DataStore.
- DataStore `MySql` example (storage/backends/mysql): `{"@type":"MySql","host":…,"database":"stalwart","authUsername":"stalwart","authSecret":{"@type":"EnvironmentVariable","variableName":"MYSQL_PASSWORD"}}`. Galera explicitly acceptable (cluster/deployment/storage).
- BlobStore: v1 uses `Default` (inside the DataStore) — no S3 in v1 because the mailstore choice is Galera-only; redundancy comes from Galera.
- Unique hostname per node via `STALWART_HOSTNAME`; node IDs are leased automatically (cluster/configuration/node-id). NTP required.
- Shared public name `SystemSettings.defaultHostname` (cluster/configuration/load-balancing).
- InMemoryStore must be configured BEFORE Coordinator, then restart (cluster/configuration/coordination).
- Keep InMemoryStore: `{"@type":"Keep","hosts":{"ip:7000":true,…},"clusterDiscovery":true,"secret":…,"tls":{"@type":"RawPublicKeys","keyPath":…,"serverKeysPath":…}}` + Coordinator `{"@type":"Default"}` (cluster/keep/stalwart).
- Redis Sentinel InMemoryStore: `{"@type":"RedisSentinel","urls":{"redis://ip:26379":true,…},"serviceName":"stalwart","authSecret":…,"sentinelSecret":…}` + Coordinator `Default` (storage/backends/redis). `maxmemory-policy volatile-lru` required (same page).
- Unattended bootstrap: write config.json, start with `STALWART_RECOVERY_MODE=1 STALWART_RECOVERY_ADMIN=admin:<pw>` (mgmt HTTP only on 8080), apply objects, restart WITHOUT those vars. RECOVERY_ADMIN is a full-access credential while set (configuration/declarative-deployments, configuration/environment-variables).
- Port 8080 must be loopback-only (install/platform/docker).
- Docs `dnsZoneFile` on Domain = full recommended record set (MX/SPF/DKIM/DMARC/SRV/MTA-STS/TLS-RPT/autoconfig/CAA); no A/AAAA (ref/object/domain).
- DKIM auto-generated (`dkimManagement` Automatic default); rotation only with automatic DNS management (domains/dkim-rotation).
- Accounts: `x:Account/set` `@type User`, `name` = local part, `domainId`, `credentials {"0":{"@type":"Password","secret":…}}`, `quotas.maxDiskQuota` bytes; JMAP lists are objects not arrays (auth/accounts/manage).
- 2FA = `credentials/0/otpUrl`; admin reset = set it to null; self-enrol at `https://<host>/account`. With 2FA, IMAP/SMTP password logins always fail → app passwords (auth/authentication/2fa, app-password).
- Suspend = `permissions` Merge with `disabledPermissions {"authenticate":true,"emailReceive":true,"emailSend":true}` (auth/accounts/manage).
- Management auth: API key `Authorization: Bearer API_…` (auth/authentication/api-key).
- Health: `/healthz/live`, `/healthz/ready` (503 if DataStore down) (cluster/configuration/load-balancing).
- ACME built in; certs stored in DataStore and shared cluster-wide (server/tls/certificates, server/tls/acme/configuration).

## Keep host requirements (keep docs/DEPLOYMENT.md §1) → wizard preflight

- Kernel ≥ 6.12, glibc ≥ 2.34 → otherwise offer kernel upgrade or Redis fallback.
- Kernel < 6.15 → set `net.ipv4.tcp_rto_min_us=5000` on Keep servers AND Stalwart nodes (DEPLOYMENT §3).
- No clock-stopped pause > 30 s, no CRIU/live migration → Keep containers pinned to host, excluded from WolfHA migration, no freeze backups.
- Peer port 7100 reachable only by members → bind to WolfNet, firewall.
- Each cluster its own peer secret; peer secret never given to clients.
- `--start bootstrap` only on first start; default `rejoin` thereafter (634 s lock quarantine after restart).
- Docker: `--network host --stop-timeout 16`.

## Kernel-upgrade guidance

Must NOT be written from memory. Per-distro package names/steps to be verified against each distro's own documentation before they appear in the UI.

## Build phases

1. **Backend module `src/stalwart/`** — cluster record (encrypted secrets via at_rest_crypto, write_secure, registered in secret_rotation), preflight (kernel/glibc/ports/port-25-outbound), Keep + Redis Sentinel deploy, Stalwart deploy + bootstrap, JMAP client.
2. **Install API + SSE job**, fan-out to chosen nodes via peer_auth.
3. **Mail Manager API** — domains, accounts, aliases, quotas, password/2FA reset, app passwords, suspend, DNS records (+ publish to DNS tier), node health, queue.
4. **UI** — wizard + Mail Manager page (ui-ux-design + ux-ui-foundation skills first), DOCS_PAGE_MAP entry.
5. **Fix app store Stalwart manifest** — `latest`→`v1`, 8080 loopback, recovery-admin not left set.
6. **Dev-cluster test** (this machine + wolfdisplay): single node, 2-node Keep, 2-node Redis fallback.
7. Website docs page.

## Kernel ≥ 6.12 routes (verified 2026-11-13, encoded in preflight.rs `kernel_guidance`)

| Distro | Default | Route |
|---|---|---|
| Debian 12 | 6.1 | bookworm-backports `linux-image-amd64`/`-arm64` 6.12.95 (packages.debian.org/bookworm-backports/linux-image-amd64; backports.debian.org/Instructions) — signed |
| Debian 13 | 6.12 | none needed |
| Ubuntu 22.04 | 5.15, HWE ceiling 6.8 | no supported route → `do-release-upgrade` (ubuntu.com/kernel/lifecycle) |
| Ubuntu 24.04 | 6.8 | `linux-generic-hwe-24.04` = 7.0 (packages.ubuntu.com/noble-updates/linux-generic-hwe-24.04) |
| Ubuntu 26.04 | 7.0 | none needed |
| Proxmox VE 8 | 6.8 | opt-in `proxmox-kernel-6.14` (Proxmox staff forum post 164497); staff recommend 6.8 for prod; or pve8to9 |
| Proxmox VE 9 | 6.14 / 6.17 / 7.0 | none needed (pve.proxmox.com/wiki/Roadmap) |
| EL 9 | 5.14 | no official route; ELRepo kernel-ml unofficial, unsigned (access.redhat.com/articles/3078, elrepo wiki) |
| EL 10 | 6.12 | none needed |

## Valkey / Sentinel fallback (verified 2026-11-13 from valkey-io/valkey 9.1.3 + valkey-container + valkey-doc)

- Image `valkey/valkey:9.1.3` (latest stable, 2026-10-26), uid 999, workdir /data; entrypoint chowns /data and drops root only when argv[1] is `valkey-server` → start Sentinel as `valkey-server /data/sentinel.conf --sentinel`.
- Image patches protected-mode OFF by default → set `bind <wolfnet ip>` + `protected-mode yes` explicitly.
- Server + Sentinel rewrite their config via rename → mount a DIRECTORY at /data, never a single file.
- `primaryauth` (alias masterauth) + `requirepass` on every node (roles swap on failover); `maxmemory-policy volatile-lru` (Stalwart storage/backends/redis.md).
- 3 Sentinels, quorum 2; failover needs a majority of Sentinels (sentinel.md:119, 232). Host networking avoids Docker NAT breakage (sentinel.md:402).
- Stalwart `authSecret` → Valkey requirepass; `sentinelSecret` → Sentinel requirepass (stalwart crates/store/src/backend/redis/mod.rs:183-198); usernames blank.

## Coordinator quorum

Keep: a member that cannot confirm a majority of the list fences itself (keep docs/DESIGN.md:42) → 2 members give NO fault tolerance. Coordinator = 1 member (no HA) or ≥3. Same for Sentinel.
