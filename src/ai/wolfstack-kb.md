# WolfStack Expert Knowledge Base

## Behavioural rules for the AI (READ THIS FIRST)
**Never hallucinate. If you don't know something, say so.**
- If the user asks about a feature, command, file path, port, config field, API endpoint, or version, and you can't verify it from this knowledge base, the running cluster, an [EXEC] tool result, or a file you've actually read — **say "I don't know"** or "I'm not sure — let me check" and then check, instead of inventing an answer.
- Never invent file paths, port numbers, environment variables, CLI flags, API routes, or config keys. If a user asks "is there a flag for X?" and this KB doesn't list one, the answer is "I don't see one — there may not be" not a guess.
- Never make up commit hashes, version numbers, dates, names, or quotes.
- Distinguish "I read this in the KB" from "I'm inferring this is probably true". Inferences are fine when labelled as such ("this is probably how it works, but I haven't verified").
- When the user asks "what's the latest version?" or similar live-state question, run an [EXEC] tool or fetch the running cluster's state — don't recite a version from training data or memory.
- If a user reports a bug or behaviour that contradicts what this KB says, trust the user, ask for the exact error message, and run a diagnostic — don't insist the KB is right.
- For diagnosing problems, prefer reading actual logs (`journalctl -u wolfstack -n 100`), config files, or live API responses over recalling general patterns. Cite what you read.

## Architecture
- Single Rust binary (actix-web 4), no database, no containers needed
- Config persisted as JSON files in /etc/wolfstack/
- Default ports: 8553 (HTTPS / dashboard), 8554 (HTTP inter-node, TLS-only installs), 8550 (public status pages)
- Requires root (reads /etc/shadow for auth)
- Background tasks: self-monitoring (2s), node polling (10s), status page checks (30s), session cleanup (300s), backup scheduling (60s)
- Startup is hardened to never hang before the dashboard binds: no unbounded subprocess execs or statvfs on possibly-dead FUSE mounts run pre-bind (whole pre-bind steps run on guarded timeout threads)

## Ports Configuration
- Per-node ports persisted to /etc/wolfstack/ports.json as `{ api, inter_node, status }`
- UI: sidebar → gear icon on a node → Node Ports panel (local node only)
- ports.json is the source of truth — the Node Ports panel writes it and it wins. CLI `--port N` only overrides the API port (pulling inter_node = N+1) for a genuine **manual** shell launch (`wolfstack --port N`). When WolfStack runs as the systemd service, a `--port` baked into the unit by an old setup.sh is reconciled into ports.json once (preserving any custom/UI value) and then ignored, so the UI takes effect. New installs no longer bake `--port` into the unit.
- Status port auto-fallback: if the configured status port is taken on boot, WolfStack scans 8550-8599 for a free one, binds there, persists the new port to ports.json, warns in logs
- API and inter_node ports hard-fail if taken (silent move would break peer polling)
- Common status-port collision: WolfDisk also defaults to 8550; auto-fallback moves WolfStack's status page aside

## VM Management (Native QEMU, Proxmox, Libvirt)
- Three backends: native QEMU (builds command line directly), Proxmox (qm commands), libvirt (virsh)
- Auto-detected: `is_proxmox()` checks for `pct`, `is_libvirt()` checks `virsh uri`
- VM configs stored in /var/lib/wolfstack/vms/{name}.json
- Disk images in /var/lib/wolfstack/vms/{name}.qcow2
- VmConfig carries `host_id: Option<String>` — the node that owns the VM. Stamped on create, rewritten by import_vm on migration target. Lets the cluster view render VMs as first-class members without a manual Scan.

### Serial Terminal
- Click the 💻 Terminal button on any running VM to open a WebSocket serial console
- Backend dispatches per platform: PVE runs `qm terminal <vmid>`, libvirt runs `virsh console <name> --force`, standalone QEMU uses socat to /var/lib/wolfstack/vms/{name}.serial.sock
- Standalone QEMU spawn wires `-chardev socket,id=serial0,path=<sock>,server=on,wait=off -serial chardev:serial0` automatically so the socket exists for socat to attach to
- Frontend pre-flights via GET /api/vms/{name}/serial-status — three outcomes:
  1. Not running → toast "start it first"
  2. Running but no serial device → Add-serial modal pops, POSTs /add-serial to wire one up
  3. Running + configured → opens terminal
- POST /api/vms/{name}/add-serial handles the fix:
  - PVE: `qm set <vmid> --serial0 socket` (reboot needed if running)
  - libvirt: dumpxml, attach only missing `<serial>` / `<console>` fragments via `virsh attach-device --config`, treats "already exists" as success
  - standalone: error message — restart the VM to pick up the new -chardev args
- Guest-side requirement (cannot be fixed from host): `console=ttyS0` on kernel cmdline + a getty on ttyS0. Terminal prints this hint at the top on every open.

### Stop vs Force Stop
- Running VMs have two stop buttons with distinct semantics
- Stop (`action: "stop"`, `force=false`): graceful ACPI — `qm shutdown --timeout 30`, `virsh shutdown`, or SIGTERM
- Force Stop (`action: "force-stop"`, `force=true`): immediate — `qm stop`, `virsh destroy`, or SIGKILL. Confirm dialog warns about unsaved data loss.
- Internal callers that need a guaranteed halt (migration export, VM delete) still pass force=true

### Import Disk Image
- When creating a VM, the "Import Disk Image" field accepts a path to an existing QCOW2, IMG, VMDK, VDI, or VHD file
- The image is converted to QCOW2 via qemu-img convert and used as the OS disk
- Supports importing from Proxmox, VMware, VirtualBox, and raw images like Home Assistant OS

### USB/PCI Passthrough
- Passthrough tab in VM settings shows host USB and PCI devices
- USB: matched by vendor:product ID (e.g. 046d:c52b)
- PCI: matched by BDF address (e.g. 0000:01:00.0), requires IOMMU/VFIO
- IOMMU group awareness — devices in the same group shown together
- Conflict guard: prevents two running VMs from claiming the same device
- Works across all three backends (native QEMU args, Proxmox qm set, libvirt hostdev XML)

### OVMF/UEFI Boot Issue
- When network config changes on a UEFI VM (WolfNet IP added, NIC added/removed, NIC model changed), OVMF boot entries reference old device paths
- WolfStack automatically resets EFI vars when network topology changes (v16.16.9+)
- Manual fix: delete /var/lib/wolfstack/vms/{name}_VARS.fd and restart VM
- Or switch to SeaBIOS temporarily — it doesn't have this issue

### Networking
- User-mode (default): VM gets NAT internet access, no incoming connections
- WolfNet IP: creates TAP interface with DHCP (requires dnsmasq installed on host)
- Bridge/Physical NIC: creates dedicated bridge for the physical interface, VM gets LAN IP via DHCP from router
- Extra NICs: add additional NICs for multi-homed VMs (e.g. OPNsense WAN+LAN)
- If VM has WolfNet IP but no DHCP response: check `ps aux | grep dnsmasq | grep tap` and install dnsmasq if missing

## Docker Container Management
- Lists containers via Docker socket API
- Start, stop, restart, remove, create
- Log viewing, exec into container
- WolfNet IP assignment for containers
- Auto-restart policy management
- Image update watcher: background checker compares local image digests against registries (Docker Hub, ghcr, lscr, private) and shows update badges; supports OCI multi-arch manifests and @sha256-pinned refs

## LXC Container Management
- Full lifecycle: create from templates, start, stop, destroy
- File manager: browse, read, write, delete files inside LXC containers
- Exec commands inside containers
- Resource limits (CPU, memory)
- Container architecture follows the host (`containers::host_container_arch()`) — arm64 hosts get arm64 templates/images; arm64 is a shipped CI target

## WolfNet (Encrypted Mesh VPN)
- Userspace VPN: X25519 key exchange + ChaCha20-Poly1305 encryption
- Does NOT use WireGuard kernel modules — only needs /dev/net/tun
- LAN auto-discovery on port 9601, tunnel traffic on port 9600
- Join flow: `wolfnet invite` on existing node → token → `wolfnet join <token>` on new node
- Docker image published to `ghcr.io/intelligentwolf/wolfnet:latest` (multi-arch: linux/amd64 + linux/arm64)
- For NAS platforms (Unraid, Synology, TrueNAS), use the satellite compose file at docker/docker-compose.satellite.yml in the WolfStack repo — bundles WolfNet + WolfDisk
- Gateway mode: NAT traffic through a WolfNet peer
- Docker containers carry WolfNet IPs via a `wolfnet.ip` container label; LXC via registered storage paths. Stale container→WolfNet DNAT rules are cleaned by `containers::cleanup_stale_wolfnet_routes`

## WolfDisk (Distributed Filesystem)
- Rust FUSE-based replicated/shared storage across nodes; roles Leader/Follower/Client/Auto; Shared vs Replicated mode; content-addressed SHA256 dedup; optional S3 gateway
- Native systemd service on Linux hosts (binary `wolfdisk`, config `/etc/wolfdisk/config.toml`) — installed from the Components page or setup script; Docker image `ghcr.io/intelligentwolf/wolfdisk:latest` for NAS boxes
- Default bind port 8550 — conflicts with WolfStack's status page when both are on the same host; WolfStack's status-port auto-fallback resolves this
- **Wire-version handshake (WDHS, wolfdisk v2.11.8+)**: peers exchange magic `WDHS` + wire version + software version before any frame. **Mixed wolfdisk versions CANNOT sync** — a version-skewed peer gets a clear log error ("peer runs pre-2.11.8 wolfdisk. Mixed versions cannot sync; upgrade all nodes together"). Fix: stop all → upgrade all → start all.
- Daemon rewrites `cluster_status.json` every ~1s with index_version, file_count, peer freshness, and (v2.11.8+) its software version
- **Cluster Health UI** (WolfDisk sidebar page): per-node index version column, software-version column, banner states — `✓ In sync`, `⟳ Syncing`, `⚠ N not reporting` (status stale >10s), `✗ Mixed wolfdisk versions` (red — cannot sync), `✗ Not progressing` (a behind node hasn't advanced for ≥3 min; suggests `journalctl -u wolfdisk | grep Re-sync`)
- Diagnostic: `wolfdisk --version` on every node is the first check for any sync-stuck report

## WolfFunctions (serverless FaaS, cluster-scoped) — v25.2.0+
Lambda-style functions instead of provisioning a container/VM. Definitions replicate to every same-cluster peer; any node accepts invocations; the cluster leader places warm instances and fires schedules.
- **Runtimes**: Python 3.12 (`def handler(event, context)`) and Node 22 (`exports.handler = async (event, context)`) — exactly two
- **Sandbox**: gVisor `runsc` is primary (auto-downloaded from Google's release bucket, sha512-verified); config-driven Docker fallback ("reduced isolation"). Per-node ExecutionMode Auto|Gvisor|Docker in local.json. **Docker is required even in gVisor mode** — rootfs images are built via `docker pull/export`
- **Placement**: `replicas` = number of NODES keeping warm copies (default 2, capped at capable-node count; 0 = scale-from-zero); `max_per_node` burst instances (default 4) reaped after 300s idle. Leader ranks nodes by load score; failover cold-starts locally as last resort
- **Triggers**: (1) public URL `/fn/{slug}` (opt-in per function, rate-limited 60/min/node); (2) interval schedules (min 60s, leader-fired); (3) thirteen internal events: alert_fired, node_offline, node_online, backup_completed, backup_failed, monitor_down, monitor_up (status-page monitor transitions), container_failover (WolfRun standby promoted), container_updated, container_update_failed (image watcher), ups_on_battery, ups_online, ups_stage_fired (UPS power engine)
- **Limits**: memory 32–8192 MB (default 128), timeout 1–900s (default 30, bounds the handler call; cold-start has a separate 90s budget)
- **`/fn/{slug}` responses** use AWS Lambda proxy-integration semantics: handler returns `{statusCode, headers, body, isBase64Encoded}` → honoured (framing headers dropped, header names case-deduped); any other return value is JSON-encoded with 200. `multiValueHeaders` NOT supported. Event = `{trigger:"http", method, query, body, source_ip}`
- **AI codegen**: describe the function in the editor → `POST /api/wolffunctions/ai-generate` drafts code via the configured AI provider; nothing deploys until saved
- Config `/etc/wolfstack/wolffunctions/functions.json` (replicated); runtime state `/var/lib/wolfstack/wolffunctions`
- Editor modal closes only via ✕/Cancel — backdrop clicks never discard work (v25.2.13)

## WolfFlow (Workflow Automation)
- Visual drag-and-drop editor. **23 action types**: UpdatePackages, UpdateWolfstack, RestartService, RunCommand, CleanLogs, CheckDiskSpace, RestartContainer, DockerPrune, DockerCheckUpdate, DockerUpdate, DockerCheckUpdateMany, DockerUpdateMany, RunBackupSchedule, HttpRequest, Condition (If/Else), NetBirdAction, TrueNasAction, UnifiAction, IntegrationAction, AiInvoke, AgentChat, SqlQuery, SendEmail
- **RunBackupSchedule**: runs a real backup schedule through the normal pipeline (appears in Backups, honours retention + pre/post hooks); HOST-scoped; step fails if any backup failed. Builder has a live schedule picker
- **SqlQuery** goes through the guarded SQL connections pool with tiered permissions (read / update / delete — DDL never allowed, statements classified by sqlparser)
- Structured outputs: each action returns key-value data referenced downstream via {{step_name.key}}; output reference picker in the Condition editor
- Retry logic per step; workflow timeout via max_runtime_secs
- 5 failure policies: Abort (default), Continue, Alert, Notify & Abort, Notify & Continue
- Cron scheduling with quick presets; parallel execution across cluster nodes; email results with HTML reports

### Check Disk Space Outputs
- available_gb, total_gb, usage_pct, mount_point, over_threshold
- Example: if {{Check Disk.available_gb}} lt 500 then run cleanup

### HTTP Request Outputs
- status_code, response_body, json (parsed response)

## Status Pages
- Public uptime monitoring at /status/{slug}
- HTTP/HTTPS/TCP/ICMP/DNS monitors
- Incident tracking with updates
- Cluster-scoped: monitors, pages, incidents all have a cluster field
- Served on BOTH the main API port (auth not required for /status/*) AND a dedicated no-auth listener on port 8550 — the main-port route is what makes reverse-proxy deployments work
- Admin UI "public URL" link uses `window.location.origin` for the local cluster, so it automatically matches whatever domain the admin is on (Cloudflare tunnel, nginx, direct IP — all work without config)

## GitHub Backup (v19.2.0+)
- Settings → 📤 **GitHub Backup** — commit WolfStack configuration to a private GitHub repo as an audit log / rollback story
- Tracked files: every `/etc/wolfstack/*.json` **except** `github-backup.json` (the token lives there — never pushed), plus every `docker-compose.yml` under `/etc/wolfstack/compose/`
- Config at `/etc/wolfstack/github-backup.json` (0600). Fields: `enabled`, `token`, `owner`, `repo`, `branch` (default `main`), `commit_name`, `commit_email`, plus last-push metadata
- Push uses the GitHub Git Data API so every push is **one atomic commit** even across many files (blobs → tree → commit → fast-forward ref). Tree is NOT based on the previous tree, so deletions (e.g. uninstalled appstore stacks) propagate to history
- Restore pulls the latest tree from the configured branch, recursively walks it, writes each known path back to `/etc/wolfstack/`. Paths outside the `config/` and `compose/` prefixes are ignored so arbitrary files committed to the repo can't be written elsewhere on the host
- Destructive actions (restore) gated by `confirmTypedYes` typed-YES modal in the frontend
- Token classic scope: `repo`. Fine-grained: `Contents: Read and write` on the single target repo. **Private repo required** — contents include API keys and passwords
- Empty repos aren't auto-initialised — the configured branch must already have at least one commit. UI Test-connection surfaces whether the branch exists
- Endpoints: `GET/POST /api/github-backup/config`, `POST /api/github-backup/push`, `POST /api/github-backup/restore`, `GET /api/github-backup/test`
- Token never reaches the browser — GET config returns `••••••••XXXX` mask; POST config with blank-or-masked token keeps the stored value untouched

## Running behind a reverse proxy (Cloudflare Tunnel, nginx, Traefik, etc.)
- Point the proxy at the main API port (default 8553, or whatever `--port` sets). Status pages, cluster browser sessions, consoles and the SPA all ride that one port.
- Required proxy headers: `Host` (preserve original), `X-Forwarded-Proto`, `X-Forwarded-For`. actix-web's `connection_info()` reads these for URL generation (cluster browser `connect_url`, etc.).
- Passkey login also reads `X-Forwarded-Proto` and `X-Forwarded-Host` (v22.6.9+). If you see "host header is incorrect for passkeys", the proxy is missing one of those — see the Authentication section.
- Enable WebSocket upgrades — consoles, VNC, k8s provisioning, and cluster browser all use WS on the same port.
- Status pages work out of the box at `https://your-domain/status/{slug}` with no extra routing.
- Port 8550 (dedicated status listener) is NOT needed behind a proxy and can be left un-forwarded; it's only there for admins who want no-auth public pages on a separate port without a proxy.
- **Public base URL pin**: `/etc/wolfstack/reverse-proxy.json` (`GET/POST /api/reverse-proxy/config`) stores a `public_base_url` so public links (status pages, cluster-browser share URLs) use the admin domain instead of the node IP.

## Backups
- Scheduled backups with multiple destination types
- Docker: commit + save + volume backup; LXC: full container backup; VM: disk image backup
- **Seven destination types**: Local, S3, Remote (another WolfStack node), WolfDisk, PBS (Proxmox Backup Server, including `pbs_file_level` pxar mode), NFS, SMB/CIFS
- **PBS file-level (pxar)** applies to Docker, native LXC, system folders AND (v25.2.35) WolfStack config backups — PBS's own UI can then browse a snapshot and restore a single file. Config snapshots are per-node (`host/wolfstack-config-<hostname>`). VMs and Proxmox LXC can't (disk image / block rootfs) — the backup log states the fallback reason explicitly. WolfStack's own restore of a file-level config snapshot applies the usual same-/new-machine rules; per-FILE restore is done in the PBS UI
- NFS/SMB backups mount the share idempotently under /mnt/wolfstack-backup/ and write through like Local
- SMB fields on BackupStorage: smb_source (//server/share or \\server\share — normalised), smb_subpath, smb_username, smb_password, smb_domain, smb_options. Defaults to SMB 3.0.
- NFS fields: nfs_source (server:/export), nfs_options (defaults to rw,soft,timeo=50)
- Pre-flight at save time: `POST /api/backups/test-storage` exercises the mount path without doing a real backup, so missing-package errors surface at schedule save instead of silently failing later
- **Pre/post hooks** per schedule: commands run via `timeout --kill-after=30 3600 bash -c <cmd>` (hard cap 1 hour, exit 124 = timed out). Env vars: `WOLFSTACK_SCHEDULE`, `WOLFSTACK_HOOK_PHASE` (pre/post), `WOLFSTACK_BACKUP_STATUS` (empty on pre; aborted/failed/completed on post). A failing pre-command **aborts the whole run** (no backups taken, synthetic Failed entry appears in the list); the post-command ALWAYS runs, even after a pre failure

## Storage
- Mount types: S3, NFS, SMB/CIFS, SSHFS, Directory (bind mount), WolfDisk
- SMB/CIFS: guest or username/password/domain auth. Defaults to SMB 3.0 (matches Synology/QNAP defaults). `smb_options` can override e.g. `vers=2.1` for older NAS firmware.
- Source normalisation: `\\server\share` gets converted to `//server/share` automatically
- Auto-mount on boot; global mounts replicate across cluster nodes
- Storage pages also list existing **network mounts** discovered from /proc/mounts (GlusterFS, NFS, CIFS, SSHFS, s3fs, rclone, Ceph, WolfDisk) even when not created through WolfStack

## Auto-install for Mount Helpers
- When a mount needs `mount.cifs` (cifs-utils) or `mount.nfs` (nfs-common/nfs-utils/nfs-client) and it's missing, WolfStack does NOT silently apt-get
- Mount helpers return a structured error `MISSING_PACKAGE|<binary>|<debian_pkg>|<redhat_pkg>` that the frontend parses
- UI pops a confirm modal: "Install cifs-utils? Run the install in a terminal window." Nothing installs without confirmation.
- On confirm: POST /api/system/prepare-install-package returns a session_id, frontend opens /console.html?type=pkg-install&name=<id> showing the install live
- Per-distro package names + package managers: Debian apt-get nfs-common/cifs-utils, RedHat dnf nfs-utils/cifs-utils, SUSE zypper nfs-client/cifs-utils, Arch pacman nfs-utils/cifs-utils, Unknown falls back to Debian
- Detected via `/etc/arch-release`, `/etc/debian_version`, `/etc/redhat-release`, `/etc/SuSE-release`, plus `/etc/os-release` fallback

## Alerting
- Threshold alerting with email notifications
- Discord, Slack, Telegram webhook support
- ntfy push notifications to phone/desktop (ntfy.sh or self-hosted server; topic + optional access token; Compromise alerts sent at max priority)
- Alert cooldown to prevent spam

## Host mail relay (v25.2.29+)
Gives HOST software (cron MAILTO, PHP mail(), monitoring scripts, app-store apps) a working `/usr/sbin/sendmail` on nodes with no MTA — distinct from WolfStack's own alert email (which speaks SMTP directly).
- Settings → AI & Email → Host Mail Relay card, with a per-node server picker. Enable installs `msmtp` on demand, writes `/etc/msmtprc` from the SMTP settings already configured for alert email, symlinks `/usr/sbin/sendmail` → msmtp
- SAFETY: refuses to replace an existing MTA (Postfix/Exim/…) unless forced; the real sendmail is backed up and restored on disable. Requires SMTP configured first
- `/etc/msmtprc` is host-readable (0644) so www-data etc. can send — recommend a dedicated relay credential, not a personal mailbox password
- Endpoints: `/api/mail-relay/{status,enable,disable,test}`

## UPS Power (NUT integration + staged shutdown) — v25.2.33+
Per-server page (server tree → UPS Power). Reads any existing NUT setup via `upsc` — WolfStack NEVER writes/manages NUT config (operators run upsd/upsmon/drivers themselves). What it adds over plain NUT: a staged, workload-aware wind-down on battery.
- **Target**: `myups` (local upsd) or `myups@host[:port]` (remote, port 3493 default). Poll 5–300s (default 15). Test-connection button does an immediate read; failures show the actual reason (v25.2.34: TLS chatter filtered out; bare "Unknown error" from upsc = the NUT server sent an unrecognised ERR reply — check exact UPS name AND the NUT server's own hostname config)
- **Stages**: rows of "at ≤X% battery run these actions". Recommended one-click layout 60/40/20. Actions in order: stop VMs (managed via qm/virsh/native + sweep of unmanaged guests), stop containers (docker + pct + lxc-*), stop shares (samba/NFS units, both spellings; mounted network FS untouched), shutdown host (systemctl poweroff, fallback shutdown -h)
- **Engine rules**: fires ONLY on live on-battery data (stale/unreadable data never acts); each stage fires once per outage (latched by threshold, cleared when mains returns); multiple thresholds crossed in one poll run gentle→harsh; boot-while-on-battery fires all due stages
- **Action log** persisted to `/var/lib/wolfstack/ups-log.json` on EVERY entry — survives the shutdown the engine causes; shown on the page after the outage
- **Faceplate UI**: live UPS front panel (status LEDs, green/amber/red LCD with charge/runtime/load, 10-segment battery bar, one switched outlet group per stage — red = that stage shed its load). NO COMMS when unreadable, SETUP when unconfigured. Also a home-dashboard widget (one per server)
- Alerts on on-battery/restored/stage-fired; WolfFunctions events ups_on_battery/ups_online/ups_stage_fired
- **Monitoring vs Enabled** (v25.33.1): a saved target is ALWAYS polled (live status, NO COMMS, battery health). The Enabled box only arms the on-battery/restored alerts and the shutdown stages. Before v25.33.1 a saved-but-disabled target was never polled and showed SETUP
- **Battery needs replacing** (v25.33.1): raised when ups.status has `RB`, battery.packs.bad > 0, OR the last self-test failed. Failed self-test = exact driver strings only: "Done and error" (usbhid-ups: APC/CyberPower/Eaton/Tripp Lite USB), "Battery Bad (Replace)" (serial Tripp Lite), "10s test failed"/"deep test failed" (serial Belkin), "Failed" or "Failed, …" (APC/CyberPower SNMP, APC Modbus). usbhid-ups sets RB only from the UPS's own NeedReplacement bit, so a failed test often shows WITHOUT RB. Surfaces as: REPLACE BATTERY LED + banner on the UPS page/widget, critical Issues entry, Predictive Inbox finding `ups_battery_replace` (High → notifies on first appearance). A failed test result persists until the next self-test, so the finding clears only after a passing test (`upscmd -u <user> <ups> test.battery.start.quick`)
- Missing `upsc` → one-click "Install NUT client tools" (nut-client on apt/dnf, nut on pacman/apk/zypper). Config `/etc/wolfstack/ups.json`
- If a driver reports no battery.charge, %-keyed stages cannot fire (logged once per outage)
- Known hardware quirk: UniFi UPS Tower's built-in NUT server can require a login for reads (plain upsc can't authenticate) and sends nonstandard replies — disable its login requirement and use the exact UPS name from the UniFi console

## Wake-on-LAN (cluster page) — v25.33.0+
Cluster tree → Wake-on-LAN. Turn on machines (e.g. a GPU desktop that is normally off) from anywhere the dashboard is reachable.
- **Per node, never replicated**: a magic packet is a LAN broadcast and does not cross routers, so each machine is stored on the node that sends it (`/etc/wolfstack/wol-targets.json` on that node). The "Send from node" choice MUST be a node on the same network as the machine. The page lists every node's machines via the node proxy; offline nodes' machines are not listed (a banner names them). To move a machine to another node: remove and re-add
- **Fields**: name, MAC (any spelling: `aa:bb:…`, `aa-bb-…`, `aabb.ccdd.eeff`, bare hex; multicast/all-zero rejected, duplicates per node rejected), optional IP/hostname (pinged from the node every 10s to show Online/Offline — without it status is "Unknown"), Advanced: broadcast address (blank = every up IPv4 interface's broadcast + 255.255.255.255; point-to-point links like WolfNet/Tailscale skipped) and UDP port (default 9, some machines want 7)
- **Wake** sends 3 copies of the 102-byte packet. "Sent" means it left the node, not that the machine woke. Status shows "Waking…" for 5 minutes, then "Still offline" with the checklist: WoL enabled in BIOS/UEFI AND on the NIC (Linux: `ethtool -s <nic> wol g`, often reset on boot; Windows: NIC Power Management + disable Fast Startup), wired NIC (Wi-Fi WoL rarely works), sending node on the same LAN/VLAN, host firewall not blocking outbound broadcast (ufw can refuse 255.255.255.255 with EPERM — set an explicit broadcast address)
- **API** (per node; reach other nodes via `/api/nodes/{id}/proxy/…`): `GET /api/wol/targets`, `POST /api/wol/targets`, `PUT|DELETE /api/wol/targets/{id}`, `POST /api/wol/targets/{id}/wake`, `GET /api/wol/status`. Changes and wakes refuse viewer sessions and are logged with the operator's name. An API key can script a wake (e.g. before starting a local-LLM client)

## Node roles + HA hosting tiers (NoroNetwork, v25.2.38-dev)
Node-ROLES keystone for HA shared hosting. Each node carries `roles: Vec<NodeRole>` (Dns/Mail/MailRelay/Ingress/Host/Database; empty = general-purpose, the default — existing clusters unchanged). Assign in node-settings modal (checkboxes, hidden for Proxmox nodes). Gossiped owner-authoritative like `site`; persisted self_roles.json. `POST /api/settings/roles`, `GET /api/cluster/roles/{available,summary}`, `ClusterState::nodes_with_role(role)`.
- **DNS tier**: WolfHost zone/record writes fan out to EVERY `dns`-role node (all ≥3 NS get the zone; PowerDNS per node). Falls back to local when no dns nodes (single-node WolfHost unchanged). Cluster-authed apply endpoints `/api/wolfhost-dns/{apply-zone,delete-zone,record}`.
- **Postgres HA** (`postgres_ha` module, Galera analogue): one primary + N streaming standbys on `Database`-role nodes. Provision (lxc + install + configure_primary/standby via pg_basebackup), status (pg_stat_replication / pg_is_in_recovery), promote_standby (pg_promote, operator-driven — NOT auto). API `/api/postgres-ha/*`. Identifiers strictly validated + SQL via quoted heredoc (injection-safe).
- **Mail tier** (`mail_tier`): derives Mail (store) + MailRelay (backup MX) from roles; generates MX/A records (primary MX pri 10, relay pri 20) published via the DNS-tier fan-out; postfix relay + dovecot replication config previews. API `/api/mail-tier/*`.
- **Site failover** (`site_failover`): tracks HostedSite (docroot on shared storage / active Host node); plan_failover deterministically reassigns an offline host's sites to the first online `Host` node; `/api/site-failover/*`.
- STATUS: management planes built + reviewed, NOT live-tested vs real hardware; UI beyond the role picker + docroot/failover automation are follow-ups pending NoroNetwork's schema. See [[project_noro_wolfhost_ha_request]].

## App Store
- **~530 one-click applications**
- **Four install targets**: Docker, LXC, bare-metal, VM — a manifest can offer any subset (`docker` / `lxc` / `bare_metal` / `vm` fields)
- User input fields for configuration (passwords, domains, etc.)
- Install modal detects which targets the manifest supports and shows matching pills
- Ports/env/memory sections auto-hide for non-Docker targets
- Installed-apps list is cluster-wide (fetches every online node via the cluster proxy)

### Docker deployment modes (v19.0.6+)
- Docker-target apps install two ways: **Standard (`docker run`)** or **Docker Compose**. The radio appears only when target is Docker AND the manifest advertises `compose_available: true`
- **Standard** is the default/legacy path — unchanged behaviour
- **Compose** writes `/etc/wolfstack/compose/appstore-{install_id}/docker-compose.yml`, runs `docker compose up -d`, records `deployment_type: "docker-compose"`. Appears on the Compose Stacks page (look for the `appstore-` prefix)
- View / edit compose via `GET`/`PUT /api/appstore/installed/{install_id}/compose.yaml`; save re-runs `up -d`
- Uninstall of a compose app runs `docker compose down -v` (wipes named volumes) behind the typed-YES modal
- Install failure rollback: failed `up -d` on a fresh install runs `down -v --remove-orphans` and deletes the stack dir

### VM Target (ISO-Based Apps)
- For apps that want a whole OS (PBS, pfSense, OPNsense, Home Assistant OS, etc.)
- VmTarget fields: iso_url, memory_mb, cores, disk_gb, optional data_disk_gb + data_disk_label, vga
- install_vm: downloads ISO to /var/lib/wolfstack/iso/<app_id>.iso (cached), auto-allocates a WolfNet IP, creates + starts the VM
- User overrides via user_inputs: disk_gb, data_disk_gb, memory_mb, cores
- Data disk works on all three VM backends (qm --scsiN, virsh --disk, standalone -drive)
- ISO fetch falls back to scraping the parent directory index for the newest matching file (handles Proxmox's no-`_latest.iso` quirk)

## Authentication
- Linux crypt() against /etc/shadow (default)
- WolfStack native user accounts with Argon2 password hashing
- TOTP two-factor authentication
- WebAuthn / passkey login (v22.3.0+) — additive, sits alongside PAM
- OIDC/SSO (Team/MSP/Enterprise licence): Authentik, Azure AD, Okta, Keycloak, any OIDC provider
- Cookie-based sessions (wolfstack_session cookie)
- Inter-node auth: X-WolfStack-Secret header

### Login lockout (brute-force protection)
- Defaults: **3 failed attempts within 5 minutes → 48-hour kernel-level block** (`/etc/wolfstack/auth-lockout.json`; pre-v23.12.13 default of 10 auto-migrates to 3)
- One limiter unifies failures from the WolfStack UI, sshd, and Proxmox pveproxy
- **Trusted IPs / CIDRs** (Security page textarea) bypass lockout entirely — operators can't lock themselves out
- Lockouts propagate fleet-wide; receiving nodes re-validate against their own trusted list so a peer can't be tricked into blocking an admin IP
- Manual unblock: `/api/security/auth-unblock` (propagates); lockout list at `/api/security/auth-lockouts`

### Passkey login behind a reverse proxy (v22.6.9+)
- `passkey_rp_origin()` reads `X-Forwarded-Proto` and `X-Forwarded-Host` first, falls back to `Host` + local TLS state. Missing headers behind a TLS-terminating proxy → "host header is incorrect for passkeys"
- Multi-hop proxy chains: takes the first comma-separated value (original client-facing host/scheme)
- Bogus `X-Forwarded-Proto` values fall back to local TLS state; IPv6 hosts handled correctly

## Certificates page (v22.6.9+)
- Three input modes: Let's Encrypt (certbot), Generate Self-Signed, Install / Update
- Self-signed: `openssl req -x509 -newkey rsa:2048 -nodes -sha256` with SAN auto-detect (DNS vs IP). Default validity 825 days.
- Install / Update: paste cert + key PEM; supports encrypted PKCS#8 and legacy encrypted PEM via `key_passphrase` (passed via env, never argv). Decrypted key is stored.
- Atomic write: `<path>.new` + `verify_cert_key_pair` + rename. A bad upload never overwrites a working cert.
- Path whitelist: `/etc/wolfstack/`, `/etc/pve/local/`, `/etc/pve/nodes/`
- Discovery scans certbot, `/etc/letsencrypt/live/`, `/etc/wolfstack/cert.pem`+`key.pem`, Proxmox pveproxy-ssl pairs across nodes
- After install: response carries `restart_service` (wolfstack or pveproxy); frontend confirms before POST `/api/certificates/restart-service` (deferred restart)

### Local CA (internal domains)
- Issues TLS certs for unregistered internal domains (e.g. `*.ai.home`) that public ACME can't validate
- Root CA: RSA-4096, 10-year, at `/etc/wolfstack/local-ca/ca-cert.pem` (downloadable to install in browsers) + `ca-key.pem` (mode 0600, **never leaves the box, never returned by any API**)
- Leaf certs: RSA-2048, 825 days, SAN covers domain + `*.domain` + IPs
- Endpoints: `/api/certificates/local-ca` (status), `/init`, `/download`, `/issue`

### Certbot engine (WolfProxy sites)
- `src/certbot`: ACME issuance/renewal for WolfProxy-managed sites. Webroot mode (default — zero-downtime, ACME served from `/var/lib/wolfstack/acme-webroot` through the running proxy) or DNS-01 for wildcards/no-port-80
- Daily renewal task runs `certbot renew --quiet` with a deploy hook reloading WolfProxy. Config `/etc/wolfstack/certbot.json`

## DNS providers + DNS-01 / wildcard certs (v22.14.12+)
- Module: `src/dns_providers/mod.rs`. Store at `/etc/wolfstack/dns-providers.json` (mode 0600); credentials AES-encrypted at rest (v2) with legacy-XOR fallback for old entries
- Plugin whitelist (`KNOWN_PLUGINS`) gates which `--dns-<plugin>` strings can land on the certbot argv; re-checked at materialise time
- Materialise-to-tmp: creds written to a unique `/run/wolfstack/dns-creds/<id>-<rand>.ini` (0600), RAII-unlinked after certbot exits
- Endpoints: `GET/POST /api/dns-providers`, `PUT/DELETE /api/dns-providers/{id}`, `POST /api/dns-providers/{id}/test` (staging dry-run)
- Cert issuance: `POST /api/certs` accepts `dns_provider_id` (wins over `challenge`). Wildcards (`*.zone.tld`) work over DNS-01
- Port-80 collision: bind-probe before certbot; busy → 409 `port_80_busy` → frontend flips the radio to DNS-01

## Installer (setup.sh)
- Curl-piped: `curl -sSL https://raw.githubusercontent.com/intelligentwolf/WolfStack/master/setup.sh | sudo bash`
- Flags: `--beta` (beta branch), `--yes`/`-y`, `--agent` (agent-only install), `--install-dir <path>` (redirect build dir for low-disk hosts)
- Pre-flight checks: DNS-on-:53 conflicts (Technitium/Pi-hole/AdGuard/BIND/Unbound/dnsmasq; systemd-resolved handled automatically), port conflicts on 8553/8554/8550, reverse proxies on 80/443 (info), existing `/etc/wolfstack/` → upgrade warning (custom-cluster-secret footgun called out), ufw/firewalld hint with exact allow command, architecture warning for non-x86_64/aarch64 (source build ~10-30 min, ~3 GB)
- Install manifest at `/var/log/wolfstack/install-<timestamp>.log` (package diff, used by uninstaller)
- Join token pre-generated at `/etc/wolfstack/join-token` (0600), printed in the completion banner
- Local uninstaller saved to `/usr/local/bin/wolfstack-uninstall` (works offline)
- **Unraid**: install/upgrade downloads the static musl binary BEFORE killing the running agent (download-before-kill — a failed download never leaves the node dark); startup wired into `/boot/config/go` with a wait-for-array loop; a post-boot bootstrapper downloads static tools (proxmox-backup-client, pxar, smartctl) from the `unraid-tools-v1` GitHub release, persists them at `/mnt/user/appdata/wolfstack/tools`, and re-links into `/usr/local/bin` every boot (Unraid's /usr/local/bin is RAM-backed). Tools already on PATH are never shadowed. Detection: `/etc/unraid-version`

## AI Agent
- **Seven providers**: Claude (Anthropic API), **Claude Code CLI** (uses the operator's Claude Pro/Max subscription login — shells out to the `claude` binary, no API key, built-in tools disabled), Gemini (Google), OpenAI (ChatGPT), OpenRouter (100+ models), Cloudflare Workers AI, Local AI (self-hosted)
- Local AI supports any OpenAI-compatible server: Ollama, LM Studio, LocalAI, vLLM, text-generation-webui, llama.cpp. Common URLs: Ollama http://localhost:11434, LM Studio http://localhost:1234/v1, LocalAI http://localhost:8080/v1
- Cloudflare Workers AI: account ID + Workers-AI token; WolfStack builds the endpoint URL. Compact system prompt (8K-context models). Free tier covers most homelabs
- Auto-detects available models per provider; every model dropdown ends with `Custom…` for any model name
- Expert knowledge base shipped with WolfStack; AI executes read-only commands via [EXEC] tags
- Health monitoring: periodic scans with AI-generated recommendations; interval can be **Off** (chat stays live, no periodic probe). Health prompts include live security findings AND a **7-day rolling metrics baseline** ("now vs ~24h vs ~7d" drift summary) so slow degradation is caught, not just threshold breaches
- **Master enable/disable toggle** (v24.7.24): hides the chat bubble, pauses health checks, preserves all keys/config
- **Tool-call cap**: off by default; 1–100 per-turn round limit (default 6 when enabled)
- Alerts go to email + Discord / Telegram / Slack on private channels — NEVER auto-posted to the public status page
- "Cleared" notifications on the alert→OK transition so no silent recoveries

## WolfAgents (named AI agents / "WolfPack")
Long-lived named AI personas with persistent memory and per-agent guardrails — distinct from the single dashboard AI chat.
- One agent = system prompt + model + append-only JSONL memory (`/etc/wolfstack/agents/<id>/memory.jsonl`, tail-bounded, default 40 lines); definitions in `/etc/wolfstack/agents.json` (0600)
- **Access levels**: ReadOnly (default), ReadWrite, ConfirmAll, Trusted
- **Target scope** restricts clusters/containers/hosts/paths/API-paths/email-recipients/SQL-connections per agent
- Chat bindings: Discord, Telegram, WhatsApp (Twilio) — per-agent bot token or the global alert config
- Chat rate limit 20 msg/min/agent; full tool_use loop on Claude, single-shot elsewhere
- UI: WolfAgents page

## Antivirus / Rootkit Scanning
- Full antivirus + rootkit stack: ClamAV (signatures), rkhunter, chkrootkit. Installed on demand from the Security page (chkrootkit unavailable on Arch — AUR-only, reported as not_available)
- **On-access scanning** via clamonacc + clamd (WolfStack manages its own `wolfstack-clamonacc.service` unit). Real-time fanotify scan; WolfStack manages the clamd.conf block between `# === WolfStack on-access begin/end ===` markers; rediscovers non-local mounts on every apply; enabling pre-seeds signatures if the DB is empty
- **🛠 Repair ClamAV button**: ensure clamav user → freshclam → verify DB; step-by-step log. Signature auto-recovery also fires mid-scan on "No supported database files"
- **clamav/logrotate self-heal**: at startup and every 30 min — recreate missing clamav user, re-run + reset-failed a stale-failed logrotate unit only when the re-run succeeds
- **Auto-actions**: auto-quarantine confirmed hits to `/var/quarantine/wolfstack` (chmod 000, one-click restore with original mode/owner); auto-kill processes holding an infected file (configurable); cluster propagation of findings
- **Scheduled scans**: `schedule_hours` (default 24, 0 = manual). Walks `/`, skips /proc /sys /dev, network mounts, live VM disks. Streams progress
- **Alert routing**: email + Discord/Telegram/Slack. NEVER public status pages
- Endpoints: `POST /api/antivirus/{install,scan,on-access,clamav/repair}`, `GET /api/antivirus/{status,findings,quarantine}`, quarantine restore/delete, findings dismiss. Status/config/scan fan out fleet-wide
- **/tmp + /dev/shm exec alarm**: any running process whose `/proc/$PID/exe` resolves under `/tmp` or `/dev/shm` is a Compromise-class finding (classic malware staging). Reports PID, ppid, cmdline, user, sha256, mtime/mode/size, open files/sockets. Never auto-kills. `/var/tmp` and `/run/user/*` intentionally out of scope

## Security page & Fleet Security
Security features live on the per-node Security page and a cross-cluster **Fleet Security** page (fan-out via the cluster proxy).

### Threat Intelligence (IP blocklists)
- Pulls public blocklists and applies them as kernel DROP rules via ipset + a `WOLFSTACK_THREAT_INTEL` iptables chain, matching both src and dst (inbound attackers AND outbound malware→C2)
- Providers: Spamhaus DROP + FireHOL Level 1 (default-on when enabled); CrowdSec community + AbuseIPDB (default-off, need API keys)
- **Opt-in and dry-run-first**: `enabled` defaults false; `dry_run` defaults TRUE (first refresh produces a preview report only). Emergency `paused` removes the rule but keeps config
- Max 250k entries, refresh every 6h (1–168 clamp), atomic ipset swap
- **Never blocks**: loopback, RFC1918, cluster node IPs, and the calling admin's IP are always stripped
- Endpoints under `/api/threat-intel/…` (config, refresh, pause/resume, status, lookup/{ip}, test-feed, fleet-status); cluster-scoped

### Outbound scan detector
- Detects a compromised local process doing outbound scanning (SYN_SENT fan-out per PID from /proc/net/tcp)
- **Default OFF** (flipped in v23.12.3 after it SIGKILL'd pmxcfs on a user's Proxmox host); threshold 50 distinct destinations / 60s window
- Hard safety list (`ESSENTIAL_SAFETY_COMMS`) is checked before the operator allowlist — never kills pmxcfs, corosync, qemu, libvirtd, etcd, kubelet, databases, NetworkManager, dnsmasq, etc.; never PID 1, never itself; UID 0 never auto-blocked
- Actions: `kill_and_block` (SIGTERM→SIGKILL + per-UID outbound REJECT) or `alert_only`. Enabling shows a destructive-action confirm

### NMAP Protection ("Gandalf")
- Optional TCP tarpit/scan-trap on **port 41910**, off by default. Any connection from outside the trusted envelope (loopback, trusted CIDRs, WolfNet, cluster peers, local LAN unless strict) gets a quiet kernel block — port scanners self-block
- Serves a decoy nginx-branded login page. Toggle: Security page "NMAP Protection" checkbox; `/api/security/gandalf`

### Secret audit & rotation
- Read-only secret auditor feeds System Check + the licence heartbeat count: flags default cluster secret (Compromise severity, red banner), legacy XOR-obfuscated credential stores (auto-clears once migrated to AES), and plaintext backup credentials in backups.json (deliberately not auto-migrated)
- **Coordinated cluster-secret rotation** (Settings → Security): 5-step operator-driven protocol — Preflight (reachability) → Propose (new 32-byte secret shown once) → Receive (pushed to peers' `.pending` under the current secret, SHA-256 ACK) → Commit (atomic promote, timestamped backups, **restart required** — no live swap) → Rollback. Audit log `/var/log/wolfstack/secret-rotation.log`; concurrent rotations rejected with 409
- Credential stores (DNS providers, cloud providers, XO tokens, TrueNAS/Unraid keys, SQL passwords, integrations vault) are **AES-256-GCM encrypted at rest**, key HKDF-derived from the cluster secret with per-store purpose labels; legacy XOR values keep decrypting forever. Rotation re-encrypts loss-free. Threat model: leaked backup tarballs, not on-host root

### Emergency root rotation
- Fleet Security → "Rotate root passwords fleet-wide": generates a strong 32-char password per node, applies via `chpasswd` on stdin (never argv), records to `/root/.wolfstack-emergency-passwords.txt` (0600), then kills all active root SSH sessions (including the operator's — the modal warns in red). Passwords shown once + CSV download, never stored in WolfStack state

### Public listening-port audit
- Fleet Security panel lists every public listener (`0.0.0.0`/`[::]`) per node with owning process (from `ss -tlnp`). Separately, System Check flags *risky* exposed services (Docker 2375 critical, Redis, MongoDB, Elasticsearch, MySQL, etc.)

### Security posture & host audit
- There is **no numeric security score** — posture renders as System Check rows: risky listeners, world-readable configs, weak/default cluster secret, sshd hardening (via `sshd -T`), fail2ban/sshguard presence, plus active-attack checks (SSH brute-force, crypto-miner processes, fresh /tmp `/dev/shm` executables, outbound RAT/C2/mining ports, IP/MAC conflicts)
- Fleet Security host audit enumerates risky workloads: `--privileged` containers, docker.sock mounts, network=host, host /proc//etc//root mounts, known-bad processes (zmap, masscan, kinsing…), recently-changed authorized_keys, cron jobs in /tmp

## Cluster firewall coordination
- **3-strike auto-block** (see Login lockout above for exact defaults): kernel-level DROP, propagates to every peer within seconds
- **FORWARD-chain coverage**: containers and VMs behind a node's bridge are protected too. macvlan/ipvlan containers bypass the host FORWARD chain by kernel design — DROP is injected inside such containers
- Survives restarts: lockouts persist to disk and reload on startup
- v4 firewall builds never name iptables built-in chains in nft flushes (avoids clobbering Docker's chains)

## Abuse reporting (MANUAL-ONLY, locked at code level)
- One-click abuse-desk email for a blocked IP, pre-filled with whois-derived abuse contact + audit-log evidence, sent via the existing SMTP transport
- **Operator-pressed Send is the ONLY trigger.** A build-time regression test walks the whole source tree and fails if `send_report` gains any caller other than the single API handler — auto-send is structurally impossible
- whois-only enrichment (no third-party IP APIs), 6h whois cache, 7-day per-IP re-report cooldown (operator-overridable), history capped at 500 (`/etc/wolfstack/abuse-reports.json`, 0600)
- Endpoints: `/api/security/abuse-report/{preview,send,history}`

## Edge (public ingress strategies for HTTP proxies)
Per-proxy "Resilience" strategy for how internet traffic reaches a WolfStack proxy node:
- **Local** (default, no automation), **DNS round-robin** (A-record failover via a DNS provider), **Cloudflare DNS** (proxied=true → CF edge TLS/WAF/DDoS), **Hetzner Load Balancer**, **DigitalOcean Load Balancer**, **Cloudflare Tunnel** (no inbound ports, CGNAT-friendly, installs cloudflared)
- Cloud infra tokens stored in the cloud-providers store (encrypted at rest)
- Endpoints: `/api/edge/cloud-providers*`, `/api/edge/cloudflare-tunnel/install/{proxy_id}`

## Internet Exposure (public URLs for workloads) — v25.2.30+
One page (Storage & Network → Internet Exposure) to give any Docker/LXC container or manual IP:port a public HTTPS URL under a wildcard zone — the fly.io-style "expose a workload, get a URL" flow. Everything is OPT-IN per workload; nothing is public until exposed.
- **Setup once**: zone (e.g. apps.example.com) + ONE wildcard DNS record (`*.zone` → ingress node's public IP) + ingress node choice + TLS cert (picker lists the ingress node's certs with expiry, or manual paths). Ingress needs the WolfRouter HTTP proxy runtime (nginx/wolfproxy) — the page warns if not running
- **Expose**: pick a container from the cluster-wide dropdown (or manual IP:port), choose subdomain + backend port; optional "backend speaks HTTPS". URL live on ingress reload
- **Under the hood**: exposures are auto-managed WolfRouter HttpProxy entries (id prefix `expose-`) — same nginx/wolfproxy render+reload+TLS pipeline; WolfRouter config is cluster-replicated so entries survive workload moves; a 30s reconciler refreshes the upstream IP when a container restarts/moves
- **Cross-node rule**: container bridge IPs are only reachable when the hosting node IS the ingress; otherwise the workload needs a host-published port (-p) — upstream becomes hostingnode:hostport — or a manual IP. Unpublished cross-node expose returns an explanatory error, not a broken route
- v1 scope: single ingress node per zone, HTTP(S) host-routing only (raw TCP/UDP → use a port mapping). Endpoints: `/api/exposure/{status,zone,expose,unexpose}`

## Fleet Logs (loghub — centralized logging)
- Native, dependency-free cluster log aggregation: every enabled node runs a shipper that tails journald (+ optional Docker/LXC logs), **redacts secrets** (key=value secrets, Bearer/Authorization, AWS keys, PEM blocks, JWTs, plus operator regexes), and forwards to a designated **hub node** which stores compressed date-segmented JSONL and answers searches
- **Off by default** (opt-in per node). Config `/etc/wolfstack/loghub.json`: retention 14 days, max 10 GiB, min-free 10%
- Hub pauses ingest (507) on low disk; shippers spool; a `dropped` counter surfaces any loss
- Collection is journald-based (`journalctl -o json` with a persistent cursor, no backlog replay)
- Endpoints: `/api/logs/{stats,ingest,search,config}` + `/api/logs/cluster/{search,stats}`

## Pricing & Tiers
Five paid tiers on Stripe plus free Community use. Authoritative pricing lives at wolfstack.org — verify there for current numbers; as of 2026-07:
- **Community** (no licence) — source-available under PolyForm Noncommercial: free for personal & non-commercial use. **No code-enforced host cap** — the limits are licence terms, not software blocks
- **Homelab £12/mo** — licence issued with max_nodes=10. Clustering, WireGuard bridge, branded status pages, scheduled backups, AI agent, Predictive Inbox + AUTOFIX, OSV scanner, REST API keys
- **Homelab Plus £29/mo** — max_nodes=25. Same feature bundle as Homelab, just a bigger host cap — the enthusiast "missing middle" between Homelab (10) and Team (150). Binary maps tier `homelab_plus` → the homelab feature bundle in compat::resolve_tier
- **Team £149/mo** — max_nodes=150. Adds OIDC/SSO and 24-hour email support (feature bundle is sso + api_keys — plugin store and white-label are MSP+)
- **MSP £499/mo** — unlimited hosts (max_nodes=0). Adds WolfCustom white-label, multi-tenant client portals, plugin SDK, WolfHost, priority support. Was "Pro" before the 2026-05 rebrand
- **Enterprise** — sales-led only, no public price. Custom cap per contract, custom SLA, SOC2/ISO collateral, on-prem/air-gap, bespoke development
- **Soft host cap**: over-cap nodes still join — a warning is attached and a dashboard banner shows, but usage is NEVER hard-blocked ("that's a sales conversation, not an outage"). `max_nodes=0` = unlimited; legacy/sponsor licences carry 0
- **Tier resolution** (`compat::resolve_tier`): signed `tier` field on the licence; `pro` → `msp` (legacy alias). Unknown slugs fall through to `enterprise` (never deny a paid customer a feature on tier-string drift)
- **Feature bundles** (`compat::has_feature`): enterprise = every feature; msp = plugins, api_keys, wolfhost, wolfcustom, multi_tenancy, sso; team = sso, api_keys; homelab/community = explicit features in the licence only (Homelab licences ship api_keys)

## Licensing model (v22.10.0+)
Dual licensing. Releases up to and including v22.9.x remain MIT in perpetuity; v22.10.0+ is dual-licensed.
- **Public source-available**: PolyForm Noncommercial 1.0.0. Free for personal & non-commercial use. NOT OSI "open source" — explicit no-commercial-use clause
- **Commercial licence**: granted by an active subscription to any paid tier. "Commercial use" = running WolfStack at a company, in a managed-service offering, or as part of a paid product; personal homelab use is non-commercial
- Contributions: contributor grants a perpetual dual-licence; a short CLA may be required for non-trivial contributions
- Licence key installed via Settings (POST `/api/platform/apply`), stored at `/etc/wolfstack/license.key`, Ed25519-signed manifest (customer, email, max_nodes, expires, features, tier). `GET /api/platform/status` shows tier/cap/expiry/over-cap state
- A daily licence heartbeat reports to wolfstack.org: licence key, node id/hostname, cluster name, version, os/arch, secret-audit finding count, default-cluster-secret flag

## Supporters (Patreon & GitHub Sponsors)
Separate from commercial licences — donations fund development and grant in-app perks, not features:
- **Patreon link**: Settings-side OAuth connect (client secret never in the binary — token exchange proxied via wolfstack.org). Tiers by pledge: Basic ($3+), Advanced ($25+), Platinum ($95+). ANY paying tier gets the same perks: beta update channel + no login support-nag. Config `/etc/wolfstack/patreon.json`
- **GitHub Sponsors**: honour-system self-attest toggle ("I'm a GitHub Sponsor") — same perks
- **Support tickets** (Support tab): available to licence holders AND declared GitHub sponsors; proxied to wolfstack.org which is authoritative for entitlement
- **Update channels**: `master` (stable) and `beta`. The beta option in the update dropdown unlocks for supporters/licence holders (`/api/patreon/status`, `/api/supporter/status`)
- Endpoints: `/api/patreon/{connect,callback,status,sync,disconnect}`, `POST /api/sponsor/github`

## Enterprise Features
- REST API keys (wsk_* tokens) with scoped permissions
- Plugin system, OIDC/SSO, WolfHost (web hosting platform), WolfCustom (white-label branding), multi-tenant portals

## Plugin System
- Plugins installed to /etc/wolfstack/plugins/{id}/ — manifest.json + web/plugin.js + optional bin/handler backend
- Backend plugins run as child processes, expose HTTP endpoints under /api/plugins/<plugin>/…
- Plugin Store: fetches index, one-click install; reinstall kills the old handler and starts the new one
- Handler binaries must be statically linked (musl) for cross-distro compatibility
- Plugins run as root — sandboxed only by Unix permissions, so trust matters

## Clustering
- Nodes discover each other via HTTP polling every 10 seconds
- Cluster secret for inter-node authentication (default secret used if no custom-cluster-secret file — flagged by the secret audit)
- Node proxy: /api/nodes/{id}/proxy/{path} forwards API calls to remote nodes
- Join failures list EVERY URL tried with its error (not just the last fallback)
- **Which NIC does cluster/migration traffic use?** A node is reached at its `address` (the IP/hostname you typed when adding it — set it to the interface you want, e.g. a 2.5GbE NIC's IP, and ALL WolfStack↔node traffic uses that link). To pin *only* migration/bulk transfer to a different NIC, set the optional **Migration address** in that node's settings (node settings card → "Migration address") to that interface's IP. VM and LXC migration uploads then ride that host, while cluster/control traffic keeps using `address`. Blank = use `address`. There is no separate "migration network" object beyond this per-node override.
  - How it reaches the source: when you start a migration from the UI, the frontend forwards the target's configured Migration address (`target_migration_address` in the migrate request) so the SOURCE node uploads over the pinned NIC even if its own gossip view of the target predates the setting (`Node::migration_host()` is the fallback for non-UI callers). If the pinned NIC turns out unreachable, migration falls back to the node's `address` rather than failing. Verify with `iftop`/`nload` on the NIC during a migrate — if you see management-NIC traffic instead, the pinned IP isn't reachable from the source (check the 2.5GbE subnet routing/firewall).

### Server vs agent install mode (v22.6.9+)
- Two install modes at setup.sh time: server (default) and agent (`--agent`)
- Server: full management UI on :8553. Run on ONE node per management domain
- Agent: cluster API stays bound (master's node-proxy works), but the SPA/static assets are NOT served; `/` returns a small explainer page
- setup.sh appends `--agent` to the systemd ExecStart; rerunning with the opposite flag sed-edits the unit (backup saved)
- Agent mode does NOT reduce runtime deps — nodes still need LXC/Docker/QEMU to run workloads
- If the master rotated the cluster secret, agents need the same `/etc/wolfstack/custom-cluster-secret`

### Federation (read-only cross-cluster links)
- Registry of OTHER WolfStack clusters this one trusts for aggregation — NOT a merge; each cluster stays its own admin domain
- Each entry = base_url + a read-scoped API key minted on the remote cluster (Settings → API Keys); stored 0600 in federations.json, never shown back in the UI
- Used by e.g. the Gateway page to surface shares from every connected cluster

### Dashboard sync (config push to peers)
- Operator-triggered only ("Push now" to chosen node IDs) — no automatic replication
- Pushes a fixed allowlist of admin-curated config files (users/auth, statuspages, alerting, backups, storage, arrays, ceph, kubernetes, vms, providers, router, ai-config, etc.); receiver rejects non-allowlisted paths
- Explicitly excluded: per-node hardware state, TLS certs, cluster secret, join token
- Endpoints: `/api/dashboard-sync/{targets,push,receive}`

## Integrations (connector framework)
Settings/page for third-party systems; credentials AES-256-GCM encrypted in `/etc/wolfstack/integrations/vault.json` (survives cluster-secret rotation via loss-free re-encrypt).
- **NetBird VPN** — peers/groups/routes/users; ops: disable/enable peer, create group
- **TrueNAS** — pools/datasets/snapshots/shares (this connector is REST-based; migration to WS pending TrueNAS 26.04)
- **UniFi** — devices/clients/networks; ops: block/unblock/reconnect client, restart device
- Actions run via `POST /api/integrations/{id}/action`; WolfFlow has matching NetBird/TrueNAS/UniFi/generic-integration steps

### TrueNAS main integration (src/truenas)
- Registers TrueNAS servers to view pools/datasets/disks/NFS exports/ZFS snapshots (create/delete)
- **Transport: WebSocket JSON-RPC 2.0 (`wss://host/api/current`) is PRIMARY** with REST `/api/v2.0` fallback, chosen per host and cached — REST-first polling triggered TrueNAS 25.10's "deprecated REST API" nag. CORE/old-SCALE hosts fail the one-time WS probe and stay on REST
- Instances in `/etc/wolfstack/truenas.json`; API key encrypted at rest, never sent to the browser; per-instance cluster tag

### Unraid integration (src/unraid)
- Registers Unraid servers over the official GraphQL API (`x-api-key`): array/disks/shares/parity history/Docker/VMs
- Store `/etc/wolfstack/unraid.json`, key encrypted at rest. GraphQL reports sizes in KILOBYTES — converted once at ingest

## WireGuard Bridge (VPN access INTO the cluster from outside)
This is the answer to "how do I connect from my office / phone / laptop to my WolfStack cluster or WolfNet?".
- Each cluster gets a unique /24 in 10.20.0.0/16 for its WireGuard bridge
- Config in /etc/wolfstack/wireguard-bridge.json (per-cluster entries)
- UI: Settings → WireGuard Bridge → Create bridge for cluster → add clients; each client gets a .conf download
- Endpoint = cluster node's public IP + listen port (default 51820, configurable)
- Client traffic routes into WolfNet, reaches every node + container/VM on the mesh
- Requires `wireguard-tools` on the host; multiple bridges per host supported
- **WolfNet is NOT WireGuard**: WolfNet is the internal mesh; the WireGuard bridge is the external-client door into it
- WG private keys written 0600 to /tmp, consumed by `wg set`, then removed

## WolfRouter (native firewall / DHCP / DNS / WAN router on any node)
- **Zones**: WAN / LAN / DMZ / WolfNet / Trusted / custom, per interface
- **LAN segments**: each LAN = subnet + DHCP range + DNS. dnsmasq per-LAN, pidfiles in /run/wolfstack-router/
- **DNS modes per LAN**: "WolfRouter" (dnsmasq serves :53) or "External" (DHCP-only, option 6 points clients at AdGuard/Pi-hole)
- **Firewall**: iptables via iptables-restore, atomic swap; pre-flight refuses rules that would lock the admin out of :8553/:8554
- **Safe-mode rollback**: firewall apply registers a deadman switch (default 120s) — no "Keep" click → previous ruleset restored
- **WAN types**: DHCP, static, PPPoE (chap-secrets 0600)
- **Host DNS panel**: release systemd-resolved's stub and/or move WolfRouter's dnsmasq off :53 — both deadman-switched
- HTTP proxy hosts (reverse-proxying sites through the router) and self-heal `fix/*` endpoints also live here
- Replicates config across cluster nodes; /etc/wolfstack/router.json is the source of truth
- Diagnostic note: `dig @router_ip` from the host itself routes via loopback — use the query log + tcpdump to diagnose LAN client DNS

## Advanced networking
- **LAN bridge builder** (`lan_bridge`): create a real L2 bridge enslaving a host NIC (e.g. br0 over eth0) so bridged LXC/VM guests are LAN-reachable. Migrates the NIC's IP to the bridge first; touching the management NIC requires accept_risk + a **90-second commit-confirm timer** that auto-reverts runtime AND persistence if not confirmed. Persists via NetworkManager/systemd-networkd/ifupdown
- **VLAN attachments** (`vlan.rs`): provider-agnostic 802.1Q attachments + routed public IPs (proxy-ARP + DNAT). Presets: **Hetzner vSwitch** (VLAN 4000-4091, MTU 1400 mandatory), OVH vRack, Equinix Metal, Custom. State `/etc/wolfstack/vlan-attachments.json`; config writers for ifupdown/netplan/NetworkManager/systemd-networkd
- **Guest VLAN attach** (`vlan_attach`): attach LXC (native + Proxmox), Docker (macvlan/bridge), and VMs to a VLAN bridge. VM IPs are staged via cloud-init (NoCloud seed ISO or `qm set --ipconfigN`) and apply on next boot — they cannot be set at runtime from the hypervisor

## WolfRun (container orchestration across the cluster)
- Services = (image, replicas, placement, restart policy). Reconciler loop every 15s
- Placement: any node, specific node, all nodes (DaemonSet-like), per-zone
- Restart policy `Always` auto-restarts exited containers next tick
- Failover events → /etc/wolfstack/wolfrun/failover-events.json
- Only the cluster LEADER runs the reconciler (lowest node_id heuristic)
- Config: /etc/wolfstack/wolfrun/services.json; UI: Datacenter → WolfRun

## WolfUSB (network USB device passthrough)
- Expose host-plugged USB devices to containers/VMs on any node via USB/IP
- Each node runs a wolfusb server on :3240 (key in /etc/wolfusb/wolfusb.env, same cluster secret)
- Requires kernel modules vhci-hcd (client) + usbip-host (server) — auto-modprobed
- Cross-node attach; re-attach on container restart is automatic (on_container_started hook)
- Common use: Zigbee/Z-Wave dongles for Home Assistant VMs, license dongles, webcams

## WolfKube (Kubernetes lifecycle + management)
- Cluster modes: self-hosted (k3s/kubeadm installed by WolfStack), or attach an existing kubeconfig
- Kubeconfigs stored at /etc/wolfstack/kubernetes/<id>.yaml mode 0600
- Pod terminal: WebSocket console to any container (`kubectl exec` under the hood)
- Scale/delete workloads from the UI; per-pod resource usage; join tokens cluster-secret-auth'd

## Cluster Browser (unified web UI for every cluster-internal service)
- A real Firefox running on a cluster node; log in from anywhere and you're inside the cluster network — no VPN, no per-app proxy
- Services are added manually via "+ Add custom URL" (pinned per-user); WolfStack does NOT auto-scan the cluster — an automatic port scan on every page visit could peg CPU on a large estate, so it was removed
- Pinned services appear on the homepage of every Cluster Browser session; config /etc/wolfstack/cluster-services-by-user/<user>.json

## Control Panel (cluster-wide workload view)
- Single view of every VM/LXC/Docker container across all nodes; group by Node/Type/Status/Cluster or drag-drop **Custom groups**
- Custom groups persist server-side (`/etc/wolfstack/control-panel.json`); vanished workloads render as "stale"
- Endpoints under `/api/control-panel/…` (inventory, groups CRUD, members)

## Home dashboard (customisable widget home) — v25.2.24+
The home "Datacenter" view is a per-user, 12-column widget grid. Default layout is identical to the classic home; Customise enters a DRAFT edit mode (drag reorder, resize 1–12 cols + px/auto height, per-widget ⚙ config; Save changes / Cancel; leaving with unsaved changes prompts).
- **20 widget types**: servers, cluster stats, infrastructure map, bookmarks, server resources (live gauges), containers, uptime monitors, recent alerts, recent backups, storage usage, TLS certificates, UPS power (live faceplate per server), threat intel, AI assistant, clock, weather (Open-Meteo, no key), web search (DDG/Google/Brave/custom, inline instant answers), notes, RSS feed, embedded page (iframe)
- **Fleet scopes** on infra widgets (containers/uptime/alerts/backups/storage/certs/threats): this cluster, a named cluster, or the whole fleet (parallel per-node fan-out)
- Layout persists per user server-side (`/etc/wolfstack/user-prefs/<user>.json` via /api/user/preferences) — follows the user across browsers. Background image upload retained
- External fetches (weather/RSS) try direct browser fetch, falling back to `GET /api/dashboard/fetch-proxy` (authed, http(s)-only, refuses link-local/metadata IPs, 1 MiB cap)

## Configurator (form-based config for Wolf components)
- Structured config UIs: **WolfProxy** (nginx sites — CRUD/enable/disable/test/reload/error-log/generate/bootstrap), **WolfServe** (Apache vhosts + modules), **WolfDisk/WolfScale** (structured TOML editing with validate/repair)
- Endpoints under `/api/configurator/…`

## Predictive Inbox (v22.7.0+)
Unified ops inbox that surfaces problems before they page someone; proposed remediations approved with a click.
- Analyzers on a tick: backup freshness, certificate expiry, cluster health, container disk/memory/restart-loop, host disk fill + disk SMART verdict (Backblaze-informed SMART 5/187/197/198 + NVMe critical-warning/spare/media-errors — failing disks raise Issues + an amber Storage badge), OSV/CVE scanner, port-conflict detector, security posture, threshold breaches, unused packages, VM disk fill, vulnerability scan, WolfNet DHCP. Source in `src/predictive/`
- Proposals carry severity, scope key (dedupe), evidence, and a RemediationPlan
- **Embedded terminal pane** per proposal — sandboxed shell on the affected host
- **AUTOFIX**: deterministic, reversible plans apply with one click through the deadman-switch framework
- **OSV.dev + CISA KEV scanner**: CVEs across OSV-indexed distros for hosts AND LXC; severity floor configurable; auto-suppresses no-fix CVEs
- **Port-conflict analyzer**: silent publish failures + host-port collisions; skips host/container-netns containers (diff meaningless there)
- Pre-flight validator dry-runs checkable proposals; multi-cluster aggregation; optimistic UI; mobile layout
- Endpoints under `/api/predictive/…`

## WolfStack Gateway (v22.9.0+)
Universal SMB/NFS share head — turn any node into a NAS frontend regardless of where storage lives.
- Sources: local dir, S3, NFS upstream, SMB upstream, SSHFS, WolfDisk, RBD, mdadm/NoNRAID arrays
- Re-exports as SMB (Samba) and/or NFS under one Gateway config
- **Cross-cluster federation**: a Gateway on cluster A can proxy a share living on cluster B (via the Federation registry)
- Orchestrator reconciles /etc/samba/ + /etc/exports to the declared config
- UI: Datacenter → WolfStack Gateway

## Storage Array (v22.9.0+)
- Disk-array management for **mdadm** and **NoNRAID** (Unraid-style) backends
- Create / assemble / start / stop / monitor from the UI; cluster-wide aggregation
- Renders as a first-class storage target; endpoints under `/api/array/…`

## Galera / WolfScale / Gluster managers (database & storage cluster provisioning)
- **Galera manager**: create or adopt MariaDB Galera clusters built from LXC containers across WolfStack nodes; live wsrep status; **evidence-based recovery** from grastate.dat seqno (split-brain rejoin from the most-advanced survivor); MaxScale deployment; default SST mariabackup. Config /etc/wolfstack/galera.json
- **WolfScale manager**: builds/manages WolfScale replication clusters (single-leader, WAL-based, lowest-node-id wins) — each node = LXC with MariaDB fronted by the `wolfscale` binary. Ports: 7654 (replication), 8007 (MySQL proxy), 8080 (control API). Config /etc/wolfstack/wolfscale.json
- **Gluster**: GlusterFS trusted-pool management by driving the `gluster` CLI — install, bootstrap, non-destructive **import/adopt** of a running glusterd, peers, volume CRUD, bricks, self-heal

## Ceph integration
- Full lifecycle, not just attach: **install + bootstrap** (mon/mgr/osd), join existing, OSD add/remove/reweight, pool CRUD, CephFS, RBD images, balancer/flags/PG actions
- RBD volumes are a first-class storage target
- Endpoints under `/api/ceph/…` (install, bootstrap, join, cluster-bundle, pools, osds, fs, rbd…)

## WolfStack Pools / XCP-ng + Xen Orchestra
Sell N VMs → auto-deploy as a federated tenant cluster.
- **XCP-ng via Xen Orchestra's REST API** (not raw XAPI): pools/hosts/VMs inventory, VM lifecycle, templates, create/delete. Tokens encrypted at rest in /etc/wolfstack/xo_pools.json, never sent to the frontend. UI: XO Pools page
- **Tenant Pools**: provision a multi-VM tenant cluster (1–10 VMs) as one unit across **three implemented backends — XO, Proxmox (clone from template + cloud-init snippet), native QEMU/libvirt (cloud-localds NoCloud seed)**. Cloud-init pre-seeds the shared cluster secret + per-VM join tokens; the tenant leader self-registers back via `/api/tenants/self-register`

## Discord / Telegram / WhatsApp bots (AI access from chat)
- Each bot runs as a supervised background task; credentials in /etc/wolfstack/ai-config.json (0600)
- Bots relay to the AI agent (same tool loop as dashboard chat)
- Discord: bot token, replies in-thread. Telegram: bot token, /start, 4096-char chunking. WhatsApp: Baileys gateway (Node.js subprocess), one-time phone pairing
- Named WolfAgents can also bind their own Discord/Telegram/WhatsApp identities

## MCP endpoints (Model Context Protocol shaped)
- NOT a full MCP server (no initialize handshake, no stdio/SSE transport). Two HTTP endpoints matching MCP JSON shapes: `POST /api/mcp/tools/list` and `POST /api/mcp/tools/call`
- Auth: standard WolfStack session cookie
- **Read-only, three tools**: list_nodes, get_metrics, list_containers_local

## SQL Connections + MySQL/MariaDB editor
- **SQL Connections** (`/api/sql-connections/…`): guarded pool shared by WolfAgents and WolfFlow SqlQuery steps. MariaDB/MySQL/Postgres. Every exec: sqlparser statement classification against the connection's declared tier (Read/Update/Delete; DDL never allowed; stacked statements rejected), 5s connect / 30s exec timeouts, 10k rows / 10 MB caps, audit log at /var/log/wolfstack/sql-audit.log. Passwords AES-encrypted at rest. Saved queries + history
- **Database Manager / MySQL editor** (older surface): browse schemas/tables, ad-hoc queries, edit rows

## Deadman-switch framework (Level 2 safety)
Any operation that can brick the node's UI registers a rollback closure with a TTL. No "Keep" click before expiry → rollback fires.
- Host DNS release: 120s → restore systemd-resolved stub
- WolfRouter firewall apply: 120s → revert ruleset
- Interface down: 90s → bring it back up (LAN-bridge builds use the same pattern)
- Endpoints: GET /api/danger/pending, POST /api/danger/confirm/{id}, POST /api/danger/rollback/{id}
- Frontend banner polls every 2s, survives session expiry and network blips

## System Check (distro-aware diagnostics)
- UI: Settings → System Check
- Battery of tests: kernel modules, iptables/nftables, services, ports, disk, memory, package manager health, plus the security posture rows
- Each failing check pairs with a distro-aware one-click "Fix" (apt/dnf/pacman/apk/zypper)

## Services Discovery
- Cluster Browser services are added manually by the user ("+ Add custom URL", pinned per-user). WolfStack does NOT auto-scan nodes for them — an automatic cluster-wide port scan on page load could peg CPU, so it was removed
- Pinned definitions at /etc/wolfstack/cluster-services-by-user/<user>.json (auto-discovered cache, if ever populated: /etc/wolfstack/cluster-services-discovered.json)

## Components page
- Installs/monitors the Wolf ecosystem components on each node: **WolfNet** (mesh VPN), **WolfProxy** (reverse proxy + firewall; counted as running when PIDs listen on :80/:443 even if its unit reads inactive — it daemonizes), **WolfServe** (web server), **WolfDisk** (distributed FS), **WolfScale**, **MariaDB**, **PostgreSQL**, **Certbot**
- Config paths: /etc/wolfnet/config.toml, /opt/wolfproxy/wolfproxy.toml, /opt/wolfserve/wolfserve.toml, /etc/wolfdisk/config.toml
- Installs run each component's setup.sh (prebuilt CI binaries — Wolf components never compile on the host)
- wolfusb and wolfrun are separate subsystems, NOT Components-page entries

## Security posture summary (file hygiene)
- All sensitive files under /etc/wolfstack/ are mode 0600; the directory itself 0700; `paths::harden_existing` migrates old installs on startup
- Cluster secret validation is constant-time including length
- AI's [READ] tool has a hard-coded deny-list covering every credential file
- AI's [EXEC] pipe allowlist applies to EVERY pipe segment; approved [ACTION]s block `;`, `&&`, `||`, newlines

## AI tool tags reference (for the agent itself)
- `[EXEC]cmd[/EXEC]` — local read-only shell, allowlist of safe commands only
- `[EXEC_ALL]cmd[/EXEC_ALL]` — same command on every cluster node, results labelled by hostname
- `[ACTION id=".." title=".." risk="low|medium|high" explain=".." target="local|all"]cmd[/ACTION]` — proposes a fix the operator approves with one click
- `[WOLFNOTE title="..."]body[/WOLFNOTE]` — save a note for the user
- `[WEBSEARCH query="..."][/WEBSEARCH]` — DuckDuckGo top 5 results
- `[FETCH url="..."][/FETCH]` — fetch a URL, strip HTML, 8 KB cap, SSRF-guarded
- `[READ path="..."][/READ]` — read a WolfStack runtime file from a sandboxed allow-list
- `[SECURITY_AUDIT][/SECURITY_AUDIT]` — run the built-in security audit

## Common Issues

### VM won't boot after NIC change (UEFI)
OVMF boot entries reference device paths. Fix: v16.16.9+ auto-resets EFI vars. Manual: delete {name}_VARS.fd.

### VM has no IP (WolfNet)
Check dnsmasq: `ps aux | grep dnsmasq | grep tap`. WolfStack starts a per-VM dnsmasq on the TAP interface.

### VM has no IP (Bridge/Physical NIC)
Check bridge exists (`ip link show type bridge`), NIC is a member (`bridge link show`), router DHCP reaches through.

### systemd-networkd-wait-online.service failed
Harmless — timed out waiting for all interfaces. Common with bridges/TAPs/VPNs.

### Plugin backend not starting
`file /etc/wolfstack/plugins/{id}/bin/handler` — must be statically linked (musl).

### WolfHost "could not reach WolfStack API"
WolfHost tries HTTPS:8553 then HTTP:8554, both custom and default cluster secrets. Restart the WolfHost handler after a WolfStack upgrade.

### VM terminal opens but is blank
Guest lacks a serial console: add `console=ttyS0` to the kernel cmdline + enable a getty on ttyS0. Host side is wired automatically.

### "VM not found in qm list" when opening terminal
PVE-only — the VM isn't in `qm list` (created outside Proxmox or PVE DB out of sync).

### "Add serial console?" prompt on a PVE VM created in the Proxmox web UI
Offers `qm set <vmid> --serial0 socket`; reboot needed if running.

### "Standalone VM was started before serial-console support was added"
Stop + start the VM (not restart — the socket is created at spawn time).

### SMB backup to Synology/QNAP hangs or fails
Default is SMB 3.0; older firmware may need `vers=2.1` in smb_options. Check share permissions/guest access.

### "MISSING_PACKAGE|mount.cifs|..." error
cifs-utils (or nfs-common/…) missing. Accept the confirm prompt — the install runs in a live terminal. Retry the mount afterwards.

### Docker container ports show strikethrough + "host ports the daemon never bound"
False positive for `network_mode: host` / `container:<id>` — fixed v22.9.47 (no diff in those modes). If a host-mode service is genuinely down, check container logs + host firewall.

### System Logs page empty on Unraid / Alpine
Those platforms have no journald. WolfStack falls back to tail-reading `/var/log/syslog` then `/var/log/messages` (v25.2.12+); the unit filter matches the syslog tag. If both files are absent it says so explicitly.

### WolfDisk node stuck at index v0 / "N behind" forever
Almost always **mixed wolfdisk versions** — check the Version column on WolfDisk Cluster Health or run `wolfdisk --version` on every node. Mixed clusters cannot sync (wire-format change); stop all, upgrade all, start all.

### Cluster node dark after reboot but service "active (running)"
Startup-hang class (fixed v25.2.8–.11): journal stops right after "Public IP:" with no "Serving web UI" line = a pre-bind subsystem (dead dockerd/containerd, wedged FUSE mount) was blocking. Current versions bind the dashboard first and WARN about the sick subsystem instead. Check `systemctl status containerd` and look for D-state docker CLI children.

### Home Assistant VM setup
1. Import the HAOS QCOW2 via "Import Disk Image"
2. BIOS = OVMF (UEFI)
3. Bridge NIC for LAN access
4. Zigbee/Z-Wave dongle via Passthrough tab (or WolfUSB from another node)
5. No IP → `ha network update enp0s3 --ipv4-method static …` from the HA CLI

## Common user questions → where to point them
- **"Connect from outside to my cluster/containers"** → WireGuard Bridge (Settings → WireGuard Bridge)
- **"How do I get two nodes to talk securely?"** → WolfNet (invite → join token)
- **"Make this node a router / firewall / DHCP server"** → WolfRouter
- **"Run code without managing a container"** → WolfFunctions (serverless, Python/Node, public URL + schedules + events)
- **"A persistent AI assistant with its own memory/permissions"** → WolfAgents
- **"Automate a maintenance job across nodes"** → WolfFlow (23 step types incl. backups, SQL, integrations, AI)
- **"Plug a USB device into my Home Assistant VM on another node"** → WolfUSB
- **"Run a container on whichever node is free"** → WolfRun
- **"Public status page for my apps"** → Status Pages
- **"Give this container a public URL / put my app on the internet"** → Internet Exposure (Storage & Network; one wildcard DNS record + ingress node, then expose per workload)
- **"Customise my home page / add widgets"** → Home dashboard (Customise button on the home view; 20 widget types incl. weather, RSS, notes, UPS)
- **"Cron / PHP / my app can't send email from the host"** → Host Mail Relay (Settings → AI & Email; installs msmtp as /usr/sbin/sendmail using the alert-email SMTP settings)
- **"Shut things down cleanly when my UPS is on battery"** → UPS Power (per-server page; reads any existing NUT setup via `upsc`, never touches NUT config; staged shutdown: at ≤X% battery stop VMs/containers, at ≤Y% stop shares, at ≤Z% power off; fires ups_on_battery/ups_online/ups_stage_fired WolfFunctions events + alerts; also a home-dashboard widget)
- **"Manage Kubernetes from WolfStack"** → WolfKube
- **"See all my web services in one place"** → Cluster Browser; **"see every workload in one table"** → Control Panel
- **"Search logs across all my nodes"** → Fleet Logs (loghub — enable it first, it's off by default)
- **"Block known-bad IPs automatically"** → Threat Intelligence (Security page; starts in dry-run)
- **"Someone is brute-forcing my login"** → Login lockout is on by default (3 strikes/48h); add your own IP to Trusted IPs first
- **"I think a node is compromised"** → Fleet Security host audit + emergency root rotation; the AI can run [SECURITY_AUDIT]
- **"Put my NAS shares / S3 bucket behind SMB/NFS"** → WolfStack Gateway
- **"Manage my TrueNAS / Unraid / UniFi / NetBird from here"** → the matching integration pages
- **"Back up my containers / VMs"** → Backups (7 destination types; pre/post hooks available)
- **"Use WolfStack from Claude Desktop / Cursor"** → the /api/mcp endpoints are read-only tool stubs (3 tools) — not a full MCP server yet; say so honestly
- **"Chat with my cluster from my phone"** → Discord / Telegram / WhatsApp bots

## Learn courses (in-app onboarding — THREE courses with a picker)
The Learn drawer opens beside the live UI (compass button, dashboard banner, Apps & Tools tile, welcome modal, per-page "?" help). Each lesson has an "Ask the AI about this lesson" button that seeds this chat. When a "how do I…" question matches a lesson, answer directly AND point to it by name.

**Getting Started** — Before you start (What even is a server?); Find your feet (What WolfStack is; 2-minute tour; The only six things); Your servers; Your first app; Build a container yourself (Docker/LXC/VM); Get a terminal; Keep your data safe (backup/automatic/restore); Lock it down (login hardening; server hardening — lockout policy, trusted IPs, exposed ports, NMAP protection, threat intel, emergency root rotation); Stay ahead of problems (Issues page; phone alerts; status page); Go further (real domain + HTTPS); The map of everything else; Starter checklist.

**Level 2 · Going Further** — Link servers with WolfNet; Run a full VM; Storage that outgrows one disk; Automate with WolfFlow; AI co-pilot (WolfAgents); You're an operator now.

**Level 3 · Defend Your Systems** — Think like a defender; Control what's reachable (firewall); Catch malware and intruders; No default secrets, no stale software; See attacks coming; When something gets in; The defender's checklist.

Routing: "how do I take a backup?" → Getting Started backup lessons. "restore my data" → Restore lesson. "I'm being attacked / secure this" → Lock it down + Level 3. "put my app on a domain / HTTPS" → Go further. "what is all this?" → Find your feet. "grow beyond one server" → Level 2.

## Video tutorials (YouTube — link users to these)

A short companion tutorial exists for most features, on the IntelligentWolf Ltd YouTube channel. When a user asks "how do I…", "show me…", or "is there a video for…" about one of these, give the direct link. The same videos are embedded in the in-app **Learn** course lessons and on the matching wolfstack.org doc page. They live on YouTube (external embeds) — nothing is stored inside WolfStack, so links never go stale on upgrade.

- **Create an LXC Container (Every Option Explained)** — https://youtu.be/ucX3BbcBT0w — Create a Linux container from a template and walk through every field — name, root password, memory, CPU, notes, storage, bind mounts, and all three networking modes. (doc: wolfstack-containers.php)
- **HA: High Availability for LXC Containers (No Quorum, 2-Node Ready)** — https://youtu.be/irbL3mZvCl0 — Protect a container so it survives a node dying. Set replicas and priority, sync interval, and automatic failover with a witness — keeping the same name, MAC and IP. (doc: wolfstack-ha.php)
- **A Tour of Every Settings Tab** — https://youtu.be/AxbtAvSSR98 — Walk through Appearance, Profile, Alerting, the AI agent, Backup, Users & Security, DNS and Cloud providers. (doc: wolfstack-settings.php)
- **Mount Network Storage (NFS, SMB, SSHFS, S3, WolfDisk)** — https://youtu.be/441fFeVer-Q — Add a network mount, see where each provider appears, and check physical disk health. (doc: wolfstack-storage.php)
- **Networking, vSwitch VLANs & Edge Exposure** — https://youtu.be/azpxpBh2Gm4 — WolfNet mesh, attaching a container to an 802.1Q VLAN vSwitch, LAN bridges, and cloud/Cloudflare edge exposure. (doc: wolfstack-networking.php)
- **Back Up & Restore Containers and VMs** — https://youtu.be/nR-Q5liyP_o — Select workloads, choose a destination, schedule automatic backups, and restore on any node. (doc: wolfstack-backups.php)
- **Manage Virtual Machines (QEMU & Proxmox)** — https://youtu.be/Gv-zOuaCQt8 — Create a VM, attach ISOs, take snapshots, and open a browser VNC console. (doc: wolfstack-vms.php)
- **Issue Free SSL Certificates (Wildcard via DNS)** — https://youtu.be/UvsZflVfFA8 — Issue a wildcard Let's Encrypt certificate over DNS validation, with auto-renewal and a local CA. (doc: wolfstack-certificates.php)
- **Security, Users, Authentication & Passkeys** — https://youtu.be/QbS0AXqi_rE — Threat detection, user and auth management, passkeys, and event logging. (doc: wolfstack-security.php)
- **SMB & NFS File Server in a Few Clicks** — https://youtu.be/8aMrSBsA9BE — Turn any node into a Samba or NFS file server and control access. (doc: wolfstack-shares.php)
- **Run a Ceph Cluster from the Dashboard** — https://youtu.be/0-QmvsuyWOc — Bootstrap Ceph, add OSDs, create pools, CephFS and RBD, and handle day-two operations — no CLI. (doc: wolfstack-ceph.php)
- **High-Availability MariaDB with Galera** — https://youtu.be/giYRzQBgecc — Provision or adopt a synchronous MariaDB Galera cluster and watch its health. (doc: wolfstack-galera.php)
- **Stand Up Kubernetes with WolfKube** — https://youtu.be/Vamdffv5Bxc — Provision a control plane, join workers, or import an existing kubeconfig. (doc: wolfkube.php)
- **Container Orchestration with WolfRun** — https://youtu.be/3BCczfowvPE — Define a service, scale copies across nodes, and get automatic self-healing — lighter than Kubernetes. (doc: wolfrun.php)
- **Build a Redundant Storage Array (mdadm + Parity)** — https://youtu.be/f3sE7hCdn5Q — Assemble a RAID or parity array from local disks, with health and parity checks. (doc: wolfstack-array.php)
- **SMART Drive Health & Failure Prediction** — https://youtu.be/Rg_-QYN90Y4 — Standby-aware SMART monitoring, sector alerts, and a drive lifespan graph. (doc: wolfstack-drive-health.php)
- **The Built-in Database Manager (MySQL/MariaDB)** — https://youtu.be/WiaQ30fnXWs — Browse databases, run queries, and edit rows inline — no separate client. (doc: wolfstack-mysql.php)
- **UPS Monitoring & Staged Shutdown** — https://youtu.be/vvgj9C-NSuo — Read UPS battery and runtime, and set per-node shutdown thresholds and order. (doc: wolfstack-ups.php)
- **Schedule Cron Jobs from the Dashboard** — https://youtu.be/oX1gT1y-XQY — Enter a command, build a schedule visually, choose the user, and manage jobs — no SSH. (doc: wolfstack-cron.php)
- **The Browser Web Terminal** — https://youtu.be/Bfl7OmImhEw — Open shells on nodes or containers, use tabs and split panes, and pop out windows. (doc: wolfstack-terminal.php)
- **The Web File Manager** — https://youtu.be/ysQxqCCwDb8 — Browse, edit with syntax highlighting, and upload or download files on any node. (doc: wolfstack-files.php)
- **The Issues Scanner & Health Checks** — https://youtu.be/n2OyB0X7Kew — Scan the fleet, read findings by severity with remediation, and act via the Predictive Inbox. (doc: wolfstack-issues.php)
- **The Predictive Inbox** — https://youtu.be/h1fTK6IvD84 — Findings once, not on every refresh — snooze, dismiss, or acknowledge known conditions. (doc: wolfstack-predictive.php)
- **Set Up Alerting (Discord, Slack, Telegram, Email)** — https://youtu.be/TioEKs3dkRU — Add channels, set thresholds, choose alert modes, and use quiet hours. (doc: wolfstack-alerting.php)
- **Public Status Pages & Uptime Monitors** — https://youtu.be/-RnZQdUgogE — Add monitors, build a branded public status page, and record incidents. (doc: wolfstack-statuspage.php)
- **Expose a Service to the Internet Safely** — https://youtu.be/lh3Y8338Wi4 — Port forward, a cloud load balancer, or a Cloudflare tunnel — provisioned and torn down automatically. (doc: wolfstack-exposure.php)
- **Deploy 500+ Apps in One Click (App Store)** — https://youtu.be/WXROyaA8Rqo — Browse by category and deploy an app as a managed container in one click. (doc: app-store.php)
- **AI Assistants for Your Fleet (WolfAgents)** — https://youtu.be/qWOTQ6sD5DA — Draft an agent, give it tools, and bind it to a chat channel like Discord or WhatsApp. (doc: wolfstack-agents.php)
- **Manage Your Whole Fleet (Cluster Browser)** — https://youtu.be/DbiNp2U1yy4 — Drive any node in the fleet — containers, storage, terminals — from one dashboard. (doc: wolfstack-cluster-browser.php)
- **Multi-Server Clustering** — https://youtu.be/xH7hAq-N8qs — How servers appear grouped by cluster, adding a node, and what spans the fleet. (doc: wolfstack-clustering.php)
- **The Customisable Home Dashboard** — https://youtu.be/DyJxgP6MQng — Add, drag and resize 20 widgets with per-cluster and fleet-wide scopes. (doc: wolfstack-home-dashboard.php)
- **Fleet-Wide Log Search (Fleet Logs)** — https://youtu.be/--ZrNOdV2n4 — Search every node at once, live-tail, and set retention. (doc: wolfstack-fleet-logs.php)
