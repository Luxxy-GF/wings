# Incus 7.0 LTS executor (experimental)

This backend follows [PR #34's LXC runtime approach](https://github.com/calagopus/wings/pull/34), with Incus replacing Proxmox and [Incus NAT proxy devices](https://linuxcontainers.org/incus/docs/main/reference/devices_proxy/) publishing allocations. Select it explicitly with `runtime.backend: incus`; Docker remains the default. Runtime configuration changes require a restart.

## Architecture

| PR #34 model | Incus implementation |
| --- | --- |
| Shared runtime factory | `create_runtime` returns an executor and an optional Docker connection |
| OCI templates in managed storage | Digest-pinned OCI imports through the official Incus client, cached by Incus fingerprint, with image environment defaults preserved |
| Separate runtime and helper LXC containers | Owned `wgs-`, `wgi-`, and `wgx-` Incus instances |
| Existing Wings server directory bound into LXC | Host directory mounted at `/home/container`, or `/mnt/server` for helpers |
| OCI user and host data ownership | Incus resolves the OCI UID/GID; `raw.idmap` maps the non-root Wings data account to that user |
| Host file APIs, quotas, backups, and inotify | Existing Wings filesystem and disk-limiter implementation remains responsible |
| Proxmox bridge/edge forwarding | Incus-managed bridge, private addresses, and TCP/UDP NAT proxy devices |

Images are pulled from the egg/helper registry reference. There is no local Containerfile/Buildah recipe path. The official Incus client handles OCI conversion through `image export` and `image import`, using temporary archives and a private client configuration without modifying operator CLI remotes. This avoids Incus 7.0.1's OCI relay-copy alias bug. Allow temporary disk space for the converted archives beneath the Wings root directory. Incus instance, storage, lifecycle, console, and forwarding operations use the REST API over the local Unix socket.

Root disks are disposable Incus storage volumes. Private launch scripts and process-control files use separate Incus custom volumes mounted at `/opt/wings-control`, outside panel-visible data and the image's `/run` mounts. A simple file entrypoint preserves multiline arguments through LXC's configuration parser. Process files live in the image-user-owned `/opt/wings-control/process` child directory. Instance cleanup preserves the host server directory. Explicit server deletion uses Wings's normal filesystem deletion path.

## Requirements and configuration

### Build on the node

Build from this branch on the node to use its native architecture and system libraries. Install Rust 1.99.0 or newer through rustup, plus a C/C++ toolchain, Clang, CMake, pkg-config, and OpenSSL development headers. The cloud build used CMake 3.30 or newer. On Debian/Ubuntu, the native packages are:

```sh
apt-get update
apt-get install -y build-essential clang cmake pkg-config libssl-dev git curl
```

From the cloned checkout:

```sh
rustup toolchain install 1.99.0 --profile minimal
cargo +1.99.0 build --locked --release -p wings-rs --bin wings-rs
./target/release/wings-rs --help
```

The first release build downloads dependencies and compiles bundled native libraries; allow several minutes and sufficient RAM. Building does not install or restart Wings or Incus. Configure the backend and run the smoke test before replacing an existing service.

If the build cannot obtain its bundled `fusequota` helper automatically, download the official release and pass its absolute path to the build. Existing compiled dependencies are reused:

```sh
mkdir -p target
curl -fL --retry 3 \
  https://github.com/calagopus/fusequota/releases/download/a39bc56/fusequota-x86_64-linux \
  -o "$PWD/target/fusequota-x86_64-linux"
FUSEQUOTA_BINARY_PATH="$PWD/target/fusequota-x86_64-linux" \
FUSEQUOTA_RELEASE=a39bc56 \
cargo +1.99.0 build --locked --release -p wings-rs --bin wings-rs
```

### Host requirements

- Linux and **Incus 7.0.1 or a later 7.0 LTS maintenance release**. The daemon version and required API extensions are checked; feature releases such as 7.1 are rejected.
- A root Wings service with local Incus socket access, an existing btrfs/ZFS pool, the Incus client, `skopeo`, and host `nftables`.
- A non-root Wings data UID/GID, with host directories owned by that account. The instance itself remains unprivileged with isolated ID maps. Helpers run as container root mapped to the Wings data account.
- When `newuidmap`/`newgidmap` are installed, delegate the Wings data IDs to the Incus daemon account (normally root) in `/etc/subuid` and `/etc/subgid`, in addition to its normal subordinate ranges. For UID/GID 1000, the additional entries are `root:1000:1` in each file. Restart Incus after changing its ID-map delegation.
- OCI images containing `/bin/sh`, used by the argv-preserving process supervisor.
- Keep existing Wings filesystem and disk-limiter settings appropriate to the host. The backend does not replace them or require disabling inotify.

Merge into the normal panel-generated configuration and use real pool names/addresses:

```yaml
runtime:
  backend: incus
  incus:
    socket: /var/lib/incus/unix.socket
    project: wings
    storage_pool: wings
    root_disk_size: 10GiB
    network: wingsbr0
    ipv4_address: 10.76.0.1/24
    # Optional concrete address for advertising wildcard allocations.
    # Does not restrict proxy listening; panel allocation IPs control that.
    listen_addresses: []
    operation_timeout_seconds: 120
    image_import_timeout_seconds: 1800
    max_concurrent_imports: 2
    incus_path: incus
    skopeo_path: skopeo
system:
  machine_id:
    enabled: false
  user:
    uid: 1000
    gid: 1000
tundra:
  enabled: false
docker:
  firewall:
    backend: nftables
```

The project owns its images, profiles, and private control volumes. It uses `features.networks=false` to share a Wings-owned managed bridge in Incus's default project. Wings creates that bridge with NAT/DHCP and assigns private instance addresses, with MAC/IP filtering and NIC port isolation.

Disable Wings's machine-ID mounts for initial hardware tests. The default product-UUID target `/sys/class/dmi/id/product_uuid` includes a sysfs symlink on physical hosts, which LXC refuses as a bind-mount target. Private process files are placed in an image-user-owned child directory inside the control volume: Incus 7.0's file API does not change permissions or ownership when asked to create a directory that already exists, including the volume root.

## Allocation proxy devices

Panel allocation IPv4 addresses are used directly, including `0.0.0.0`. Each instance gets two NAT proxy devices per allocation IP: TCP and UDP, with the allocated port list connected to the same ports on its static private bridge IP. For example, `0.0.0.0:5000` listens on all host IPv4 destinations; `10.0.10.20:5000` listens only on that destination IP. `nat=true` avoids a userspace relay and preserves the client's source address. The host must be the container's gateway, as it is with the Wings-managed bridge.

`listen_addresses` is retained for compatibility with earlier configurations and is not used by the Incus executor. Allocation IPs directly determine proxy bindings; use a concrete allocation IP when a feature needs a reachable advertised address. Wings does not assign external IPs or configure upstream routing; a public address translated by a router still needs that router's port forwarding. Current support is IPv4 on managed bridges.

Wings reserves instance device names beginning with `wings-port-`. It updates only these allocation devices, preserves the other instance settings/devices, sends instance ETags, and waits for asynchronous REST operations. Publication occurs after the guest acquires its private address. Cleanup removes the allocation devices; deleting the instance also deletes its device definitions and active NAT rules. Devices remain attached when a container stops, so their allocations remain reserved for that server.

Before adding devices, Wings rejects wildcard/concrete port overlaps within a server and checks existing host-bound proxies across all Incus projects, including profile devices. Use one Wings process for the node; simultaneous external edits and unrelated host NAT rules are not coordinated by this check.

On startup, Wings migrates its previous network forwards to proxy devices and republishes running instances from their allocation journals. Panel reconciliation then refreshes running instances from current allocations. Migration removes only forwards owned entirely by this node. A forward mixed with unrelated entries causes a clear error without removing those entries. Incus 7.0 rejects a concrete-IP proxy if a network forward already uses that IP, even for different ports, so the old forward object must be removed before the new proxy is installed. Migration briefly interrupts published traffic; game files and container processes are retained.

Inspect the devices with:

```bash
incus config device show wgs-SERVER_UUID --project wings
```

`incus network forward list` no longer shows the allocations after migration.

Incus owns forwarding/NAT. The existing host nftables firewall preserves panel rule order and source-file sets. Incus ACLs have different action ordering, so they do not replace Wings's ordered firewall. The `docker.firewall.backend` setting currently selects this host policy backend; `auto`, `nftables`, and explicit `disabled` are supported.

## Panel Private Network (Tundra)

Set `tundra.enabled: true` to enable the existing panel private-network control plane. With Incus, Wings runs its bundled Tundra node as a supervised host child process. No Docker daemon, daemon image, or separate executable installation is needed. Leave `tundra.binary` empty; `tundra.image` and `tundra.source_image` are used only by the Docker provider.

```yaml
tundra:
  enabled: true
  binary: ""
```

The embedded node comes from the pinned `Luxxy-GF/tundra` fork, with native Incus REST discovery. Snapshots contain stable `wgs-SERVER_UUID` references rather than cached PIDs. Discovery is scoped to the configured Incus project and Wings ownership marker and excludes installers/script helpers. The node inspects each game's private IPv4 and host PID, binds the existing TCP/UDP private frontends in its network namespace, and updates the Wings-owned hosts file for `.tunnel` names. Incus stages that read-only file at `/opt/wings-private-hosts`; a final relative LXC bind mounts it over Incus 7.0's generated `/etc/hosts`. Namespace starts, stops, and PID changes are detected by one-second polling. Frozen containers retain their namespace association.

The panel still controls server membership, advertised private ports, peer certificates, and directional ACLs. The existing QUIC relay, JWT admission checks, revocation, and panel-unreachable behavior stay shared with Docker. Allow the panel-configured node tunnel UDP port through the host/upstream firewall. NIC port isolation stays enabled; private traffic passes through Tundra rather than allowing unrestricted direct bridge traffic. Killing Wings also kills its child; Wings restarts a failed node during reconciliation. Changing node configuration restarts the child and can interrupt active private flows.

Like the upstream Docker implementation, private frontend ports must not collide with wildcard listeners already running in the source container. Give servers distinct service ports when a source's application binds all IPv4 addresses on a destination's private port.

## Extra mounts and game-data quotas

Panel mounts go through the same normalized-path and `allowed_mounts` checks used by Docker. Incus disk devices preserve `read_only`; administrator-provided files/directories must already have permissions suitable for the image user. The image UID/GID is mapped to the Wings host data account for the whole instance. Extra mounts are not automatically owned or charged to the server data quota.

The persistent data directory remains outside the disposable Incus root disk. `runtime.incus.root_disk_size` limits the image/system disk; it does not limit files in `/home/container`. Choose Wings's existing filesystem limiter to enforce the panel's game-data disk limit:

```yaml
system:
  disk_limiter_mode: fuse_quota
```

`fuse_quota` supports an ordinary host data directory and uses the bundled fusequota helper, host FUSE support, and `/dev/fuse`. Incus waits for the quota mount and control socket before binding it into a game, installer, or script helper. Quota attachment/update failures abort creation instead of falling back to an unprotected directory. `btrfs_subvolume` requires the Wings **data directory** to reside on a Btrfs filesystem; using a Btrfs Incus storage pool alone is insufficient. Existing ordinary directories need an explicit filesystem migration before switching to Btrfs subvolumes. XFS and ZFS keep their shared limiter paths but require their filesystem-specific host setup and separate live validation.

`disk_limiter_mode: none` keeps the existing usage checks without a kernel/FUSE write quota. Changing the limiter on an existing running node requires stopping servers and planning the data/mount transition.

## Image progress and installer permissions

Image checks, cache hits, OCI export/conversion, import, and completion are reported to the panel console. Incus CLI carriage-return progress updates become bounded console lines; long silent operations emit a periodic elapsed-time message. The official Incus client handles daemon operation events during import. Registry download/conversion happens in the client, so subscribing only to `/1.0/events` would miss it. Incus 7.0 does not expose Docker-style per-layer registry byte progress through this conversion path; no synthetic percentages are reported.

Before an installer or script helper starts, Wings repairs ownership of its server data using the configured Wings UID/GID. This prevents mapped OCI root from receiving permission errors on a freshly root-owned `/mnt/server`. Administrator extra mounts are not changed. An installer that ignores errors and exits successfully can still report success; its script should fail on failed commands.

## Restart recovery, backups, and transfers

Wings owns game autostart (`boot.autostart=false` in Incus). On a Wings restart it reattaches to an existing running game, checks the data mount's device/inode against the guest mount, reapplies the quota, and reconciles allocations and firewall policy. An unavailable daemon or stale mount produces a recovery error and blocks automatic replacement. After a node reboot, Wings uses the saved server state and the panel's `auto_start_behavior` to start games again. Keep the Wings root/data directories on persistent storage and run Wings after Incus is ready.

Local backups and node transfers contain the persistent game files, not the disposable OCI root disk or supervisor volume. Restored/transferred files use the destination Wings data UID/GID. Incus node transfers enforce the destination game-data limit; an oversized transfer reports failure and may leave partial files for the normal transfer cleanup/retry workflow. Other backends retain their existing transfer behavior. A transfer does not migrate arbitrary administrator extra mounts: configure those paths separately on the destination.

## Registry credentials and image cleanup

Incus uses the existing registry map, with exact registry host/port keys:

```yaml
docker:
  registries:
    registry.example.com:
      username: pull-user
      password: YOUR_REGISTRY_PASSWORD
runtime:
  backend: incus
  incus:
    image_cache_retention_days: 30
```

For Docker Hub, use `docker.io` (the conventional `https://index.docker.io/v1/` key is also accepted). Credentials are stored in a mode-0600 temporary auth file inside a private import directory, supplied to both Skopeo inspection and Incus conversion, and removed when the operation finishes. Passwords are not passed in URLs or command arguments. A private Skopeo wrapper preserves authentication and configured CA trust when Incus 7.0 replaces its subprocess environment for an HTTP proxy. TLS verification stays enabled. Credential prefixes do not match other registry hosts.

Cleanup runs at startup and hourly. The default retention is 30 days since the last cache use; `0` disables it. It removes only cache records and Incus images bearing this node's owner/cache markers. Running and stopped instances protect their base images, administrator aliases protect images, and pulls serialize against cleanup. A failed inventory request stops cleanup. Images imported by earlier releases without ownership markers, and administrator images deduplicated by Incus, are retained. Cleanup never removes game files, storage pools, or instance root disks. Use a single Wings process for a project and coordinate external image/instance edits with cleanup: Incus 7.0 image deletion has no atomic conditional ETag check.

## Current limitations

This is an experimental implementation following the PR's architecture, with incomplete feature parity. On 2026-10-03, the complete live smoke test passed against Incus 7.0.1 in a disposable Debian VM with a Btrfs pool, using `python:3.13-alpine`. It covered OCI import, real TCP/UDP forward traffic, console reconnect and command stop with exit code 7, host data ownership/persistence, installer progress/status files, script exit code 9, and owned-resource cleanup. On 2026-10-04, the same full test passed with the non-root `ghcr.io/pterodactyl/yolks:python_3.11` image after the control-directory and state-monitor fixes.

- IPv6, remote Incus, clusters/OVN, forced outgoing-IP SNAT, device passthrough, custom seccomp, OOM-disable, and CPU boosts remain unsupported and are rejected when requested.
- **Non-root OCI startup has been smoke-tested with `ghcr.io/pterodactyl/yolks:python_3.11`.** Console I/O, control-file writes, forwarding, and helper execution passed. Full game eggs and their installer scripts still require hardware validation; this remains an experimental backend.
- Native Incus `raw.idmap` is an instance-wide mapping, unlike Proxmox's per-mount `mpN` ID maps. The live tests verified both guest root and the non-root Python yolk mapped to host data UID 1000; Extra directories must be accessible to the mapped Wings data UID/GID; the executor does not recursively change administrator-owned mount contents.
- Repository-scoped credential keys, token/helper-based authentication overrides, and private-registry proxy combinations need separate validation; the implemented credential map uses exact registry host/port keys.
- Console replay completeness, XFS/ZFS data quotas, snapshot/remote backup adapters, multiplex transfers, and automated backend migration need separate validation.
- I/O priority supports Docker weights 10 or multiples of 100 through 1000. Other weights are rejected.
- Console input waits five seconds after WebSocket attachment, but Incus does not acknowledge native relay readiness. Reconnect input was intermittently lost in the slow QEMU/TCG lab, including with an additional 15-second test delay; a later command through the official client succeeded. Early-input reliability remains a limitation requiring hardware checks.
- The supervisor records exit codes. Forced kills can leave an unknown code (`-1`); there is no inferred OOM flag.
- `used_ports` reflects Incus proxies and remaining legacy forwards, but does not completely represent host-service conflicts or unrelated NAT rules.

## Validation

Local Incus and installation regression tests: **30 passed, 4 live tests ignored**. The quality refactor also checks operation failures, malformed error responses, API path constraints, console handshake deadlines, preserved instance settings, recovery ownership checks, and reclamation of unused image locks. Before the proxy migration change, the full live lifecycle/helper test passed separately with the root Python image and the non-root Python yolk. Incus installers with a nonzero or unknown exit code now report failure even if no status file was written. Direct REST checks also passed for managed bridge/forward CRUD, shared-IP entries, collision/subnet rejection, unattached custom-volume file access, quota configuration, and cleanup. Earlier checks covered quota configuration; the 2026-10-04 Btrfs test below also verified write-quota enforcement.

On 2026-10-04, the focused `live_incus_allocation_proxies_and_cleanup` test passed against Incus 7.0.1 with `python:3.13-alpine` and a Btrfs pool. It verified concrete and wildcard TCP/UDP traffic, client source-IP preservation, migration of a running instance, preservation of unrelated forward entries, allocation update/removal and overlap rejection, used-port reporting, Incus API stop, host file ownership/persistence after deletion, installer status/progress, script exit code 9, and owned-resource cleanup. Production Clippy passed with warnings denied. Rechecking the full console test encountered intermittent reconnect-input loss, including with an extra 15-second settling delay; that limitation remains unresolved.

On 2026-10-04, extended Btrfs and FUSE runs passed with an 8 MiB game-data limit. A guest attempted 32 MiB of writes and received a quota/full-disk error. It verified allowlisted read-only/write mounts, the private hosts file, Tundra Incus ownership/project checks and TCP/UDP namespace listeners, and installation into a deliberately root-owned data directory. Real Incus export/import progress reached the console. The FUSE run also verified that the quota mount was active before attaching data to Incus, installer/script-helper completion, and owned-resource cleanup. Tundra regression tests: **181 passed, 2 ignored**; Wings Tundra tests: **8 passed, 2 ignored**.

On 2026-10-04, the expanded tests also verified fresh executor/filesystem reattachment after an Incus daemon restart, unchanged game PID, FUSE mount identity, and restored TCP/UDP publication. A real local backup/restore and checksummed HTTP node transfer passed with source UID/GID 1000 and destination UID/GID 1001, preserving file contents, mode and symlinks; a 16 MiB transfer into an 8 MiB destination was rejected. These checks passed with Btrfs and FUSE. A private HTTPS registry fixture verified manifest/config/layer authentication with a password containing spaces and punctuation, using a trusted test CA and normal TLS verification. The full FUSE lifecycle/helper run passed with that registry, including stopped-image protection and deletion of expired, unused, owned images. The wrapper unit test separately checks credential/CA preservation when Incus replaces the Skopeo environment for a proxy.

A real VM reboot test passed after verifying the kernel boot ID changed. Incus left the game stopped (`boot.autostart=false`), and Wings’s normal `ServerManager::boot` path autostarted it from the saved running state and panel policy. Persistent files, rebuilt FUSE quota mounts, and TCP/UDP allocations passed.

After the quality refactor, the focused lifecycle/helper test passed again on Incus 7.0.1 with FUSE quotas and the private HTTPS registry. It covered allocation proxies, daemon reattachment, backups/transfers, destination ownership, helper exit status, and image cleanup. All **20** existing `LineBuffer` tests also passed; Incus console output now uses that shared Wings implementation. Production Clippy passed with warnings denied.

The standalone Tundra workspace suite passed: **301 passed, 4 ignored**. The broader Wings suite on the cloud host reported **794 passed, 10 failed, 22 ignored**. The same ten failures reproduced in the baseline build: eight inotify tests fail when run with the full suite but pass in isolation, and two TCP congestion-control tests fail on the cloud host but pass on the VM's Linux kernel. All eight inotify tests also passed on that VM. The complete single-process cloud-host suite therefore remains failing; these baseline failures are separate from the successful Incus integration checks.

Two-node private-network validation used the upstream Tundra test panel and verified TCP/UDP through QUIC, `.tunnel` names, ACL revocation/restoration, and adoption after a native Incus restart. The production panel UI was not exercised. Tundra's native runtime source is maintained separately in [Luxxy-GF/tundra](https://github.com/Luxxy-GF/tundra); Wings uses the original `calagopus/tundra.git` dependency for `tundra-common` and pins the Incus node crate to the fork revision.

Run the local regression tests with:

```sh
cargo test --locked -p wings-rs incus
```

For an initial hardware smoke test, use a spare Linux node with Incus 7.0.1, an existing Btrfs/ZFS test pool, the required tools, and the UID/GID delegation above. Run the following as root from this checkout, supplying the node's real IPv4 address. The test creates its own random project and bridge and retains your existing pool:

```sh
INCUS_TEST_POOL=your-test-pool \
INCUS_TEST_LISTEN_IP=your-node-ipv4 \
cargo test --locked -p wings-rs live_incus_allocation_proxies_and_cleanup -- --ignored --nocapture
```

The expanded backup/transfer fixture maps source UID/GID 1000 to destination UID/GID 1001 on the same test node. Delegate both test IDs to the Incus daemon account before running it; for root, add `root:1000:1` and `root:1001:1` to both `/etc/subuid` and `/etc/subgid` alongside the normal subordinate ranges, then restart Incus. Production nodes need delegation for their configured Wings account.

FUSE control sockets must fit Linux’s Unix-socket path limit. Use a short `INCUS_TEST_DATA_ROOT`; for reboot tests it must be persistent, such as `/var/tmp/wings-test`. The default temporary directory is unsuitable for reboot checkpoints.

Use `INCUS_TEST_CIDR` if the default `10.237.19.0/24` conflicts with your network. Test from the node first; public ingress and upstream routing need separate hardware checks.

```sh
cargo fmt --all -- --check
cargo clippy -p wings-rs --bin wings-rs -- -D warnings
cargo test -p wings-rs incus -- --skip live_incus_lifecycle_volume_console_and_forwards
```

A focused networking/helper test uses the Incus stop API and checks allocation proxies, legacy-forward migration, conflict rejection, persistent data and cleanup independently of console input:

```sh
INCUS_TEST_POOL=your-test-pool INCUS_TEST_LISTEN_IP=your-node-ipv4 \
  cargo test -p wings-rs live_incus_allocation_proxies_and_cleanup -- --ignored --nocapture
```

The full console test also accepts `INCUS_TEST_CONSOLE_SETTLE_SECONDS` (maximum 60 seconds) for diagnosis on slow emulated hosts. Additional settling did not eliminate the observed intermittent reconnect-input failure; it is not a runtime readiness fix.

The ignored live test uses an explicitly selected disposable Incus host/pool. It creates a random project/bridge, imports an OCI image, tests TCP/UDP forwarding, reconnects the console, checks exit status and stopped-server host-file access, and deletes its owned resources. It retains the supplied storage pool.

```sh
INCUS_TEST_POOL=test-btrfs \
INCUS_TEST_LISTEN_IP=192.0.2.10 \
INCUS_TEST_CIDR=10.237.19.1/24 \
cargo test -p wings-rs live_incus_lifecycle_volume_console_and_forwards -- --ignored --nocapture
```

To exercise write-quota enforcement and mounts, use the focused test with `INCUS_TEST_QUOTA=btrfs` and `INCUS_TEST_DATA_ROOT=/path/on/btrfs`, or `INCUS_TEST_QUOTA=fuse` on a host supporting the bundled FUSE helper. The test creates its own data directory below the supplied root and tests an 8 MiB quota.

Optional overrides: `INCUS_TEST_SOCKET`, `INCUS_TEST_PORT`, and `INCUS_TEST_IMAGE` (default `python:3.13-alpine`). `INCUS_TEST_KEEP_FAILURE=1` explicitly retains failed test resources and their temporary data for inspection; remove those owned resources after debugging.

The former experimental `wgv-*` data volumes are not migrated or deleted by this host-directory implementation. If any exist from earlier live use, stop their instances, back up and restore their data to the normal Wings directory with correct ownership, then verify through Wings before switching allocations.
