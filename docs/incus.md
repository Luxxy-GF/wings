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

`listen_addresses` is no longer used to expand wildcard allocations. It remains an optional concrete address hint for features that advertise a wildcard allocation. Wings does not assign external IPs or configure upstream routing; a public address translated by a router still needs that router's port forwarding. Current support is IPv4 on managed bridges.

Wings reserves instance device names beginning with `wings-port-`. It updates only these allocation devices, preserves the other instance settings/devices, sends instance ETags, and waits for asynchronous REST operations. Publication occurs after the guest acquires its private address. Cleanup removes the allocation devices; deleting the instance also deletes its device definitions and active NAT rules. Devices remain attached when a container stops, so their allocations remain reserved for that server.

Before adding devices, Wings rejects wildcard/concrete port overlaps within a server and checks existing host-bound proxies across all Incus projects, including profile devices. Use one Wings process for the node; simultaneous external edits and unrelated host NAT rules are not coordinated by this check.

On startup, Wings migrates its previous network forwards to proxy devices and republishes running instances from their allocation journals. Panel reconciliation then refreshes running instances from current allocations. Migration removes only forwards owned entirely by this node. A forward mixed with unrelated entries causes a clear error without removing those entries. Incus 7.0 rejects a concrete-IP proxy if a network forward already uses that IP, even for different ports, so the old forward object must be removed before the new proxy is installed. Migration briefly interrupts published traffic; game files and container processes are retained.

Inspect the devices with:

```bash
incus config device show wgs-SERVER_UUID --project wings
```

`incus network forward list` no longer shows the allocations after migration.

Incus owns forwarding/NAT. The existing host nftables firewall preserves panel rule order and source-file sets. Incus ACLs have different action ordering, so they do not replace Wings's ordered firewall. The `docker.firewall.backend` setting currently selects this host policy backend; `auto`, `nftables`, and explicit `disabled` are supported.

## Current limitations

This is an experimental implementation following the PR's architecture, with incomplete feature parity. On 2026-10-03, the complete live smoke test passed against Incus 7.0.1 in a disposable Debian VM with a Btrfs pool, using `python:3.13-alpine`. It covered OCI import, real TCP/UDP forward traffic, console reconnect and command stop with exit code 7, host data ownership/persistence, installer progress/status files, script exit code 9, and owned-resource cleanup. On 2026-10-04, the same full test passed with the non-root `ghcr.io/pterodactyl/yolks:python_3.11` image after the control-directory and state-monitor fixes.

- Tundra provisioning, IPv6, remote Incus, clusters/OVN, forced outgoing-IP SNAT, device passthrough, custom seccomp, OOM-disable, and CPU boosts remain unsupported and are rejected when requested.
- **Non-root OCI startup has been smoke-tested with `ghcr.io/pterodactyl/yolks:python_3.11`.** Console I/O, control-file writes, forwarding, and helper execution passed. Full game eggs and their installer scripts still require hardware validation; this remains an experimental backend.
- Native Incus `raw.idmap` is an instance-wide mapping, unlike Proxmox's per-mount `mpN` ID maps. The live tests verified both guest root and the non-root Python yolk mapped to host data UID 1000; extra mount ownership still requires validation.
- The existing `docker.registries` credential map is not wired into Incus. Standard service-account registry authentication is used; private-registry/proxy combinations require validation.
- Image replacement, console replay completeness, backups/transfers, host quota mounts, and daemon restart recovery need live validation. Cached-image garbage collection and automated backend migration are not implemented.
- I/O priority supports Docker weights 10 or multiples of 100 through 1000. Other weights are rejected.
- Console input waits five seconds after WebSocket attachment, but Incus does not acknowledge native relay readiness. Reconnect input was intermittently lost in the slow QEMU/TCG lab, including with an additional 15-second test delay; a later command through the official client succeeded. Early-input reliability remains a limitation requiring hardware checks.
- The supervisor records exit codes. Forced kills can leave an unknown code (`-1`); there is no inferred OOM flag.
- `used_ports` reflects Incus proxies and remaining legacy forwards, but does not completely represent host-service conflicts or unrelated NAT rules.

## Validation

Local Incus and installation regression tests: **19 passed**. Before the proxy migration change, the full live lifecycle/helper test passed separately with the root Python image and the non-root Python yolk. Incus installers with a nonzero or unknown exit code now report failure even if no status file was written. Direct REST checks also passed for managed bridge/forward CRUD, shared-IP entries, collision/subnet rejection, unattached custom-volume file access, quota configuration, and cleanup. Quota configuration was checked; quota-overflow enforcement was not tested.

On 2026-10-04, the focused `live_incus_allocation_proxies_and_cleanup` test passed against Incus 7.0.1 with `python:3.13-alpine` and a Btrfs pool. It verified concrete and wildcard TCP/UDP traffic, client source-IP preservation, migration of a running instance, preservation of unrelated forward entries, allocation update/removal and overlap rejection, used-port reporting, Incus API stop, host file ownership/persistence after deletion, installer status/progress, script exit code 9, and owned-resource cleanup. Production Clippy passed with warnings denied. Rechecking the full console test encountered intermittent reconnect-input loss, including with an extra 15-second settling delay; that limitation remains unresolved.

For an initial hardware smoke test, use a spare Linux node with Incus 7.0.1, an existing Btrfs/ZFS test pool, the required tools, and the UID/GID delegation above. Run the following as root from this checkout, supplying the node's real IPv4 address. The test creates its own random project and bridge and retains your existing pool:

```sh
INCUS_TEST_POOL=your-test-pool \
INCUS_TEST_LISTEN_IP=your-node-ipv4 \
scripts/incus-smoke-test.sh
```

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

Optional overrides: `INCUS_TEST_SOCKET`, `INCUS_TEST_PORT`, and `INCUS_TEST_IMAGE` (default `python:3.13-alpine`). `INCUS_TEST_KEEP_FAILURE=1` explicitly retains failed test resources and their temporary data for inspection; remove those owned resources after debugging.

The former experimental `wgv-*` data volumes are not migrated or deleted by this host-directory implementation. If any exist from earlier live use, stop their instances, back up and restore their data to the normal Wings directory with correct ownership, then verify through Wings before switching allocations.
