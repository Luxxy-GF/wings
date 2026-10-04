# Incus 7.0 LTS executor (experimental)

This backend follows [PR #34's LXC runtime approach](https://github.com/calagopus/wings/pull/34), with Incus replacing Proxmox and [Incus network forwards](https://linuxcontainers.org/incus/docs/main/howto/network_forwards/) publishing allocations. Select it explicitly with `runtime.backend: incus`; Docker remains the default. Runtime configuration changes require a restart.

## Architecture

| PR #34 model | Incus implementation |
| --- | --- |
| Shared runtime factory | `create_runtime` returns an executor and an optional Docker connection |
| OCI templates in managed storage | Digest-pinned OCI imports through the official Incus client, cached by Incus fingerprint, with image environment defaults preserved |
| Separate runtime and helper LXC containers | Owned `wgs-`, `wgi-`, and `wgx-` Incus instances |
| Existing Wings server directory bound into LXC | Host directory mounted at `/home/container`, or `/mnt/server` for helpers |
| OCI user and host data ownership | Incus resolves the OCI UID/GID; `raw.idmap` maps the non-root Wings data account to that user |
| Host file APIs, quotas, backups, and inotify | Existing Wings filesystem and disk-limiter implementation remains responsible |
| Proxmox bridge/edge forwarding | Incus-managed bridge, private addresses, and TCP/UDP network forwards |

Images are pulled from the egg/helper registry reference. There is no local Containerfile/Buildah recipe path. The official Incus client handles OCI conversion through `image export` and `image import`, using temporary archives and a private client configuration without modifying operator CLI remotes. This avoids Incus 7.0.1's OCI relay-copy alias bug. Allow temporary disk space for the converted archives beneath the Wings root directory. Incus instance, storage, lifecycle, console, and forwarding operations use the REST API over the local Unix socket.

Root disks are disposable Incus storage volumes. Private launch scripts and process-control files use separate Incus custom volumes mounted at `/opt/wings-control`, outside panel-visible data and the image's `/run` mounts. A simple file entrypoint preserves multiline arguments through LXC's configuration parser. Instance cleanup preserves the host server directory. Explicit server deletion uses Wings's normal filesystem deletion path.

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
    listen_addresses:
      - 192.0.2.10
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

## Network forwards

One Incus forward is shared per concrete allocation IP. Its TCP and UDP port entries point to each server's private IP and matching game port. A whole-address `target_address` is avoided because it would send unmatched ports to a single server.

Updates preserve unrelated entries, tag entries with node/server ownership, reject overlapping port mappings, and serialize changes within the Wings process. Requests send ETags and retry precondition failures, but **Incus 7.0.1 does not enforce `If-Match` on network-forward updates**. Use one Wings process per managed network and avoid concurrent external edits to its forwards; those edits can otherwise be overwritten. A runtime start publishes allocations only after its assigned address is present. Failed publication attempts to remove its partial forwards and stop the instance. Cleanup removes only the server's entries.

Wildcard allocations require `listen_addresses` to expand them to concrete host IPs. These IPs must satisfy Incus's bridge-forward restrictions and be reachable through the host/upstream network. Wings does not assign external IPs or configure upstream routing. Current support is IPv4 on managed bridges.

Incus owns forwarding/NAT. The existing host nftables firewall preserves panel rule order and source-file sets. Incus ACLs have different action ordering, so they do not replace Wings's ordered firewall. The `docker.firewall.backend` setting currently selects this host policy backend; `auto`, `nftables`, and explicit `disabled` are supported.

## Current limitations

This is an experimental implementation following the PR's architecture, with incomplete feature parity. On 2026-10-03, the complete live smoke test passed against Incus 7.0.1 in a disposable Debian VM with a Btrfs pool, using `python:3.13-alpine`. It covered OCI import, real TCP/UDP forward traffic, console reconnect and command stop with exit code 7, host data ownership/persistence, installer progress/status files, script exit code 9, and owned-resource cleanup.

- Tundra provisioning, IPv6, remote Incus, clusters/OVN, forced outgoing-IP SNAT, device passthrough, custom seccomp, OOM-disable, and CPU boosts remain unsupported and are rejected when requested.
- **Non-root OCI images are not ready for general use.** The current console launch path opens `/dev/console` as the image user, while Incus creates it with root-only access. Most normal Wings yolks use a non-root user and need an additional bootstrap fix. Use the root-user smoke image for hardware validation; do not deploy this backend to existing game servers yet.
- Native Incus `raw.idmap` is an instance-wide mapping, unlike Proxmox's per-mount `mpN` ID maps. The live smoke test verified guest root mapped to host data UID 1000; other image users and extra mount ownership still require validation.
- The existing `docker.registries` credential map is not wired into Incus. Standard service-account registry authentication is used; private-registry/proxy combinations require validation.
- Image replacement, console replay completeness, backups/transfers, host quota mounts, and daemon restart recovery need live validation. Cached-image garbage collection and automated backend migration are not implemented.
- I/O priority supports Docker weights 10 or multiples of 100 through 1000. Other weights are rejected.
- The supervisor records exit codes. Forced kills can leave an unknown code (`-1`); there is no inferred OOM flag.
- `used_ports` reflects Incus forwards, but does not completely represent host-service conflicts or unrelated NAT rules.

## Validation

Local Incus and installation regression tests: **19 passed**. The full live lifecycle/helper test: **1 passed**. Direct REST checks also passed for managed bridge/forward CRUD, shared-IP entries, collision/subnet rejection, unattached custom-volume file access, quota configuration, and cleanup. Quota configuration was checked; quota-overflow enforcement was not tested.

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

The ignored live test uses an explicitly selected disposable Incus host/pool. It creates a random project/bridge, imports an OCI image, tests TCP/UDP forwarding, reconnects the console, checks exit status and stopped-server host-file access, and deletes its owned resources. It retains the supplied storage pool.

```sh
INCUS_TEST_POOL=test-btrfs \
INCUS_TEST_LISTEN_IP=192.0.2.10 \
INCUS_TEST_CIDR=10.237.19.1/24 \
cargo test -p wings-rs live_incus_lifecycle_volume_console_and_forwards -- --ignored --nocapture
```

Optional overrides: `INCUS_TEST_SOCKET`, `INCUS_TEST_PORT`, and `INCUS_TEST_IMAGE` (default `python:3.13-alpine`). `INCUS_TEST_KEEP_FAILURE=1` explicitly retains failed test resources and their temporary data for inspection; remove those owned resources after debugging.

The former experimental `wgv-*` data volumes are not migrated or deleted by this host-directory implementation. If any exist from earlier live use, stop their instances, back up and restore their data to the normal Wings directory with correct ownership, then verify through Wings before switching allocations.
