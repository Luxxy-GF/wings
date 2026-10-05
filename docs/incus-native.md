# Native Incus operating systems

## Stock panel extension

The `xyz.luxxy.incus` Calagopus extension provides native instance creation,
image selection and the interactive console on an unmodified panel. Install
and rebuild the extension before enabling its metadata adapter on Wings:

```yaml
runtime:
  backend: incus
  incus:
    panel_extension: true
```

The adapter reads authenticated `POST /api/remote/incus/servers` metadata
during startup, individual server fetches and configuration updates. Each
requested server must have exactly one metadata entry; application servers
have an explicit `null` instance. Invalid, missing or conflicting metadata
fails loading instead of converting an OS instance into an application
container. Requests are batched at 1,000 servers and use normal node
authentication. The setting defaults to `false` for compatibility with the
existing native panel branch.

## Native runtime

This branch extends the Incus application-container backend with persistent system containers and virtual machines. The panel's server creation form discovers node capabilities and offers an instance type and OS image selector. Application containers remain the default.

Use Incus 7.0 LTS. Install `sshfs` and `fuse3` on the Wings host for guest file access. Virtual machines also require the full Incus package with QEMU, working KVM and an Incus agent in the guest. Installing only `incus-base` does not provide the VM runtime. Images from the default repository normally include the agent.

```yaml
runtime:
  backend: incus
  incus:
    image_server: https://images.linuxcontainers.org
    native_storage_pool: wings-native
    native_storage_driver: dir
    native_storage_config: {}
```

Wings creates the native pool automatically. With `dir`, its default source is `/var/lib/calagopus-wings/incus/storage-pools/wings-native`, following the configured Wings root directory. Incus manages VM `root.img` files beneath this pool. System containers use directories. Other Incus root-disk storage drivers can be selected through `native_storage_driver` and `native_storage_config`; block-backed drivers manage their own volumes rather than exposing an image file. Existing pools retain their configuration.

Guest root disks persist across stops, restarts, and daemon restarts. Explicit server deletion removes the owned Incus instance. The configured server disk limit sets the native root disk size. Container filesystem quota enforcement with `dir` requires project quotas on the backing filesystem; choose Btrfs, ZFS, or another quota-capable driver for enforced container disk limits. VM disk capacity is enforced by its virtual block device.

The console opens an interactive root terminal through Incus exec, using Bash when available and otherwise the image's `/bin/sh`. The companion panel streams terminal bytes without waiting for a newline, so installation confirmations and shell prompts appear immediately. Click inside the terminal to type, use Enter to accept a default answer, or Ctrl+C to interrupt the current command. The command box also remains available. Resizing the console or changing its font size updates the guest's terminal dimensions. Both Wings and the panel must be updated for this protocol.

The panel file manager and Wings SFTP expose the guest root filesystem through Incus SFTP without rewriting OS ownership. VM file access and shell sessions require the guest to be running with its agent available. Guest pseudo-filesystems are excluded by the built-in OS template.

Allocations, bridge networking, port publication, and the existing Incus firewall implementation are shared with application containers. CPU and memory limits map to Incus instance limits; VM CPU limits are rounded up to a whole vCPU. Egg startup commands and installer scripts do not run inside native OS instances.

Install the companion panel branch and apply its database migrations before creating OS instances. The migration adds the native instance configuration and a built-in operating-system template. Instance type and image are fixed at creation. Tundra private networking is not supported for native OS instances. VM creation is disabled on nodes that enable Tundra, whose namespace adapter currently handles containers only. Full native backup/export, migration, extra mounts, and OS reinstallation are not implemented in this branch; ordinary game-data backup and transfer operations are rejected for native instances. Application-container backup and transfer behavior is unchanged.
