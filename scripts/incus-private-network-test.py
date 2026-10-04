#!/usr/bin/env python3
"""Private-network integration fixture for a disposable Incus 7.0.1 host.

Requires root, an existing Btrfs/ZFS pool, a built Wings binary, and the
upstream Tundra test-panel binary. Uses local ports 7443, 7151/7152, 7161/7162.
Creates only random owned projects/instances and retains the supplied pool.
Logs and private fixture credentials remain in a mode-0700 temporary directory.
"""
import json
import os
import pathlib
import secrets
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import time
import urllib.request

if os.geteuid() != 0:
    raise SystemExit("Run this fixture as root on a disposable Incus host")
pool = os.environ["INCUS_TEST_POOL"]
wings_binary = str(
    pathlib.Path(os.environ["INCUS_TEST_WINGS_BINARY"]).resolve(strict=True)
)
panel_binary = str(
    pathlib.Path(os.environ["INCUS_TEST_TUNDRA_PANEL_BINARY"]).resolve(strict=True)
)
root = pathlib.Path(tempfile.mkdtemp(prefix="wings-mesh-"))
admin = secrets.token_hex(24)
processes = []
projects = []
instances = []
network = "wgm" + secrets.token_hex(4)
network_created = False
network_owner = "wings:mesh-test:" + secrets.token_hex(16)


def incus(*args, data=None):
    p = subprocess.run(
        ["incus", *args]
        + (
            ["-X", "POST", "--wait", "-d", json.dumps(data)] if data is not None else []
        ),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if p.returncode:
        if args[0] == "start":
            detail = subprocess.run(
                ["incus", "info", args[1], *args[2:], "--show-log"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            raise RuntimeError("Incus start: " + p.stderr + "\n" + detail.stdout)
        raise RuntimeError("Incus " + args[0] + ": " + p.stderr)
    return p.stdout


def start(args, env, name):
    f = open(root / (name + ".log"), "w")
    p = subprocess.Popen(
        args, env=env, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT
    )
    processes.append(p)
    f.close()
    return p


try:
    panel = root / "panel"
    panel.mkdir()
    config = root / "panel.yml"
    config.write_text(
        json.dumps(
            {
                "bind": "127.0.0.1:7443",
                "public_url": "https://127.0.0.1:7443",
                "db_path": str(panel / "db.sqlite"),
                "data_dir": str(panel),
                "admin_token": admin,
            }
        )
    )
    start([panel_binary, "--config", str(config)], os.environ.copy(), "panel")
    for _ in range(100):
        if (panel / "https.crt.pem").exists():
            break
        time.sleep(0.1)
    context = ssl.create_default_context(cafile=str(panel / "https.crt.pem"))

    def api(path, data=None, method=None):
        req = urllib.request.Request(
            "https://127.0.0.1:7443/api/" + path,
            data=None if data is None else json.dumps(data).encode(),
            method=method,
            headers={
                "Authorization": "Bearer " + admin,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, context=context, timeout=10) as r:
            b = r.read()
            return json.loads(b) if b else None

    for _ in range(100):
        try:
            api("nodes")
            break
        except OSError:
            time.sleep(0.1)
    incus(
        "network",
        "create",
        network,
        "ipv4.address=10.238.44.1/24",
        "ipv4.nat=true",
        "ipv6.address=none",
        "user.wings.owner=" + network_owner,
        "--project",
        "default",
    )
    network_created = True
    nodes = [
        api("nodes", {"name": "incus-a", "host": "127.0.0.1", "tunnel_port": 7151}),
        api("nodes", {"name": "incus-b", "host": "127.0.0.1", "tunnel_port": 7152}),
    ]
    servers = []
    for i, node in enumerate(nodes):
        s = api(
            "servers",
            {
                "node_uuid": node["uuid"],
                "name": "mesh-" + str(i),
                "container_ref": "pending",
                "ports": [{"port": 23455 + i, "proto": "both"}],
            },
        )
        servers.append(s)
        with sqlite3.connect(panel / "db.sqlite") as db:
            db.execute(
                "UPDATE servers SET container_ref=? WHERE uuid=?",
                ("wgs-" + s["uuid"], s["uuid"]),
            )
    api("acls", {"src_server": servers[0]["uuid"], "dst_server": servers[1]["uuid"]})
    conf = root / "incus-conf"
    conf.mkdir()
    (conf / "config.yml").write_text(
        json.dumps(
            {
                "default-remote": "local",
                "remotes": {
                    "local": {"addr": "unix://", "protocol": "incus"},
                    "oci": {
                        "addr": "https://docker.io",
                        "protocol": "oci",
                        "public": True,
                    },
                },
            }
        )
    )
    image_env = os.environ.copy()
    image_env["INCUS_CONF"] = str(conf)
    archive = root / "python.tar.gz"
    cached = os.environ.get("INCUS_TEST_IMAGE_ARCHIVE")
    if cached:
        shutil.copyfile(cached, archive)
        shutil.copyfile(cached + ".root", str(archive) + ".root")
    else:
        p = subprocess.run(
            [
                "incus",
                "image",
                "export",
                "oci:library/python:3.13-alpine",
                str(archive),
            ],
            env=image_env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if p.returncode:
            raise RuntimeError("OCI export: " + p.stderr)
    for i, (node, s) in enumerate(zip(nodes, servers)):
        project = "wings-mesh-" + node["uuid"].replace("-", "")
        projects.append((project, "wings:" + node["uuid"]))
        incus(
            "project",
            "create",
            project,
            "-c",
            "features.networks=false",
            "-c",
            "user.wings.owner=wings:" + node["uuid"],
        )
        incus(
            "image",
            "import",
            str(archive),
            str(archive) + ".root",
            "--alias",
            "mesh-python",
            "--project",
            project,
        )
        hosts = root / ("hosts-" + str(i))
        hosts.mkdir()
        hp = hosts / s["uuid"]
        hp.mkdir()
        (hp / "hosts").write_text("127.0.0.1 localhost\n")
        entry = [
            "python3",
            "-u",
            "-c",
            "import socket, threading, time\ndef tcp():\n s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',23456)); s.listen()\n while True:\n  c,a=s.accept(); d=c.recv(100); c.sendall(b'mesh-tcp:'+d); c.close()\ndef udp():\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',23456))\n while True:\n  d,a=s.recvfrom(100); s.sendto(b'mesh-udp:'+d,a)\nthreading.Thread(target=tcp,daemon=True).start(); threading.Thread(target=udp,daemon=True).start(); time.sleep(1800)",
        ]
        entry[3] = entry[3].replace("23456", str(23455 + i))
        (hp / "mesh.py").write_text(entry[3])
        name = "wgs-" + s["uuid"]
        instances.append((project, name))
        incus(
            "query",
            "/1.0/instances?project=" + project,
            data={
                "name": name,
                "type": "container",
                "profiles": [],
                "source": {"type": "image", "alias": "mesh-python"},
                "config": {
                    "oci.entrypoint": "/usr/local/bin/python3 -u /opt/mesh.py",
                    "raw.lxc": "lxc.mount.entry = opt/wings-private-hosts etc/hosts none bind,ro,relative,create=file 0 0\n",
                    "user.wings.owner": "wings:" + node["uuid"],
                    "user.wings.server": s["uuid"],
                    "user.wings.ip": "10.238.44." + str(i + 2),
                },
                "devices": {
                    "root": {"type": "disk", "path": "/", "pool": pool},
                    "eth0": {
                        "type": "nic",
                        "network": network,
                        "name": "eth0",
                        "ipv4.address": "10.238.44." + str(i + 2),
                        "security.port_isolation": "true",
                    },
                    "command": {
                        "type": "disk",
                        "path": "/opt/mesh.py",
                        "source": str(hp / "mesh.py"),
                        "readonly": "true",
                    },
                    "hosts": {
                        "type": "disk",
                        "path": "/opt/wings-private-hosts",
                        "source": str(hp / "hosts"),
                        "readonly": "true",
                    },
                },
            },
        )
        incus("start", name, "--project", project)
        node_dir = root / ("node-" + str(i))
        node_dir.mkdir()
        node_cfg = root / ("node-" + str(i) + ".yml")
        node_cfg.write_text(
            json.dumps(
                {
                    "remote": {
                        "url": "https://127.0.0.1:7443",
                        "token": node["node_token"],
                        "cert_sha256": (panel / "https.fingerprint")
                        .read_text()
                        .strip(),
                    },
                    "tunnel_bind": "127.0.0.1:" + str(7151 + i),
                    "metrics_bind": "127.0.0.1:" + str(7161 + i),
                    "data_dir": str(node_dir),
                    "hosts_path": str(hosts / "{server}" / "hosts"),
                }
            )
        )
        env = os.environ.copy()
        env.update(
            {
                "WINGS_TUNDRA_CHILD": "1",
                "WINGS_INCUS_SOCKET": os.environ.get(
                    "INCUS_SOCKET", "/var/lib/incus/unix.socket"
                ),
                "WINGS_INCUS_PROJECT": project,
                "WINGS_INCUS_OWNER": "wings:" + node["uuid"],
            }
        )
        start([wings_binary, "--config", str(node_cfg)], env, "node-" + str(i))
    src_project, src_name = instances[0]
    dest = servers[1]
    ip = "127.0." + str(1 + dest["idx"] // 256) + "." + str(dest["idx"] % 256)
    probe = (
        "import socket; assert socket.gethostbyname('mesh-1.tunnel') == '"
        + ip
        + "'; t=socket.create_connection(('mesh-1.tunnel',23456),timeout=2); t.sendall(b'ok'); assert t.recv(100)==b'mesh-tcp:ok'; t.close(); u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(2); u.sendto(b'ok',('mesh-1.tunnel',23456)); assert u.recv(100)==b'mesh-udp:ok'"
    )
    passed = False
    for _ in range(45):
        p = subprocess.run(
            [
                "incus",
                "exec",
                src_name,
                "--project",
                src_project,
                "--",
                "python3",
                "-c",
                probe,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if p.returncode == 0:
            passed = True
            break
        time.sleep(1)
    if not passed:
        raise RuntimeError("Mesh probe failed: " + p.stderr)
    print(
        "PASS cross-node QUIC TCP/UDP relay with private .tunnel names, Incus namespace adoption, and NIC isolation",
        flush=True,
    )
    api("acls/" + servers[0]["uuid"] + "/" + servers[1]["uuid"], method="DELETE")
    denied_probe = (
        "import socket; t=socket.create_connection(('"
        + ip
        + "',23456),timeout=2); t.sendall(b'ok'); assert t.recv(100)==b'mesh-tcp:ok'"
    )
    denied = False
    for _ in range(15):
        p = subprocess.run(
            [
                "incus",
                "exec",
                src_name,
                "--project",
                src_project,
                "--",
                "python3",
                "-c",
                denied_probe,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if p.returncode != 0:
            denied = True
            break
        time.sleep(1)
    if not denied:
        raise RuntimeError("Revoked private ACL still permits relay")
    print("PASS private-network ACL revocation", flush=True)
    api("acls", {"src_server": servers[0]["uuid"], "dst_server": servers[1]["uuid"]})
    recovered = False
    for _ in range(20):
        p = subprocess.run(
            [
                "incus",
                "exec",
                src_name,
                "--project",
                src_project,
                "--",
                "python3",
                "-c",
                probe,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if p.returncode == 0:
            recovered = True
            break
        time.sleep(1)
    if not recovered:
        raise RuntimeError("Restored private ACL did not restore relay: " + p.stderr)
    print("PASS private-network ACL restoration", flush=True)
    incus("stop", src_name, "--force", "--project", src_project)
    incus("start", src_name, "--project", src_project)
    recovered = False
    for _ in range(20):
        p = subprocess.run(
            [
                "incus",
                "exec",
                src_name,
                "--project",
                src_project,
                "--",
                "python3",
                "-c",
                probe,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if p.returncode == 0:
            recovered = True
            break
        time.sleep(1)
    if not recovered:
        raise RuntimeError(
            "Private relay failed after native Incus restart: " + p.stderr
        )
    print("PASS native Incus restart re-adoption", flush=True)
finally:
    for p in reversed(processes):
        if p.poll() is None:
            p.kill()
        p.wait(timeout=10)
    for project, name in instances:
        try:
            incus("delete", name, "--force", "--project", project)
        except Exception as e:
            print("Cleanup instance:", e)
    for project, owner in projects:
        try:
            info = json.loads(incus("query", "/1.0/projects/" + project))
            assert info["config"]["user.wings.owner"] == owner
            images = json.loads(
                incus("query", "/1.0/images?recursion=1&project=" + project)
            )
            for image in images:
                incus("image", "delete", image["fingerprint"], "--project", project)
            incus("project", "delete", project)
        except Exception as e:
            print("Cleanup project:", e)
    if network_created:
        try:
            info = json.loads(incus("query", "/1.0/networks/" + network))
            assert info["config"]["user.wings.owner"] == network_owner and (
                not info["used_by"]
            )
            incus("network", "delete", network, "--project", "default")
        except Exception as e:
            print("Cleanup network:", e)
    print("Mesh test logs:", root, flush=True)
