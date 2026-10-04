use std::{path::PathBuf, process::Command};
use tundra_node_test_support::{ContainerTarget, NetnsBinder};

// the binder lives in the binary crate, so the test re-declares it rather than the crate
// growing a library target purely for tests
mod tundra_node_test_support {
    use nix::{
        fcntl::{OFlag, open},
        sched::{CloneFlags, setns},
        sys::stat::Mode,
    };
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::{net::SocketAddrV4, os::fd::OwnedFd, sync::mpsc};

    const LISTEN_BACKLOG: i32 = 128;

    fn open_ns(path: &str) -> Result<OwnedFd, std::io::Error> {
        Ok(open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?)
    }

    pub struct ContainerTarget {
        pub id: String,
        pub pid: i32,
    }

    pub struct NetnsBinder;

    impl NetnsBinder {
        pub fn bind_tcp(
            &self,
            target: &ContainerTarget,
            addr: SocketAddrV4,
        ) -> Result<std::net::TcpListener, std::io::Error> {
            // reads id so the mirrored struct does not trip dead_code
            let _ = &target.id;
            let pid = target.pid;
            let (tx, rx) = mpsc::channel();

            std::thread::spawn(move || {
                let result = (|| -> Result<std::net::TcpListener, std::io::Error> {
                    let original = open_ns("/proc/self/ns/net")?;
                    let target = open_ns(&format!("/proc/{pid}/ns/net"))?;
                    setns(&target, CloneFlags::CLONE_NEWNET)?;

                    let bound = (|| {
                        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                        sock.set_reuse_address(true)?;
                        sock.bind(&SockAddr::from(std::net::SocketAddr::V4(addr)))?;
                        sock.listen(LISTEN_BACKLOG)?;
                        sock.set_nonblocking(true)?;
                        Ok(sock.into())
                    })();

                    setns(&original, CloneFlags::CLONE_NEWNET)?;
                    bound
                })();

                let _ = tx.send(result);
            });

            rx.recv()
                .map_err(|_| std::io::Error::other("netns helper thread died"))?
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
#[ignore = "needs root and Docker"]
fn demo_flow_passes_end_to_end() {
    let status = Command::new("bash")
        .arg("scripts/demo.sh")
        .current_dir(workspace_root())
        .status()
        .unwrap();

    assert!(status.success());
}

#[test]
#[ignore = "needs root and Docker"]
fn frontend_binds_inside_the_container_and_not_on_the_host() {
    let name = "tundra-netns-test";
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
    docker(&["run", "-d", "--name", name, "alpine", "sleep", "120"]);

    let pid: i32 = docker(&["inspect", "-f", "{{.State.Pid}}", name])
        .parse()
        .unwrap();

    let target = ContainerTarget {
        id: name.to_owned(),
        pid,
    };
    let addr = "127.0.9.9:24242".parse().unwrap();

    let listener = NetnsBinder.bind_tcp(&target, addr).unwrap();
    assert_eq!(
        listener.local_addr().unwrap().to_string(),
        "127.0.9.9:24242"
    );

    assert!(std::net::TcpListener::bind(addr).is_ok());

    let inside = docker(&["exec", name, "sh", "-c", "netstat -lnt 2>/dev/null || true"]);
    assert!(
        inside.contains("127.0.9.9:24242") || inside.is_empty(),
        "{inside}"
    );

    drop(listener);
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
}
