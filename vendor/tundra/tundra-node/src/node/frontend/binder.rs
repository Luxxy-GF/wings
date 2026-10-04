use anyhow::Context;
use nix::{
    fcntl::{OFlag, open},
    sched::{CloneFlags, setns},
    sys::stat::Mode,
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    net::{SocketAddr, SocketAddrV4},
    os::fd::OwnedFd,
    sync::mpsc,
};

const LISTEN_BACKLOG: i32 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerTarget {
    pub pid: i32,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Tcp,
    Udp,
}

impl Kind {
    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

pub trait FrontendBinder: std::fmt::Debug + Send + Sync {
    fn bind_tcp(
        &self,
        target: &ContainerTarget,
        addr: SocketAddrV4,
    ) -> Result<std::net::TcpListener, std::io::Error>;

    fn bind_udp(
        &self,
        target: &ContainerTarget,
        addr: SocketAddrV4,
    ) -> Result<std::net::UdpSocket, std::io::Error>;
}

#[derive(Debug, Default)]
pub struct NetnsBinder;

impl FrontendBinder for NetnsBinder {
    fn bind_tcp(
        &self,
        target: &ContainerTarget,
        addr: SocketAddrV4,
    ) -> Result<std::net::TcpListener, std::io::Error> {
        in_netns(target.pid, move || {
            let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            sock.set_reuse_address(true)?;
            sock.bind(&SockAddr::from(SocketAddr::V4(addr)))?;
            sock.listen(LISTEN_BACKLOG)?;
            sock.set_nonblocking(true)?;
            Ok(sock.into())
        })
    }

    fn bind_udp(
        &self,
        target: &ContainerTarget,
        addr: SocketAddrV4,
    ) -> Result<std::net::UdpSocket, std::io::Error> {
        in_netns(target.pid, move || {
            let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_reuse_address(true)?;
            sock.bind(&SockAddr::from(SocketAddr::V4(addr)))?;
            sock.set_nonblocking(true)?;
            Ok(sock.into())
        })
    }
}

/// setns is per-thread and permanent for that thread, so it must never touch a tokio worker.
/// The thread is discarded once the socket is handed back, so it never returns to the
/// namespace it came from - and under a rootless engine it could not: the daemon holds
/// CAP_SYS_ADMIN in the user namespace it runs in, which owns the container namespaces
/// below it but not the initial one that owns the host's own netns.
fn in_netns<T: Send + 'static>(
    pid: i32,
    f: impl FnOnce() -> Result<T, std::io::Error> + Send + 'static,
) -> Result<T, std::io::Error> {
    let (tx, rx) = mpsc::channel();

    let thread = std::thread::Builder::new()
        .name(format!("tundra-netns-{pid}"))
        .spawn(move || {
            let result = (|| {
                let target = open_ns(&format!("/proc/{pid}/ns/net"))?;
                setns(&target, CloneFlags::CLONE_NEWNET)?;

                f()
            })();

            let _ = tx.send(result);
        })?;

    let result = rx
        .recv()
        .map_err(|_| std::io::Error::other("netns helper thread died before binding"));
    let _ = thread.join();

    result?
}

fn open_ns(path: &str) -> Result<OwnedFd, std::io::Error> {
    Ok(open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?)
}

pub async fn bind_tcp(
    binder: std::sync::Arc<dyn FrontendBinder>,
    target: ContainerTarget,
    addr: SocketAddrV4,
) -> Result<tokio::net::TcpListener, anyhow::Error> {
    let std =
        tokio::task::spawn_blocking(move || -> Result<std::net::TcpListener, std::io::Error> {
            binder.bind_tcp(&target, addr)
        })
        .await?
        .context(format!("failed to bind tcp {addr} inside the container"))?;

    Ok(tokio::net::TcpListener::from_std(std)?)
}

pub async fn bind_udp(
    binder: std::sync::Arc<dyn FrontendBinder>,
    target: ContainerTarget,
    addr: SocketAddrV4,
) -> Result<tokio::net::UdpSocket, anyhow::Error> {
    let std =
        tokio::task::spawn_blocking(move || -> Result<std::net::UdpSocket, std::io::Error> {
            binder.bind_udp(&target, addr)
        })
        .await?
        .context(format!("failed to bind udp {addr} inside the container"))?;

    Ok(tokio::net::UdpSocket::from_std(std)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // in_netns

    #[test]
    #[ignore = "needs root for setns"]
    fn binding_in_our_own_namespace_round_trips_through_the_helper_thread() {
        let target = ContainerTarget {
            pid: std::process::id() as i32,
        };
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0);

        let listener = NetnsBinder.bind_tcp(&target, addr).unwrap();
        assert!(listener.local_addr().unwrap().port() > 0);

        let sock = NetnsBinder.bind_udp(&target, addr).unwrap();
        assert!(sock.local_addr().unwrap().port() > 0);
    }

    #[test]
    #[ignore = "needs root for setns"]
    fn sockets_come_back_non_blocking_as_tokio_requires() {
        let target = ContainerTarget {
            pid: std::process::id() as i32,
        };
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0);

        let listener = NetnsBinder.bind_tcp(&target, addr).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn a_bind_failure_is_reported_rather_than_panicking_the_helper() {
        let target = ContainerTarget {
            pid: std::process::id() as i32,
        };
        // 240.0.0.1 is reserved and not assigned to any local interface
        let addr = SocketAddrV4::new(Ipv4Addr::new(240, 0, 0, 1), 9);
        assert!(NetnsBinder.bind_tcp(&target, addr).is_err());
    }

    #[test]
    fn entering_a_nonexistent_namespace_fails_cleanly() {
        let target = ContainerTarget { pid: 0x7fff_fffe };
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0);
        assert!(NetnsBinder.bind_tcp(&target, addr).is_err());
    }
}
