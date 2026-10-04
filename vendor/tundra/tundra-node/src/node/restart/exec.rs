use super::blob::RESUME_FD_ENV;
use anyhow::Context;
use nix::fcntl::{
    FcntlArg::{F_GETFD, F_SETFD},
    FdFlag, fcntl,
};
use std::{
    ffi::{CString, OsStr, OsString},
    io::{Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
};

/// The dup has CLOEXEC clear and shares the open file description; a socket only sends its
/// FIN when the *last* descriptor for it goes, so the exec closing the original is invisible.
#[derive(Debug, Default)]
pub struct Carrier {
    dups: Vec<RawFd>,
}

impl Carrier {
    pub fn carry(&mut self, fd: RawFd) -> Result<RawFd, anyhow::Error> {
        // SAFETY: the caller holds fd open in an object it owns for the length of the dup.
        let dup = nix::unistd::dup(unsafe { borrow(fd) }).context(format!(
            "failed to duplicate descriptor {fd} for the handover"
        ))?;
        let raw = dup.as_raw_fd();
        std::mem::forget(dup);
        self.dups.push(raw);

        Ok(raw)
    }

    pub fn abandon(self) {
        for fd in &self.dups {
            close_raw(*fd);
        }
    }
}

// SAFETY: the caller must hold fd open for the borrow; every call site takes it from an object it owns.
unsafe fn borrow(fd: RawFd) -> std::os::fd::BorrowedFd<'static> {
    unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }
}

#[inline]
pub fn close_raw(fd: RawFd) {
    // SAFETY: the handover holds this descriptor by number alone and never names it again.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
}

/// Zero linger, so a relay that could not be handed over looks like the failure it is.
pub fn reset_raw(fd: RawFd) {
    // SAFETY: fd is open here and the borrow is dead before close_raw takes it below.
    let borrowed = unsafe { borrow(fd) };
    let _ = socket2::SockRef::from(&borrowed).set_linger(Some(std::time::Duration::ZERO));
    close_raw(fd);
}

#[inline]
pub fn discard(carried: super::blob::Carried) {
    match carried.1 {
        super::blob::FdKind::Relay => reset_raw(carried.0),
        super::blob::FdKind::Plain => close_raw(carried.0),
    }
}

pub fn stage(body: &[u8]) -> Result<RawFd, anyhow::Error> {
    let fd = nix::sys::memfd::memfd_create(c"tundra-handover", nix::sys::memfd::MFdFlags::empty())
        .context("failed to create the handover memfd")?;

    let mut file = std::fs::File::from(fd);
    file.write_all(body)
        .context("failed to write the handover blob")?;
    file.rewind()
        .context("failed to rewind the handover blob")?;

    let raw = file.as_raw_fd();
    std::mem::forget(file);

    Ok(raw)
}

pub fn read_staged(fd: RawFd) -> Result<Vec<u8>, anyhow::Error> {
    use std::io::Read;

    // SAFETY: fd is the inherited handover memfd and nothing else owns it.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.seek(SeekFrom::Start(0))
        .context("failed to rewind the handover blob")?;
    let mut body = Vec::new();
    file.read_to_end(&mut body)
        .context("failed to read the handover blob")?;

    Ok(body)
}

/// Deliberately not `/proc/self/exe`: that names the inode this process started from, which is
/// exactly the file the operator has just replaced.
pub fn resolve_binary(argv0: &OsStr, cwd: &Path, path_var: Option<&OsStr>) -> Option<PathBuf> {
    let raw = Path::new(argv0);
    if raw.as_os_str().is_empty() {
        return None;
    }
    if raw.is_absolute() {
        return Some(raw.to_path_buf());
    }
    if raw.components().count() > 1 {
        return Some(cwd.join(raw));
    }

    let path_var = path_var?;
    std::env::split_paths(path_var)
        .map(|dir| dir.join(raw))
        .find(|candidate| candidate.is_file())
}

/// Returns only on failure, with the caller still a healthy daemon that must undo the handover.
pub fn exec(binary: &Path, args: &[OsString], blob_fd: RawFd, fds: &[RawFd]) -> anyhow::Error {
    for fd in fds.iter().chain(std::iter::once(&blob_fd)) {
        if let Err(err) = set_cloexec(*fd, false) {
            // leave the rest alone: the caller restores whatever is already cleared
            return err.context(format!("failed to clear CLOEXEC on descriptor {fd}"));
        }
    }

    let path = match CString::new(binary.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(err) => {
            return anyhow::Error::new(err)
                .context("failed to encode the binary path, it contains a nul");
        }
    };

    let argv: Vec<CString> = std::iter::once(binary.as_os_str().to_os_string())
        .chain(args.iter().cloned())
        .filter_map(|a| CString::new(a.as_bytes()).ok())
        .collect();
    let envp = environment(blob_fd);

    tracing::info!(
        binary = %binary.display(),
        fds = fds.len(),
        "execing the new image"
    );
    let _ = std::io::stderr().flush();

    let argv: Vec<&std::ffi::CStr> = argv.iter().map(CString::as_c_str).collect();
    let envp: Vec<&std::ffi::CStr> = envp.iter().map(CString::as_c_str).collect();

    match nix::unistd::execve(&path, &argv, &envp) {
        Ok(never) => match never {},
        Err(err) => {
            anyhow::Error::new(err).context(format!("failed to execve {}", binary.display()))
        }
    }
}

/// Built explicitly rather than by `setenv`, which is not safe once the runtime has threads.
fn environment(blob_fd: RawFd) -> Vec<CString> {
    let mut env: Vec<CString> = std::env::vars_os()
        .filter(|(k, _)| k != OsStr::new(RESUME_FD_ENV))
        .filter_map(|(k, v)| {
            let mut entry = k.into_vec();
            entry.push(b'=');
            entry.extend_from_slice(v.as_bytes());
            CString::new(entry).ok()
        })
        .collect();
    env.push(
        CString::new(format!("{RESUME_FD_ENV}={blob_fd}"))
            .expect("failed to encode the resume descriptor variable"),
    );

    env
}

pub fn set_cloexec(fd: RawFd, on: bool) -> Result<(), anyhow::Error> {
    // SAFETY: every caller holds fd open for the length of the call.
    let borrowed = unsafe { borrow(fd) };
    let current = FdFlag::from_bits_truncate(fcntl(borrowed, F_GETFD)?);
    let mut wanted = current;
    wanted.set(FdFlag::FD_CLOEXEC, on);
    if wanted != current {
        fcntl(borrowed, F_SETFD(wanted))?;
    }

    Ok(())
}

pub fn restore_cloexec(fds: &[RawFd], blob_fd: RawFd) {
    for fd in fds.iter().chain(std::iter::once(&blob_fd)) {
        if let Err(err) = set_cloexec(*fd, true) {
            tracing::error!(
                fd,
                "failed to restore CLOEXEC after a failed exec: {:?}",
                err
            );
        }
    }
}

pub fn resume_fd() -> Result<Option<RawFd>, anyhow::Error> {
    let Some(raw) = std::env::var_os(RESUME_FD_ENV) else {
        return Ok(None);
    };

    let text = raw.to_string_lossy().into_owned();
    let fd: RawFd = text.parse().context(format!(
        "failed to parse {RESUME_FD_ENV}, {text:?} is not a descriptor"
    ))?;
    if fd < 3 {
        return Err(anyhow::anyhow!(
            "{RESUME_FD_ENV} names descriptor {fd}, which cannot be a handover blob"
        ));
    }

    Ok(Some(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::{fd::AsRawFd, unix::net::UnixStream},
    };

    // resolve_binary

    #[test]
    fn resolve_binary_resolves_the_path_the_operator_typed() {
        let cwd = Path::new("/srv/work");

        assert_eq!(
            resolve_binary(OsStr::new("/usr/bin/tundra-node"), cwd, None),
            Some(PathBuf::from("/usr/bin/tundra-node"))
        );
        assert_eq!(
            resolve_binary(OsStr::new("./target/release/tundra-node"), cwd, None),
            Some(PathBuf::from("/srv/work/./target/release/tundra-node"))
        );
        assert_eq!(resolve_binary(OsStr::new(""), cwd, None), None);
        assert_eq!(resolve_binary(OsStr::new("tundra-node"), cwd, None), None);
    }

    #[test]
    fn resolve_binary_looks_a_bare_name_up_on_the_path() {
        let cwd = Path::new("/srv/work");
        let path = OsString::from("/nonexistent:/usr/bin:/bin");
        // sh exists in one of those on every system this daemon runs on
        let found = resolve_binary(OsStr::new("sh"), cwd, Some(&path));
        assert!(
            found.as_deref().is_some_and(Path::is_file),
            "expected to find sh, got {found:?}"
        );
        assert_eq!(
            resolve_binary(OsStr::new("nope-not-here"), cwd, Some(&path)),
            None
        );
    }

    // stage / read_staged

    #[test]
    fn stage_and_read_staged_round_trip_byte_for_byte() {
        let body: Vec<u8> = (0..=255u8).cycle().take(9000).collect();
        let fd = stage(&body).unwrap();
        assert_eq!(read_staged(fd).unwrap(), body);
    }

    // set_cloexec

    #[test]
    fn set_cloexec_clears_the_flag_and_puts_it_back() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.as_raw_fd();

        // sockets are created CLOEXEC, which is what makes clearing it deliberate
        assert!(is_cloexec(fd));
        set_cloexec(fd, false).unwrap();
        assert!(!is_cloexec(fd));
        set_cloexec(fd, true).unwrap();
        assert!(is_cloexec(fd));
    }

    // Carrier

    #[test]
    fn carry_returns_a_duplicate_that_outlives_the_original() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut carrier = Carrier::default();
        let dup = carrier.carry(listener.as_raw_fd()).unwrap();
        assert!(!is_cloexec(dup));

        drop(listener);
        // SAFETY: dup is the carrier's still-unabandoned duplicate, so this test is its only owner
        let adopted = unsafe { std::net::TcpListener::from_raw_fd(dup) };
        assert_eq!(adopted.local_addr().unwrap(), addr);
    }

    #[test]
    fn carry_holds_the_socket_open_until_abandon_lets_go() {
        // asserted through the peer: a closed descriptor number is immediately reusable
        let (near, far) = UnixStream::pair().unwrap();
        far.set_nonblocking(true).unwrap();
        let mut far = far;
        let mut buf = [0; 1];

        let mut carrier = Carrier::default();
        carrier.carry(near.as_raw_fd()).unwrap();

        drop(near);
        assert_eq!(
            far.read(&mut buf).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        carrier.abandon();
        assert_eq!(far.read(&mut buf).unwrap(), 0);
    }

    fn is_cloexec(fd: RawFd) -> bool {
        // SAFETY: callers pass a descriptor they still hold open for the length of the fcntl
        let flags = FdFlag::from_bits_truncate(fcntl(unsafe { borrow(fd) }, F_GETFD).unwrap());
        flags.contains(FdFlag::FD_CLOEXEC)
    }
}
