use std::{
    fmt::Write as _,
    io::{ErrorKind, Read as _},
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

pub const SERVER_PLACEHOLDER: &str = "{server}";
pub const BEGIN: &str = "# tundra begin";
pub const END: &str = "# tundra end";
pub const SUFFIX: &str = ".tunnel";
pub const MAX_HOSTS_LEN: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub ip: Ipv4Addr,
    pub name: String,
}

/// A control plane that mounts its own hosts file into the container names it here, which
/// keeps the file reachable without access to the engine's container storage.
#[inline]
pub fn templated_path(template: &str, server: &uuid::Uuid) -> Option<PathBuf> {
    if template.is_empty() {
        return None;
    }

    Some(PathBuf::from(
        template.replace(SERVER_PLACEHOLDER, &server.to_string()),
    ))
}

/// The control plane owns naming, but a name reaches this file verbatim and a malformed
/// one would splice arbitrary lines into a container's hosts file. Anything that is not a
/// plain DNS label is refused here rather than written.
#[inline]
pub fn is_valid_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[inline]
pub fn render(entries: &[Entry]) -> String {
    let mut out = String::from(BEGIN);
    out.push('\n');
    for entry in entries {
        let _ = writeln!(out, "{} {}{SUFFIX}", entry.ip, entry.name);
    }

    out.push_str(END);
    out.push('\n');

    out
}

#[inline]
pub fn splice(existing: &str, block: &str) -> String {
    let mut out = String::with_capacity(existing.len() + block.len());
    let mut lines = existing.lines();
    let mut replaced = false;

    while let Some(line) = lines.next() {
        if line.trim_end() == BEGIN {
            out.push_str(block);
            replaced = true;
            for inner in lines.by_ref() {
                if inner.trim_end() == END {
                    break;
                }
            }

            continue;
        }

        out.push_str(line);
        out.push('\n');
    }

    if !replaced {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(block);
    }

    out
}

fn read_bounded(path: &Path) -> Result<String, std::io::Error> {
    let file = std::fs::File::open(path)?;

    let mut bytes = Vec::new();
    file.take(MAX_HOSTS_LEN + 1).read_to_end(&mut bytes)?;

    if bytes.len() as u64 > MAX_HOSTS_LEN {
        return Err(std::io::Error::new(
            ErrorKind::FileTooLarge,
            "the hosts file exceeds the managed size cap",
        ));
    }

    String::from_utf8(bytes)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "the hosts file is not utf-8"))
}

pub fn apply(path: &Path, entries: &[Entry]) -> Result<bool, std::io::Error> {
    let existing = read_bounded(path)?;
    let updated = splice(&existing, &render(entries));
    if updated == existing {
        return Ok(false);
    }

    std::fs::write(path, updated)?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // templated_path

    #[test]
    fn an_empty_template_leaves_the_engine_owning_the_file() {
        assert!(templated_path("", &uuid::Uuid::nil()).is_none());
    }

    #[test]
    fn the_placeholder_is_replaced_with_the_server_uuid() {
        let server = uuid::uuid!("2f4a1b90-5c3d-4e8f-9a0b-1c2d3e4f5a6b");
        assert_eq!(
            templated_path("/var/lib/wings/vmounts/{server}/hosts", &server).unwrap(),
            PathBuf::from("/var/lib/wings/vmounts/2f4a1b90-5c3d-4e8f-9a0b-1c2d3e4f5a6b/hosts")
        );
    }

    fn entry(last: u8, name: &str) -> Entry {
        Entry {
            ip: Ipv4Addr::new(127, 0, 1, last),
            name: name.to_owned(),
        }
    }

    // is_valid_label

    #[test]
    fn only_plain_dns_labels_are_accepted() {
        assert!(is_valid_label("alpha"));
        assert!(is_valid_label("a-1"));

        assert!(!is_valid_label(""));
        assert!(!is_valid_label("-lead"));
        assert!(!is_valid_label("trail-"));
        assert!(!is_valid_label("Upper"));
        assert!(!is_valid_label("has space"));
        assert!(!is_valid_label("two\nlines"));
        assert!(!is_valid_label("has.dot"));
        assert!(!is_valid_label(&"a".repeat(64)));
    }

    // render

    #[test]
    fn render_marks_the_block_and_emits_one_line_per_peer() {
        let text = render(&[entry(1, "alpha"), entry(2, "beta")]);
        assert_eq!(
            text,
            "# tundra begin\n127.0.1.1 alpha.tunnel\n127.0.1.2 beta.tunnel\n# tundra end\n"
        );
    }

    #[test]
    fn render_emits_the_markers_for_an_empty_peer_set() {
        assert_eq!(render(&[]), "# tundra begin\n# tundra end\n");
    }

    // splice

    #[test]
    fn splice_appends_below_dockers_own_entries() {
        let docker = "127.0.0.1\tlocalhost\n172.17.0.2\tabc123\n";
        let out = splice(docker, &render(&[entry(1, "alpha")]));

        assert!(out.starts_with(docker));
        assert!(out.contains("127.0.1.1 alpha.tunnel"));
    }

    #[test]
    fn splice_replaces_only_the_managed_block() {
        let docker = "127.0.0.1\tlocalhost\n";
        let first = splice(docker, &render(&[entry(1, "alpha"), entry(2, "beta")]));
        let second = splice(&first, &render(&[entry(3, "gamma")]));

        assert!(second.starts_with(docker));
        assert!(second.contains("127.0.1.3 gamma.tunnel"));
        assert!(!second.contains("alpha"));
        assert!(!second.contains("beta"));
        assert_eq!(second.matches(BEGIN).count(), 1);
        assert_eq!(second.matches(END).count(), 1);
    }

    #[test]
    fn splice_keeps_content_after_the_block() {
        let original = format!("{BEGIN}\n127.0.1.1 alpha.tunnel\n{END}\ntrailing 1.2.3.4\n");
        let out = splice(&original, &render(&[entry(9, "omega")]));

        assert!(out.contains("trailing 1.2.3.4"));
        assert!(out.contains("127.0.1.9 omega.tunnel"));
        assert!(!out.contains("alpha"));
    }

    #[test]
    fn splice_is_idempotent() {
        let block = render(&[entry(1, "alpha")]);
        let once = splice("127.0.0.1\tlocalhost\n", &block);
        assert_eq!(splice(&once, &block), once);
    }

    #[test]
    fn splice_does_not_glue_onto_a_missing_trailing_newline() {
        let out = splice("127.0.0.1\tlocalhost", &render(&[entry(1, "alpha")]));
        assert!(out.contains("localhost\n# tundra begin"));
    }

    #[test]
    fn splice_replaces_an_unterminated_block_cleanly() {
        let broken = format!("host line\n{BEGIN}\n127.0.1.1 alpha.tunnel\n");
        let out = splice(&broken, &render(&[entry(2, "beta")]));

        assert!(out.starts_with("host line\n"));
        assert!(out.contains("127.0.1.2 beta.tunnel"));
        assert!(!out.contains("alpha"));
        assert_eq!(out.matches(BEGIN).count(), 1);
    }

    // apply

    #[test]
    fn apply_reports_whether_the_file_changed() {
        let dir = std::env::temp_dir().join(format!("tundra-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1\tlocalhost\n").unwrap();

        assert!(apply(&path, &[entry(1, "alpha")]).unwrap());
        assert!(!apply(&path, &[entry(1, "alpha")]).unwrap());
        assert!(apply(&path, &[entry(2, "beta")]).unwrap());

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("127.0.0.1\tlocalhost"));
        assert!(text.contains("127.0.1.2 beta.tunnel"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_refuses_a_hosts_file_it_cannot_read_as_text() {
        let dir = std::env::temp_dir().join(format!("tundra-hosts-binary-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01]).unwrap();

        let err = apply(&path, &[entry(1, "alpha")]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), vec![0xff, 0xfe, 0x00, 0x01]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_refuses_to_create_a_hosts_file_that_is_not_there_yet() {
        let dir = std::env::temp_dir().join(format!("tundra-hosts-gone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");

        let err = apply(&path, &[entry(1, "alpha")]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(!path.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_refuses_an_oversized_hosts_file_without_touching_it() {
        let dir = std::env::temp_dir().join(format!("tundra-hosts-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        let size = MAX_HOSTS_LEN + 2;
        std::fs::write(&path, vec![b'x'; size as usize]).unwrap();

        let err = apply(&path, &[entry(1, "alpha")]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileTooLarge);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);

        // an invalid-UTF-8 oversized file must still be refused, not degraded to empty
        std::fs::write(&path, vec![0xff; size as usize]).unwrap();
        let err = apply(&path, &[entry(1, "alpha")]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileTooLarge);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);

        std::fs::remove_dir_all(&dir).ok();
    }
}
