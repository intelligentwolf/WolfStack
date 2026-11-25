// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Read files inside a scan target (the host, or a running container)
//! without ever letting the target steer the read outside itself.
//!
//! ## Why not just `std::fs::read("/proc/<pid>/root/etc/profile")`
//!
//! `/proc/<pid>/root` is a magic link to the container's root, but the
//! kernel resolves *absolute symlinks found beyond it* against the
//! CALLER's root — WolfStack's, i.e. the host. A root user inside a
//! compromised container could plant `/root/.bashrc -> /etc/shadow`
//! and every scanner that "reads the container's .bashrc" would read
//! the host's shadow file instead, and quote it into an inbox card.
//!
//! `openat2(2)` with `RESOLVE_IN_ROOT` resolves every component —
//! including absolute and `..` symlinks — as if the opened directory
//! were `/`, so a lookup can never escape the target.
//! `RESOLVE_NO_MAGICLINKS` additionally refuses `/proc/self/fd/N`-style
//! jumps. Linux 5.6+; on an older kernel `openat2` returns ENOSYS and
//! every read here fails closed (returns nothing) rather than falling
//! back to an unsafe path walk.
//!
//! ## Never block the scan
//!
//! * Files are opened `O_NONBLOCK` and checked before a byte is read, so a
//!   FIFO planted where a config file should be cannot park the scanner
//!   thread in `read(2)` forever, and a device node (`/dev/zero`) cannot be
//!   streamed. A file larger than the caller's cap is an error, never a
//!   silently truncated prefix (padding a file must not hide its tail).
//! * Network and FUSE filesystems (an rclone mount with a dead backend is the
//!   classic case on this fleet) are never entered. Matching their mount
//!   points by path text is not enough — a container can plant
//!   `/etc/profile -> /mnt/rclone/x`, and root inside a container can even
//!   mount its own FUSE filesystem. So every walk is confined to ONE mount
//!   (`RESOLVE_NO_XDEV`: the kernel refuses to step into another mount
//!   before any filesystem code runs). Other mounts are entered only at
//!   their canonical mount point, as listed in the target's own
//!   `mountinfo`, with symlinks forbidden on the way (`RESOLVE_NO_SYMLINKS`)
//!   and only when neither they nor any mount above them can block.
//! * Metadata comes from `statx(AT_STATX_DONT_SYNC)`, which FUSE and NFS
//!   answer from cached attributes without a round trip to the daemon or
//!   server, so even a directory entry that IS a wedged mount point can be
//!   listed.

use std::collections::HashSet;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

/// Metadata subset the checks need. Taken from `fstatat(2)`.
#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub mode: u32,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
}

impl Meta {
    pub fn is_file(&self) -> bool { self.mode & libc::S_IFMT == libc::S_IFREG }
    pub fn is_dir(&self) -> bool { self.mode & libc::S_IFMT == libc::S_IFDIR }
    pub fn is_symlink(&self) -> bool { self.mode & libc::S_IFMT == libc::S_IFLNK }

}

/// A directory entry with its own (non-followed) metadata.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub meta: Meta,
}

/// A target's filesystem, opened once as a directory fd.
pub struct RootFs {
    dir: OwnedFd,
    /// Mount points (target-relative, no leading slash) whose filesystem
    /// type can block indefinitely.
    blocking_mounts: HashSet<String>,
    /// Mount points that may be entered: not blocking, nothing blocking
    /// above them. Longest first. "" (the target's root) is always present.
    safe_mounts: Vec<String>,
    /// Host path of the container's writable overlay layer, when its root
    /// is an overlay (Docker / Podman / CRI). None for the host and for
    /// LXC on dir / ZFS / LVM roots.
    pub upperdir: Option<String>,
}

/// Filesystem types a scan must never enter: a `stat` or `readdir` on
/// them waits for a userspace daemon or a remote server. Matched
/// against field 9 of `/proc/<pid>/mountinfo` (proc(5)).
pub fn fstype_can_block(fstype: &str) -> bool {
    fstype.starts_with("fuse")
        || matches!(fstype,
            "nfs" | "nfs4" | "cifs" | "smb3" | "smbfs" | "ceph" | "9p"
            | "afs" | "lustre" | "glusterfs" | "autofs" | "davfs" | "sshfs")
}

/// Undo the octal escaping proc(5) applies to mountinfo paths
/// (space = `\040`, tab = `\011`, newline = `\012`, backslash = `\134`).
fn unescape_mount_path(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a mountinfo body into (blocking mount points, enterable mount
/// points), all normalised to "no leading slash". Field layout per proc(5):
/// `id parent maj:min root mountpoint opts [optional...] - fstype src superopts`.
/// A mount is enterable when it cannot block and no mount above it can.
pub fn parse_mounts(mountinfo: &str) -> (HashSet<String>, Vec<String>) {
    let mut all: Vec<(String, bool)> = Vec::new();
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 7 { continue; }
        let Some(sep) = fields.iter().position(|f| *f == "-") else { continue };
        let Some(fstype) = fields.get(sep + 1) else { continue };
        let mp = unescape_mount_path(fields[4]);
        all.push((mp.trim_start_matches('/').trim_end_matches('/').to_string(), fstype_can_block(fstype)));
    }
    let blocking: HashSet<String> = all.iter().filter(|(_, b)| *b).map(|(m, _)| m.clone()).collect();
    let under_blocking = |m: &str| blocking.iter().any(|b| !b.is_empty() && (m == b || m.starts_with(&format!("{}/", b))));
    let mut safe: Vec<String> = all.iter()
        .filter(|(m, b)| !*b && !under_blocking(m))
        .map(|(m, _)| m.clone())
        .collect();
    safe.push(String::new());
    safe.sort_by_key(|m| std::cmp::Reverse(m.len()));
    safe.dedup();
    (blocking, safe)
}

/// The writable layer of an overlay-rooted container: the `upperdir=`
/// super-option of the mount whose mount point is `/` (proc(5) field 5)
/// and whose fstype is `overlay`. Docker's overlay2 driver, the containerd
/// snapshotter, Podman and CRI runtimes all root containers this way; the
/// path is a HOST path. overlayfs escapes a literal comma in a path as
/// `\,`, so the option ends at the first unescaped comma.
pub fn parse_overlay_upperdir(mountinfo: &str) -> Option<String> {
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 7 || fields[4] != "/" { continue; }
        let Some(sep) = fields.iter().position(|f| *f == "-") else { continue };
        if fields.get(sep + 1) != Some(&"overlay") { continue; }
        let opts = fields.get(sep + 3)?;
        let start = opts.find("upperdir=")? + "upperdir=".len();
        let mut out = String::new();
        let mut chars = opts[start..].chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => if let Some(n) = chars.next() { out.push(n) },
                ',' => break,
                _ => out.push(c),
            }
        }
        return Some(unescape_mount_path(&out)).filter(|p| p.starts_with('/'));
    }
    None
}

/// `openat2(dirfd, path, how)`, retried on EINTR / EAGAIN. EAGAIN is
/// what RESOLVE_IN_ROOT returns when a concurrent rename races the
/// lookup (openat2(2)); a couple of retries is the documented answer.
fn openat2(dirfd: i32, path: &CString, flags: i32, resolve: u64) -> std::io::Result<OwnedFd> {
    // `open_how` is #[non_exhaustive] in libc and the kernel requires
    // every field it does not know to be zero (openat2(2): E2BIG /
    // EINVAL otherwise) — so start from all-zero and set the three.
    // SAFETY: open_how is a plain-integer C struct; all-zero is valid.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.mode = 0;
    how.resolve = resolve;
    for _ in 0..4 {
        // SAFETY: `how` is a valid, fully-initialised open_how and its
        // exact size is passed; `path` is a NUL-terminated C string that
        // outlives the call. The returned descriptor is owned below.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                &how as *const libc::open_how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd >= 0 {
            // SAFETY: the kernel just returned this fd to us; nothing
            // else owns it.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
            _ => return Err(err),
        }
    }
    Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
}

/// `statx` without a server round trip (AT_STATX_DONT_SYNC) and without
/// triggering an automount. `name` empty = the fd itself (AT_EMPTY_PATH).
fn statx_meta(dirfd: i32, name: &CString, nofollow: bool) -> Option<Meta> {
    let mut flags = libc::AT_STATX_DONT_SYNC | libc::AT_NO_AUTOMOUNT;
    if nofollow { flags |= libc::AT_SYMLINK_NOFOLLOW; }
    if name.as_bytes().is_empty() { flags |= libc::AT_EMPTY_PATH; }
    // SAFETY: zeroed statx is a valid out-parameter; dirfd is live and
    // name is NUL-terminated.
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe { libc::statx(dirfd, name.as_ptr(), flags, libc::STATX_BASIC_STATS, &mut st) } != 0 {
        return None;
    }
    Some(Meta {
        mode: st.stx_mode as u32,
        size: st.stx_size,
        mtime: st.stx_mtime.tv_sec,
        mtime_nsec: st.stx_mtime.tv_nsec as i64,
        ctime: st.stx_ctime.tv_sec,
    })
}

fn fstat(fd: i32) -> Option<Meta> {
    statx_meta(fd, &CString::default(), false)
}

fn fstatat_nofollow(dirfd: i32, name: &CString) -> Option<Meta> {
    statx_meta(dirfd, name, true)
}

/// Why a read produced nothing — callers that keep baselines must not
/// treat "could not read" as "not there".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadErr {
    Missing,
    TooLarge,
    Unreadable,
}

/// Normalise a target-relative path: strip leading/trailing slashes.
/// `..` components are left in place — RESOLVE_IN_ROOT clamps them at
/// the target root, so they cannot escape.
fn rel(path: &str) -> &str {
    let p = path.trim_start_matches('/').trim_end_matches('/');
    if p.is_empty() { "." } else { p }
}

impl RootFs {
    /// Open the filesystem of the process `pid` (1 for the host).
    ///
    /// Always through `/proc/<pid>/root`, PID 1 included: on a normal host
    /// that IS `/`, but when WolfStack itself runs in a container (or a
    /// test harness does) `/` is its own root, and reading the host's
    /// filesystem there would silently read the wrong one.
    pub fn for_pid(pid: u32) -> Option<Self> {
        let root_path = format!("/proc/{}/root", pid);
        let c = CString::new(root_path.clone()).ok()?;
        // Plain open (not openat2) for the root itself: following the
        // /proc/<pid>/root magic link is exactly the point here.
        // SAFETY: valid C string; result checked.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 { return None; }
        // SAFETY: freshly returned descriptor, owned here.
        let dir = unsafe { OwnedFd::from_raw_fd(fd) };
        let mountinfo = std::fs::read_to_string(format!("/proc/{}/mountinfo", pid)).unwrap_or_default();
        let upperdir = if pid == 1 { None } else { parse_overlay_upperdir(&mountinfo) };
        let (blocking_mounts, safe_mounts) = parse_mounts(&mountinfo);
        Some(RootFs { dir, blocking_mounts, safe_mounts, upperdir })
    }

    /// True when `path` is (or is inside) a mount that can block.
    pub fn is_blocking(&self, path: &str) -> bool {
        let p = path.trim_start_matches('/').trim_end_matches('/');
        self.blocking_mounts.iter().any(|m| {
            !m.is_empty() && (p == m || p.starts_with(&format!("{}/", m)))
        })
    }

    /// Open `path` without ever entering a mount that is not the deepest
    /// enterable mount on its canonical path (see the module docs).
    /// Err carries the errno (ENOENT/ENOTDIR = missing).
    fn open(&self, path: &str, flags: i32) -> Result<OwnedFd, i32> {
        self.open_resolve(path, flags, 0)
    }

    /// [`open`](Self::open) with extra `RESOLVE_*` flags for the walk
    /// inside the final mount.
    fn open_resolve(&self, path: &str, flags: i32, extra_resolve: u64) -> Result<OwnedFd, i32> {
        if self.is_blocking(path) { return Err(libc::EXDEV); }
        let p = rel(path);
        let mount = self.safe_mounts.iter()
            .find(|m| m.is_empty() || p == m.as_str() || p.starts_with(&format!("{}/", m)))
            .cloned()
            .unwrap_or_default();
        let err = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        let in_mount = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_XDEV | libc::RESOLVE_NO_MAGICLINKS | extra_resolve;
        let to_mount = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
        if mount.is_empty() {
            let c = CString::new(p).map_err(|_| libc::EINVAL)?;
            return openat2(self.dir.as_raw_fd(), &c, flags, in_mount).map_err(err);
        }
        let cm = CString::new(mount.as_str()).map_err(|_| libc::EINVAL)?;
        if p == mount {
            // The target IS a mount point (a bind-mounted file or dir).
            return openat2(self.dir.as_raw_fd(), &cm, flags, to_mount).map_err(err);
        }
        let base = openat2(self.dir.as_raw_fd(), &cm, libc::O_PATH | libc::O_DIRECTORY, to_mount).map_err(err)?;
        let rest = CString::new(&p[mount.len() + 1..]).map_err(|_| libc::EINVAL)?;
        openat2(base.as_raw_fd(), &rest, flags, in_mount).map_err(err)
    }

    /// Read a regular file of at most `cap` bytes, distinguishing a file
    /// that is not there from one that could not be read or is too big.
    pub fn read_checked(&self, path: &str, cap: usize) -> Result<Vec<u8>, ReadErr> {
        use std::io::Read;
        let fd = self.open(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY)
            .map_err(|e| if e == libc::ENOENT || e == libc::ENOTDIR { ReadErr::Missing } else { ReadErr::Unreadable })?;
        let meta = fstat(fd.as_raw_fd()).ok_or(ReadErr::Unreadable)?;
        if !meta.is_file() { return Err(ReadErr::Unreadable); }
        if meta.size as usize > cap { return Err(ReadErr::TooLarge); }
        let mut f = std::fs::File::from(fd);
        let mut buf = Vec::with_capacity(meta.size as usize);
        // +1 so a file that grew past the cap after fstat is still caught.
        f.by_ref().take(cap as u64 + 1).read_to_end(&mut buf).map_err(|_| ReadErr::Unreadable)?;
        if buf.len() > cap { return Err(ReadErr::TooLarge); }
        Ok(buf)
    }

    /// [`read_checked`](Self::read_checked) for callers to whom every
    /// failure means the same thing.
    pub fn read(&self, path: &str, cap: usize) -> Option<Vec<u8>> {
        self.read_checked(path, cap).ok()
    }

    pub fn read_string(&self, path: &str, cap: usize) -> Option<String> {
        self.read(path, cap).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// `lstat` of a target path (the final component is not followed).
    pub fn lstat(&self, path: &str) -> Option<Meta> {
        let p = rel(path);
        if p == "." {
            return fstat(self.dir.as_raw_fd());
        }
        let (parent, name) = match p.rsplit_once('/') {
            Some((a, b)) => (a, b),
            None => (".", p),
        };
        let dir = self.open(parent, libc::O_PATH | libc::O_DIRECTORY).ok()?;
        if self.is_blocking(p) { return None; }
        let cname = CString::new(name).ok()?;
        fstatat_nofollow(dir.as_raw_fd(), &cname)
    }

    /// True only when `path` provably does not exist in the target: walked
    /// WITHOUT following any symlink, some component is absent (ENOENT) or
    /// a parent is not a directory (ENOTDIR). Every other failure —
    /// permission, a blocking mount, any symlink on the way (ELOOP) — is
    /// "not known to be missing", so a caller that treats "missing" as
    /// "nothing to report" can never be talked into silence by an error.
    ///
    /// Symlinks are refused rather than followed because [`open`](Self::open)
    /// resolves an absolute link relative to the mount it sits in, not
    /// the target's `/`: a package dir swapped for an absolute symlink on
    /// a sub-mount would otherwise look absent while node runs through it.
    pub fn is_missing(&self, path: &str) -> bool {
        matches!(self.open_resolve(path, libc::O_PATH, libc::RESOLVE_NO_SYMLINKS),
            Err(e) if e == libc::ENOENT || e == libc::ENOTDIR)
    }

    /// List a directory. Entries carry their own lstat metadata;
    /// entries that sit on a blocking mount are omitted.
    pub fn list_dir(&self, path: &str) -> Vec<Entry> {
        let mut out = Vec::new();
        let Ok(dir) = self.open(path, libc::O_RDONLY | libc::O_DIRECTORY) else { return out };
        // Iterate through the already-resolved descriptor. Re-opening
        // /proc/self/fd/N reaches the same directory inode; the names
        // it yields are single components, statted relative to `dir`.
        let Ok(rd) = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd())) else { return out };
        let base = rel(path);
        for ent in rd.flatten() {
            let name_os = ent.file_name();
            let Ok(cname) = CString::new(name_os.as_bytes()) else { continue };
            let name = name_os.to_string_lossy().into_owned();
            let child = if base == "." { name.clone() } else { format!("{}/{}", base, name) };
            if self.is_blocking(&child) { continue; }
            if let Some(meta) = fstatat_nofollow(dir.as_raw_fd(), &cname) {
                out.push(Entry { name, meta });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_mount_parsing_uses_fstype_after_separator() {
        // Real mountinfo lines (this host + an rclone FUSE mount).
        let mi = "26 33 0:24 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw\n\
                  91 33 0:61 / /mnt/backups rw,nosuid,nodev,relatime shared:44 - fuse.rclone ff2:backups rw,user_id=0\n\
                  92 33 0:62 / /mnt/my\\040share rw - cifs //nas/share rw\n\
                  93 33 0:63 / /srv/data rw shared:1 - ext4 /dev/sdb1 rw\n";
        let (set, safe) = parse_mounts(mi);
        assert!(set.contains("mnt/backups"));
        assert!(set.contains("mnt/my share"), "octal escape must be decoded: {:?}", set);
        assert!(!set.contains("proc"));
        assert!(!set.contains("srv/data"));
        // Enterable: the non-blocking mounts plus the root, longest first.
        assert!(safe.contains(&"proc".to_string()) && safe.contains(&"srv/data".to_string()));
        assert!(!safe.contains(&"mnt/backups".to_string()));
        assert_eq!(safe.last().map(|s| s.as_str()), Some(""));
    }

    #[test]
    fn mounts_under_a_blocking_mount_are_not_enterable() {
        let mi = "1 0 0:1 / /mnt/nfs rw - nfs4 srv:/x rw\n2 1 0:2 / /mnt/nfs/inner rw - ext4 /dev/sdb rw\n";
        let (_, safe) = parse_mounts(mi);
        assert!(!safe.contains(&"mnt/nfs/inner".to_string()));
    }

    #[test]
    fn symlinks_into_another_mount_are_not_followed() {
        // A planted symlink that points into a different filesystem
        // (/proc here; an rclone FUSE mount in the attack) must not be
        // followed — the walk stays inside the mount it started in.
        let dir = std::env::temp_dir().join(format!("ws-rootfs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("profile");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/proc/version", &link).unwrap();
        let root = RootFs::for_pid(std::process::id()).expect("open own root");
        assert!(root.read(link.to_str().unwrap(), 4096).is_none());
        // A same-filesystem file next to it is still readable.
        let plain = dir.join("plain");
        std::fs::write(&plain, b"ok").unwrap();
        assert_eq!(root.read(plain.to_str().unwrap(), 4096).as_deref(), Some(&b"ok"[..]));
        // Too large is an error, not a truncated prefix.
        assert_eq!(root.read_checked(plain.to_str().unwrap(), 1), Err(ReadErr::TooLarge));
        assert_eq!(root.read_checked(dir.join("absent").to_str().unwrap(), 10), Err(ReadErr::Missing));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_missing_only_for_paths_that_do_not_exist() {
        let dir = std::env::temp_dir().join(format!("ws-rootfs-missing-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("pkg")).unwrap();
        std::fs::write(dir.join("file"), b"x").unwrap();
        let _ = std::fs::remove_file(dir.join("escape"));
        std::os::unix::fs::symlink("/proc/version", dir.join("escape")).unwrap();
        let root = RootFs::for_pid(std::process::id()).expect("open own root");
        let p = |s: &str| dir.join(s).to_str().unwrap().to_string();
        assert!(!root.is_missing(&p("pkg")));
        assert!(!root.is_missing(&p("file")));
        // Symlinks are never followed (ELOOP): unknown, not missing —
        // whether they point into another mount, at an absolute path that
        // would resolve inside this mount, or nowhere at all.
        assert!(!root.is_missing(&p("escape")));
        let _ = std::fs::remove_file(dir.join("dangling"));
        std::os::unix::fs::symlink("no-such-dir", dir.join("dangling")).unwrap();
        assert!(!root.is_missing(&p("dangling")));
        assert!(!root.is_missing(&p("dangling/bin/vite.js")));
        assert!(root.is_missing(&p("absent")));
        // ENOTDIR: a parent component is a file.
        assert!(root.is_missing(&p("file/inside")));
        std::fs::remove_dir(dir.join("pkg")).unwrap();
        assert!(root.is_missing(&p("pkg")));
        assert!(root.is_missing(&p("pkg/bin/vite.js")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlay_upperdir_from_the_root_mount() {
        // Root mount of a Docker container on the containerd snapshotter,
        // captured from a live host (lowerdir list shortened).
        let mi = "1546 1400 0:120 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1545/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/615/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1546/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1546/work\n                  1547 1546 0:121 / /proc rw - proc proc rw\n";
        assert_eq!(parse_overlay_upperdir(mi).as_deref(),
            Some("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1546/fs"));
        // Escaped comma inside the path.
        let mi = "1 0 0:1 / / rw - overlay overlay rw,lowerdir=/a,upperdir=/x\\,y/fs,workdir=/w\n";
        assert_eq!(parse_overlay_upperdir(mi).as_deref(), Some("/x,y/fs"));
        // An LXC on a plain directory root has no upper layer.
        assert_eq!(parse_overlay_upperdir("1 0 8:1 /var/lib/lxc/web/rootfs / rw - ext4 /dev/sda1 rw\n"), None);
    }

    #[test]
    fn host_root_reads_and_refuses_non_regular_files() {
        // Own root: same openat2 path, no privileges needed (PID 1's root
        // is only readable by root; tests run unprivileged locally and in CI).
        let root = RootFs::for_pid(std::process::id()).expect("open own root");
        // A regular file is read and capped.
        let os = root.read("/etc/hostname", 4096)
            .or_else(|| root.read("/proc/version", 4096));
        // /proc/version is not S_IFREG-sized but IS a regular file in procfs.
        assert!(os.is_some());
        // A directory is not a file.
        assert!(root.read("/etc", 10).is_none());
        // A character device is refused before any read.
        assert!(root.read("/dev/zero", 10).is_none());
    }

    #[test]
    fn in_root_resolution_clamps_dotdot() {
        // Own root: same openat2 path, no privileges needed (PID 1's root
        // is only readable by root; tests run unprivileged locally and in CI).
        let root = RootFs::for_pid(std::process::id()).expect("open own root");
        // `..` above the root resolves to the root itself under
        // RESOLVE_IN_ROOT, so this reads /etc/passwd, never anything
        // outside the target.
        let a = root.read("/../../etc/passwd", 1 << 20);
        let b = root.read("/etc/passwd", 1 << 20);
        assert_eq!(a, b);
    }

    #[test]
    fn list_dir_reports_lstat_metadata() {
        // Own root: same openat2 path, no privileges needed (PID 1's root
        // is only readable by root; tests run unprivileged locally and in CI).
        let root = RootFs::for_pid(std::process::id()).expect("open own root");
        let ents = root.list_dir("/etc");
        assert!(ents.iter().any(|e| e.name == "passwd" && e.meta.is_file()));
    }
}
