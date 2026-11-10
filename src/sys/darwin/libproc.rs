//! libproc: processes, their file descriptors, sockets and open vnodes straight from the kernel
//! (what `lsof` does internally, without the subprocess or its text output).
//!
//! The socket structs are not in the `libc` crate; they mirror `<sys/proc_info.h>` exactly and
//! their sizes and field offsets are checked at compile time against the values the C compiler
//! reports for the macOS SDK (see the `const _` asserts and the `layouts` test). The kernel only
//! fills a PROC_PIDFDSOCKETINFO / PROC_PIDFDVNODEPATHINFO buffer of exactly that size.
//!
//! Without root, the fd calls fail with EPERM for other users' processes, so only the current
//! user's sockets and files are seen (same as `lsof` without root).
use std::mem::{offset_of, size_of};

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDFDVNODEPATHINFO: i32 = 2;
const PROC_PIDFDSOCKETINFO: i32 = 3;
/// PROC_PIDREGIONPATHINFO2 (xnu `proc_info.h`, used by lsof for `txt`/`mem` entries): the first
/// *vnode-backed* region at or after an address, with its vnode and path.
const PROC_PIDREGIONPATHINFO2: i32 = 22;
/// Never walk more mapped regions than this in one process.
const MAX_REGIONS: usize = 20_000;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const TSI_S_LISTEN: i32 = 1;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const VREG: i32 = 1;
/// `fi_openflags` is the kernel's FREAD/FWRITE (O_* + 1).
const FWRITE: u32 = 0x2;
/// Never read more fds than this from one process.
const MAX_FDS: usize = 65_536;

/// `struct proc_fileinfo`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcFileInfo {
    pub fi_openflags: u32,
    pub fi_status: u32,
    pub fi_offset: i64,
    pub fi_type: i32,
    pub fi_guardflags: u32,
}

/// `struct in4in6_addr` / `struct in6_addr` union: 16 bytes, 4-byte aligned. For IPv4 the
/// address is the last 4 bytes (after `i46a_pad32[3]`), in network order.
#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct Addr46(pub [u8; 16]);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InSockV4 {
    pub in4_tos: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InSockV6 {
    pub in6_hlim: u8,
    pub in6_cksum: i32,
    pub in6_ifindex: u16,
    pub in6_hops: i16,
}

/// `struct in_sockinfo`. Ports are in network byte order in the low 16 bits.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InSockInfo {
    pub insi_fport: i32,
    pub insi_lport: i32,
    pub insi_gencnt: u64,
    pub insi_flags: u32,
    pub insi_flow: u32,
    pub insi_vflag: u8,
    pub insi_ip_ttl: u8,
    pub rfu_1: u32,
    pub insi_faddr: Addr46,
    pub insi_laddr: Addr46,
    pub insi_v4: InSockV4,
    pub insi_v6: InSockV6,
}

/// `struct tcp_sockinfo`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpSockInfo {
    pub tcpsi_ini: InSockInfo,
    pub tcpsi_state: i32,
    pub tcpsi_timer: [i32; 4],
    pub tcpsi_mss: i32,
    pub tcpsi_flags: u32,
    pub rfu_1: u32,
    pub tcpsi_tp: u64,
}

/// `struct sockbuf_info`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockbufInfo {
    pub sbi_cc: u32,
    pub sbi_hiwat: u32,
    pub sbi_mbcnt: u32,
    pub sbi_mbmax: u32,
    pub sbi_lowat: u32,
    pub sbi_flags: i16,
    pub sbi_timeo: i16,
}

/// `soi_proto`: the largest member is `un_sockinfo` (528 bytes, 8-aligned).
#[repr(C)]
#[derive(Clone, Copy)]
pub union SoiProto {
    pub pri_in: InSockInfo,
    pub pri_tcp: TcpSockInfo,
    _un: [u64; 66],
}

/// `struct socket_info`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketInfo {
    pub soi_stat: libc::vinfo_stat,
    pub soi_so: u64,
    pub soi_pcb: u64,
    pub soi_type: i32,
    pub soi_protocol: i32,
    pub soi_family: i32,
    pub soi_options: i16,
    pub soi_linger: i16,
    pub soi_state: i16,
    pub soi_qlen: i16,
    pub soi_incqlen: i16,
    pub soi_qlimit: i16,
    pub soi_timeo: i16,
    pub soi_error: u16,
    pub soi_oobmark: u32,
    pub soi_rcv: SockbufInfo,
    pub soi_snd: SockbufInfo,
    pub soi_kind: i32,
    pub rfu_1: u32,
    pub soi_proto: SoiProto,
}

/// `struct socket_fdinfo` (PROC_PIDFDSOCKETINFO).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketFdInfo {
    pub pfi: ProcFileInfo,
    pub psi: SocketInfo,
}

/// `struct proc_regioninfo`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcRegionInfo {
    pub pri_protection: u32,
    pub pri_max_protection: u32,
    pub pri_inheritance: u32,
    pub pri_flags: u32,
    pub pri_offset: u64,
    pub pri_behavior: u32,
    pub pri_user_wired_count: u32,
    pub pri_user_tag: u32,
    pub pri_pages_resident: u32,
    pub pri_pages_shared_now_private: u32,
    pub pri_pages_swapped_out: u32,
    pub pri_pages_dirtied: u32,
    pub pri_ref_count: u32,
    pub pri_shadow_depth: u32,
    pub pri_share_mode: u32,
    pub pri_private_pages_resident: u32,
    pub pri_shared_pages_resident: u32,
    pub pri_obj_id: u32,
    pub pri_depth: u32,
    pub pri_address: u64,
    pub pri_size: u64,
}

/// `struct proc_regionwithpathinfo` (PROC_PIDREGIONPATHINFO / PROC_PIDREGIONPATHINFO2).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RegionWithPathInfo {
    pub prp_prinfo: ProcRegionInfo,
    pub prp_vip: libc::vnode_info_path,
}

/// `struct vnode_fdinfowithpath` (PROC_PIDFDVNODEPATHINFO).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnodeFdInfoWithPath {
    pub pfi: ProcFileInfo,
    pub pvip: libc::vnode_info_path,
}

// Sizes and offsets from the macOS SDK's <sys/proc_info.h> (clang, arm64 and x86_64 alike).
const _: () = {
    assert!(size_of::<ProcFileInfo>() == 24);
    assert!(size_of::<libc::vinfo_stat>() == 136);
    assert!(size_of::<Addr46>() == 16);
    assert!(size_of::<InSockInfo>() == 80);
    assert!(offset_of!(InSockInfo, insi_vflag) == 24);
    assert!(offset_of!(InSockInfo, insi_faddr) == 32);
    assert!(offset_of!(InSockInfo, insi_laddr) == 48);
    assert!(offset_of!(InSockInfo, insi_v4) == 64);
    assert!(offset_of!(InSockInfo, insi_v6) == 68);
    assert!(size_of::<TcpSockInfo>() == 120);
    assert!(offset_of!(TcpSockInfo, tcpsi_state) == 80);
    assert!(offset_of!(TcpSockInfo, tcpsi_tp) == 112);
    assert!(size_of::<SockbufInfo>() == 24);
    assert!(size_of::<SoiProto>() == 528);
    assert!(size_of::<SocketInfo>() == 768);
    assert!(offset_of!(SocketInfo, soi_so) == 136);
    assert!(offset_of!(SocketInfo, soi_type) == 152);
    assert!(offset_of!(SocketInfo, soi_family) == 160);
    assert!(offset_of!(SocketInfo, soi_rcv) == 184);
    assert!(offset_of!(SocketInfo, soi_kind) == 232);
    assert!(offset_of!(SocketInfo, soi_proto) == 240);
    assert!(size_of::<SocketFdInfo>() == 792);
    assert!(offset_of!(SocketFdInfo, psi) == 24);
    assert!(size_of::<VnodeFdInfoWithPath>() == 1200);
    assert!(size_of::<ProcRegionInfo>() == 96);
    assert!(offset_of!(ProcRegionInfo, pri_address) == 80);
    assert!(size_of::<RegionWithPathInfo>() == 1272);
    assert!(size_of::<libc::proc_fdinfo>() == 8);
    assert!(size_of::<libc::proc_bsdshortinfo>() == 64);
};

/// All pids, or None when the kernel call fails (the caller then falls back to lsof).
pub fn all_pids() -> Option<Vec<i32>> {
    // SAFETY: first call with a NULL buffer returns the needed byte count; the second fills
    // our buffer (sized in bytes) and returns the bytes written.
    unsafe {
        let need = libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
        if need <= 0 {
            return None;
        }
        let cap = need as usize / size_of::<i32>() + 64;
        let mut v: Vec<i32> = vec![0; cap];
        let got = libc::proc_listpids(PROC_ALL_PIDS, 0, v.as_mut_ptr() as *mut _, (cap * size_of::<i32>()) as i32);
        if got <= 0 {
            return None;
        }
        v.truncate(got as usize / size_of::<i32>());
        v.retain(|&p| p > 0);
        // Ascending like lsof, so "first pid seen" attribution is the same (the parent of a fork).
        v.sort_unstable();
        Some(v)
    }
}

/// (ppid, uid, comm) of `pid`.
pub fn short_info(pid: i32) -> Option<(u32, u32, String)> {
    // SAFETY: zeroed out-struct of the exact size the flavor fills.
    unsafe {
        let mut si: libc::proc_bsdshortinfo = std::mem::zeroed();
        let sz = size_of::<libc::proc_bsdshortinfo>() as i32;
        if libc::proc_pidinfo(pid, libc::PROC_PIDT_SHORTBSDINFO, 0, &mut si as *mut _ as *mut _, sz) != sz {
            return None;
        }
        let comm = cstr_bytes(std::slice::from_raw_parts(si.pbsi_comm.as_ptr() as *const u8, si.pbsi_comm.len()));
        Some((si.pbsi_ppid, si.pbsi_uid, comm))
    }
}

fn cstr_bytes(b: &[u8]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..n]).into_owned()
}

/// The process name (up to 32 bytes, e.g. "Brave Browser Helper (Renderer)"), unlike `comm`,
/// which the kernel cuts at 16. None when not permitted.
pub fn long_name(pid: i32) -> Option<String> {
    let mut buf = [0u8; 2 * libc::MAXCOMLEN + 1];
    // SAFETY: the kernel writes at most `len` bytes into our buffer.
    let n = unsafe { libc::proc_name(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
    (n > 0).then(|| cstr_bytes(&buf[..n as usize])).filter(|s| !s.is_empty())
}

/// Open file descriptors of `pid`; None when not permitted (another user's process) or gone.
pub fn fds(pid: i32) -> Option<Vec<libc::proc_fdinfo>> {
    let sz = size_of::<libc::proc_fdinfo>();
    // SAFETY: probe for the size, then fill a buffer of `cap` entries (passed in bytes); the
    // returned byte count never exceeds the buffer.
    unsafe {
        let need = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
        if need <= 0 {
            return None;
        }
        let cap = (need as usize / sz + 32).min(MAX_FDS);
        let mut v: Vec<libc::proc_fdinfo> = Vec::with_capacity(cap);
        let got = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, v.as_mut_ptr() as *mut _, (cap * sz) as i32);
        if got <= 0 {
            return None;
        }
        v.set_len((got as usize / sz).min(cap));
        Some(v)
    }
}

pub fn socket_info(pid: i32, fd: i32) -> Option<SocketFdInfo> {
    // SAFETY: all-zero is a valid SocketFdInfo (plain integers); the kernel fills exactly
    // size_of bytes or fails.
    unsafe {
        let mut si: SocketFdInfo = std::mem::zeroed();
        let sz = size_of::<SocketFdInfo>() as i32;
        (libc::proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &mut si as *mut _ as *mut _, sz) == sz).then_some(si)
    }
}

pub fn vnode_info(pid: i32, fd: i32) -> Option<VnodeFdInfoWithPath> {
    // SAFETY: as in `socket_info`.
    unsafe {
        let mut vi: VnodeFdInfoWithPath = std::mem::zeroed();
        let sz = size_of::<VnodeFdInfoWithPath>() as i32;
        (libc::proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &mut vi as *mut _ as *mut _, sz) == sz).then_some(vi)
    }
}

/// The vnode-backed mapped regions of `pid` (executable, dylibs, mmapped files), one entry per
/// run of consecutive regions of the same file. Empty when not permitted.
pub fn mapped_files(pid: i32) -> Vec<RegionWithPathInfo> {
    let mut out: Vec<RegionWithPathInfo> = Vec::new();
    let sz = size_of::<RegionWithPathInfo>() as i32;
    let mut addr = 0u64;
    for _ in 0..MAX_REGIONS {
        // SAFETY: zeroed plain-data out-struct of exactly the size the flavor fills.
        let mut r: RegionWithPathInfo = unsafe { std::mem::zeroed() };
        if unsafe { libc::proc_pidinfo(pid, PROC_PIDREGIONPATHINFO2, addr, &mut r as *mut _ as *mut _, sz) } != sz {
            break;
        }
        let next = r.prp_prinfo.pri_address.saturating_add(r.prp_prinfo.pri_size);
        if next <= addr {
            break;
        }
        addr = next;
        let st = &r.prp_vip.vip_vi.vi_stat;
        if out.last().is_some_and(|l| {
            l.prp_vip.vip_vi.vi_stat.vst_dev == st.vst_dev && l.prp_vip.vip_vi.vi_stat.vst_ino == st.vst_ino
        }) {
            continue;
        }
        out.push(r);
    }
    out
}

fn vip_path(vip: &libc::vnode_info_path) -> Option<String> {
    // SAFETY: vip_path is a 1024-byte char array inside vip.
    let raw = unsafe { std::slice::from_raw_parts(vip.vip_path.as_ptr() as *const u8, 1024) };
    let n = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    std::str::from_utf8(&raw[..n]).ok().filter(|p| !p.is_empty()).map(str::to_string)
}

impl VnodeFdInfoWithPath {
    pub fn path(&self) -> Option<String> {
        vip_path(&self.pvip)
    }
    pub fn is_regular(&self) -> bool {
        self.pvip.vip_vi.vi_type == VREG
    }
    pub fn writable(&self) -> bool {
        self.pfi.fi_openflags & FWRITE != 0
    }
}

/// A listening TCP socket or a bound, unconnected UDP socket.
#[derive(Debug, Clone, PartialEq)]
pub struct Listener {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub tcp: bool,
    pub addr: std::net::IpAddr,
    pub port: u16,
}

fn port_of(raw: i32) -> u16 {
    u16::from_be(raw as u16)
}

/// Local address of an inet socket: IPv4 when the socket is IPv4-only, else IPv6 (an
/// IPv4-mapped IPv6 address is shown as IPv4).
pub fn local_addr(ini: &InSockInfo) -> std::net::IpAddr {
    addr_of(ini.insi_vflag, &ini.insi_laddr)
}

fn addr_of(vflag: u8, a: &Addr46) -> std::net::IpAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    if vflag & INI_IPV4 != 0 && vflag & INI_IPV6 == 0 {
        IpAddr::V4(Ipv4Addr::new(a.0[12], a.0[13], a.0[14], a.0[15]))
    } else {
        let v6 = Ipv6Addr::from(a.0);
        match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }
    }
}

/// Classify one socket: Some((tcp, addr, port)) for a TCP listener or a bound UDP socket with
/// no peer (connected UDP sockets are clients, e.g. QUIC, and are skipped like the lsof path did).
pub fn listener_of(si: &SocketFdInfo) -> Option<(bool, std::net::IpAddr, u16)> {
    let psi = &si.psi;
    if psi.soi_family != libc::AF_INET && psi.soi_family != libc::AF_INET6 {
        return None;
    }
    // SAFETY: soi_kind says which union member the kernel filled.
    match psi.soi_kind {
        SOCKINFO_TCP => {
            let tcp = unsafe { psi.soi_proto.pri_tcp };
            let port = port_of(tcp.tcpsi_ini.insi_lport);
            (tcp.tcpsi_state == TSI_S_LISTEN && port != 0).then(|| (true, local_addr(&tcp.tcpsi_ini), port))
        }
        SOCKINFO_IN if psi.soi_protocol == libc::IPPROTO_UDP => {
            let ini = unsafe { psi.soi_proto.pri_in };
            let port = port_of(ini.insi_lport);
            let connected = port_of(ini.insi_fport) != 0 || !addr_of(ini.insi_vflag, &ini.insi_faddr).is_unspecified();
            (port != 0 && !connected).then(|| (false, local_addr(&ini), port))
        }
        _ => None,
    }
}

/// Every listening TCP / bound UDP socket we may see, with its owning process. None only when
/// the process list itself cannot be read.
pub fn listeners() -> Option<Vec<Listener>> {
    let mut out = Vec::new();
    for pid in all_pids()? {
        let Some(fds) = fds(pid) else { continue };
        let mut owner: Option<(u32, String)> = None;
        for fd in fds.iter().filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32) {
            let Some(si) = socket_info(pid, fd.proc_fd) else { continue };
            let Some((tcp, addr, port)) = listener_of(&si) else { continue };
            let (ppid, comm) = owner
                .get_or_insert_with(|| short_info(pid).map(|(pp, _, c)| (pp, c)).unwrap_or((0, String::new())))
                .clone();
            out.push(Listener { pid: pid as u32, ppid, comm, tcp, addr, port });
        }
    }
    Some(out)
}

/// Deleted regular files (link count 0) still held open or mapped: (pid, name, path, size bytes),
/// one entry per (dev, inode), under the lowest pid holding it. Like `lsof +L1` this covers
/// open fds and memory-mapped files (a replaced executable or dylib still in use); the mapped
/// walk is most of the cost: every region of every process, 0.22-0.4 s for one user's ~600
/// processes on macOS 15, no faster than `lsof +L1`. Mapped files whose vnode attributes the
/// kernel withholds (all-zero stat, seen for files in TCC-protected folders) are skipped: their
/// link count is unknown. `uid`: only that user's processes
/// (None = all, for root). None only when the process list cannot be read.
pub fn deleted_open(uid: Option<u32>) -> Option<Vec<(u32, String, String, u64)>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for pid in all_pids()? {
        let Some((_, puid, comm)) = short_info(pid) else { continue };
        if uid.is_some_and(|u| u != puid) {
            continue;
        }
        let Some(fds) = fds(pid) else { continue };
        // Looked up only for the few processes that hold a deleted file.
        let mut name: Option<String> = None;
        let mut name_of = || name.get_or_insert_with(|| long_name(pid).unwrap_or_else(|| comm.clone())).clone();
        for fd in fds.iter().filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_VNODE as u32) {
            let Some(vi) = vnode_info(pid, fd.proc_fd) else { continue };
            let st = &vi.pvip.vip_vi.vi_stat;
            if !vi.is_regular() || st.vst_nlink != 0 {
                continue;
            }
            let path = vi.path().unwrap_or_default();
            if !seen.insert(file_key(st, &path)) {
                continue;
            }
            out.push((pid as u32, name_of(), path, st.vst_size.max(0) as u64));
        }
        for r in mapped_files(pid) {
            let vi = &r.prp_vip.vip_vi;
            let st = &vi.vi_stat;
            if vi.vi_type != VREG || st.vst_nlink != 0 {
                continue;
            }
            let path = vip_path(&r.prp_vip).unwrap_or_default();
            if !seen.insert(file_key(st, &path)) {
                continue;
            }
            out.push((pid as u32, name_of(), path, st.vst_size.max(0) as u64));
        }
    }
    Some(out)
}

/// Identity of a file for de-duplication: (dev, inode); the kernel reports inode 0 for some
/// mapped files (e.g. LaunchServices' csstore), and those are told apart by path.
fn file_key(st: &libc::vinfo_stat, path: &str) -> (u32, u64, String) {
    (st.vst_dev, st.vst_ino, if st.vst_ino == 0 { path.to_string() } else { String::new() })
}

/// Regular files `pid` holds open for writing: (path, allocated bytes).
pub fn writable_files(pid: i32) -> Vec<(String, u64)> {
    let Some(fds) = fds(pid) else { return Vec::new() };
    fds.iter()
        .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_VNODE as u32)
        .filter_map(|f| vnode_info(pid, f.proc_fd))
        .filter(|vi| vi.writable() && vi.is_regular())
        .filter_map(|vi| {
            let p = vi.path()?;
            (p.starts_with('/') && !p.starts_with("/dev/"))
                .then(|| (p, vi.pvip.vip_vi.vi_stat.vst_blocks.max(0) as u64 * 512))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn layouts() {
        // Mirrors the compile-time asserts so a failure names the struct.
        assert_eq!(size_of::<SocketFdInfo>(), 792, "socket_fdinfo");
        assert_eq!(size_of::<SocketInfo>(), 768, "socket_info");
        assert_eq!(size_of::<InSockInfo>(), 80, "in_sockinfo");
        assert_eq!(size_of::<TcpSockInfo>(), 120, "tcp_sockinfo");
        assert_eq!(size_of::<VnodeFdInfoWithPath>(), 1200, "vnode_fdinfowithpath");
        assert_eq!(std::mem::align_of::<SocketFdInfo>(), 8);
    }

    #[test]
    fn long_name_is_not_cut_at_comm() {
        let me = std::process::id() as i32;
        let (_, _, comm) = short_info(me).unwrap();
        let long = long_name(me).unwrap();
        assert!(long.starts_with(&comm), "{long:?} vs {comm:?}");
        assert_eq!(long_name(-5), None);
    }

    #[test]
    fn addresses() {
        let mut a = Addr46([0; 16]);
        a.0[12..].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(addr_of(INI_IPV4, &a), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut m = Addr46([0; 16]);
        m.0[10] = 0xff;
        m.0[11] = 0xff;
        m.0[12..].copy_from_slice(&[10, 1, 2, 3]);
        assert_eq!(addr_of(INI_IPV6, &m), IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), "v4-mapped");
        let mut l = Addr46([0; 16]);
        l.0[15] = 1;
        assert_eq!(addr_of(INI_IPV6, &l).to_string(), "::1");
        assert!(addr_of(INI_IPV4 | INI_IPV6, &Addr46([0; 16])).is_unspecified());
        assert_eq!(port_of(i32::from(8080u16.to_be())), 8080);
    }

    #[test]
    fn lists_own_process() {
        let pids = all_pids().unwrap();
        let me = std::process::id() as i32;
        assert!(pids.contains(&me));
        let (ppid, uid, comm) = short_info(me).unwrap();
        // SAFETY: getppid/getuid have no preconditions.
        assert_eq!(ppid, unsafe { libc::getppid() } as u32);
        assert_eq!(uid, unsafe { libc::getuid() });
        assert!(!comm.is_empty());
        assert!(fds(me).unwrap().len() >= 3);
    }

    /// A TCP listener and a bound UDP socket of our own are found with our pid; a connected UDP
    /// socket is not listed.
    #[test]
    fn finds_own_listening_sockets() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tport = tcp.local_addr().unwrap().port();
        let tcp6 = std::net::TcpListener::bind("[::1]:0").ok();
        let udp = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let uport = udp.local_addr().unwrap().port();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(("127.0.0.1", uport)).unwrap();
        let cport = client.local_addr().unwrap().port();
        let me = std::process::id();
        let l = listeners().unwrap();
        let mine: Vec<&Listener> = l.iter().filter(|x| x.pid == me).collect();
        assert!(mine.iter().any(|x| x.tcp && x.port == tport && x.addr == IpAddr::V4(Ipv4Addr::LOCALHOST)), "{mine:?}");
        assert!(mine.iter().any(|x| !x.tcp && x.port == uport && x.addr.is_unspecified()), "{mine:?}");
        assert!(!mine.iter().any(|x| !x.tcp && x.port == cport), "connected UDP excluded: {mine:?}");
        if let Some(t6) = &tcp6 {
            let p6 = t6.local_addr().unwrap().port();
            assert!(mine.iter().any(|x| x.tcp && x.port == p6 && x.addr.to_string() == "::1"), "{mine:?}");
        }
        let e = mine.iter().find(|x| x.port == tport).unwrap();
        // SAFETY: no preconditions.
        assert_eq!(e.ppid, unsafe { libc::getppid() } as u32);
        drop((tcp, tcp6, udp, client));
    }

    /// A temp file we create, keep open, and unlink is reported as deleted-but-open, once.
    #[test]
    fn finds_own_deleted_file() {
        use std::io::Write;
        let p = std::env::temp_dir().join(format!("fat-libproc-deleted-{}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&[7u8; 50_000]).unwrap();
        f.flush().unwrap();
        let dup = std::fs::File::open(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        // SAFETY: no preconditions.
        let uid = unsafe { libc::getuid() };
        let d = deleted_open(Some(uid)).unwrap();
        let me = std::process::id();
        let hits: Vec<_> = d.iter().filter(|e| e.0 == me && e.2.contains("fat-libproc-deleted-")).collect();
        assert_eq!(hits.len(), 1, "two fds of one file listed once: {d:?}");
        assert_eq!(hits[0].3, 50_000);
        assert!(!hits[0].1.is_empty());
        drop((f, dup));
        let d = deleted_open(Some(uid)).unwrap();
        assert!(!d.iter().any(|e| e.0 == me && e.2.contains("fat-libproc-deleted-")), "closed: gone");
    }

    /// A file we mmap and then unlink and close: only the mapping holds it, and it is found.
    #[test]
    fn finds_own_deleted_mapping() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let p = std::env::temp_dir().join(format!("fat-libproc-mapped-{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&p).unwrap();
        f.write_all(&[9u8; 3 * 16384]).unwrap();
        f.sync_all().unwrap();
        // SAFETY: mapping a regular file we own, read-only, unmapped below.
        let m =
            unsafe { libc::mmap(std::ptr::null_mut(), 3 * 16384, libc::PROT_READ, libc::MAP_SHARED, f.as_raw_fd(), 0) };
        assert_ne!(m, libc::MAP_FAILED);
        drop(f);
        std::fs::remove_file(&p).unwrap();
        // SAFETY: no preconditions.
        let d = deleted_open(Some(unsafe { libc::getuid() })).unwrap();
        let me = std::process::id();
        let hit = d.iter().find(|e| e.0 == me && e.2.contains("fat-libproc-mapped-"));
        // SAFETY: the mapping created above.
        unsafe { libc::munmap(m, 3 * 16384) };
        assert_eq!(hit.map(|h| h.3), Some(3 * 16384), "{:?}", d.iter().filter(|e| e.0 == me).collect::<Vec<_>>());
    }

    #[test]
    fn writable_files_of_self() {
        use std::io::Write;
        let p = std::env::temp_dir().join(format!("fat-libproc-w-{}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&[1u8; 64 * 1024]).unwrap();
        f.sync_all().unwrap();
        let ro = std::fs::File::open(&p).unwrap();
        let w = writable_files(std::process::id() as i32);
        let hits: Vec<_> =
            w.iter().filter(|x| x.0.ends_with(&format!("fat-libproc-w-{}", std::process::id()))).collect();
        assert_eq!(hits.len(), 1, "{w:?}");
        assert!(hits[0].1 >= 64 * 1024);
        drop((f, ro));
        let _ = std::fs::remove_file(&p);
    }
}
