//! Process table + per-process energy (proc_pid_rusage). OWNER: collect-core agent.
//!
//! sysinfo gives us the portable bits (name, cmd, cpu%, memory, user). On macOS we add a few
//! cheap per-pid syscalls that sysinfo does not expose:
//!   * `proc_pid_rusage(RUSAGE_INFO_V4)` -> billed energy (nJ), cpu time, disk io bytes
//!   * `proc_pidinfo(PROC_PIDTASKINFO)` -> thread count
//!   * `getpriority(PRIO_PROCESS)` -> nice
//! All of them fail with EPERM for other users' processes when unprivileged; we skip silently.

use std::collections::HashMap;

use sysinfo::ProcessStatus;

/// Fallback power model when the kernel doesn't bill energy: milliwatts per fully busy core.
/// Roughly an Apple Silicon P-core under load; only used when `ri_billed_energy` is unavailable.
pub const FALLBACK_MW_PER_CORE: f64 = 2500.0;

/// Raw per-process counters read from the kernel (monotonic, cumulative since process start).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Counters {
    /// Energy of the task's own execution in nanojoules (`ri_energy_nj`, macOS 12+).
    pub energy_nj: u64,
    /// True when `energy_nj` is a real kernel counter; false -> estimate power from cpu time.
    pub has_energy: bool,
    /// User + system cpu time in nanoseconds.
    pub cpu_ns: u64,
    pub disk_read: u64,
    pub disk_write: u64,
}

/// Rates derived from two `Counters` readings.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Rates {
    /// CPU percent, 100 = one full core.
    pub cpu: f32,
    pub power_mw: f32,
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
}

/// Compute rates between two counter readings `dt_s` seconds apart. Counter resets (pid reuse,
/// wraparound) yield zero rather than garbage.
pub fn rates(prev: &Counters, cur: &Counters, dt_s: f64) -> Rates {
    if dt_s <= 0.0 {
        return Rates::default();
    }
    let d = |a: u64, b: u64| b.saturating_sub(a) as f64;
    let power_mw = if cur.has_energy && prev.has_energy {
        // nJ / s = nW; / 1e6 = mW
        d(prev.energy_nj, cur.energy_nj) / dt_s / 1e6
    } else {
        // cpu-seconds per second == cores busy
        let cores = d(prev.cpu_ns, cur.cpu_ns) / 1e9 / dt_s;
        cores * FALLBACK_MW_PER_CORE
    };
    Rates {
        cpu: (d(prev.cpu_ns, cur.cpu_ns) / 1e9 / dt_s * 100.0) as f32,
        power_mw: power_mw as f32,
        disk_read_bps: (d(prev.disk_read, cur.disk_read) / dt_s) as u64,
        disk_write_bps: (d(prev.disk_write, cur.disk_write) / dt_s) as u64,
    }
}

/// Map sysinfo's status to the single-char codes in `Proc::status`.
pub fn status_char(s: ProcessStatus) -> &'static str {
    match s {
        ProcessStatus::Run => "R",
        ProcessStatus::Sleep | ProcessStatus::Parked | ProcessStatus::Waking => "S",
        ProcessStatus::Idle => "I",
        ProcessStatus::Stop | ProcessStatus::Tracing => "T",
        ProcessStatus::Zombie | ProcessStatus::Dead => "Z",
        ProcessStatus::UninterruptibleDiskSleep => "U",
        _ => "S",
    }
}

/// Remembers the previous counters per (pid, start_time) so pid reuse never produces a bogus delta.
#[derive(Default)]
pub struct DeltaTracker {
    prev: HashMap<(u32, u64), Counters>,
}

impl DeltaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `cur` and return rates vs. the previous reading (zero for first sighting).
    pub fn update(&mut self, pid: u32, start: u64, cur: Counters, dt_s: f64) -> Rates {
        match self.prev.insert((pid, start), cur) {
            Some(prev) => rates(&prev, &cur, dt_s),
            None => Rates::default(),
        }
    }

    /// Drop entries for processes that no longer exist.
    pub fn retain(&mut self, alive: &std::collections::HashSet<(u32, u64)>) {
        self.prev.retain(|k, _| alive.contains(k));
    }
}

/// Nice value via getpriority; None if it fails (no such process / not permitted).
pub fn nice(pid: u32) -> Option<i32> {
    // getpriority legitimately returns -1, so errno must be cleared and checked.
    // SAFETY: getpriority has no pointer args; errno access is thread-local.
    unsafe {
        set_errno(0);
        let v = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
        if v == -1 && std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != 0 {
            None
        } else {
            Some(v)
        }
    }
}

#[cfg(target_os = "macos")]
unsafe fn set_errno(v: i32) {
    // SAFETY: __error returns a valid pointer to this thread's errno.
    unsafe { *libc::__error() = v }
}

#[cfg(target_os = "linux")]
unsafe fn set_errno(v: i32) {
    // SAFETY: __errno_location returns a valid pointer to this thread's errno.
    unsafe { *libc::__errno_location() = v }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
unsafe fn set_errno(_v: i32) {}

#[cfg(target_os = "macos")]
mod mac {
    use super::Counters;
    use std::sync::OnceLock;

    /// (numer, denom) to convert mach absolute ticks to nanoseconds. 125/3 on Apple Silicon.
    #[allow(deprecated)] // libc points at mach2 for these; the ABI is stable.
    fn timebase() -> (u64, u64) {
        static TB: OnceLock<(u64, u64)> = OnceLock::new();
        *TB.get_or_init(|| {
            let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: valid out pointer to a properly sized struct.
            let rc = unsafe { libc::mach_timebase_info(&mut info) };
            if rc != 0 || info.numer == 0 || info.denom == 0 {
                (1, 1)
            } else {
                (info.numer as u64, info.denom as u64)
            }
        })
    }

    pub fn ticks_to_ns(ticks: u64) -> u64 {
        let (n, d) = timebase();
        ((ticks as u128 * n as u128) / d as u128) as u64
    }

    /// `struct rusage_info_v6` from <sys/resource.h> (macOS 12+). libc only ships up to v4, so we
    /// declare the v5/v6 tail ourselves. v4 is all u64s plus a 16-byte uuid, so embedding it keeps
    /// the C layout exactly.
    #[repr(C)]
    struct RusageInfoV6 {
        v4: libc::rusage_info_v4,
        ri_flags: u64,
        ri_user_ptime: u64,
        ri_system_ptime: u64,
        ri_pinstructions: u64,
        ri_pcycles: u64,
        /// Energy consumed by this task's own execution, nanojoules.
        ri_energy_nj: u64,
        ri_penergy_nj: u64,
        ri_secure_time_in_system: u64,
        ri_secure_ptime_in_system: u64,
        ri_neural_footprint: u64,
        ri_lifetime_max_neural_footprint: u64,
        ri_interval_max_neural_footprint: u64,
        ri_reserved: [u64; 9],
    }

    const RUSAGE_INFO_V6: libc::c_int = 6;

    /// Raw rusage call; returns true on success.
    ///
    /// SAFETY: `T` must be the struct matching `flavor` (the kernel writes sizeof that struct).
    unsafe fn rusage<T>(pid: u32, flavor: libc::c_int, out: &mut T) -> bool {
        // libc declares the buffer as `*mut rusage_info_t` (a void**); it's really a struct pointer.
        let rc = unsafe {
            libc::proc_pid_rusage(pid as libc::c_int, flavor, out as *mut T as *mut libc::rusage_info_t)
        };
        rc == 0
    }

    pub fn counters(pid: u32) -> Option<Counters> {
        // SAFETY: plain-old-data structs; all-zero is valid, and each matches its flavor.
        let mut v6: RusageInfoV6 = unsafe { std::mem::zeroed() };
        let (ri, energy_nj) = if unsafe { rusage(pid, RUSAGE_INFO_V6, &mut v6) } {
            (v6.v4, Some(v6.ri_energy_nj))
        } else {
            // Older kernels reject V6 with EINVAL; EPERM/ESRCH will fail V4 too.
            let mut v4: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
            if !unsafe { rusage(pid, libc::RUSAGE_INFO_V4, &mut v4) } {
                return None;
            }
            // ri_billed_energy is energy billed *to* this task by others (vouchers), not its
            // own; don't use it. `has_energy: false` makes `rates` use the cpu-time model.
            (v4, None)
        };
        Some(Counters {
            energy_nj: energy_nj.unwrap_or(0),
            has_energy: energy_nj.is_some(),
            cpu_ns: ticks_to_ns(ri.ri_user_time.saturating_add(ri.ri_system_time)),
            disk_read: ri.ri_diskio_bytesread,
            disk_write: ri.ri_diskio_byteswritten,
        })
    }

    pub fn threads(pid: u32) -> Option<u32> {
        // SAFETY: proc_taskinfo is POD.
        let mut ti: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        // SAFETY: buffer pointer/size describe `ti` exactly.
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                &mut ti as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then_some(ti.pti_threadnum.max(0) as u32)
    }
}

/// Kernel counters for `pid` (macOS only; None elsewhere or when not permitted).
pub fn counters(pid: u32) -> Option<Counters> {
    #[cfg(target_os = "macos")]
    {
        mac::counters(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// Thread count for `pid` if obtainable.
pub fn threads(pid: u32) -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        mac::threads(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn energy_rate_mw() {
        let a = Counters { energy_nj: 1_000_000_000, has_energy: true, ..Default::default() };
        let b = Counters { energy_nj: 3_000_000_000, has_energy: true, cpu_ns: 9_000_000_000, ..Default::default() }; // +2 J
        let r = rates(&a, &b, 2.0); // 1 W
        assert!((r.power_mw - 1000.0).abs() < 0.01);
    }

    #[test]
    fn cpu_fallback_when_no_energy() {
        let a = Counters { cpu_ns: 0, ..Default::default() };
        let b = Counters { cpu_ns: 500_000_000, ..Default::default() }; // 0.5 core for 1s
        let r = rates(&a, &b, 1.0);
        assert!((r.power_mw as f64 - FALLBACK_MW_PER_CORE / 2.0).abs() < 0.01);
        assert!((r.cpu - 50.0).abs() < 0.01);
    }

    #[test]
    fn counter_reset_is_zero_not_huge() {
        let a = Counters { energy_nj: 10, has_energy: true, disk_read: 100, ..Default::default() };
        let b = Counters { energy_nj: 5, has_energy: true, disk_read: 50, ..Default::default() };
        let r = rates(&a, &b, 1.0);
        assert_eq!(r.power_mw, 0.0);
        assert_eq!(r.disk_read_bps, 0);
        assert_eq!(rates(&a, &b, 0.0), Rates::default());
    }

    #[test]
    fn tracker_first_sighting_zero() {
        let mut t = DeltaTracker::new();
        let c = Counters { disk_write: 4096, ..Default::default() };
        assert_eq!(t.update(1, 10, c, 1.0), Rates::default());
        let c2 = Counters { disk_write: 8192, ..Default::default() };
        assert_eq!(t.update(1, 10, c2, 1.0).disk_write_bps, 4096);
        // same pid, different start time = new process
        assert_eq!(t.update(1, 11, c2, 1.0), Rates::default());
    }

    #[test]
    fn status_mapping() {
        assert_eq!(status_char(ProcessStatus::Run), "R");
        assert_eq!(status_char(ProcessStatus::Stop), "T");
        assert_eq!(status_char(ProcessStatus::Zombie), "Z");
    }

    #[test]
    fn own_process_counters() {
        let me = std::process::id();
        assert!(nice(me).is_some());
        #[cfg(target_os = "macos")]
        {
            let c = counters(me).expect("rusage on self");
            assert!(c.cpu_ns > 0);
            assert!(threads(me).unwrap_or(0) >= 1);
        }
    }
}


#[cfg(all(test, target_os = "macos"))]
mod live {
    /// Spinning one thread must register real energy (V6 counter) on this machine.
    #[test]
    fn self_spin_has_energy() {
        let me = std::process::id();
        let a = super::counters(me).unwrap();
        let t = std::time::Instant::now();
        let mut x = 0u64;
        while t.elapsed().as_millis() < 300 {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(7));
        }
        let b = super::counters(me).unwrap();
        let r = super::rates(&a, &b, t.elapsed().as_secs_f64());
        eprintln!("self spin: {:.0} mW (has_energy={})", r.power_mw, b.has_energy);
        assert!(b.cpu_ns > a.cpu_ns);
        assert!(r.power_mw > 0.0);
    }
}
