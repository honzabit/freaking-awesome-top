use super::*;

/// A throwaway fixture root (proc/..., sys/...) removed on drop.
struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Root {
        let p = std::env::temp_dir().join(format!("fat-kernel-{tag}-{}-{}", std::process::id(), now_ms()));
        fs::create_dir_all(&p).unwrap();
        Root(p)
    }
    fn put(&self, rel: &str, body: &str) {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Real lines from a live OOM in a transient scope with MemoryMax=50M (7.2 kernel, a host
// running inside a VM whose cgroup namespace is nested, hence the long memcg path).
const OOM_INVOKED: &str =
    "6,2233,316540620461,-;tail invoked oom-killer: gfp_mask=0x100cca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0";
const OOM_CTX: &str = "6,2320,316540620638,-;oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=child,mems_allowed=0,oom_memcg=/scon/container/01M6YQ2MJJZ9B1T0GT6R8Q13ZE.nl1gfr/child/system.slice/fat-oomtest.scope,task_memcg=/scon/container/01M6YQ2MJJZ9B1T0GT6R8Q13ZE.nl1gfr/child/system.slice/fat-oomtest.scope,task=tail,pid=2417529,uid=0";
const OOM_KILLED: &str = "3,2321,316540620648,-;Memory cgroup out of memory: Killed process 2417529 (tail) total-vm:58868kB, anon-rss:51200kB, file-rss:1576kB, shmem-rss:0kB, UID:0 pgtables:152kB oom_score_adj:0";

#[test]
fn oom_report_folds_into_one_event() {
    let boot = 1_700_000_000_000;
    let mut asm = OomAssembler::default();
    assert!(asm.feed(OOM_INVOKED, boot).is_none());
    assert!(asm.feed("4,2241,316540620537,-; oom_kill_process+0x64/0x278", boot).is_none());
    assert!(asm.feed(OOM_CTX, boot).is_none());
    let e = asm.feed(OOM_KILLED, boot).expect("oom event");
    assert_eq!(e.kind, EventKind::OomKill);
    assert_eq!(e.severity, Severity::Crit);
    assert_eq!(e.pid, Some(2417529));
    assert_eq!(e.subject, "pid:2417529");
    assert_eq!(e.ts, boot + 316540620);
    assert_eq!(e.extra["victim"], "tail");
    assert_eq!(e.extra["constraint"], "CONSTRAINT_MEMCG");
    assert!(e.extra["memcg"].ends_with("/system.slice/fat-oomtest.scope"));
    assert_eq!(e.extra["anon_rss_kb"], "51200");
    assert_eq!(e.extra["invoker"], "tail");
    assert_eq!(e.unit.as_deref(), Some("fat-oomtest.scope"));
    assert_eq!(e.value, Some(((51200 + 1576) * 1024) as f64));
    assert!(e.detail.contains("hit its memory limit"), "{}", e.detail);
    // memory.oom.group repeats the Killed line: one event only.
    assert!(asm.feed(OOM_KILLED, boot).is_none());
}

#[test]
fn parse_oom_variants() {
    let o = parse_oom(&[
        &OOM_INVOKED[OOM_INVOKED.find(';').unwrap() + 1..],
        &OOM_CTX[OOM_CTX.find(';').unwrap() + 1..],
        &OOM_KILLED[OOM_KILLED.find(';').unwrap() + 1..],
    ])
    .unwrap();
    assert_eq!(
        (o.victim_pid, o.victim_name.as_str(), o.anon_rss_kb, o.file_rss_kb, o.oom_score_adj),
        (2417529, "tail", 51200, 1576, 0)
    );
    assert_eq!(o.invoker.as_deref(), Some("tail"));
    // Host-wide OOM, name with spaces and parens, negative adj (5.x format).
    let o = parse_oom(&[
        "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/system.slice/app.service,task=Web Content,pid=4242,uid=1000",
        "Out of memory: Killed process 4242 (Web (Content)) total-vm:9000kB, anon-rss:2048kB, file-rss:4kB, shmem-rss:8kB, UID:1000 pgtables:100kB oom_score_adj:-500",
    ])
    .unwrap();
    assert_eq!(o.victim_name, "Web (Content)");
    assert_eq!(o.constraint, "CONSTRAINT_NONE");
    assert_eq!(o.memcg, "/system.slice/app.service");
    assert_eq!((o.anon_rss_kb, o.shmem_rss_kb, o.oom_score_adj), (2048, 8, -500));
    // 4.x: no oom-kill: line, no UID.
    let o =
        parse_oom(&["Killed process 77 (java) total-vm:100kB, anon-rss:50kB, file-rss:0kB, shmem-rss:0kB"]).unwrap();
    assert_eq!((o.victim_pid, o.victim_name.as_str(), o.anon_rss_kb), (77, "java", 50));
    assert!(parse_oom(&["nothing here"]).is_none());
}

/// Kernels before 4.19 log no oom-kill: line: the memcg and constraint come from "Task in ...
/// killed as a result of limit of ..." and the "Memory cgroup out of memory:" prefix, so a
/// cgroup-limit kill is not explained as "host out of memory".
#[test]
fn legacy_memcg_oom_report() {
    let boot = 1_700_000_000_000;
    let mut asm = OomAssembler::default();
    assert!(asm.feed("4,100,5000,-;java invoked oom-killer: gfp_mask=0x14000c0(GFP_KERNEL), nodemask=(null), order=0, oom_score_adj=0", boot).is_none());
    assert!(
        asm.feed(
            "6,104,5000,-;Task in /system.slice/java.service killed as a result of limit of /system.slice/java.service",
            boot
        )
        .is_none()
    );
    assert!(asm.feed("6,105,5000,-;memory: usage 65536kB, limit 65536kB, failcnt 12", boot).is_none());
    assert!(
        asm.feed(
            "3,106,5000,-;Memory cgroup out of memory: Kill process 1234 (java) score 999 or sacrifice child",
            boot
        )
        .is_none()
    );
    let e = asm
        .feed(
            "3,107,5000,-;Killed process 1234 (java) total-vm:2000kB, anon-rss:1000kB, file-rss:0kB, shmem-rss:0kB",
            boot,
        )
        .expect("oom event");
    assert_eq!(e.extra["constraint"], "CONSTRAINT_MEMCG");
    assert_eq!(e.extra["memcg"], "/system.slice/java.service");
    assert_eq!(e.extra["task_memcg"], "/system.slice/java.service");
    assert_eq!(e.unit.as_deref(), Some("java.service"));
    assert!(e.detail.contains("hit its memory limit") && !e.detail.contains("host out of memory"), "{}", e.detail);
    // A host-wide OOM on the same kernels stays "host out of memory".
    let mut asm = OomAssembler::default();
    assert!(
        asm.feed("4,200,5000,-;app invoked oom-killer: gfp_mask=0x14200ca, order=0, oom_score_adj=0", boot).is_none()
    );
    assert!(asm.feed("3,201,5000,-;Out of memory: Kill process 77 (app) score 900 or sacrifice child", boot).is_none());
    let e = asm
        .feed("3,202,5000,-;Killed process 77 (app) total-vm:100kB, anon-rss:50kB, file-rss:0kB, shmem-rss:0kB", boot)
        .unwrap();
    assert_eq!(e.extra["constraint"], "CONSTRAINT_NONE");
    assert!(e.detail.contains("host out of memory"), "{}", e.detail);
}

/// SCSI and older buffer I/O errors name the block device, so they join the disk's other events.
#[test]
fn disk_error_device_names() {
    let k = |r: &str| parse_kmsg_record(r, 0).unwrap();
    assert_eq!(
        k("3,100,5000,-;sd 2:0:0:0: [sdb] tag#0 FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_SENSE").subject,
        "disk:sdb"
    );
    assert_eq!(k("3,102,5000,-;Buffer I/O error on device sdb1, logical block 0").subject, "disk:sdb1");
    assert_eq!(k("3,103,5000,-;Buffer I/O error on dev dm-0, logical block 0, async page read").subject, "disk:dm-0");
}

#[test]
fn kmsg_classification() {
    let boot = 0;
    let k = |r: &str| parse_kmsg_record(r, boot);
    let e = k("3,10,5000000,-;INFO: task kworker/u8:2:123 blocked for more than 122 seconds.").unwrap();
    assert_eq!((e.kind, e.pid, e.value), (EventKind::HungTask, Some(123), Some(122.0)));
    assert_eq!(e.ts, 5000);
    assert!(e.detail.contains("kworker/u8:2"));
    let e = k("0,11,1,-;watchdog: BUG: soft lockup - CPU#3 stuck for 22s! [stress:991]").unwrap();
    assert_eq!((e.kind, e.severity, e.pid), (EventKind::KernelWarn, Severity::Crit, Some(991)));
    let e = k("6,12,1,-;nginx[2211]: segfault at 0 ip 000055d5 sp 00007ffd error 4 in nginx[55d5+1000] likely on CPU 1 (core 1, socket 0)").unwrap();
    assert_eq!((e.kind, e.pid, e.subject.as_str()), (EventKind::KernelWarn, Some(2211), "pid:2211"));
    let e =
        k("6,13,1,-;traps: python3[4040] general protection fault ip:7f sp:7ffc error:0 in libc.so.6[7f+1]").unwrap();
    assert_eq!(e.pid, Some(4040));
    let e =
        k("3,14,1,-;EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0")
            .unwrap();
    assert_eq!((e.kind, e.subject.as_str()), (EventKind::DiskError, "disk:sda1"));
    let e = k("2,15,1,-;EXT4-fs (sda1): Remounting filesystem read-only").unwrap();
    assert_eq!((e.kind, e.subject.as_str()), (EventKind::RoRemount, "disk:sda1"));
    let e = k("3,16,1,-;I/O error, dev nvme0n1, sector 123456 op 0x0:(READ) flags 0x80700 phys_seg 1 prio class 2")
        .unwrap();
    assert_eq!((e.kind, e.subject.as_str()), (EventKind::DiskError, "disk:nvme0n1"));
    let e = k("3,17,1,-;blk_update_request: I/O error, dev sdb, sector 2048 op 0x1:(WRITE) flags 0x0").unwrap();
    assert_eq!(e.subject, "disk:sdb");
    let e = k("3,18,1,-;Buffer I/O error on dev dm-0, logical block 0, async page read").unwrap();
    assert_eq!(e.subject, "disk:dm-0");
    let e = k("1,19,1,-;XFS (vdb1): Corruption detected. Unmount and run xfs_repair").unwrap();
    assert_eq!((e.kind, e.subject.as_str()), (EventKind::DiskError, "disk:vdb1"));
    let e = k("4,20,1,-;nvme nvme0: I/O 12 QID 3 timeout, aborting").unwrap();
    assert_eq!((e.kind, e.subject.as_str()), (EventKind::DiskError, "disk:nvme0"));
    let e = k("3,21,1,-;ata1.00: failed command: READ FPDMA QUEUED").unwrap();
    assert_eq!(e.subject, "disk:ata1");
    let e = k("4,22,1,-;nf_conntrack: nf_conntrack: table full, dropping packet").unwrap();
    assert_eq!((e.kind, e.extra["resource"].as_str()), (EventKind::Exhaustion, "conntrack"));
    let e =
        k("6,23,1,-;TCP: request_sock_TCP: Possible SYN flooding on port 8080. Sending cookies.  Check SNMP counters.")
            .unwrap();
    assert_eq!((e.extra["resource"].as_str(), e.extra["port"].as_str()), ("syn_backlog", "8080"));
    let e = k("6,24,1,-;cgroup: fork rejected by pids controller in /system.slice/worker.service").unwrap();
    assert_eq!((e.unit.as_deref(), e.subject.as_str()), (Some("worker.service"), "unit:worker.service"));
    let e = k("6,25,1,-;e1000e: eth0 NIC Link is Down").unwrap();
    assert_eq!((e.kind, e.severity, e.extra["iface"].as_str()), (EventKind::Other, Severity::Warn, "eth0"));
    let e = k("6,26,1,-;ixgbe 0000:01:00.0 eth1: NIC Link is Up 10 Gbps, Flow Control: RX/TX").unwrap();
    assert_eq!((e.severity, e.extra["iface"].as_str()), (Severity::Info, "eth1"));
    let e = k("4,27,1,-;WARNING: CPU: 1 PID: 123 at mm/page_alloc.c:4000 foo+0x10/0x20").unwrap();
    assert_eq!((e.kind, e.severity), (EventKind::KernelWarn, Severity::Warn));
    let e = k("1,28,1,-;BUG: unable to handle page fault for address: 0000000000001234").unwrap();
    assert_eq!(e.severity, Severity::Crit);
    let e = k("4,29,1,-;VFS: file-max limit 1000 reached").unwrap();
    assert_eq!(e.extra["resource"], "fd");
    // Noise and userspace facilities are ignored; unknown crit kernel lines are kept.
    assert!(k("6,30,1,-;br-6a9680f9d08c: port 4(vethfc5295c) entered disabled state").is_none());
    assert!(k("6,31,1,-;veth624c30e: renamed from eth0").is_none());
    assert!(k("30,32,1,-;systemd[1]: Started foo.service - BUG: not a kernel line.").is_none());
    assert!(k("2,33,1,-;something unknown but critical").is_some());
    assert!(k("garbage").is_none());
    assert!(k("6,34,1,-;oom_reaper: reaped process 7 (x), now anon-rss:0kB, file-rss:0kB, shmem-rss:0kB").is_none());
}

#[test]
fn diskstats_and_partitions() {
    // Real /proc/diskstats lines (VM, 7.2 kernel) plus classic names.
    let t = "   7       0 loop0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
   7       1 loop1 5 0 10 1 0 0 0 0 0 1 1 0 0 0 0 0 0
 254       0 vda 2092720 6106 279099152 32326 0 0 0 0 0 2323811 32326 0 0 0 0 0 0
 254      16 vdb 1942118 31477 273037762 47544 11461492 3456141 610359416 2528555 0 2134656 4558956 307753 0 538463584 184446 3493140 1798410
 254      17 vdb1 1942016 31477 273036808 47544 11461492 3456141 610359416 2528555 0 2129621 2760546 307753 0 538463584 184446 0 0
 253       0 zram0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 259       0 nvme0n1 10 0 80 3 4 0 32 5 1 7 8
 259       1 nvme0n1p1 10 0 80 3 4 0 32 5 0 7 8
 179       0 mmcblk0p2 1 0 1 1 1 0 1 1 0 1 1
   8       0 sda 1 0 1 1 1 0 1 1 0 1 1
   8       1 sda1 1 0 1 1 1 0 1 1 0 1 1
 253       1 dm-0 1 0 1 1 1 0 1 1 0 1 1
   9       0 md127 1 0 1 1 1 0 1 1 0 1 1";
    let d = parse_diskstats(t);
    let names: Vec<&str> = d.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(names, ["loop1", "vda", "vdb", "nvme0n1", "sda", "dm-0", "md127"]);
    let vdb = &d[2];
    assert_eq!(
        (vdb.reads, vdb.read_sectors, vdb.read_ms, vdb.writes, vdb.write_ms, vdb.io_ms, vdb.weighted_ms),
        (1942118, 273037762, 47544, 11461492, 2528555, 2134656, 4558956)
    );
    // Old 2.6-era 14-field line still parses.
    assert_eq!(d[3].weighted_ms, 8);
    for (n, p) in [
        ("sda1", true),
        ("xvda12", true),
        ("nvme0n1p3", true),
        ("mmcblk0p1", true),
        ("nvme0n1", false),
        ("mmcblk0", false),
        ("md0", false),
        ("dm-3", false),
        ("sdaa", false),
        ("loop7", false),
    ] {
        assert_eq!(is_partition_name(n), p, "{n}");
    }
}

#[test]
fn taint_mdstat_misc() {
    assert_eq!(decode_taint(0), "");
    assert_eq!(decode_taint(1 | (1 << 12) | (1 << 13)), "POE");
    assert_eq!(decode_taint(1 << 9), "W");
    assert_eq!(decode_taint(1 << 40), "?");
    let md = parse_mdstat(
        "Personalities : [raid1] [raid6] [raid5] [raid4]
md1 : active raid1 sdb2[1](F) sda2[0]
      976630336 blocks super 1.2 [2/1] [U_]
      [=>...................]  recovery =  8.5% (83312640/976630336) finish=80.1min speed=185628K/sec
      bitmap: 2/8 pages [8KB], 65536KB chunk

md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]

md2 : active (auto-read-only) raid5 sdc[0] sdd[1] sde[3]
      2093056 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/3] [UUU]

md3 : inactive sdf[0](S)
      1047552 blocks super 1.2

unused devices: <none>
",
    );
    assert_eq!(md.len(), 4);
    assert_eq!(
        (md[0].name.as_str(), md[0].level.as_str(), md[0].degraded, md[0].state.as_str(), md[0].sync_pct),
        ("md1", "raid1", true, "recovering", Some(8.5))
    );
    assert!(!md[1].degraded && md[1].state == "active");
    assert_eq!(md[2].level, "raid5");
    assert_eq!(md[3].state, "inactive");
    assert_eq!(parse_file_nr("220225\t0\t9223372036854775807\n"), Some((220225, 9223372036854775807)));
    assert_eq!(parse_port_range("32768\t60999\n"), Some((32768, 60999)));
    assert_eq!(
        stat_state_start("42 (a (b) c) D 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 10"),
        Some(('D', 98765))
    );
    let mi = parse_mountinfo(
        "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
23 22 8:2 / /var\\040data rw,relatime - ext4 /dev/sda2 ro,errors=remount-ro
24 22 0:5 / /proc rw - proc proc rw",
    );
    assert_eq!(mi.len(), 3);
    assert!(!mi[0].read_only);
    assert_eq!(mi[1].mount_point, "/var data");
    assert!(mi[1].read_only, "superblock ro counts");
    assert_eq!(decode_endpoint("0100007F:1F90"), "127.0.0.1:8080");
    assert_eq!(decode_endpoint("0000000000000000FFFF00000100007F:0050"), "127.0.0.1:80");
}

#[test]
fn snmp_and_ephemeral() {
    let m = parse_snmp(
        "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 100 50 3 2 7 1000 900 42 0 5 0
TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPBacklogDrop
TcpExt: 0 11 13 2",
    );
    assert_eq!(
        (m["Tcp.RetransSegs"], m["TcpExt.ListenOverflows"], m["TcpExt.ListenDrops"], m["Tcp.MaxConn"]),
        (42, 11, 13, 0)
    );
    let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:8001 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:8002 0100007F:1F90 06 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:8002 0200007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 20 4 30 10 -1
   4: 0100007F:0016 0100007F:9000 01 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 20 4 30 10 -1";
    // 0x8001, 0x8002 in range; the listener (0A) and port 22 are not.
    let (used, dest) = ephemeral_usage(&[tcp], (32768, 60999));
    assert_eq!(used, 2);
    assert_eq!(dest, "127.0.0.1:8080");
}

fn proc_d(pid: u32, name: &str, cg: &str) -> Proc {
    Proc { pid, name: name.into(), status: "U".into(), cgroup: cg.into(), ..Default::default() }
}

fn fixture(r: &Root, cpu: &str, disk: &str, retrans: u64, conntrack: u64, oom: u64, mount_opts: &str) {
    r.put("proc/stat", &format!("cpu  {cpu}\ncpu0 1 1 1 1 1 1 1 1 0 0\nprocs_running 3\nprocs_blocked 2\n"));
    r.put("proc/pressure/cpu", "some avg10=1.00 avg60=0 avg300=0 total=1\nfull avg10=0.00 avg60=0 avg300=0 total=0\n");
    r.put(
        "proc/pressure/memory",
        "some avg10=30.00 avg60=0 avg300=0 total=1\nfull avg10=25.50 avg60=0 avg300=0 total=1\n",
    );
    r.put("proc/pressure/io", "some avg10=2.00 avg60=0 avg300=0 total=1\nfull avg10=1.00 avg60=0 avg300=0 total=1\n");
    r.put("proc/meminfo", "MemTotal: 8000000 kB\nMemFree: 1000 kB\nMemAvailable: 4000000 kB\n");
    r.put("proc/vmstat", &format!("nr_free_pages 1\npswpin 100\npswpout 200\noom_kill {oom}\n"));
    r.put(
        "sys/devices/system/node/node0/meminfo",
        "Node 0 MemTotal:       8000000 kB\nNode 0 MemFree:         1000 kB\n",
    );
    r.put("proc/diskstats", &format!(" 8 0 sda {disk}\n 8 1 sda1 1 0 1 1 1 0 1 1 0 1 1\n"));
    r.put("sys/class/block/sda1/partition", "1\n");
    r.put("sys/block/sda/device/ioerr_cnt", "0x3\n");
    r.put("proc/sys/fs/file-nr", "900\t0\t1000\n");
    r.put("proc/sys/net/netfilter/nf_conntrack_count", &format!("{conntrack}\n"));
    r.put("proc/sys/net/netfilter/nf_conntrack_max", "1000\n");
    r.put("proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n");
    r.put("proc/net/tcp", "  sl  local_address rem_address   st\n   1: 0100007F:8001 0100007F:1F90 01 0\n");
    r.put("proc/net/snmp", &format!("Tcp: RetransSegs\nTcp: {retrans}\n"));
    r.put("proc/net/netstat", "TcpExt: ListenOverflows ListenDrops TCPBacklogDrop\nTcpExt: 0 0 0\n");
    r.put("proc/77/stat", "77 (dd) D 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5555 1 1");
    r.put("proc/77/wchan", "io_schedule");
    r.put("proc/88/stat", "88 (sleepy) S 1 88 88 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 6666 1 1");
    r.put("proc/self/mountinfo", &format!("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n30 22 8:2 / /data rw - xfs /dev/sdb1 {mount_opts}\n31 22 0:5 / /proc rw - proc proc rw\n"));
    r.put("sys/fs/ext4/sda1/errors_count", if mount_opts == "ro" { "4\n" } else { "1\n" });
    r.put("proc/sys/kernel/tainted", if mount_opts == "ro" { "4609\n" } else { "4097\n" });
    r.put("proc/mdstat", "md0 : active raid1 sdb1[1](F) sda1[0]\n      100 blocks [2/1] [U_]\n");
    r.put("ntp_synced", "0\n");
}

#[test]
fn sampler_over_fixture_root() {
    let r = Root::new("sampler");
    let cfg = ServerCfg { dstate_min_s: 5, disk_await_warn_ms: 100.0, exhaustion_warn: 0.85, ..Default::default() };
    let mut ks = KernelSampler::with_root(&cfg, &r.0, false);
    let units = vec![Unit {
        name: "backup.service".into(),
        cgroup: "/system.slice/backup.service".into(),
        ..Default::default()
    }];
    let procs = vec![proc_d(77, "dd", "/system.slice/backup.service"), proc_d(88, "sleepy", "/")];

    // user nice system idle iowait irq softirq steal
    fixture(&r, "100 0 100 700 50 10 20 20 0 0", "100 0 800 100 100 0 800 100 0 100 200", 1000, 500, 3, "rw");
    let k = ks.sample_at(&procs, &units, 1_000_000, None);
    assert_eq!((k.procs_running, k.procs_blocked), (3, 2));
    assert_eq!(k.steal_pct, 0.0, "first sample has no rates");
    assert_eq!(k.mem_available, 4_000_000 * 1024);
    assert_eq!(k.oom_kills_total, 3);
    assert_eq!(k.numa, vec![NumaNode { node: 0, mem_total: 8_000_000 * 1024, mem_free: 1000 * 1024 }]);
    assert_eq!(k.disks.len(), 1, "partition dropped via sysfs");
    assert_eq!(k.disks[0].io_errors, Some(3));
    assert_eq!((k.fd_used, k.fd_max), (Some(900), Some(1000)));
    assert_eq!((k.conntrack_used, k.conntrack_max), (Some(500), Some(1000)));
    assert_eq!((k.ephemeral_used, k.ephemeral_range), (Some(1), Some((32768, 60999))));
    assert_eq!(k.pressure.unwrap().mem_full, 25.5);
    assert!(k.d_state.is_empty(), "not yet blocked long enough");
    assert_eq!((k.taint, k.taint_flags.as_str()), (4097, "PO"));
    assert_eq!(k.ntp_synced, Some(false));
    assert!(k.mdraid[0].degraded);
    let ev = ks.drain_events();
    let kinds: Vec<EventKind> = ev.iter().map(|e| e.kind).collect();
    // fd 90% -> exhaustion; mem full 25.5 -> pressure spike; clock; md degraded.
    assert!(kinds.contains(&EventKind::Exhaustion), "{kinds:?}");
    assert!(kinds.contains(&EventKind::PressureSpike));
    assert!(kinds.contains(&EventKind::ClockUnsynced));
    assert!(kinds.contains(&EventKind::DiskError));
    assert!(!kinds.contains(&EventKind::OomKill));

    // 10 s later: 1000 ticks elapsed; disk did 100 reads taking 30 000 ms (300 ms await).
    fixture(&r, "200 0 200 1270 150 20 40 120 0 0", "200 0 1600 30100 100 0 800 100 2 1100 30200", 1100, 950, 5, "ro");
    let k = ks.sample_at(&procs, &units, 1_010_000, Some(10.0));
    assert_eq!((k.iowait_pct, k.irq_pct, k.softirq_pct, k.steal_pct), (10.0, 1.0, 2.0, 10.0));
    let d = &k.disks[0];
    assert_eq!((d.r_iops, d.r_await_ms, d.w_iops, d.util_pct), (10.0, 300.0, 0.0, 10.0));
    assert_eq!(d.queue_depth, 3.0);
    assert_eq!(d.r_bps, 800 * 512 / 10);
    assert_eq!(k.tcp_retrans_ps, 10.0);
    assert_eq!(k.d_state.len(), 1);
    assert_eq!(
        k.d_state[0],
        DStateProc {
            pid: 77,
            name: "dd".into(),
            wchan: "io_schedule".into(),
            seconds: 10,
            unit: Some("backup.service".into())
        }
    );
    assert_eq!(k.ro_remounts, vec!["/data".to_string()]);
    assert_eq!(
        k.fs_errors,
        vec![FsErrorStat { device: "sda1".into(), mount: Some("/".into()), errors: 4, read_only: false }]
    );
    assert_eq!(k.taint_flags, "PWO");
    let ev = ks.drain_events();
    let get = |kind| ev.iter().filter(|e| e.kind == kind).collect::<Vec<_>>();
    assert_eq!(get(EventKind::DiskLatencySpike).len(), 1);
    assert_eq!(get(EventKind::DiskLatencySpike)[0].subject, "disk:sda");
    assert_eq!(get(EventKind::HungTask)[0].unit.as_deref(), Some("backup.service"));
    assert_eq!(get(EventKind::RoRemount)[0].subject, "mount:/data");
    assert!(get(EventKind::DiskError).iter().any(|e| e.detail.contains("3 new error")));
    assert!(get(EventKind::KernelWarn).iter().any(|e| e.detail.contains("gained W")));
    let exh: Vec<&str> = get(EventKind::Exhaustion).iter().map(|e| e.extra["resource"].as_str()).collect();
    assert_eq!(exh, ["conntrack"], "fd already active: edge-triggered");
    // Kernel log is off for fixture roots, so the vmstat delta reports the OOM kills.
    let oom = get(EventKind::OomKill);
    assert_eq!((oom.len(), oom[0].value), (1, Some(2.0)));
    assert!(!ev.iter().any(|e| e.kind == EventKind::ClockUnsynced), "no repeat while still unsynced");
    assert!(!ev.iter().any(|e| e.kind == EventKind::PressureSpike), "no repeat while still high");
}

#[test]
fn collapse_merges_floods() {
    let mk = |d: &str| event(1, EventKind::DiskError, Severity::Crit, "disk:sdb", d.into(), "kmsg");
    let mut v = vec![
        mk("I/O error, dev sdb, sector 1"),
        mk("I/O error, dev sdb, sector 2"),
        mk("I/O error, dev sdb, sector 3"),
        event(2, EventKind::Other, Severity::Info, "host", "x".into(), "kmsg"),
    ];
    collapse(&mut v);
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].extra["repeats"], "3");
}

#[test]
fn render_and_report_off_linux_are_safe() {
    let r = KernelReport {
        kernel: Some(Kernel {
            disks: vec![DiskStat { name: "sda".into(), ..Default::default() }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let s = render(&r);
    assert!(s.contains("sda") && s.contains("steal"));
    if !cfg!(target_os = "linux") {
        let r = report(&ServerCfg::default(), &[], &[], std::time::Duration::ZERO, 0, 10);
        assert!(r.kernel.is_none() && !r.notes.is_empty());
        assert!(KernelSampler::new(&ServerCfg::default()).sample(&[], &[]).is_none());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn live_procfs_sample_is_sane() {
    let cfg = ServerCfg { kmsg: false, ..Default::default() };
    let mut ks = KernelSampler::new(&cfg);
    let first = ks.sample(&[], &[]).expect("linux");
    std::thread::sleep(std::time::Duration::from_millis(200));
    let k = ks.sample(&[], &[]).expect("linux");
    assert!(k.fd_max.is_some_and(|m| m > 0), "{:?}", k.fd_max);
    assert!(k.mem_available > 0);
    let share = k.steal_pct + k.iowait_pct + k.irq_pct + k.softirq_pct;
    assert!((0.0..=100.0).contains(&share), "{share}");
    assert!(first.ephemeral_range.is_none_or(|(a, b)| a <= b));
    let _ = ks.drain_events();
}

/// Cost of one sample on this machine and of the socket-table scan at scale.
/// `cargo test --release bench_kernel_sample -- --ignored --nocapture`
#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn bench_kernel_sample() {
    let cfg = ServerCfg { kmsg: true, ..Default::default() };
    let mut ks = KernelSampler::new(&cfg);
    let _ = ks.sample(&[], &[]);
    let n = 200;
    let t = Instant::now();
    for _ in 0..n {
        let _ = ks.sample(&[], &[]);
        let _ = ks.drain_events();
    }
    let per = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    println!("kernel sample: {per:.0} us (cached socket scan)");
    let t = Instant::now();
    for _ in 0..n {
        ks.eph_cache = None;
        let _ = ks.sample(&[], &[]);
    }
    println!("kernel sample: {:.0} us (fresh socket scan)", t.elapsed().as_secs_f64() * 1e6 / n as f64);
    // 100k sockets: the scan that unit_refresh_s rate-limits.
    let mut tcp = String::from("  sl  local_address rem_address   st\n");
    for i in 0..100_000u32 {
        // 4 local addresses x 25k connections to one remote endpoint.
        tcp.push_str(&format!(
            "{i:>6}: 0{}00007F:{:04X} 0200007F:1F90 01 00000000:00000000 00:00000000 00000000 0 0 1 1\n",
            1 + i % 4,
            32768 + (i / 4) % 28000
        ));
    }
    let t = Instant::now();
    let (u, _) = ephemeral_usage(&[&tcp], (32768, 60999));
    println!(
        "ephemeral scan of 100k sockets ({} MB): {:.1} ms, used {u}",
        tcp.len() / 1_000_000,
        t.elapsed().as_secs_f64() * 1e3
    );
    assert_eq!(u, 25_000);
}

/// A worker thread stuck in D under a sleeping main thread (thread-pool servers) is found:
/// /proc/stat counts it, /proc/<pid>/stat does not show it.
#[test]
fn dstate_worker_thread_found() {
    let r = Root::new("dthread");
    let cfg = ServerCfg { dstate_min_s: 5, ..Default::default() };
    let mut ks = KernelSampler::with_root(&cfg, &r.0, false);
    r.put("proc/stat", "cpu  1 0 1 10 0 0 0 0 0 0\nprocs_running 1\nprocs_blocked 1\n");
    r.put("proc/99/stat", "99 (java) S 1 99 99 0 -1 0 0 0 0 0 0 0 0 0 20 0 3 0 4000 1 1");
    r.put("proc/99/task/99/stat", "99 (java) S 1 99 99 0 -1 0 0 0 0 0 0 0 0 0 20 0 3 0 4000 1 1");
    r.put("proc/99/task/101/stat", "101 (io-worker) D 1 99 99 0 -1 0 0 0 0 0 0 0 0 0 20 0 3 0 4100 1 1");
    r.put("proc/99/task/101/wchan", "io_schedule");
    r.put("proc/99/task/102/stat", "102 (gc) S 1 99 99 0 -1 0 0 0 0 0 0 0 0 0 20 0 3 0 4200 1 1");
    let units =
        vec![Unit { name: "app.service".into(), cgroup: "/system.slice/app.service".into(), ..Default::default() }];
    let procs = vec![Proc {
        pid: 99,
        name: "java".into(),
        status: "S".into(),
        threads: 3,
        cgroup: "/system.slice/app.service".into(),
        ..Default::default()
    }];
    let k = ks.sample_at(&procs, &units, 1_000_000, None);
    assert!(k.d_state.is_empty(), "not yet blocked long enough");
    let k = ks.sample_at(&procs, &units, 1_010_000, Some(10.0));
    assert_eq!(
        k.d_state,
        vec![DStateProc {
            pid: 99,
            name: "java".into(),
            wchan: "io_schedule".into(),
            seconds: 10,
            unit: Some("app.service".into())
        }]
    );
    let ev = ks.drain_events();
    assert_eq!(ev.iter().filter(|e| e.kind == EventKind::HungTask).count(), 1, "{ev:?}");
    // Nothing more blocked than found: no thread walk.
    r.put("proc/stat", "cpu  1 0 1 10 0 0 0 0 0 0\nprocs_running 1\nprocs_blocked 0\n");
    let k = ks.sample_at(&procs, &units, 1_020_000, Some(10.0));
    assert!(k.d_state.is_empty());
}
