use super::*;
use std::sync::{Arc, Mutex};

fn fixture(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fat-svc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn put(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel.trim_start_matches('/'));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

/// A v2 unit directory with the usual files.
fn unit_dir(root: &Path, rel: &str, usage: u64, periods: u64, throttled: u64, mem: u64, oom: u64) {
    put(root, &format!("{rel}/cpu.stat"), &format!("usage_usec {usage}\nuser_usec 1\nsystem_usec 1\nnr_periods {periods}\nnr_throttled {throttled}\nthrottled_usec 9\n"));
    put(root, &format!("{rel}/memory.current"), &format!("{mem}\n"));
    put(root, &format!("{rel}/memory.events"), &format!("low 0\nhigh 0\nmax 3\noom 1\noom_kill {oom}\n"));
    put(root, &format!("{rel}/io.stat"), "8:0 rbytes=1000 wbytes=2000 rios=1 wios=2 dbytes=0 dios=0\n");
    put(root, &format!("{rel}/pids.current"), "3\n");
    put(root, &format!("{rel}/cpu.pressure"), "some avg10=1.50 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.50 avg60=0.00 avg300=0.00 total=1\n");
    put(root, &format!("{rel}/memory.pressure"), "some avg10=2.00 avg60=0.00 avg300=0.00 total=1\nfull avg10=1.00 avg60=0.00 avg300=0.00 total=1\n");
}

#[derive(Default)]
struct FakeSd {
    list: String,
    show: String,
    calls: Vec<String>,
}

fn runner(sd: Arc<Mutex<FakeSd>>) -> Runner {
    Box::new(move |args: &[&str]| {
        let mut g = sd.lock().unwrap();
        g.calls.push(args.join(" "));
        Some(if args[0] == "list-units" { g.list.clone() } else { g.show.clone() })
    })
}

fn show_block(id: &str, active: &str, sub: &str, result: &str, restarts: u32, pid: u32, cg: &str) -> String {
    format!(
        "Id={id}\nDescription=The {id}\nLoadState=loaded\nActiveState={active}\nSubState={sub}\nResult={result}\nNRestarts={restarts}\nMainPID={pid}\nExecMainCode=1\nExecMainStatus={}\nControlGroup={cg}\nStateChangeTimestampMonotonic=5000000\nMemoryMax=infinity\n\n",
        if result == "success" { 0 } else { 1 }
    )
}

const HEX: &str = "410892b21be2ffda255ceb4e7e2077d968864674cefc8174a3843e6f01c860f7";
const HEX2: &str = "7a1d00c0ffee11223344556677889900aabbccddeeff00112233445566778899";
const POD: &str = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234abcd_5678_90ef_1234_567890abcdef.slice";

fn cfg() -> ServerCfg {
    ServerCfg { unit_refresh_s: 0, unit_full_refresh_s: 0, flap_restarts: 3, flap_window_s: 600, burst_procs: 3, ..Default::default() }
}

fn proc(pid: u32, ppid: u32, cg: &str) -> Proc {
    Proc { pid, ppid, name: format!("p{pid}"), cgroup: cg.into(), cpu: 1.0, mem: 1 << 20, ..Default::default() }
}

#[test]
fn parse_show_blocks() {
    let text = "Id=nginx.service\nDescription=A high performance web server\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=oom-kill\nNRestarts=4\nMainPID=0\nExecMainCode=2\nExecMainStatus=9\nControlGroup=/system.slice/nginx.service\nStateChangeTimestampMonotonic=2000000\nMemoryMax=536870912\nUnknownKey=x\n\nId=cron.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=812\nExecMainCode=0\nExecMainStatus=0\nControlGroup=\nStateChangeTimestampMonotonic=0\nMemoryMax=infinity\n";
    let v = parse_systemctl_show_at(text, 1_000_000);
    assert_eq!(v.len(), 2);
    let n = &v[0];
    assert_eq!((n.id.as_str(), n.active_state.as_str(), n.result.as_str(), n.n_restarts), ("nginx.service", "failed", "oom-kill", 4));
    assert_eq!((n.main_pid, n.exit_status, n.exit_signal, n.memory_max), (None, Some(137), Some(9), Some(536_870_912)), "killed by SIGKILL: 128 + 9");
    assert_eq!(outcome(&Unit { result: n.result.clone(), exit_code: n.exit_status, ..Default::default() }), " (oom-kill, signal 9)");
    assert_eq!((n.state_change_ts, n.state_change_mono_us), (Some(1_002_000), Some(2_000_000)));
    assert_eq!(n.control_group, "/system.slice/nginx.service");
    let c = &v[1];
    assert_eq!((c.main_pid, c.exit_status, c.memory_max, c.state_change_ts), (Some(812), None, None, None), "ExecMainCode=0: never exited");
    assert!(parse_systemctl_show("").is_empty());
    // A property old systemd lacks (NRestarts) just stays default.
    assert_eq!(parse_systemctl_show_at("Id=a.service\nActiveState=active\n", 0)[0].n_restarts, 0);
}

#[test]
fn parse_list() {
    let t = "nginx.service loaded active running A high performance web server\n● bad.service loaded failed failed Bad thing\nauditd.service masked inactive dead auditd.service\n\n";
    let v = parse_list_units(t);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0], Listed { id: "nginx.service".into(), load: "loaded".into(), active: "active".into(), sub: "running".into(), description: "A high performance web server".into() });
    assert_eq!((v[1].id.as_str(), v[1].active.as_str()), ("bad.service", "failed"));
    assert!(wanted(&v[0]) && wanted(&v[1]) && !wanted(&v[2]));
    assert!(!wanted(&Listed { id: format!("docker-{HEX}.scope"), load: "loaded".into(), active: "active".into(), ..Default::default() }), "container scopes are containers");
    assert!(wanted(&Listed { id: "data.mount".into(), load: "loaded".into(), active: "failed".into(), ..Default::default() }), "failed units of any type");
    assert!(!wanted(&Listed { id: "data.mount".into(), load: "loaded".into(), active: "active".into(), ..Default::default() }));
}

#[test]
fn parse_cgroup_files() {
    assert_eq!(parse_cpu_stat("usage_usec 100\nuser_usec 60\nsystem_usec 40\nnr_periods 10\nnr_throttled 4\nthrottled_usec 5000\n"), (100, 10, 4, 5000));
    assert_eq!(parse_cpu_stat("usage_usec 7\n"), (7, 0, 0, 0), "no cpu controller: only usage");
    assert_eq!(parse_io_stat("8:0 rbytes=10 wbytes=20 rios=1 wios=1\n259:0 rbytes=5 wbytes=1 rios=1 wios=1\n"), (15, 21));
    assert_eq!(parse_io_stat(""), (0, 0));
    assert_eq!(parse_pressure("some avg10=12.50 avg60=1.00 avg300=0.00 total=9\nfull avg10=3.25 avg60=0.00 avg300=0.00 total=1\n"), (12.5, 3.25));
    assert_eq!(parse_pressure("some avg10=1.00 avg60=0 avg300=0 total=0\n"), (1.0, 0.0));
    assert_eq!(parse_cpu_max("50000 100000\n"), Some(0.5));
    assert_eq!(parse_cpu_max("max 100000\n"), None);
    assert_eq!(kv("anon 5\noom_kill 3\n", "oom_kill"), Some(3));
    assert_eq!(kv("oom_kill_x 3\n", "oom_kill"), None);
}

#[test]
fn flapping_window() {
    let now = 1_000_000;
    let ts = [now - 700_000, now - 500_000, now - 10_000, now];
    assert_eq!(flap_state(&ts, now, 600, 3), (3, true));
    assert_eq!(flap_state(&ts, now, 60, 3), (2, false));
    assert_eq!(flap_state(&[], now, 600, 3), (0, false));
    assert_eq!(flap_state(&ts, now, 600, 0), (3, false), "threshold 0 disables");
}

/// Full pipeline on a fixture cgroup v2 tree with a fake systemctl: units of every kind,
/// rates, nested-unit folding, process join, and transition events.
#[test]
fn sample_fixture_tree() {
    let root = fixture("v2");
    let nginx = "/system.slice/nginx.service";
    unit_dir(&root, nginx, 1_000_000, 100, 0, 50 << 20, 0);
    put(&root, &format!("{nginx}/memory.max"), &format!("{}\n", 100u64 << 20));
    put(&root, &format!("{nginx}/cpu.max"), "50000 100000\n");
    unit_dir(&root, "/system.slice/cron.service", 10, 0, 0, 1 << 20, 0);
    let ctr = format!("/system.slice/docker-{HEX}.scope");
    unit_dir(&root, &ctr, 0, 0, 0, 10 << 20, 0);
    unit_dir(&root, POD, 0, 0, 0, 30 << 20, 0);
    let podc = format!("{POD}/cri-containerd-{HEX2}.scope");
    unit_dir(&root, &podc, 0, 0, 0, 20 << 20, 0);
    let user = "/user.slice/user-1000.slice/user@1000.service";
    unit_dir(&root, user, 0, 0, 0, 1 << 20, 0);
    unit_dir(&root, &format!("{user}/app.slice/dbus.service"), 0, 0, 0, 1 << 20, 0);
    unit_dir(&root, "/mygroup/worker", 0, 0, 0, 2 << 20, 0);
    // Runtime metadata for the pod's container (OCI annotations).
    let rt = fixture("v2-rt");
    let run = rt.join("run");
    put(&run, &format!("k8s.io/{HEX2}/config.json"), r#"{"annotations":{"io.kubernetes.cri.sandbox-name":"api","io.kubernetes.cri.sandbox-namespace":"shop","io.kubernetes.cri.sandbox-uid":"1234abcd-5678-90ef-1234-567890abcdef","io.kubernetes.cri.container-name":"app"}}"#);
    let docker = rt.join("docker");
    put(&docker, &format!("containers/{HEX}/config.v2.json"), r#"{"Name":"/web","Config":{"Image":"nginx:1"},"State":{"Running":true},"RestartCount":0}"#);

    let sd = Arc::new(Mutex::new(FakeSd {
        list: "nginx.service loaded active running The nginx.service\ncron.service loaded active running The cron\ngone.service not-found inactive dead gone.service\n".into(),
        show: show_block("nginx.service", "active", "running", "success", 0, 100, nginx) + &show_block("cron.service", "active", "running", "success", 0, 200, "/system.slice/cron.service"),
        ..Default::default()
    }));
    let mut s = Services::with_sources(&cfg(), CgMode::V2(root.clone()), Some(runner(sd.clone())), runtime::Resolver::with_roots(&docker, vec![run.clone()], vec![]));
    let procs = vec![
        proc(100, 1, nginx),
        proc(101, 100, nginx),
        proc(200, 1, "/system.slice/cron.service"),
        proc(300, 1, &format!("{user}/app.slice/dbus.service")),
        proc(400, 1, "/mygroup/worker"),
        proc(401, 400, "/mygroup/worker"),
    ];
    let u1 = s.sample_at(&procs, 1_000_000, 0);
    assert!(s.drain_events().is_empty(), "baseline sample emits nothing");
    let names: Vec<(&str, UnitKind)> = u1.iter().map(|u| (u.name.as_str(), u.kind)).collect();
    for want in [("nginx.service", UnitKind::Systemd), ("cron.service", UnitKind::Systemd), ("web", UnitKind::Container), ("shop/api/app", UnitKind::Container), ("shop/api", UnitKind::Pod), ("user@1000.service", UnitKind::Systemd), ("/mygroup/worker", UnitKind::Cgroup)] {
        assert!(names.contains(&want), "missing {want:?} in {names:?}");
    }
    assert!(!names.iter().any(|(n, _)| *n == "dbus.service"), "user units fold into user@: {names:?}");
    assert!(!names.iter().any(|(n, _)| *n == "gone.service"), "not-found units are skipped");
    let ng = u1.iter().find(|u| u.name == "nginx.service").unwrap();
    assert_eq!((ng.mem, ng.mem_limit, ng.cpu_quota, ng.pids, ng.main_pid), (50 << 20, Some(100 << 20), Some(0.5), 2, Some(100)));
    assert_eq!(ng.psi.unwrap().cpu_some, 1.5);
    assert_eq!(ng.since, Some(s.boot_ms + 5000));
    let user_u = u1.iter().find(|u| u.name == "user@1000.service").unwrap();
    assert_eq!((user_u.pids, user_u.main_pid), (1, Some(300)), "nested process joins the outer unit");
    let w = u1.iter().find(|u| u.name == "/mygroup/worker").unwrap();
    assert_eq!((w.pids, w.main_pid, w.mem), (2, Some(400), 2 << 20));
    let web = u1.iter().find(|u| u.name == "web").unwrap();
    assert_eq!((web.description.as_str(), web.container.as_ref().unwrap().runtime.as_str()), ("nginx:1", "docker"));

    // One second later: nginx used 0.5 s of cpu, was throttled in 40 of 100 periods, wrote io,
    // got an OOM kill and restarted twice; cron failed; a burst of processes in the worker.
    unit_dir(&root, nginx, 1_500_000, 200, 40, 95 << 20, 1);
    put(&root, &format!("{nginx}/io.stat"), "8:0 rbytes=1000 wbytes=1002000\n");
    put(&root, &format!("{nginx}/memory.stat"), "anon 99000000\ninactive_file 0\n");
    {
        let mut g = sd.lock().unwrap();
        g.list = "nginx.service loaded active running The nginx.service\ncron.service loaded failed failed The cron\n".into();
        g.show = show_block("nginx.service", "active", "running", "success", 2, 102, nginx) + &show_block("cron.service", "failed", "failed", "exit-code", 0, 0, "/system.slice/cron.service");
    }
    let mut procs2: Vec<Proc> = procs.iter().filter(|p| p.pid != 100 && p.pid != 200).cloned().collect();
    procs2.push(proc(102, 1, nginx));
    procs2.extend((500..505).map(|i| proc(i, 400, "/mygroup/worker")));
    let u2 = s.sample_at(&procs2, 1_001_000, 1000);
    let ng = u2.iter().find(|u| u.name == "nginx.service").unwrap();
    assert!((ng.cpu - 50.0).abs() < 0.01, "{}", ng.cpu);
    assert!((ng.cpu_throttled_pct - 40.0).abs() < 0.01);
    assert_eq!((ng.io_read_bps, ng.io_write_bps), (0, 1_000_000));
    assert_eq!((ng.restarts, ng.recent_restarts, ng.oom_kills, ng.main_pid), (2, 2, 1, Some(102)));
    assert_eq!(u2[0].name, "cron.service", "failed units sort first");
    let ev = s.drain_events();
    let kinds: Vec<(EventKind, &str)> = ev.iter().map(|e| (e.kind, e.subject.as_str())).collect();
    for want in [
        (EventKind::UnitRestart, "unit:nginx.service"),
        (EventKind::OomKill, "unit:nginx.service"),
        (EventKind::Throttle, "unit:nginx.service"),
        (EventKind::Exhaustion, "unit:nginx.service"),
        (EventKind::UnitFailed, "unit:cron.service"),
        (EventKind::DeployBurst, "unit:/mygroup/worker"),
    ] {
        assert!(kinds.contains(&want), "missing {want:?} in {kinds:?}");
    }
    assert!(!kinds.iter().any(|(k, _)| *k == EventKind::UnitFlapping), "2 restarts < threshold 3");
    let restart = ev.iter().find(|e| e.kind == EventKind::UnitRestart).unwrap();
    assert_eq!(restart.value, Some(2.0));
    assert!(restart.detail.contains("2 restart(s) in the last 10 min"), "{}", restart.detail);
    let failed = ev.iter().find(|e| e.kind == EventKind::UnitFailed).unwrap();
    assert!(failed.detail.contains("exit-code, status 1") && failed.severity == Severity::Warn, "{failed:?}");

    // A third restart within the window: flapping, once; throttling does not re-fire while it lasts.
    unit_dir(&root, nginx, 2_000_000, 300, 80, 50 << 20, 1);
    sd.lock().unwrap().show = show_block("nginx.service", "active", "running", "success", 3, 102, nginx);
    s.sample_at(&procs2, 1_002_000, 2000);
    let ev = s.drain_events();
    assert!(ev.iter().any(|e| e.kind == EventKind::UnitFlapping && e.severity == Severity::Crit), "{ev:?}");
    assert!(!ev.iter().any(|e| e.kind == EventKind::Throttle || e.kind == EventKind::OomKill), "edge-triggered: {ev:?}");
    let u = s.sample_at(&procs2, 1_003_000, 3000);
    assert!(u.iter().find(|u| u.name == "nginx.service").unwrap().flapping);
    assert!(!s.drain_events().iter().any(|e| e.kind == EventKind::UnitFlapping), "flapping fires once");


    // The container goes away (stop event, still listed as inactive), then comes back (restart).
    std::fs::remove_dir_all(root.join(ctr.trim_start_matches('/'))).unwrap();
    let u = s.sample_at(&procs2, 1_004_000, 4000);
    let web = u.iter().find(|u| u.name == "web").unwrap();
    assert_eq!(web.state, "inactive");
    assert!(s.drain_events().iter().any(|e| e.kind == EventKind::UnitStop && e.subject == "container:web"));
    unit_dir(&root, &ctr, 0, 0, 0, 10 << 20, 0);
    let u = s.sample_at(&procs2, 1_005_000, 5000);
    assert_eq!(u.iter().filter(|u| u.name == "web").count(), 1);
    let ev = s.drain_events();
    assert!(ev.iter().any(|e| e.kind == EventKind::UnitRestart && e.subject == "container:web"), "{ev:?}");

    // Delta strategy: with a long full-refresh period, an unchanged unit is not re-read.
    s.cfg.unit_full_refresh_s = 3600;
    sd.lock().unwrap().calls.clear();
    s.sample_at(&procs2, 1_006_000, 6000);
    let calls = sd.lock().unwrap().calls.clone();
    assert!(calls[0].starts_with("list-units"));
    assert!(calls.iter().skip(1).all(|c| !c.contains("cron.service") && !c.contains("nginx.service")), "{calls:?}");

    // While nginx keeps flapping, restarts are coalesced: none reported within the cooldown,
    // then one event whose value carries every restart since the last report (at 1_002_000).
    s.cfg.unit_full_refresh_s = 0;
    s.cfg.spike_cooldown_s = 10;
    sd.lock().unwrap().show = show_block("nginx.service", "active", "running", "success", 4, 102, nginx);
    s.sample_at(&procs2, 1_007_000, 7000);
    assert!(!s.drain_events().iter().any(|e| e.kind == EventKind::UnitRestart), "coalesced while flapping");
    sd.lock().unwrap().show = show_block("nginx.service", "active", "running", "success", 5, 102, nginx);
    s.sample_at(&procs2, 1_012_000, 12_000);
    let ev = s.drain_events();
    let r = ev.iter().find(|e| e.kind == EventKind::UnitRestart).expect("restart reported after the cooldown");
    assert_eq!(r.value, Some(2.0), "{}", r.detail);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&rt);
}

#[test]
fn cgroup_v1_and_no_systemd() {
    let root = fixture("v1");
    let rel = "/system.slice/app.service";
    put(&root, &format!("systemd{rel}/cgroup.procs"), "1\n");
    put(&root, &format!("memory{rel}/memory.usage_in_bytes"), "4096\n");
    put(&root, &format!("memory{rel}/memory.limit_in_bytes"), "9223372036854771712\n");
    put(&root, &format!("memory{rel}/memory.oom_control"), "oom_kill_disable 0\nunder_oom 0\noom_kill 2\n");
    put(&root, &format!("cpuacct{rel}/cpuacct.usage"), "1000000000\n");
    put(&root, &format!("cpu{rel}/cpu.cfs_quota_us"), "200000\n");
    put(&root, &format!("cpu{rel}/cpu.cfs_period_us"), "100000\n");
    let mut s = Services::with_sources(&cfg(), CgMode::V1 { root: root.clone(), tree: root.join("systemd") }, None, runtime::Resolver::with_roots(&root, vec![], vec![]));
    let u = s.sample_at(&[proc(9, 1, rel)], 0, 0);
    let a = u.iter().find(|u| u.name == "app.service").expect("discovered from the systemd hierarchy");
    assert_eq!((a.mem, a.mem_limit, a.cpu_quota, a.oom_kills, a.pids), (4096, None, Some(2.0), 2, 1));
    if cfg!(target_os = "linux") {
        assert!(s.notes().iter().any(|n| n.contains("cgroup v1")) && s.notes().iter().any(|n| n.contains("systemd not detected")), "{:?}", s.notes());
    }
    put(&root, &format!("cpuacct{rel}/cpuacct.usage"), "1250000000\n");
    let u = s.sample_at(&[proc(9, 1, rel)], 500, 500);
    assert!((u[0].cpu - 50.0).abs() < 0.01, "{}", u[0].cpu);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn bounded_by_max_units() {
    let root = fixture("cap");
    let mut list = String::new();
    for i in 0..30 {
        let state = if i < 5 { "active running" } else { "inactive dead" };
        list.push_str(&format!("s{i:02}.service loaded {state} S{i}\n"));
    }
    list.push_str("zz.service loaded failed failed Broken\n");
    let sd = Arc::new(Mutex::new(FakeSd { list, ..Default::default() }));
    let c = ServerCfg { max_units: 8, ..cfg() };
    let mut s = Services::with_sources(&c, CgMode::V2(root.clone()), Some(runner(sd)), runtime::Resolver::with_roots(&root, vec![], vec![]));
    let u = s.sample_at(&[], 0, 0);
    assert_eq!(u.len(), 8);
    assert_eq!(u[0].name, "zz.service");
    assert_eq!(u.iter().filter(|u| u.state == "active").count(), 5, "inactive dropped first");
    assert!(s.notes().iter().any(|n| n.contains("max_units")));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn render_and_filter() {
    let units = vec![
        Unit { name: "a.service".into(), state: "failed".into(), sub_state: "failed".into(), result: "oom-kill".into(), ..Default::default() },
        Unit { name: "b.service".into(), state: "active".into(), sub_state: "running".into(), cpu: 12.5, mem: 3 << 20, restarts: 4, recent_restarts: 4, flapping: true, ..Default::default() },
        Unit { name: "web".into(), kind: UnitKind::Container, state: "active".into(), sub_state: "running".into(), ..Default::default() },
    ];
    let t = render(&units, &["needs root".into()]);
    assert!(t.starts_with("3 units: 2 active, 1 failed, 1 flapping"), "{t}");
    assert!(t.contains("active!flap") && t.contains("(oom-kill)") && t.contains("4*") && t.contains("note: needs root"), "{t}");
    assert_eq!(filter(units.clone(), true, None).len(), 2);
    assert_eq!(filter(units, false, parse_kind("container")).len(), 1);
    assert_eq!(parse_kind("k8s-pod"), Some(UnitKind::Pod));
    assert_eq!(parse_kind("bogus"), None);
}

/// Live probe for real hosts (not run by default): samples the real sources in a loop and
/// prints units, events and the sampler's own CPU cost (self + systemctl children).
/// `FAT_SVC_PROBE_SAMPLES` (default 12) and `FAT_SVC_PROBE_INTERVAL_MS` (default 5000).
#[test]
#[ignore]
fn live_probe() {
    fn cpu_ms(who: i32) -> f64 {
        // SAFETY: zeroed rusage is a valid out-buffer.
        let mut r: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(who, &mut r) };
        let tv = |t: libc::timeval| t.tv_sec as f64 * 1000.0 + t.tv_usec as f64 / 1000.0;
        tv(r.ru_utime) + tv(r.ru_stime)
    }
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let (n, every) = (env("FAT_SVC_PROBE_SAMPLES", 12), env("FAT_SVC_PROBE_INTERVAL_MS", 5000));
    let mut c = crate::collect::Collector::new();
    let mut s = Services::new(&ServerCfg::default());
    // This thread only (the collector's own threads are not the sampler's cost).
    #[cfg(target_os = "linux")]
    let me = libc::RUSAGE_THREAD;
    #[cfg(not(target_os = "linux"))]
    let me = libc::RUSAGE_SELF;
    let (mut own, mut kids, mut max_ms) = (0.0, 0.0, 0.0f64);
    for i in 0..n {
        let snap = c.sample();
        let (a, b, t) = (cpu_ms(me), cpu_ms(libc::RUSAGE_CHILDREN), std::time::Instant::now());
        let units = s.sample(&snap.procs);
        let wall = t.elapsed().as_secs_f64() * 1000.0;
        let (da, db) = (cpu_ms(me) - a, cpu_ms(libc::RUSAGE_CHILDREN) - b);
        if i > 0 {
            own += da;
            kids += db;
            max_ms = max_ms.max(da + db);
        }
        let flap: Vec<String> = units.iter().filter(|u| u.flapping || u.is_failed() || u.cpu_throttled_pct > 0.0 || u.oom_kills > 0).map(|u| format!("{}[{} rst={}/{} thr={:.0}% oom={} mem={}]", u.name, u.state, u.recent_restarts, u.restarts, u.cpu_throttled_pct, u.oom_kills, u.mem)).collect();
        println!("sample {i}: {} units, sampler cpu {da:.1} ms + systemctl {db:.1} ms, wall {wall:.1} ms; notable: {flap:?}", units.len());
        for e in s.drain_events() {
            println!("  EVENT {:?} {:?} {} | {}", e.kind, e.severity, e.subject, e.detail);
        }
        for note in s.notes() {
            println!("  note: {note}");
        }
        std::thread::sleep(Duration::from_millis(every));
    }
    let span_ms = (n.saturating_sub(1) * every) as f64;
    if span_ms > 0.0 {
        println!("avg sampler cost: {:.3}% of one core (self {:.1} ms + systemctl {:.1} ms over {:.0} s), worst sample {max_ms:.1} ms", (own + kids) / span_ms * 100.0, own, kids, span_ms / 1000.0);
    }
}

/// A unit OOM-killed between samples (cgroup already gone) still yields an oom_kill event from
/// systemd's Result, and a crit unit_failed.
#[test]
fn oom_from_systemd_result() {
    let root = fixture("oomres");
    let sd = Arc::new(Mutex::new(FakeSd {
        list: "job.service loaded active running Job\n".into(),
        show: show_block("job.service", "active", "running", "success", 0, 0, "/system.slice/job.service"),
        ..Default::default()
    }));
    let mut s = Services::with_sources(&cfg(), CgMode::V2(root.clone()), Some(runner(sd.clone())), runtime::Resolver::with_roots(&root, vec![], vec![]));
    s.sample_at(&[], 0, 0);
    {
        let mut g = sd.lock().unwrap();
        g.list = "job.service loaded failed failed Job\n".into();
        g.show = show_block("job.service", "failed", "failed", "oom-kill", 0, 0, "").replace("ExecMainCode=1", "ExecMainCode=2").replace("ExecMainStatus=1", "ExecMainStatus=9");
    }
    let u = s.sample_at(&[], 1000, 1000);
    assert_eq!((u[0].state.as_str(), u[0].exit_code), ("failed", Some(137)));
    let ev = s.drain_events();
    assert!(ev.iter().any(|e| e.kind == EventKind::OomKill && e.subject == "unit:job.service"), "{ev:?}");
    let f = ev.iter().find(|e| e.kind == EventKind::UnitFailed).unwrap();
    assert_eq!(f.severity, Severity::Crit);
    assert!(f.detail.ends_with("(oom-kill, signal 9)"), "{}", f.detail);
    let _ = std::fs::remove_dir_all(&root);
}

/// One OOM kill seen first in the cgroup's memory.events and then as systemd's Result=oom-kill
/// is one oom_kill event; `systemctl reset-failed` afterwards is cleanup, not a second failure.
#[test]
fn oom_counted_once_and_reset_failed_is_quiet() {
    let root = fixture("oomonce");
    let cg = "/system.slice/job.service";
    unit_dir(&root, cg, 0, 0, 0, 1 << 20, 0);
    let sd = Arc::new(Mutex::new(FakeSd {
        list: "job.service loaded active running Job\n".into(),
        show: show_block("job.service", "active", "running", "success", 0, 10, cg),
        ..Default::default()
    }));
    let mut s = Services::with_sources(&cfg(), CgMode::V2(root.clone()), Some(runner(sd.clone())), runtime::Resolver::with_roots(&root, vec![], vec![]));
    let procs = vec![proc(10, 1, cg)];
    s.sample_at(&procs, 0, 0);
    assert!(s.drain_events().is_empty());
    // The kernel kills a process in the unit: memory.events counts it, the unit is still up.
    unit_dir(&root, cg, 0, 0, 0, 1 << 20, 1);
    s.sample_at(&procs, 1000, 1000);
    let ev = s.drain_events();
    assert_eq!(ev.iter().filter(|e| e.kind == EventKind::OomKill).count(), 1, "{ev:?}");
    // systemd stops it (OOMPolicy=stop) a sample later: failed, Result=oom-kill.
    let _ = std::fs::remove_dir_all(root.join(cg.trim_start_matches('/')));
    {
        let mut g = sd.lock().unwrap();
        g.list = "job.service loaded failed failed Job\n".into();
        g.show = show_block("job.service", "failed", "failed", "oom-kill", 0, 0, "");
    }
    s.sample_at(&[], 2000, 2000);
    let ev = s.drain_events();
    assert!(!ev.iter().any(|e| e.kind == EventKind::OomKill), "same kill, not again: {ev:?}");
    assert!(ev.iter().any(|e| e.kind == EventKind::UnitFailed), "{ev:?}");
    // reset-failed: the unit leaves the list.
    {
        let mut g = sd.lock().unwrap();
        g.list = String::new();
        g.show = String::new();
    }
    s.sample_at(&[], 3000, 3000);
    let ev = s.drain_events();
    assert!(!ev.iter().any(|e| e.kind == EventKind::UnitFailed), "cleanup is not a failure: {ev:?}");
    // Started again and OOM-killed between samples: systemd's result is a new kill.
    {
        let mut g = sd.lock().unwrap();
        g.list = "job.service loaded active running Job\n".into();
        g.show = show_block("job.service", "active", "running", "success", 0, 11, cg);
    }
    unit_dir(&root, cg, 0, 0, 0, 1 << 20, 0);
    s.sample_at(&[proc(11, 1, cg)], 4000, 4000);
    s.drain_events();
    let _ = std::fs::remove_dir_all(root.join(cg.trim_start_matches('/')));
    {
        let mut g = sd.lock().unwrap();
        g.list = "job.service loaded failed failed Job\n".into();
        g.show = show_block("job.service", "failed", "failed", "oom-kill", 0, 0, "");
    }
    s.sample_at(&[], 5000, 5000);
    let ev = s.drain_events();
    assert_eq!(ev.iter().filter(|e| e.kind == EventKind::OomKill).count(), 1, "{ev:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// `fat services --failed` on a healthy host says so, with the real unit count.
#[test]
fn render_filtered_empty_and_counts() {
    let t = render_filtered(&[], 94, "failed or flapping units", &[]);
    assert_eq!(t, "no failed or flapping units (94 units in all)\n");
    let u = vec![Unit { name: "a.service".into(), state: "failed".into(), ..Default::default() }];
    let t = render_filtered(&u, 94, "failed or flapping units", &[]);
    assert!(t.starts_with("1 failed or flapping units of 94 units\n1 units: 0 active, 1 failed"), "{t}");
    assert_eq!(render_filtered(&u, 1, "", &[]), render(&u, &[]));
}
