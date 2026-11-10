//! Container names and state without calling a runtime CLI on the hot path. OWNER: services agent.
//!
//! A container's cgroup gives its id and (from the scope prefix) its runtime; everything else
//! comes from the first source that answers, each optional:
//! 1. `crate::fleet::cached_containers()`: whatever the TUI/CLI already fetched (never blocks).
//! 2. Docker's own state file `<data-root>/containers/<id>/config.v2.json` (data-root from
//!    /etc/docker/daemon.json, default /var/lib/docker): name, image, running/restarting/paused,
//!    exit code, restart count, health, Kubernetes labels. Needs read access (usually root).
//! 3. The OCI bundle `config.json` the runtime wrote for the container (containerd tasks under
//!    /run/containerd/io.containerd.runtime.v2.task/<ns>/<id>, CRI-O and podman under
//!    /run/containers/storage/overlay-containers/<id>/userdata): Kubernetes pod/namespace/
//!    container names from CRI annotations.
//! 4. podman's container index (`containers.json`) for names.
//!
//! Otherwise the 12-hex short id is the name. Static metadata is cached per container; state
//! is re-read when the caller asks (once per unit refresh).
use crate::model::Ts;
use crate::server::ContainerMeta;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Runtime-reported state, when a source exposes it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RtState {
    /// Normalised unit state (see `Unit.state`), None when unknown.
    pub state: Option<String>,
    pub sub_state: String,
    pub exit_code: Option<i32>,
    pub restarts: Option<u32>,
    pub started: Option<Ts>,
}

#[derive(Default)]
struct Entry {
    meta: ContainerMeta,
    state: RtState,
    /// Source file that answered (re-read for state), if any.
    docker_file: Option<PathBuf>,
}

pub struct Resolver {
    cache: HashMap<String, Entry>,
    docker_root: Option<PathBuf>,
    /// Overrides for tests: (docker data root, run dir for OCI bundles).
    run_roots: Vec<PathBuf>,
    podman_index: Vec<PathBuf>,
}

impl Resolver {
    pub fn new() -> Resolver {
        let docker_root = std::fs::read_to_string("/etc/docker/daemon.json")
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.get("data-root").and_then(Value::as_str).map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/var/lib/docker"));
        let mut podman_index = vec![PathBuf::from("/var/lib/containers/storage/overlay-containers/containers.json")];
        if let Some(h) = dirs::home_dir() {
            podman_index.push(h.join(".local/share/containers/storage/overlay-containers/containers.json"));
        }
        Resolver {
            cache: HashMap::new(),
            docker_root: Some(docker_root),
            run_roots: vec![PathBuf::from("/run/containerd/io.containerd.runtime.v2.task"), PathBuf::from("/run/containers/storage/overlay-containers")],
            podman_index,
        }
    }

    #[cfg(test)]
    pub fn with_roots(docker_root: &Path, run_roots: Vec<PathBuf>, podman_index: Vec<PathBuf>) -> Resolver {
        Resolver { cache: HashMap::new(), docker_root: Some(docker_root.to_path_buf()), run_roots, podman_index }
    }

    /// Metadata and state for a container. `full_id` is the hex id from the cgroup path (12 or
    /// 64 chars), `runtime` the runtime guessed from the cgroup. `refresh` re-reads state.
    pub fn resolve(&mut self, full_id: &str, runtime: &str, refresh: bool) -> (ContainerMeta, RtState) {
        let short: String = full_id.chars().take(12).collect::<String>().to_ascii_lowercase();
        if !self.cache.contains_key(&short) {
            let e = self.lookup(full_id, &short, runtime);
            self.cache.insert(short.clone(), e);
        } else if refresh {
            let e = self.cache.get_mut(&short).expect("present");
            if let Some(f) = e.docker_file.clone()
                && let Some((m, s)) = read_docker(&f)
            {
                e.state = s;
                e.meta.health = m.health;
            }
        }
        // Names from the TUI's cache may arrive later; adopt them when ours is only the id.
        let e = self.cache.get_mut(&short).expect("present");
        if e.meta.name == short
            && let Some(c) = crate::fleet::cached_containers().and_then(|l| l.into_iter().find(|c| !c.id.is_empty() && (c.id.starts_with(&short) || short.starts_with(&c.id))))
        {
            merge_cli(&mut e.meta, &mut e.state, &c);
        }
        (e.meta.clone(), e.state.clone())
    }

    /// Forget containers not seen any more (bounded cache).
    pub fn retain(&mut self, live: &std::collections::HashSet<String>) {
        self.cache.retain(|k, _| live.contains(k));
    }

    fn lookup(&self, full_id: &str, short: &str, runtime: &str) -> Entry {
        let mut e = Entry { meta: ContainerMeta { id: short.to_string(), name: short.to_string(), runtime: runtime.to_string(), ..Default::default() }, ..Default::default() };
        if full_id.len() == 64 {
            if let Some(root) = &self.docker_root {
                let f = root.join("containers").join(full_id).join("config.v2.json");
                if let Some((m, s)) = read_docker(&f) {
                    let rt = if e.meta.runtime.is_empty() || e.meta.runtime == "cri" { "docker".to_string() } else { e.meta.runtime.clone() };
                    e.meta = ContainerMeta { runtime: rt, ..m };
                    e.state = s;
                    e.docker_file = Some(f);
                    return e;
                }
            }
            for root in &self.run_roots {
                if let Some(cfg) = find_bundle(root, full_id)
                    && let Some(m) = read_oci(&cfg)
                {
                    apply_annotations(&mut e.meta, &m);
                    break;
                }
            }
            if e.meta.name == short {
                for idx in &self.podman_index {
                    if let Some(n) = podman_name(idx, full_id) {
                        e.meta.name = n;
                        break;
                    }
                }
            }
        }
        if let Some(c) = crate::fleet::cached_containers().and_then(|l| l.into_iter().find(|c| !c.id.is_empty() && (c.id.starts_with(short) || short.starts_with(&c.id)))) {
            merge_cli(&mut e.meta, &mut e.state, &c);
        }
        e
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

fn merge_cli(meta: &mut ContainerMeta, state: &mut RtState, c: &crate::model::Container) {
    if meta.name == meta.id && !c.name.is_empty() {
        meta.name = c.name.clone();
    }
    if meta.image.is_empty() {
        meta.image = c.image.clone();
    }
    if !c.runtime.is_empty() && (meta.runtime.is_empty() || meta.runtime == "cri") {
        meta.runtime = c.runtime.clone();
    }
    let st = c.status.to_ascii_lowercase();
    if meta.health.is_none() {
        meta.health = ["unhealthy", "healthy", "starting"].into_iter().find(|h| st.contains(&format!("({h}"))).map(str::to_string);
    }
    if state.state.is_none() && !st.is_empty() {
        let (s, sub) = if st.starts_with("up") && st.contains("paused") {
            ("active", "paused")
        } else if st.starts_with("up") {
            ("active", "running")
        } else if st.starts_with("restarting") {
            ("activating", "restarting")
        } else {
            ("unknown", "")
        };
        state.state = Some(s.into());
        state.sub_state = sub.into();
    }
}

/// Docker `config.v2.json` -> (meta, state).
fn read_docker(f: &Path) -> Option<(ContainerMeta, RtState)> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(f).ok()?).ok()?;
    Some(parse_docker_config(&v))
}

pub fn parse_docker_config(v: &Value) -> (ContainerMeta, RtState) {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str).unwrap_or_default().to_string();
    let b = |p: &str| v.pointer(p).and_then(Value::as_bool).unwrap_or(false);
    let id = s("/ID");
    let mut meta = ContainerMeta {
        id: id.chars().take(12).collect(),
        name: s("/Name").trim_start_matches('/').to_string(),
        image: s("/Config/Image"),
        runtime: "docker".into(),
        ..Default::default()
    };
    if meta.name.is_empty() {
        meta.name = meta.id.clone();
    }
    let h = s("/State/Health/Status");
    meta.health = (!h.is_empty()).then_some(h);
    if let Some(labels) = v.pointer("/Config/Labels").and_then(Value::as_object) {
        let m: HashMap<String, String> = labels.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect();
        apply_annotations(&mut meta, &m);
    }
    let exit = v.pointer("/State/ExitCode").and_then(Value::as_i64).map(|x| x as i32);
    let (state, sub) = if b("/State/Paused") {
        ("active", "paused")
    } else if b("/State/Restarting") {
        ("activating", "restarting")
    } else if b("/State/Running") {
        ("active", "running")
    } else if b("/State/Dead") || exit.is_some_and(|c| c != 0) {
        ("failed", "exited")
    } else {
        ("inactive", "exited")
    };
    let started = chrono::DateTime::parse_from_rfc3339(&s("/State/StartedAt")).ok().map(|t| t.timestamp_millis()).filter(|&t| t > 0);
    let st = RtState {
        state: Some(state.into()),
        sub_state: sub.into(),
        exit_code: exit,
        restarts: v.get("RestartCount").and_then(Value::as_u64).map(|x| x as u32),
        started,
    };
    (meta, st)
}

/// `<root>/<id>/config.json`, `<root>/<ns>/<id>/config.json` or `<root>/<id>/userdata/config.json`.
fn find_bundle(root: &Path, id: &str) -> Option<PathBuf> {
    let direct = [root.join(id).join("config.json"), root.join(id).join("userdata/config.json")];
    if let Some(p) = direct.into_iter().find(|p| p.is_file()) {
        return Some(p);
    }
    std::fs::read_dir(root).ok()?.flatten().map(|ns| ns.path().join(id).join("config.json")).find(|p| p.is_file())
}

fn read_oci(f: &Path) -> Option<HashMap<String, String>> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(f).ok()?).ok()?;
    Some(oci_annotations(&v))
}

pub fn oci_annotations(v: &Value) -> HashMap<String, String> {
    v.get("annotations").and_then(Value::as_object).map(|a| a.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect()).unwrap_or_default()
}

/// Kubernetes identity from CRI annotations / docker labels (containerd, CRI-O, cri-dockerd).
pub fn apply_annotations(meta: &mut ContainerMeta, a: &HashMap<String, String>) {
    let get = |keys: &[&str]| keys.iter().find_map(|k| a.get(*k)).filter(|s| !s.is_empty()).cloned();
    let pod = get(&["io.kubernetes.cri.sandbox-name", "io.kubernetes.pod.name"]);
    let ns = get(&["io.kubernetes.cri.sandbox-namespace", "io.kubernetes.pod.namespace"]);
    let uid = get(&["io.kubernetes.cri.sandbox-uid", "io.kubernetes.pod.uid"]);
    let cname = get(&["io.kubernetes.cri.container-name", "io.kubernetes.container.name"]);
    let image = get(&["io.kubernetes.cri.image-name", "io.kubernetes.cri-o.ImageName"]);
    let sandbox = get(&["io.kubernetes.cri.container-type", "io.kubernetes.cri-o.ContainerType"]).is_some_and(|t| t == "sandbox")
        || get(&["io.kubernetes.docker.type"]).is_some_and(|t| t == "podsandbox");
    if pod.is_some() {
        meta.pod = pod.clone();
        meta.namespace = ns.clone();
        meta.pod_uid = uid.map(|u| u.replace('_', "-"));
        let base = match (&ns, &pod) {
            (Some(n), Some(p)) => format!("{n}/{p}"),
            (_, Some(p)) => p.clone(),
            _ => String::new(),
        };
        meta.name = match (sandbox, cname) {
            (true, _) => format!("{base}/(sandbox)"),
            (false, Some(c)) => format!("{base}/{c}"),
            (false, None) if meta.name == meta.id => format!("{base}/{}", meta.id),
            _ => meta.name.clone(),
        };
    }
    if let Some(i) = image
        && meta.image.is_empty()
    {
        meta.image = i;
    }
}

/// Name for `id` in podman's containers.json (`[{"id": ..., "names": [...]}]`).
fn podman_name(index: &Path, id: &str) -> Option<String> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(index).ok()?).ok()?;
    v.as_array()?.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(id))?.get("names")?.as_array()?.first()?.as_str().map(str::to_string)
}

/// Runtime implied by a container cgroup segment.
pub fn runtime_of_segment(seg: &str, path: &str) -> &'static str {
    if seg.starts_with("docker-") || path.starts_with("/docker/") || path.contains("/docker/") {
        "docker"
    } else if seg.starts_with("libpod-") {
        "podman"
    } else if seg.starts_with("cri-containerd-") {
        "containerd"
    } else if seg.starts_with("crio-") {
        "cri-o"
    } else if path.contains("kubepods") {
        "cri"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn docker_config_parsing() {
        let v = json!({"ID": "abcdef0123456789", "Name": "/web", "Config": {"Image": "nginx:1", "Labels": {}}, "RestartCount": 4,
            "State": {"Running": false, "Restarting": true, "ExitCode": 1, "StartedAt": "2026-11-10T09:12:33.5Z", "Health": {"Status": "unhealthy"}}});
        let (m, s) = parse_docker_config(&v);
        assert_eq!((m.id.as_str(), m.name.as_str(), m.image.as_str(), m.health.as_deref()), ("abcdef012345", "web", "nginx:1", Some("unhealthy")));
        assert_eq!((s.state.as_deref(), s.sub_state.as_str(), s.exit_code, s.restarts), (Some("activating"), "restarting", Some(1), Some(4)));
        assert_eq!(s.started, Some(chrono::DateTime::parse_from_rfc3339("2026-11-10T09:12:33.5Z").unwrap().timestamp_millis()));
        let (_, s) = parse_docker_config(&json!({"State": {"Running": false, "ExitCode": 137}}));
        assert_eq!(s.state.as_deref(), Some("failed"));
        let (_, s) = parse_docker_config(&json!({"State": {"Running": false, "ExitCode": 0}}));
        assert_eq!(s.state.as_deref(), Some("inactive"));
    }

    #[test]
    fn kubernetes_annotations() {
        let mut m = ContainerMeta { id: "0123456789ab".into(), name: "0123456789ab".into(), ..Default::default() };
        let a: HashMap<String, String> = [
            ("io.kubernetes.cri.sandbox-name", "api-7d9f"),
            ("io.kubernetes.cri.sandbox-namespace", "shop"),
            ("io.kubernetes.cri.sandbox-uid", "1234_ab"),
            ("io.kubernetes.cri.container-name", "app"),
            ("io.kubernetes.cri.image-name", "example.com/app:2"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        apply_annotations(&mut m, &a);
        assert_eq!(m.name, "shop/api-7d9f/app");
        assert_eq!((m.pod.as_deref(), m.namespace.as_deref(), m.pod_uid.as_deref(), m.image.as_str()), (Some("api-7d9f"), Some("shop"), Some("1234-ab"), "example.com/app:2"));
    }

    #[test]
    fn resolver_reads_files() {
        let d = std::env::temp_dir().join(format!("fat-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let id = "a".repeat(64);
        let id2 = "b".repeat(64);
        std::fs::create_dir_all(d.join("docker/containers").join(&id)).unwrap();
        std::fs::write(d.join("docker/containers").join(&id).join("config.v2.json"), r#"{"ID":"x","Name":"/db","Config":{"Image":"pg"},"State":{"Running":true}}"#).unwrap();
        std::fs::create_dir_all(d.join("run/k8s.io").join(&id2)).unwrap();
        std::fs::write(d.join("run/k8s.io").join(&id2).join("config.json"), r#"{"annotations":{"io.kubernetes.cri.sandbox-name":"p","io.kubernetes.cri.sandbox-namespace":"n","io.kubernetes.cri.container-name":"c"}}"#).unwrap();
        let mut r = Resolver::with_roots(&d.join("docker"), vec![d.join("run")], vec![]);
        let (m, s) = r.resolve(&id, "docker", false);
        assert_eq!((m.name.as_str(), m.image.as_str(), s.state.as_deref()), ("db", "pg", Some("active")));
        let (m, _) = r.resolve(&id2, "containerd", false);
        assert_eq!((m.name.as_str(), m.runtime.as_str()), ("n/p/c", "containerd"));
        let (m, s) = r.resolve(&"c".repeat(64), "cri-o", false);
        assert_eq!((m.name.as_str(), s.state), ("cccccccccccc", None));
        let _ = std::fs::remove_dir_all(&d);
    }
}
