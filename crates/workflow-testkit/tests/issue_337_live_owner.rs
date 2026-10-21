use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use workflow_testkit::live_conformance::{ConformanceDisposition, LiveConformance};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "issue-337-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("private fixture");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private permissions");
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Release(PathBuf);
impl Drop for Release {
    fn drop(&mut self) {
        let _ = fs::write(self.0.join("release"), b"release");
        let _ = fs::write(self.0.join("leader-release"), b"release");
    }
}

#[derive(Clone, Copy, Debug)]
struct Process {
    pid: u32,
    start: u64,
}
fn process_state(process: Process) -> io::Result<Option<char>> {
    let text = match fs::read_to_string(format!("/proc/{}/stat", process.pid)) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let fields: Vec<_> = text
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("invalid process stat"))?
        .1
        .split_ascii_whitespace()
        .collect();
    let start = fields
        .get(19)
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| io::Error::other("invalid start"))?;
    if start != process.start {
        return Ok(None);
    }
    fields
        .first()
        .and_then(|s| s.chars().next())
        .map(Some)
        .ok_or_else(|| io::Error::other("invalid state"))
}
fn ready_process(path: &Path) -> Process {
    let text = fs::read_to_string(path).expect("ready identity");
    let (pid, start) = text.trim().split_once(':').expect("pid/start marker");
    Process {
        pid: pid.parse().expect("pid"),
        start: start.parse().expect("start"),
    }
}
fn rescue_leader(process: Process) {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match process_state(process) {
            Ok(None) => return,
            Ok(Some(_)) => {}
            Err(error) => {
                eprintln!("rescue identity unknown: {error}");
                std::process::abort();
            }
        }
        let mut status = 0;
        // SAFETY: readiness retained this direct child's original start identity;
        // process_state above rejects replacement PIDs before the owned wait.
        let waited = unsafe { libc::waitpid(process.pid as i32, &mut status, libc::WNOHANG) };
        if waited == process.pid as i32 {
            return;
        }
        if waited < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            eprintln!("rescue direct wait unproven");
            std::process::abort();
        }
        if Instant::now() >= deadline {
            eprintln!("cooperative leader rescue did not settle");
            std::process::abort();
        }
        thread::sleep(Duration::from_millis(2));
    }
}

// A spawned holder is wrapped before readiness IO or channel publication.
// It owns only that helper, never the library's leader or its process group.
struct Holder {
    child: Option<Child>,
    root: PathBuf,
    process: Option<Process>,
    group: i32,
    waited: Option<Arc<AtomicBool>>,
}
impl Holder {
    fn new(child: Child, root: PathBuf) -> Self {
        let mut owner = Self {
            child: Some(child),
            root,
            process: None,
            group: 0,
            waited: None,
        };
        let pid = owner.child.as_ref().expect("owned holder").id();
        let text =
            fs::read_to_string(format!("/proc/{pid}/stat")).expect("original helper identity");
        let fields: Vec<_> = text
            .rsplit_once(") ")
            .expect("stat format")
            .1
            .split_ascii_whitespace()
            .collect();
        owner.process = Some(Process {
            pid,
            start: fields
                .get(19)
                .expect("start")
                .parse()
                .expect("start number"),
        });
        owner.group = fields.get(2).expect("group").parse().expect("group number");
        owner
    }
    fn finish(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let _ = fs::write(self.root.join("release"), b"release");
        let started = Instant::now();
        let deadline = started + Duration::from_secs(1);
        let mut signalled = false;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child = None;
                    if let Some(waited) = &self.waited {
                        waited.store(true, Ordering::Release);
                    }
                    return;
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    eprintln!("holder actual wait failed: {error}");
                    std::process::abort();
                }
            }
            if !signalled && started.elapsed() >= Duration::from_millis(50) {
                if let Some(process) = self.process {
                    let text = fs::read_to_string(format!("/proc/{}/stat", process.pid))
                        .expect("retained helper identity");
                    let fields: Vec<_> = text
                        .rsplit_once(") ")
                        .expect("stat format")
                        .1
                        .split_ascii_whitespace()
                        .collect();
                    let fenced = fields.get(1).and_then(|s| s.parse::<u32>().ok())
                        == Some(std::process::id())
                        && fields.get(2).and_then(|s| s.parse::<i32>().ok()) == Some(self.group)
                        && fields.get(19).and_then(|s| s.parse::<u64>().ok())
                            == Some(process.start);
                    if !fenced {
                        std::process::abort();
                    }
                    // SAFETY: this unreaped direct helper's original PID/start,
                    // parent and group are verified; only the helper is signalled.
                    if unsafe { libc::kill(process.pid as i32, libc::SIGKILL) } != 0 {
                        std::process::abort();
                    }
                }
                signalled = true;
            }
            if Instant::now() >= deadline {
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Drop for Holder {
    fn drop(&mut self) {
        self.finish();
    }
}

struct Boundary {
    leader: io::Result<Option<char>>,
    holder: Option<io::Result<Option<char>>>,
    rescued: bool,
}
struct Rescue {
    done: Option<mpsc::Sender<()>>,
    ready: mpsc::Receiver<(Process, Option<Process>)>,
    root: PathBuf,
    handle: Option<thread::JoinHandle<()>>,
}
impl Rescue {
    fn start(root: &Path, inherited_pipe: bool) -> Self {
        let fixture_root = root.to_owned();
        let root = root.to_owned();
        let (done, stopped) = mpsc::channel();
        let (published, ready) = mpsc::channel();
        let handle = thread::spawn(move || {
            let readiness = Instant::now() + Duration::from_secs(3);
            while !root.join("ready").exists() {
                assert!(
                    Instant::now() < readiness,
                    "original command reached fixture"
                );
                thread::sleep(Duration::from_millis(5));
            }
            let leader = ready_process(&root.join("ready"));
            let _release_on_unwind = Release(root.clone());
            let mut holder = if inherited_pipe {
                let pipe = OpenOptions::new()
                    .write(true)
                    .open(format!("/proc/{}/fd/1", leader.pid))
                    .expect("owned leader pipe");
                // SAFETY: getpgid only queries the ready direct owned leader.
                let group = unsafe { libc::getpgid(leader.pid as i32) };
                let holder_root = root.clone();
                let child = Command::new("/usr/bin/python3")
                    .args(["-c", "import os,pathlib,sys,time; p=pathlib.Path(sys.argv[1]); start=pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19]; marker=p.with_name('holder-ready'); temporary=p.with_name('holder-ready.tmp'); temporary.write_text(str(os.getpid())+':'+start); temporary.replace(marker);\nwhile not p.exists(): time.sleep(.005)", root.join("release").to_str().expect("path")])
                    .process_group(group).stdout(Stdio::from(pipe)).stderr(Stdio::null()).spawn().expect("direct owned pipe holder");
                let child = Holder::new(child, holder_root);
                let ready = Instant::now() + Duration::from_secs(1);
                while !root.join("holder-ready").exists() {
                    assert!(Instant::now() < ready, "pipe holder ready");
                    thread::sleep(Duration::from_millis(5));
                }
                fs::write(root.join("leader-release"), b"release").expect("release leader only");
                Some(child)
            } else {
                None
            };
            let holder_identity = holder.as_ref().and_then(|holder| holder.process);
            published
                .send((leader, holder_identity))
                .expect("publish original identities");
            let _ = stopped.recv_timeout(Duration::from_secs(3));
            fs::write(root.join("release"), b"release").expect("cooperative independent rescue");
            if let Some(child) = holder.as_mut() {
                child.finish();
            }
            rescue_leader(leader);
        });
        Self {
            done: Some(done),
            ready,
            root: fixture_root,
            handle: Some(handle),
        }
    }
    fn boundary(&self) -> Boundary {
        let (leader, holder) = self
            .ready
            .recv_timeout(Duration::from_secs(1))
            .expect("ready before return");
        // Capture before ANY rescue message/release and before the holder's wait.
        Boundary {
            leader: process_state(leader),
            holder: holder.map(process_state),
            rescued: self.root.join("release").exists(),
        }
    }
    fn finish(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.join().expect("rescue worker joined");
        }
    }
}
impl Drop for Rescue {
    fn drop(&mut self) {
        self.finish();
    }
}

fn blocked_case(mode: &str) {
    let fixture = Fixture::new();
    let root = &fixture.0;
    let program = root.join("workflowctl");
    fs::write(
        &program,
        format!(
            r#"#!/usr/bin/python3
import json,os,pathlib,time
root=pathlib.Path({root:?})
start=pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19]
(root/'ready.tmp').write_text(str(os.getpid())+':'+start)
(root/'ready.tmp').replace(root/'ready')
if {mode:?} == 'overflow':
 os.write(1,b'x'*(1024*1024+8192))
if {mode:?} == 'receipt':
 print(json.dumps({{'status':'succeeded','run_root':str(root/'published')}}),flush=True)
release=root/('leader-release' if {mode:?} == 'pipe' else 'release')
while not release.exists(): time.sleep(.005)
"#,
            root = root.to_str().expect("path")
        ),
    )
    .expect("fixture executable");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("executable");
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/01-code-investigation");
    let mut profile: serde_json::Value = serde_json::from_slice(
        &fs::read(example.join("profiles/fake.json")).expect("checked-in profile"),
    )
    .expect("profile");
    profile["loop_policy"] = serde_json::json!({"schema_version":1,"max_model_iterations":4,"max_total_tool_calls":8,"max_tool_calls_per_tool":4,"wall_time_ms":1,"idle_time_ms":1,"tool_time_ms":1,"max_tool_output_bytes":65536});
    let profile_path = root.join("profile.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&profile).expect("profile bytes"),
    )
    .expect("profile write");
    fs::create_dir(root.join("published")).expect("published root");
    fs::write(
        root.join("published/events.jsonl"),
        "{\"node_id\":\"publish\"}\n",
    )
    .expect("published event");
    let workdir = root.join("work");
    fs::create_dir(&workdir).expect("writable metrics directory");
    let mut rescue = Rescue::start(root, mode == "pipe");
    let started = Instant::now();
    let report = LiveConformance::opt_in().run_canonical(
        &program,
        &example,
        &profile_path,
        &workdir,
        Duration::from_millis(1100),
    );
    let elapsed = started.elapsed();
    let boundary = rescue.boundary();
    rescue.finish();
    assert!(
        !boundary.rescued,
        "no independent rescue preceded API-return observation"
    );
    assert!(
        matches!(boundary.leader, Ok(None)),
        "direct leader was not reaped at API return: {:?}",
        boundary.leader
    );
    if let Some(holder) = boundary.holder {
        assert!(
            matches!(holder, Ok(Some('Z' | 'X'))),
            "holder had not terminated before rescue/wait: {holder:?}"
        );
    }
    assert!(
        elapsed < Duration::from_millis(2200),
        "{mode}: independent rescue was needed; elapsed={elapsed:?}"
    );
    assert_eq!(
        report.disposition(),
        ConformanceDisposition::Fail,
        "timed-out output must never classify as success"
    );
    assert_eq!(
        report.metrics().expect("failure metrics").error_category(),
        Some("fail_closed")
    );
    let persisted: serde_json::Value = serde_json::from_slice(
        &fs::read(workdir.join("conformance.json")).expect("persisted failure metrics"),
    )
    .expect("metrics JSON");
    assert_eq!(persisted["error_category"], "fail_closed");
}

#[test]
fn blocked_live_command_is_bounded() {
    blocked_case("blocked");
}
#[test]
fn succeeded_receipt_then_hang_is_not_success() {
    blocked_case("receipt");
}
#[test]
fn exited_leader_with_inherited_pipe_is_bounded() {
    blocked_case("pipe");
}

#[test]
fn disabled_skip_precedes_invalid_budget_and_profile_io() {
    let fixture = Fixture::new();
    let missing = fixture.0.join("missing");
    for budget in [Duration::ZERO, Duration::MAX] {
        let report = LiveConformance::default().run_canonical_with_env(
            &missing,
            &missing,
            &missing,
            &missing,
            &[("IGNORED", "value")],
            budget,
        );
        assert_eq!(report.disposition(), ConformanceDisposition::Skip);
        assert!(report.metrics().is_none());
        assert_eq!(
            fs::read_dir(&fixture.0).expect("fixture unchanged").count(),
            0
        );
    }
}
#[test]
fn admission_preserves_default_and_custom_workflow_limits() {
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/01-code-investigation");
    let mut profile: serde_json::Value =
        serde_json::from_slice(&fs::read(example.join("profiles/fake.json")).expect("profile"))
            .expect("JSON");
    assert_eq!(
        LiveConformance::command_budget(&serde_json::to_vec(&profile).expect("bytes")),
        Some(Duration::from_secs(61))
    );
    profile["loop_policy"] = serde_json::json!({"schema_version":1,"max_model_iterations":4,"max_total_tool_calls":8,"max_tool_calls_per_tool":4,"wall_time_ms":500,"idle_time_ms":100,"tool_time_ms":100,"max_tool_output_bytes":65536});
    assert_eq!(
        LiveConformance::command_budget(&serde_json::to_vec(&profile).expect("bytes")),
        Some(Duration::from_millis(1500))
    );
    assert!(LiveConformance::command_budget(b"invalid").is_none());
    let fixture = Fixture::new();
    let path = fixture.0.join("profile.json");
    fs::write(&path, serde_json::to_vec(&profile).expect("bytes")).expect("write");
    // A profile replaced between a caller's budget calculation and admission
    // must fail before spawn when the executed snapshot requires more wall time.
    profile["loop_policy"]["wall_time_ms"] = 2000.into();
    fs::write(&path, serde_json::to_vec(&profile).expect("bytes")).expect("replace");
    let marker = fixture.0.join("spawned");
    let program = fixture.0.join("workflowctl");
    fs::write(
        &program,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .expect("program");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("executable");
    assert_eq!(
        LiveConformance::opt_in()
            .run_canonical(
                &program,
                &example,
                &path,
                &fixture.0.join("work"),
                Duration::from_millis(1500)
            )
            .disposition(),
        ConformanceDisposition::Fail
    );
    assert!(
        !marker.exists(),
        "changed profile was rejected before spawn"
    );
}

#[test]
fn collection_output_limit_settles_child_before_return() {
    blocked_case("overflow");
}

#[test]
fn holder_setup_failure_unwind_actually_reaps_owned_helper() {
    let fixture = Fixture::new();
    let root = fixture.0.clone();
    let child = Command::new("/usr/bin/python3")
        .args(["-c", "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]);\nwhile not p.exists(): time.sleep(.005)", root.join("release").to_str().expect("path")])
        .process_group(0).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("owned helper");
    let mut holder = Holder::new(child, root);
    let process = holder.process.expect("captured before setup failure");
    let waited = Arc::new(AtomicBool::new(false));
    holder.waited = Some(Arc::clone(&waited));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _holder = holder;
        panic!("controlled holder readiness/setup failure");
    }));
    assert!(result.is_err());
    assert!(
        waited.load(Ordering::Acquire),
        "RAII performed actual helper wait"
    );
    assert!(
        matches!(process_state(process), Ok(None)),
        "original helper absent before fixture exit"
    );
}
