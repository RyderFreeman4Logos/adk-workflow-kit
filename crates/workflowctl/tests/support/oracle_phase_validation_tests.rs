use super::*;

fn frame(role: u8, stage: u8, pid: u32, sequence: u32, value: u32) -> [u8; 24] {
    let mut f = [0; 24];
    f[0] = 1;
    f[1] = role;
    f[2] = stage;
    f[4..8].copy_from_slice(&pid.to_le_bytes());
    f[8..12].copy_from_slice(&sequence.to_le_bytes());
    f[12..16].copy_from_slice(&value.to_le_bytes());
    f[16..24].copy_from_slice(&1_u64.to_le_bytes());
    f
}
fn normal() -> Received {
    let parent = std::process::id();
    let mut out = Received::default();
    let mut seq = 0;
    for role in [1, 3] {
        for (stage, value) in [(2, 0), (4, 0x365), (90, 4), (91, 4), (3, 0)] {
            out.push(frame(role, stage, parent, seq, value));
            seq += 1;
        }
    }
    out.push(frame(1, 35, parent, seq, 0));
    for (seq, (stage, value)) in [
        (2, 0),
        (4, 0x365),
        (90, 4),
        (91, 4),
        (52, 0),
        (3, 0),
        (35, 0),
    ]
    .into_iter()
    .enumerate()
    {
        out.push(frame(2, stage, parent + 1, seq as u32, value));
    }
    out
}
fn report(received: Received) -> Value {
    summarize(
        received,
        Some(OracleChildIdentity {
            pid: std::process::id() + 1,
            starttime: 1,
        }),
        true,
        true,
    )
}
#[test]
fn bounded_records_identity_loss_and_publication() {
    assert_eq!(report(normal())["capture_qualified"], true);
    let mut r = normal();
    r.frames.pop();
    assert_eq!(report(r)["child_tail"], "UNKNOWN");
    let mut r = normal();
    r.frames.last_mut().unwrap()[12..16].copy_from_slice(&1_u32.to_le_bytes());
    assert_eq!(report(r)["child_tail"], "UNKNOWN");
    let mut r = normal();
    r.frames.push(r.frames[0]);
    assert_eq!(report(r)["duplicate"], 1);
    let mut r = normal();
    r.frames.remove(2);
    assert_eq!(report(r)["missing_before_max"], 1);
    for bad in [
        frame(4, 2, std::process::id(), 40, 0),
        frame(2, 2, std::process::id() + 2, 40, 0),
        frame(1, 255, std::process::id(), 40, 0),
        frame(1, 2, std::process::id(), 4096, 0),
    ] {
        let mut r = normal();
        r.push(bad);
        let v = report(r);
        assert_eq!(v["invalid"], 1);
        assert_eq!(v["capture_qualified"], false);
    }
    for index in [0, 3] {
        let mut r = normal();
        r.frames[0][index] = 99;
        assert_eq!(report(r)["invalid"], 1);
    }
    let mut r = Received::default();
    for _ in 0..=CAP {
        r.push([0; 24]);
    }
    assert_eq!(r.frames.len(), CAP);
    assert_eq!(r.overflow, 1);
    let pid = std::process::id();
    // SAFETY: this read-only process identity query has no pointer argument.
    let uid = unsafe { libc::geteuid() };
    assert!(credential_matches(
        Some(libc::ucred {
            pid: pid as i32,
            uid,
            gid: 0
        }),
        pid,
        uid
    ));
    assert!(!credential_matches(None, pid, uid));
    assert!(!credential_matches(
        Some(libc::ucred {
            pid: pid as i32,
            uid: uid.wrapping_add(1),
            gid: 0
        }),
        pid,
        uid
    ));
    assert!(!credential_matches(
        Some(libc::ucred {
            pid: pid as i32 + 1,
            uid,
            gid: 0
        }),
        pid,
        uid
    ));
    let (sender, receiver) = UnixDatagram::pair().unwrap();
    sender.set_nonblocking(true).unwrap();
    let sender = Sender {
        socket: Arc::new(sender),
        sequence: Arc::new(AtomicU32::new(0)),
        failed: Arc::new(AtomicU32::new(0)),
        identity: Arc::new(std::sync::Mutex::new(None)),
        role: 1,
        reaped: Arc::new(AtomicBool::new(false)),
    };
    let starttime = match owned_child_stat(pid) {
        OwnedChildStat::Ready { starttime, .. } => starttime,
        _ => panic!("own PID identity unavailable"),
    };
    sender.child(OracleChildIdentity { pid, starttime });
    assert!(
        sender.identity.lock().unwrap().is_none(),
        "the harness itself is not its child"
    );
    drop(receiver);
    sender.mark(2, 0);
    assert_eq!(sender.failed.load(Ordering::Relaxed), 1);
    let mut r = normal();
    r.frames.insert(0, frame(2, 69, pid + 1, 200, 4));
    assert_eq!(report(r)["pair_errors"], 1);
    let root = temp_root("phase-publication");
    let path = root.join("sink");
    let value = json!({"rows":[]});
    publish(path.as_os_str(), &value);
    assert_eq!(
        fs::read(&path).unwrap(),
        serde_json::to_vec(&value).unwrap()
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    publish(path.as_os_str(), &json!({"overwrite":true}));
    assert_eq!(
        fs::read(&path).unwrap(),
        serde_json::to_vec(&value).unwrap()
    );
    let link = root.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    publish(link.as_os_str(), &json!(null));
    assert!(link.is_symlink());
    let fifo = root.join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: owned, NUL-terminated test path; no file descriptor is assumed.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let start = Instant::now();
    publish(fifo.as_os_str(), &value);
    assert!(start.elapsed() < Duration::from_secs(1));
}
