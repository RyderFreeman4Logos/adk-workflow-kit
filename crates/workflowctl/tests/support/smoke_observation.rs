//! Finite opt-in smoke diagnostics; never changes workload decisions or exposes payload.
use serde_json::Value;
use std::{fs, time::Duration};

// Temporary #374 observation; never changes the original timeout decision.
pub(super) struct SmokeObservation {
    socket: std::os::unix::net::UnixDatagram,
    header: std::cell::Cell<[u64; 14]>,
}

impl SmokeObservation {
    pub(super) fn connect(enabled: bool) -> Option<Self> {
        if !enabled
            || std::env::var("WORKFLOWCTL_SMOKE_OBSERVE_374_R2").as_deref()
                != Ok("d757362aab5a5fcd8b8fa1b9f1c2e3902b2215b7:v2")
        {
            return None;
        }
        let socket = std::os::unix::net::UnixDatagram::unbound().ok()?;
        socket.set_nonblocking(true).ok()?;
        socket
            .connect("/home/obj/tmp/adk-takeover-20261012/374-smoke-observe-r2.sock")
            .ok()?;
        let mut header = [0; 14];
        header[0] = u64::from_le_bytes(*b"SMOKE374");
        header[1] = 1;
        header[7] = u64::from(std::process::id());
        Some(Self {
            socket,
            header: std::cell::Cell::new(header),
        })
    }

    pub(super) fn monotonic_ns() -> u64 {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: time is a writable timespec; CLOCK_MONOTONIC has no side effects.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
            return 0;
        }
        u64::try_from(time.tv_sec)
            .unwrap_or(0)
            .saturating_mul(1_000_000_000)
            .saturating_add(u64::try_from(time.tv_nsec).unwrap_or(0))
    }

    pub(super) fn arm(&self, child: u32, lower: u64, upper: u64, timeout: Duration) {
        let mut header = self.header.get();
        let timeout_ns = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
        header[5] = if lower == 0 || upper < lower {
            0
        } else {
            lower.saturating_add(timeout_ns)
        };
        header[6] = upper.saturating_add(timeout_ns);
        header[8] = u64::from(child);
        header[9] = fs::read_to_string(format!("/proc/{child}/stat"))
            .ok()
            .and_then(|text| text.rsplit_once(") ").map(|(_, tail)| tail.to_owned()))
            .and_then(|tail| tail.split_whitespace().nth(19)?.parse().ok())
            .unwrap_or(0);
        self.header.set(header);
        self.emit(1, [0, 0, 0]);
    }

    pub(super) fn emit(&self, event: u64, values: [u64; 3]) {
        let mut header = self.header.get();
        header[2] = event;
        header[4] = Self::monotonic_ns();
        header[10..13].copy_from_slice(&values);
        let mut bytes = [0; 112];
        for (field, chunk) in header.iter().zip(bytes.as_chunks_mut::<8>().0) {
            chunk.copy_from_slice(&field.to_le_bytes());
        }
        if self.socket.send(&bytes).ok() != Some(bytes.len()) {
            header[13] = header[13].saturating_add(1);
        }
        header[3] = header[3].saturating_add(1);
        self.header.set(header);
    }

    pub(super) fn pre_kill(&self, child: u32) {
        // SAFETY: zero is valid initialization for the waitid output buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: child is still the owned unreaped direct child; WNOWAIT never reaps.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        let state = if result != 0 {
            2
        } else {
            // SAFETY: waitid initialized info on success.
            u64::from(unsafe { info.si_pid() } == child as libc::pid_t)
        };
        self.emit(2, [state, 0, 0]);
    }
}

pub(super) fn last_observed_output(bytes: &[u8]) -> u64 {
    let mut observed = 0;
    for line in bytes.split(|byte| *byte == b'\n') {
        if line == b"valid" {
            if observed != 0 {
                return 0;
            }
            observed = 1;
            continue;
        }
        if line.first() != Some(&b'{') {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            return 0;
        };
        let run = [
            "run_id",
            "workflow_id",
            "status",
            "artifact_id",
            "run_root",
            "plan_hash",
            "resume_identity",
        ]
        .iter()
        .all(|field| value.get(field).is_some_and(Value::is_string));
        observed = match (observed, value.get("resume_count").and_then(Value::as_u64)) {
            (1 | 2, Some(0)) if run => observed + 1,
            (3, Some(1)) if run => 4,
            (4, None)
                if value.get("disposition").and_then(Value::as_str) == Some("replay_run")
                    && value
                        .get("fixture_count")
                        .and_then(Value::as_u64)
                        .is_some_and(|n| n > 0)
                    && value.get("payload_len").is_some_and(Value::is_u64)
                    && value.get("run_id").is_none() =>
            {
                5
            }
            _ => return 0,
        };
    }
    observed
}

#[test]
fn structural_output_marker_requires_ordered_closed_stages() {
    let run = serde_json::json!({
        "run_id":"PRIVATE_MARKER_CONTROL", "workflow_id":"fixed", "status":"fixed",
        "artifact_id":"fixed", "run_root":"fixed", "plan_hash":"fixed",
        "resume_identity":"fixed", "resume_count":0
    });
    let mut resumed = run.clone();
    resumed["resume_count"] = serde_json::json!(1);
    let replay =
        serde_json::json!({"disposition":"replay_run", "fixture_count":1, "payload_len":0});
    let records = [
        "valid".to_owned(),
        run.to_string(),
        run.to_string(),
        resumed.to_string(),
        replay.to_string(),
    ];
    for count in 1..=records.len() {
        let bytes = records[..count].join("\n");
        assert_eq!(last_observed_output(bytes.as_bytes()), count as u64);
    }
    let mut wrong_type = run.clone();
    wrong_type["run_id"] = serde_json::json!(1);
    for bytes in [
        "valid\nvalid\n".to_owned(),
        "valid\n{malformed\n".to_owned(),
        run.to_string(),
        format!("valid\n{resumed}\n"),
        format!("valid\n{replay}\n"),
        format!("valid\n{wrong_type}\n"),
        format!("{}\n{run}\n", records.join("\n")),
    ] {
        assert_eq!(last_observed_output(bytes.as_bytes()), 0);
    }
    // Non-JSON graph output does not claim a structured stage or expose content.
    assert_eq!(last_observed_output(b"digraph fixed {\n}\nvalid\n"), 1);
    assert_eq!(last_observed_output(b"PRIVATE_MARKER_CONTROL"), 0);
}
