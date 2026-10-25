//! Bounded pipe capture and owned process-group supervision for Bubblewrap.
use super::BubblewrapError;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    process::ExitStatus,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(super) struct OutputBudget {
    remaining: AtomicUsize,
    exceeded: AtomicBool,
}

impl OutputBudget {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(limit),
            exceeded: AtomicBool::new(false),
        }
    }

    fn retain(&self, bytes: usize) -> usize {
        let previous = self
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                Some(remaining.saturating_sub(bytes))
            })
            .expect("output budget update is infallible");
        if previous < bytes {
            self.exceeded.store(true, Ordering::Release);
        }
        previous.min(bytes)
    }

    pub(super) fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Acquire)
    }
}

pub(super) fn spawn_pipe_reader(
    mut pipe: impl Read + Send + 'static,
    budget: Option<Arc<OutputBudget>>,
) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 8_192];
        loop {
            let read = pipe.read(&mut buffer)?;
            if read == 0 {
                return Ok(bytes);
            }
            let retained = budget.as_ref().map_or(read, |budget| budget.retain(read));
            bytes.extend_from_slice(&buffer[..retained]);
        }
    })
}

pub(super) fn spawn_stdin_writer(
    mut pipe: impl Write + Send + 'static,
    bytes: Vec<u8>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = pipe.write_all(&bytes);
    })
}

pub(super) fn join_stdin_writer(writer: Option<JoinHandle<()>>) {
    if let Some(writer) = writer {
        let _ = writer.join();
    }
}

pub(super) fn join_pipe_reader(
    reader: JoinHandle<io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, BubblewrapError> {
    let result = reader.join().map_err(|_| BubblewrapError::Run {
        source: io::Error::other("bubblewrap output reader panicked"),
    })?;
    result.map_err(|source| BubblewrapError::Run { source })
}

const D_STATE_REAP_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_REAP_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) fn cleanup_deadline() -> Instant {
    Instant::now() + CLEANUP_REAP_TIMEOUT
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReapOutcome {
    Reaped(ExitStatus),
    Unreaped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitProgress {
    Reaped(ExitStatus),
    Poll,
    Kill,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReapProgress {
    Reaped(ExitStatus),
    Poll,
    Kill,
    Unreaped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChildStat {
    Ready {
        state: char,
        ppid: u32,
        pgid: u32,
        starttime: u64,
    },
    Other,
}

fn child_stat(pid: u32) -> ChildStat {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .map_or(ChildStat::Other, |contents| parse_child_stat(&contents))
}

fn parse_child_stat(contents: &str) -> ChildStat {
    let Some(fields) = contents.rsplit_once(") ").map(|(_, fields)| fields) else {
        return ChildStat::Other;
    };
    let mut fields = fields.split_whitespace();
    let Some(state) = fields.next().and_then(|field| {
        let mut chars = field.chars();
        match (chars.next(), chars.next()) {
            (Some(state), None) if state.is_ascii_alphabetic() => Some(state),
            _ => None,
        }
    }) else {
        return ChildStat::Other;
    };
    let Some(ppid) = fields.next().and_then(|field| field.parse().ok()) else {
        return ChildStat::Other;
    };
    let Some(pgid) = fields.next().and_then(|field| field.parse().ok()) else {
        return ChildStat::Other;
    };
    let Some(starttime) = fields.nth(16).and_then(|field| field.parse().ok()) else {
        return ChildStat::Other;
    };
    ChildStat::Ready {
        state,
        ppid,
        pgid,
        starttime,
    }
}

pub(super) fn child_starttime(pid: u32) -> Option<u64> {
    match child_stat(pid) {
        ChildStat::Ready { starttime, .. } => Some(starttime),
        ChildStat::Other => None,
    }
}

fn matching_uninterruptible_io_stat(stat: ChildStat, recorded_starttime: Option<u64>) -> bool {
    matches!(
        (stat, recorded_starttime),
        (
            ChildStat::Ready {
                state: 'D',
                starttime,
                ..
            },
            Some(recorded)
        ) if starttime == recorded
    )
}

fn matching_uninterruptible_io(pid: u32, recorded_starttime: Option<u64>) -> bool {
    matching_uninterruptible_io_stat(child_stat(pid), recorded_starttime)
}

fn matching_group_uninterruptible_io_stats(
    process_group: u32,
    recorded_starttime: Option<u64>,
    stats: impl IntoIterator<Item = (u32, ChildStat)>,
) -> bool {
    let stats = stats.into_iter().collect::<Vec<_>>();
    let ppid_by_pid = stats
        .iter()
        .filter_map(|(pid, stat)| match stat {
            ChildStat::Ready { ppid, .. } => Some((*pid, *ppid)),
            ChildStat::Other => None,
        })
        .collect::<BTreeMap<_, _>>();
    stats.iter().any(|(pid, stat)| match stat {
        ChildStat::Ready {
            state: 'D',
            pgid,
            starttime,
            ..
        } if recorded_starttime.is_none_or(|recorded| *starttime >= recorded) => {
            *pid == process_group
                || *pgid == process_group
                || owned_descendant(*pid, process_group, &ppid_by_pid)
        }
        _ => false,
    })
}

fn owned_descendant(mut pid: u32, process_group: u32, ppid_by_pid: &BTreeMap<u32, u32>) -> bool {
    for _ in 0..32 {
        let Some(&ppid) = ppid_by_pid.get(&pid) else {
            return false;
        };
        if ppid == process_group {
            return true;
        }
        if ppid <= 1 || ppid == pid {
            return false;
        }
        pid = ppid;
    }
    false
}

pub(super) fn matching_group_uninterruptible_io(
    process_group: u32,
    recorded_starttime: Option<u64>,
) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return matching_uninterruptible_io(process_group, recorded_starttime);
    };
    matching_group_uninterruptible_io_stats(
        process_group,
        recorded_starttime,
        entries.filter_map(|entry| {
            let pid = entry.ok()?.file_name().to_str()?.parse().ok()?;
            Some((pid, child_stat(pid)))
        }),
    )
}

fn d_state_grace(wall_time: Option<Duration>) -> Duration {
    match wall_time {
        Some(limit) if limit < D_STATE_REAP_TIMEOUT => limit.max(Duration::from_millis(10)),
        _ => D_STATE_REAP_TIMEOUT,
    }
}

pub(super) fn wait_progress(
    reaped: Option<ExitStatus>,
    matching_d: bool,
    now: Instant,
    wall_deadline: Option<Instant>,
    d_state_deadline: &mut Option<Instant>,
    output_exceeded: bool,
    wall_time: Option<Duration>,
) -> WaitProgress {
    if let Some(status) = reaped {
        return WaitProgress::Reaped(status);
    }
    let kill_requested = output_exceeded || wall_deadline.is_some_and(|limit| now >= limit);
    if !kill_requested {
        return WaitProgress::Poll;
    }
    if matching_d || d_state_deadline.is_some() {
        let deadline = *d_state_deadline.get_or_insert(now + d_state_grace(wall_time));
        if now < deadline {
            return WaitProgress::Poll;
        }
        return WaitProgress::Kill;
    }
    WaitProgress::Kill
}

fn reap_progress(
    reaped: Option<ExitStatus>,
    matching_d: bool,
    now: Instant,
    cleanup_deadline: Instant,
    d_state_deadline: &mut Option<Instant>,
    kill_sent: bool,
    wall_time: Option<Duration>,
) -> ReapProgress {
    if let Some(status) = reaped {
        return ReapProgress::Reaped(status);
    }
    if matching_d || d_state_deadline.is_some() {
        let deadline = *d_state_deadline.get_or_insert(now + d_state_grace(wall_time));
        if now < deadline {
            return ReapProgress::Poll;
        }
        if !kill_sent {
            return ReapProgress::Kill;
        }
        return ReapProgress::Unreaped;
    }
    if !kill_sent {
        return ReapProgress::Kill;
    }
    if now >= cleanup_deadline {
        ReapProgress::Unreaped
    } else {
        ReapProgress::Poll
    }
}

fn conventional_exit_code(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
}

pub(super) fn receipt_exit_code(outcome: ReapOutcome) -> Option<i32> {
    match outcome {
        ReapOutcome::Reaped(status) => conventional_exit_code(status),
        ReapOutcome::Unreaped => None,
    }
}

pub(super) fn terminate_and_reap(
    child: &mut std::process::Child,
    process_group: u32,
    recorded_starttime: Option<u64>,
    wall_time: Option<Duration>,
    cleanup_deadline: Instant,
) -> ReapOutcome {
    let mut d_state_deadline = None;
    let mut kill_sent = false;
    loop {
        let reaped = child.try_wait().unwrap_or_default();
        let matching_d = matching_group_uninterruptible_io(process_group, recorded_starttime);
        match reap_progress(
            reaped,
            matching_d,
            Instant::now(),
            cleanup_deadline,
            &mut d_state_deadline,
            kill_sent,
            wall_time,
        ) {
            ReapProgress::Reaped(status) => return ReapOutcome::Reaped(status),
            ReapProgress::Unreaped => return ReapOutcome::Unreaped,
            ReapProgress::Kill => {
                let _ = kill_process_group(process_group);
                kill_sent = true;
            }
            ReapProgress::Poll => thread::sleep(Duration::from_millis(10)),
        }
    }
}

pub(super) fn kill_process_group(process_group: u32) -> io::Result<()> {
    let process_group = i32::try_from(process_group).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "process group ID is too large")
    })?;

    unsafe extern "C" {
        fn killpg(process_group: i32, signal: i32) -> i32;
    }

    // SAFETY: `process_group` is the PID of the child created with
    // `process_group(0)`, so the signal is restricted to the group owned by
    // this executor. `SIGKILL` is async-signal-safe and has no Rust callback.
    let result = unsafe { killpg(process_group, 9) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn timed_out_status() -> ExitStatus {
    // A synthetic non-zero exit status when the wall ceiling is hit.
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(137) // 128 + SIGKILL
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn matching_d_state_after_sigkill_maps_to_exit_137() {
        let starttime = 114_922_562;
        assert!(matching_uninterruptible_io_stat(
            ChildStat::Ready {
                state: 'D',
                ppid: 1,
                pgid: 7,
                starttime,
            },
            Some(starttime),
        ));
        assert_eq!(
            receipt_exit_code(ReapOutcome::Reaped(ExitStatus::from_raw(9))),
            Some(137)
        );
    }

    #[test]
    fn unreaped_child_after_hard_timeout_is_none() {
        assert_eq!(receipt_exit_code(ReapOutcome::Unreaped), None);
    }

    #[test]
    fn runnable_matching_pid_is_not_uninterruptible_io() {
        assert!(!matching_uninterruptible_io_stat(
            ChildStat::Ready {
                state: 'R',
                ppid: 1,
                pgid: 1,
                starttime: 1,
            },
            Some(1),
        ));
    }

    #[test]
    fn parse_stat_reads_state_ppid_pgid_and_starttime() {
        let stat = "42 (python3) D 7 42 42 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 114922565 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(
            parse_child_stat(stat),
            ChildStat::Ready {
                state: 'D',
                ppid: 7,
                pgid: 42,
                starttime: 114_922_565,
            }
        );
    }

    #[test]
    fn matching_group_d_state_during_script_fsync_is_owned() {
        let starttime = 114_922_562;
        assert!(matching_group_uninterruptible_io_stats(
            7,
            Some(starttime),
            [
                (
                    7,
                    ChildStat::Ready {
                        state: 'S',
                        ppid: 1,
                        pgid: 7,
                        starttime,
                    }
                ),
                (
                    42,
                    ChildStat::Ready {
                        state: 'D',
                        ppid: 7,
                        pgid: 42,
                        starttime: starttime + 3,
                    }
                ),
            ],
        ));
        assert!(!matching_group_uninterruptible_io_stats(
            7,
            Some(starttime),
            [
                (
                    7,
                    ChildStat::Ready {
                        state: 'S',
                        ppid: 1,
                        pgid: 7,
                        starttime,
                    }
                ),
                (
                    99,
                    ChildStat::Ready {
                        state: 'D',
                        ppid: 1,
                        pgid: 99,
                        starttime: starttime + 3,
                    }
                ),
            ],
        ));
    }

    #[test]
    fn matching_d_state_does_not_timeout_kill_before_hard_bound() {
        let now = Instant::now();
        let wall_deadline = Some(now);
        let mut d_state_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(
                None,
                true,
                now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                true,
                now + D_STATE_REAP_TIMEOUT,
                wall_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            WaitProgress::Kill
        );
        let mut no_match_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(
                None,
                false,
                now,
                wall_deadline,
                &mut no_match_deadline,
                false,
                None,
            ),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                false,
                now + D_STATE_REAP_TIMEOUT,
                wall_deadline,
                &mut no_match_deadline,
                false,
                None,
            ),
            WaitProgress::Kill
        );
        let mut never_d = None;
        assert_eq!(
            wait_progress(None, false, now, wall_deadline, &mut never_d, false, None,),
            WaitProgress::Kill
        );
    }

    #[test]
    fn matching_d_state_does_not_output_timeout_kill_before_hard_bound() {
        let now = Instant::now();
        let mut d_state_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(None, true, now, None, &mut d_state_deadline, true, None),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                true,
                now + D_STATE_REAP_TIMEOUT,
                None,
                &mut d_state_deadline,
                true,
                None,
            ),
            WaitProgress::Kill
        );
        let mut no_match_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(None, false, now, None, &mut no_match_deadline, true, None),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                false,
                now + D_STATE_REAP_TIMEOUT,
                None,
                &mut no_match_deadline,
                true,
                None,
            ),
            WaitProgress::Kill
        );
        let mut never_d = None;
        assert_eq!(
            wait_progress(None, false, now, None, &mut never_d, true, None),
            WaitProgress::Kill
        );
    }

    #[test]
    fn matching_d_state_self_reap_is_not_killed() {
        let now = Instant::now();
        let status = ExitStatus::from_raw(9);
        let mut d_state_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(
                Some(status),
                true,
                now,
                Some(now),
                &mut d_state_deadline,
                true,
                None,
            ),
            WaitProgress::Reaped(status)
        );
    }

    #[test]
    fn production_order_wall_after_30s_matching_d_does_not_kill_immediately() {
        let wait_started = Instant::now();
        let wall_deadline = Some(wait_started + Duration::from_secs(60));
        let mut d_state_deadline = None;
        let wall_now = wait_started + Duration::from_secs(60);
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(wall_now + D_STATE_REAP_TIMEOUT));
        let later = wall_now + Duration::from_secs(10);
        assert_eq!(
            wait_progress(
                None,
                true,
                later,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(wall_now + D_STATE_REAP_TIMEOUT));
    }

    #[test]
    fn production_order_output_after_30s_matching_d_does_not_kill_immediately() {
        let wait_started = Instant::now();
        let mut d_state_deadline = None;
        let output_now = wait_started + Duration::from_secs(45);
        assert_eq!(
            wait_progress(
                None,
                true,
                output_now,
                None,
                &mut d_state_deadline,
                true,
                None
            ),
            WaitProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(output_now + D_STATE_REAP_TIMEOUT));
        let later = output_now + Duration::from_secs(10);
        assert_eq!(
            wait_progress(None, true, later, None, &mut d_state_deadline, true, None),
            WaitProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(output_now + D_STATE_REAP_TIMEOUT));
    }

    #[test]
    fn production_order_matching_d_self_reaps_before_grace() {
        let wait_started = Instant::now();
        let wall_deadline = Some(wait_started + Duration::from_secs(60));
        let mut d_state_deadline = None;
        let wall_now = wait_started + Duration::from_secs(60);
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Poll
        );
        let status = ExitStatus::from_raw(0);
        assert_eq!(
            wait_progress(
                Some(status),
                true,
                wall_now + Duration::from_secs(1),
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Reaped(status)
        );
    }

    #[test]
    fn production_order_matching_d_kills_after_grace() {
        let wait_started = Instant::now();
        let wall_deadline = Some(wait_started + Duration::from_secs(60));
        let mut d_state_deadline = None;
        let wall_now = wait_started + Duration::from_secs(60);
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now + D_STATE_REAP_TIMEOUT,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Kill
        );
        let mut output_deadline = None;
        let output_now = wait_started + Duration::from_secs(45);
        assert_eq!(
            wait_progress(
                None,
                true,
                output_now,
                None,
                &mut output_deadline,
                true,
                None
            ),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                true,
                output_now + D_STATE_REAP_TIMEOUT,
                None,
                &mut output_deadline,
                true,
                None,
            ),
            WaitProgress::Kill
        );
    }

    #[test]
    fn short_expired_wall_matching_d_starts_grace_without_full_30s() {
        let wait_started = Instant::now();
        let wall_deadline = Some(wait_started + Duration::from_millis(500));
        let mut d_state_deadline = None;
        let wall_now = wait_started + Duration::from_millis(500);
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_millis(500)),
            ),
            WaitProgress::Poll
        );
        let deadline = d_state_deadline.expect("matching-D grace starts on first observation");
        let grace = deadline.saturating_duration_since(wall_now);
        assert!(
            grace < Duration::from_secs(5),
            "short wall must not stack a 30s D-state grace; grace={grace:?}"
        );
        assert!(grace > Duration::ZERO, "grace must be in the future");
        assert_eq!(
            wait_progress(
                None,
                true,
                deadline,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_millis(500)),
            ),
            WaitProgress::Kill
        );
    }

    #[test]
    fn terminate_and_reap_matching_d_does_not_sigkill_before_grace() {
        let now = Instant::now();
        let cleanup_deadline = now + CLEANUP_REAP_TIMEOUT;
        let mut d_state_deadline = None;
        assert_eq!(
            reap_progress(
                None,
                true,
                now,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(now + D_STATE_REAP_TIMEOUT));
        assert_eq!(
            reap_progress(
                None,
                false,
                now + Duration::from_secs(1),
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(now + D_STATE_REAP_TIMEOUT));
    }

    #[test]
    fn terminate_and_reap_matching_d_sigkills_only_after_observed_grace() {
        let now = Instant::now();
        let cleanup_deadline = now + CLEANUP_REAP_TIMEOUT;
        let mut d_state_deadline = None;
        assert_eq!(
            reap_progress(
                None,
                true,
                now,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Poll
        );
        let deadline = d_state_deadline.expect("matching-D grace starts on first observation");
        assert_eq!(
            reap_progress(
                None,
                true,
                deadline,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Kill
        );
        let mut short = None;
        let short_now = Instant::now();
        assert_eq!(
            reap_progress(
                None,
                true,
                short_now,
                short_now + CLEANUP_REAP_TIMEOUT,
                &mut short,
                false,
                Some(Duration::from_millis(500)),
            ),
            ReapProgress::Poll
        );
        let short_deadline = short.expect("short wall grace starts on first observation");
        let grace = short_deadline.saturating_duration_since(short_now);
        assert!(
            grace < Duration::from_secs(5),
            "short wall must not stack a 30s D-state grace; grace={grace:?}"
        );
    }

    #[test]
    fn terminate_and_reap_runnable_child_still_sigkills_immediately() {
        let now = Instant::now();
        let cleanup_deadline = now + CLEANUP_REAP_TIMEOUT;
        let mut d_state_deadline = None;
        assert_eq!(
            reap_progress(
                None,
                false,
                now,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Kill
        );
        assert_eq!(d_state_deadline, None);
        let status = ExitStatus::from_raw(9);
        assert_eq!(
            reap_progress(
                Some(status),
                true,
                now,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Reaped(status)
        );
    }
}
