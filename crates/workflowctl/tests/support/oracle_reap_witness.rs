// Private, content-free evidence for the oracle cleanup test harness.
use super::{OracleWait, OwnedChildStat, matching_uninterruptible_io};
use std::{io::Write, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Deadline {
    Ordinary,
    DState,
    ForcedFixture,
}

pub(super) fn selected_deadline(
    kill_ok: bool,
    wait: OracleWait,
    terminal: &OwnedChildStat,
    recorded: Option<u64>,
    now: Instant,
    d_state_deadline: Instant,
) -> Deadline {
    if wait == OracleWait::StillAlive
        && matching_uninterruptible_io(kill_ok, terminal, recorded)
        && now < d_state_deadline
    {
        Deadline::DState
    } else {
        Deadline::Ordinary
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Sample {
    wait: OracleWait,
    state: &'static str,
    identity_match: bool,
    deadline: Deadline,
    forced_fixture: bool,
}

#[derive(Clone, Copy)]
struct Row {
    elapsed_us: u128,
    sample: Sample,
}

pub(super) struct Witness {
    started: Instant,
    rows: [Option<Row>; 8],
    len: usize,
}

impl Witness {
    pub(super) fn new(started: Instant) -> Self {
        Self {
            started,
            rows: [None; 8],
            len: 0,
        }
    }

    pub(super) fn record(
        &mut self,
        now: Instant,
        wait: OracleWait,
        terminal: &OwnedChildStat,
        recorded: Option<u64>,
        deadline: Deadline,
        forced_fixture: bool,
    ) {
        let state = match terminal {
            OwnedChildStat::Ready { state: 'D', .. } => "d",
            OwnedChildStat::Ready { state: 'R', .. } => "r",
            OwnedChildStat::Ready { .. } => "other",
            OwnedChildStat::Errno(errno) if *errno == libc::ENOENT || *errno == libc::ESRCH => {
                "missing"
            }
            OwnedChildStat::Errno(_) => "error",
            OwnedChildStat::Unavailable => "unavailable",
        };
        let sample = Sample {
            wait,
            state,
            identity_match: matches!(terminal, OwnedChildStat::Ready { starttime, .. } if Some(*starttime) == recorded),
            deadline,
            forced_fixture,
        };
        let row = Row {
            elapsed_us: now.saturating_duration_since(self.started).as_micros(),
            sample,
        };
        // Keep the latest observation of each transition, including the abort check.
        if self.len > 0 && self.rows[self.len - 1].is_some_and(|prior| prior.sample == sample) {
            self.rows[self.len - 1] = Some(row);
            return;
        }
        if self.len == self.rows.len() {
            self.rows.rotate_left(1);
            self.len -= 1;
        }
        self.rows[self.len] = Some(row);
        self.len += 1;
    }

    pub(super) fn emit(&self, output: &mut impl Write) {
        for row in self.rows[..self.len].iter().flatten() {
            let sample = row.sample;
            let wait = match sample.wait {
                OracleWait::Reaped => "reaped",
                OracleWait::StillAlive => "still-alive",
                OracleWait::Error => "error",
            };
            let deadline = match sample.deadline {
                Deadline::Ordinary => "ordinary",
                Deadline::DState => "d-state",
                Deadline::ForcedFixture => "forced-fixture",
            };
            let _ = writeln!(
                output,
                "oracle reap transition elapsed_us={} wait={wait} state={} identity_match={} deadline={deadline} forced_fixture={}",
                row.elapsed_us, sample.state, sample.identity_match, sample.forced_fixture
            );
        }
    }
}

pub(super) fn assert_abort_witness(stderr: &str) {
    let rows: Vec<_> = stderr
        .lines()
        .filter(|line| line.starts_with("oracle reap transition "))
        .collect();
    assert!(
        !rows.is_empty(),
        "pre-abort reap transition witness missing"
    );
    assert!(rows.len() <= 8);
    let mut previous = 0;
    for row in rows {
        assert!(row.len() <= 192);
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 9);
        assert_eq!(&fields[..3], &["oracle", "reap", "transition"]);
        let elapsed: u128 = fields[3]
            .strip_prefix("elapsed_us=")
            .expect("elapsed field")
            .parse()
            .expect("numeric elapsed");
        assert!(elapsed >= previous);
        previous = elapsed;
        assert!(matches!(
            fields[4],
            "wait=reaped" | "wait=still-alive" | "wait=error"
        ));
        assert!(matches!(
            fields[5],
            "state=d"
                | "state=r"
                | "state=other"
                | "state=missing"
                | "state=error"
                | "state=unavailable"
        ));
        assert!(matches!(
            fields[6],
            "identity_match=true" | "identity_match=false"
        ));
        assert_eq!(fields[7], "deadline=forced-fixture");
        assert_eq!(fields[8], "forced_fixture=true");
    }
    assert!(
        stderr.find("oracle reap transition ").expect("transition")
            < stderr
                .find("oracle child terminal reap not proven; aborting")
                .expect("abort")
    );
}

#[test]
fn transitions_distinguish_d_to_r_fallback_and_remain_bounded() {
    use super::{OracleReapProgress, oracle_reap_progress};
    use std::time::Duration;

    let started = Instant::now();
    let cleanup_deadline = started;
    let d_deadline = started + Duration::from_secs(30);
    let mut witness = Witness::new(started);
    for (offset, state, expected, deadline) in [
        (1, 'D', OracleReapProgress::Wait, Deadline::DState),
        (2, 'D', OracleReapProgress::Wait, Deadline::DState),
        (
            3,
            'R',
            OracleReapProgress::AbortUnproven,
            Deadline::Ordinary,
        ),
    ] {
        let now = started + Duration::from_micros(offset);
        let terminal = OwnedChildStat::Ready {
            state,
            starttime: 42,
        };
        assert_eq!(
            oracle_reap_progress(
                true,
                OracleWait::StillAlive,
                &terminal,
                Some(42),
                now,
                cleanup_deadline,
                d_deadline
            ),
            expected
        );
        let selected = selected_deadline(
            true,
            OracleWait::StillAlive,
            &terminal,
            Some(42),
            now,
            d_deadline,
        );
        assert_eq!(selected, deadline);
        witness.record(
            now,
            OracleWait::StillAlive,
            &terminal,
            Some(42),
            selected,
            false,
        );
    }
    let mut bytes = Vec::new();
    witness.emit(&mut bytes);
    assert_eq!(
        std::str::from_utf8(&bytes).expect("witness UTF-8"),
        concat!(
            "oracle reap transition elapsed_us=2 wait=still-alive state=d identity_match=true deadline=d-state forced_fixture=false\n",
            "oracle reap transition elapsed_us=3 wait=still-alive state=r identity_match=true deadline=ordinary forced_fixture=false\n",
        )
    );

    // Overflow retains only the latest eight transitions, never stat content.
    for offset in 4..20 {
        let terminal = if offset % 2 == 0 {
            OwnedChildStat::Ready {
                state: '/',
                starttime: 999,
            }
        } else {
            OwnedChildStat::Unavailable
        };
        witness.record(
            started + Duration::from_micros(offset),
            OracleWait::Error,
            &terminal,
            Some(42),
            Deadline::Ordinary,
            false,
        );
    }
    bytes.clear();
    witness.emit(&mut bytes);
    let rendered = std::str::from_utf8(&bytes).expect("bounded witness UTF-8");
    assert_eq!(rendered.lines().count(), 8);
    assert!(rendered.starts_with("oracle reap transition elapsed_us=12 "));
    assert!(rendered.contains("elapsed_us=19 "));
    assert!(
        rendered
            .lines()
            .all(|row| row.len() <= 192 && row.contains("identity_match=false"))
    );
    assert!(!rendered.contains('/') && !rendered.contains("999"));
}
