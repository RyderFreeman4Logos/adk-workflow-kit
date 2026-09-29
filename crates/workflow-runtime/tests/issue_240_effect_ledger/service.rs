//! Independent loopback fake service with a concurrent pre-commit transaction.
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::mpsc::{self, Receiver, Sender},
    thread::{self, JoinHandle},
    time::Duration,
};
use workflow_runtime::{effect_ledger::*, firewall::ToolProposal};

pub fn call(address: SocketAddr, message: Value) -> Value {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(stream, "{message}").unwrap();
    let mut line = String::new();
    BufReader::new(stream)
        .take(4096)
        .read_line(&mut line)
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

pub struct RemoteExecutor(pub SocketAddr);
impl EffectExecutor for RemoteExecutor {
    fn reconcile(&mut self, request: &ApprovalRequest) -> RemoteObservation {
        match call(self.0, json!({"op":"lookup","key":request.effect_key()}))["result"]
            .as_str()
            .unwrap()
        {
            "absent" => RemoteObservation::Absent,
            "committed" => RemoteObservation::Committed,
            _ => RemoteObservation::Unknown,
        }
    }
    fn execute(&mut self, request: &ApprovalRequest) -> ExecutionOutcome {
        let ToolProposal {
            intent, arguments, ..
        } = request.proposal();
        match call(
            self.0,
            json!({"op":"apply","key":request.effect_key(),
            "version":intent.target_version.revision,"arguments":arguments}),
        )["result"]
            .as_str()
            .unwrap()
        {
            "committed" => ExecutionOutcome::Committed,
            "rejected" => ExecutionOutcome::Rejected,
            _ => ExecutionOutcome::Unknown,
        }
    }
    fn verify(&mut self, request: &ApprovalRequest) -> Postcondition {
        match call(self.0, json!({"op":"verify","key":request.effect_key()}))["result"]
            .as_str()
            .unwrap()
        {
            "satisfied" => Postcondition::Satisfied,
            "violated" => Postcondition::Violated,
            _ => Postcondition::Unknown,
        }
    }
}

type Pause = (String, Sender<()>);
pub struct FakeService {
    pub address: SocketAddr,
    pauses: Receiver<Pause>,
    thread: Option<JoinHandle<()>>,
}
impl FakeService {
    pub fn start(path: &Path, stop: &str) -> Self {
        let database = Connection::open(path.join("remote.db")).unwrap();
        database
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE remote_effects (key TEXT PRIMARY KEY, amount INTEGER NOT NULL);
            CREATE TABLE counter (value INTEGER NOT NULL, revision TEXT NOT NULL);
            INSERT INTO counter VALUES(0,'r1');",
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, pauses) = mpsc::channel();
        let stop = stop.to_owned();
        let thread = thread::spawn(move || serve(listener, database, &stop, sender));
        Self {
            address,
            pauses,
            thread: Some(thread),
        }
    }
    pub fn paused(&self, expected: &str) -> Sender<()> {
        let (stage, release) = self
            .pauses
            .recv_timeout(Duration::from_secs(20))
            .expect("bounded crash handshake");
        assert_eq!(stage, expected);
        release
    }
    pub fn stats(&self) -> Value {
        call(self.address, json!({"op":"stats"}))
    }
}
impl Drop for FakeService {
    fn drop(&mut self) {
        let _ = call(self.address, json!({"op":"shutdown"}));
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn pause(stage: &str, stop: &str, sender: &Sender<Pause>) {
    if stage == stop {
        let (release, wait) = mpsc::channel();
        sender.send((stage.to_owned(), release)).unwrap();
        // A failed parent assertion drops the sender: release for bounded cleanup.
        let _ = wait.recv_timeout(Duration::from_secs(5));
    }
}
fn serve(listener: TcpListener, mut database: Connection, stop: &str, sender: Sender<Pause>) {
    let mut stop = stop;
    let mut applies = 0;
    let mut lookups = 0;
    let mut verifies = 0;
    let mut rejections = 0;
    let mut unknown = false;
    let mut violation = false;
    let mut pending: Option<JoinHandle<()>> = None;
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut line = String::new();
        BufReader::new(&stream)
            .take(4096)
            .read_line(&mut line)
            .unwrap();
        let message: Value = serde_json::from_str(&line).unwrap();
        let op = message["op"].as_str().unwrap();
        let key = message["key"].as_str().unwrap_or("");
        let result = match op {
            "lookup" => {
                lookups += 1;
                if unknown {
                    "unknown"
                } else if database
                    .query_row("SELECT 1 FROM remote_effects WHERE key=?1", [key], |_| {
                        Ok(())
                    })
                    .optional()
                    .unwrap()
                    .is_some()
                {
                    "committed"
                } else {
                    // Keep the truthful snapshot while A commits before retry B.
                    if stop == "after-absent" {
                        pause("after-absent", stop, &sender);
                        pending.take().unwrap().join().unwrap();
                    }
                    "absent"
                }
            }
            "apply" => {
                applies += 1;
                if stop == "before-remote-commit" {
                    assert!(pending.is_none(), "only one in-flight mutation");
                    let mut writer = Connection::open(database.path().unwrap()).unwrap();
                    let sender = sender.clone();
                    pending = Some(thread::spawn(move || {
                        apply(&mut writer, &message, "before-remote-commit", &sender);
                    }));
                    let _ = writeln!(stream, "{}", json!({"result":"unknown"}));
                    continue;
                }
                let outcome = if stop == "reject-retry" {
                    // Admission rejects only B; the pending A is unaffected.
                    "rejected"
                } else {
                    apply(&mut database, &message, stop, &sender)
                };
                pause("after-request", stop, &sender);
                if stop == "lost-response" {
                    "unknown"
                } else {
                    outcome
                }
            }
            "verify" => {
                verifies += 1;
                pause("before-verify", stop, &sender);
                let present = database
                    .query_row("SELECT 1 FROM remote_effects WHERE key=?1", [key], |_| {
                        Ok(())
                    })
                    .optional()
                    .unwrap()
                    .is_some();
                let result = if unknown {
                    "unknown"
                } else if present && !violation {
                    "satisfied"
                } else {
                    "violated"
                };
                pause("after-verify", stop, &sender);
                result
            }
            "settle" => {
                pending.take().unwrap().join().unwrap();
                "ok"
            }
            "disarm" => {
                stop = "";
                "ok"
            }
            "retry-mode" => {
                stop = if message["commit_first"].as_bool().unwrap() {
                    "after-absent"
                } else {
                    "reject-retry"
                };
                "ok"
            }
            "drift" => {
                database
                    .execute("UPDATE counter SET revision='drift'", [])
                    .unwrap();
                "ok"
            }
            "unknown" => {
                unknown = message["enabled"].as_bool().unwrap();
                "ok"
            }
            "violate" => {
                violation = true;
                "ok"
            }
            "barrier" => {
                pause(message["stage"].as_str().unwrap(), stop, &sender);
                "ok"
            }
            "stats" => {
                let (count, value): (i64, i64) = database
                    .query_row(
                        "SELECT (SELECT COUNT(*) FROM remote_effects), value FROM counter",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                writeln!(stream,"{}",json!({"count":count,"value":value,"applies":applies,"lookups":lookups,"verifies":verifies,"rejections":rejections})).unwrap();
                continue;
            }
            "shutdown" => {
                if let Some(writer) = pending.take() {
                    writer.join().unwrap();
                }
                writeln!(stream, "{{}}").unwrap();
                break;
            }
            _ => panic!("unknown fake service command"),
        };
        if result == "rejected" {
            rejections += 1;
        }
        // A killed client intentionally drops its socket before the response.
        let _ = writeln!(stream, "{}", json!({"result":result}));
    }
}
fn apply(
    database: &mut Connection,
    message: &Value,
    stop: &str,
    sender: &Sender<Pause>,
) -> &'static str {
    let key = message["key"].as_str().unwrap();
    let tx = database.transaction().unwrap();
    let existing = tx
        .query_row("SELECT 1 FROM remote_effects WHERE key=?1", [key], |_| {
            Ok(())
        })
        .optional()
        .unwrap()
        .is_some();
    let version: String = tx
        .query_row("SELECT revision FROM counter", [], |r| r.get(0))
        .unwrap();
    // CAS-first services reject a stale retry even when its key already committed.
    let outcome = if version != message["version"].as_str().unwrap() {
        "rejected"
    } else if existing {
        "committed"
    } else {
        let amount = message["arguments"]["count"].as_i64().unwrap();
        tx.execute(
            "INSERT INTO remote_effects VALUES(?1,?2)",
            params![key, amount],
        )
        .unwrap();
        tx.execute("UPDATE counter SET value=value+?1,revision='r2'", [amount])
            .unwrap();
        "committed"
    };
    pause("before-remote-commit", stop, sender);
    tx.commit().unwrap();
    outcome
}
