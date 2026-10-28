use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{sync::mpsc, thread, time::Duration};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "effect-journal-bootstrap-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).expect("exclusive fixture root");
        Self(path)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned fixture");
    }
}

#[test]
fn rejected_version_rolls_back_bootstrap() {
    let root = Root::new();
    let path = root.0.join("effects.sqlite");
    let connection = Connection::open(&path).expect("incompatible fixture");
    connection.execute_batch("CREATE TABLE kit_effect_journal_meta (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL); INSERT INTO kit_effect_journal_meta VALUES (1, 2);").expect("existing metadata");
    drop(connection);
    assert_eq!(
        EffectJournal::open(&path)
            .err()
            .expect("reject version")
            .kind(),
        EffectJournalErrorKind::Corrupt
    );
    let connection = Connection::open(path).expect("read refused journal");
    let version: i64 = connection
        .query_row(
            "SELECT schema_version FROM kit_effect_journal_meta WHERE id=1",
            [],
            |row| row.get(0),
        )
        .expect("existing version");
    assert_eq!(version, 2);
    let effects_tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='kit_effects'",
            [],
            |row| row.get(0),
        )
        .expect("schema readback");
    assert_eq!(
        effects_tables, 0,
        "refusal must not publish partial bootstrap"
    );
}

#[test]
fn reopen_waits_for_finishing_writer_without_rejecting_healthy_journal() {
    let root = Root::new();
    let path = root.0.join("effects.sqlite");
    let journal = EffectJournal::open(&path).expect("existing journal");
    let key = EffectKey::new("run", "node", "send", &serde_json::json!({"n":2}));
    let result = serde_json::json!({"accepted":true});
    let mut connection = journal.connection.lock().expect("writer connection");
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .expect("durability mode");
    assert_eq!((mode.as_str(), synchronous), ("wal", 2));
    let writer = connection.transaction().expect("writer transaction");
    writer
        .execute(
            "INSERT INTO kit_effects (effect_key, result_json) VALUES (?1, ?2)",
            params![
                key.as_str(),
                serde_json::to_vec(&result).expect("fixture bytes")
            ],
        )
        .expect("hold real writer");
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let reopen = thread::spawn(move || {
        started_tx.send(()).expect("start receiver");
        let opened = EffectJournal::open(path);
        result_tx
            .send(opened.as_ref().map(|_| ()).map_err(|error| error.kind()))
            .expect("result receiver");
        opened
    });
    let started = started_rx.recv_timeout(Duration::from_secs(2));
    // A positive error while the writer is held witnesses the regression.
    // A timeout only bounds observation; it does not prove an inner SQL phase.
    let early = result_rx.recv_timeout(Duration::from_secs(1));
    let committed = writer.commit();
    drop(connection);
    let completed = match early {
        Ok(result) => Ok(result),
        Err(mpsc::RecvTimeoutError::Timeout) => result_rx.recv_timeout(Duration::from_secs(6)),
        Err(error) => Err(error),
    };
    // Release the writer and join before assertions, including failure paths.
    let joined = reopen.join();
    assert!(started.is_ok(), "reopen thread started");
    committed.expect("finish writer");
    assert_eq!(completed, Ok(Ok(())), "healthy journal reopen must succeed");
    let reopened = joined.expect("joined reopener").expect("reopen journal");
    assert_eq!(reopened.load(&key).expect("durable readback"), Some(result));
    assert_eq!(reopened.committed_count().expect("one committed effect"), 1);
}

#[test]
fn writer_contention_is_unavailable_without_corrupting_journal() {
    let root = Root::new();
    let path = root.0.join("effects.sqlite");
    let journal = EffectJournal::open(&path).expect("existing journal");
    let key = EffectKey::new("run", "node", "send", &serde_json::json!({"n":3}));
    let result = serde_json::json!({"accepted":true});
    let mut connection = journal.connection.lock().expect("writer connection");
    let writer = connection.transaction().expect("writer transaction");
    writer
        .execute(
            "INSERT INTO kit_effects (effect_key, result_json) VALUES (?1, ?2)",
            params![
                key.as_str(),
                serde_json::to_vec(&result).expect("fixture bytes")
            ],
        )
        .expect("hold real writer");
    let control = Connection::open(&path).expect("independent contention control");
    control
        .busy_timeout(Duration::ZERO)
        .expect("no-wait control only");
    let busy_code = control
        .execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; BEGIN IMMEDIATE;")
        .err()
        .and_then(|error| error.sqlite_error_code());
    drop(control);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let reopen_path = path.clone();
    let reopen = thread::spawn(move || {
        started_tx.send(()).expect("start receiver");
        let opened = EffectJournal::open(reopen_path);
        result_tx
            .send(opened.as_ref().map(|_| ()).map_err(|error| error.kind()))
            .expect("result receiver");
        opened
    });
    let started = started_rx.recv_timeout(Duration::from_secs(2));
    let completed = result_rx.recv_timeout(Duration::from_secs(6));
    let committed = writer.commit();
    drop(connection);
    let joined = reopen.join();
    assert!(started.is_ok(), "reopen thread started");
    committed.expect("finish writer");
    assert_eq!(busy_code, Some(rusqlite::ErrorCode::DatabaseBusy));
    assert_eq!(
        completed,
        Ok(Err(EffectJournalErrorKind::Unavailable)),
        "a held writer is unavailable, not evidence of corruption"
    );
    assert_eq!(
        joined
            .expect("joined reopener")
            .err()
            .expect("finite refusal")
            .kind(),
        EffectJournalErrorKind::Unavailable
    );
    let reopened = EffectJournal::open(path).expect("healthy after writer release");
    assert_eq!(reopened.load(&key).expect("durable readback"), Some(result));
    assert_eq!(reopened.committed_count().expect("one committed effect"), 1);
}

#[test]
fn malformed_journal_reports_corrupt() {
    let root = Root::new();
    let path = root.0.join("effects.sqlite");
    fs::write(&path, b"not sqlite").expect("malformed journal fixture");

    let error = EffectJournal::open(path)
        .err()
        .expect("reject malformed journal");

    assert_eq!(error.kind(), EffectJournalErrorKind::Corrupt);
}
