use workflow_runtime::{Checkpoint, RunId};
use workflow_testkit::{KillResumeFixture, SideEffectLedger};

#[test]
fn kill_resume_fixture_does_not_duplicate_side_effect() {
    let run_id = RunId::new(String::from("kill-resume-run")).expect("run ID is valid");
    let mut fixture = KillResumeFixture::new(SideEffectLedger::default());
    fixture.kill_after_checkpoint(Checkpoint::new(run_id.clone(), b"done".to_vec()).unwrap());
    fixture.resume(&run_id).expect("resume must succeed");
    assert_eq!(fixture.ledger().commits(), 1);
}
