use workflow_runtime::{Checkpoint, CheckpointBackend, CheckpointErrorKind, RunId};

struct MissingBackend;

impl CheckpointBackend for MissingBackend {
    fn load(
        &self,
        _run_id: &RunId,
    ) -> Result<Option<Checkpoint>, workflow_runtime::CheckpointError> {
        Ok(None)
    }

    fn save(&mut self, _checkpoint: Checkpoint) -> Result<(), workflow_runtime::CheckpointError> {
        Err(workflow_runtime::CheckpointError::new(
            CheckpointErrorKind::Unavailable,
        ))
    }
}

#[test]
fn checkpoint_contract_preserves_run_identity_and_typed_failure() {
    let run_id = RunId::new(String::from("checkpoint-run")).expect("run ID is valid");
    let checkpoint = Checkpoint::new(run_id.clone(), b"side-effect-complete".to_vec())
        .expect("checkpoint payload is valid");
    assert_eq!(checkpoint.run_id(), &run_id);
    assert_eq!(checkpoint.state(), b"side-effect-complete");

    let mut backend = MissingBackend;
    let error = backend
        .save(checkpoint)
        .expect_err("backend failure is typed");
    assert_eq!(error.kind(), CheckpointErrorKind::Unavailable);
}
