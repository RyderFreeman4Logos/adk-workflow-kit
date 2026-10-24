//! The sealed worker has no CLI, profile, credentials, or general execution mode.
fn main() -> std::process::ExitCode {
    if std::env::args_os().len() != 1 {
        return std::process::ExitCode::FAILURE;
    }
    match workflow_runtime::behavioral::worker::run_worker(
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    ) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}
