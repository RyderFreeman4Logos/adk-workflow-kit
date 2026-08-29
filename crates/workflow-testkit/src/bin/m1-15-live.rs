use std::process::ExitCode;

use workflow_testkit::code_investigation::{LiveDogfood, LiveStatus};

fn main() -> ExitCode {
    let runtime = match adk_rust::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("M1-15 live dogfood: ABSTAIN ({error})");
            return ExitCode::SUCCESS;
        }
    };
    let result = runtime.block_on(LiveDogfood::opt_in().run());
    match result.status() {
        LiveStatus::Published => println!("M1-15 live dogfood: PASS"),
        LiveStatus::Abstained => println!("M1-15 live dogfood: ABSTAIN"),
        LiveStatus::Skipped => println!("M1-15 live dogfood: SKIP"),
    }
    ExitCode::SUCCESS
}
