use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use workflow_testkit::live_conformance::{ConformanceDisposition, LiveConformance};

fn example_root() -> PathBuf {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let candidate = cwd.join("examples/01-code-investigation");
    if candidate.join("workflow.toml").is_file() {
        candidate
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/01-code-investigation")
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(workflowctl) = args.next() else {
        eprintln!("M3-07 live conformance: FAIL (missing workflowctl)");
        return ExitCode::from(2);
    };
    let Some(profile) = args.next() else {
        eprintln!("M3-07 live conformance: FAIL (missing profile)");
        return ExitCode::from(2);
    };
    let workdir = env::temp_dir().join(format!("m3-07-live-{}", std::process::id()));
    if std::fs::create_dir_all(&workdir).is_err() {
        eprintln!("M3-07 live conformance: FAIL (workdir)");
        return ExitCode::from(2);
    }
    let report = LiveConformance::opt_in().run_canonical(
        workflowctl.as_ref(),
        &example_root(),
        profile.as_ref(),
        &workdir,
    );
    match report.disposition() {
        ConformanceDisposition::Skip => {
            println!("M3-07 live conformance: SKIP");
            ExitCode::SUCCESS
        }
        ConformanceDisposition::Pass => {
            println!("M3-07 live conformance: PASS");
            ExitCode::SUCCESS
        }
        ConformanceDisposition::Abstain => {
            println!("M3-07 live conformance: ABSTAIN");
            ExitCode::SUCCESS
        }
        ConformanceDisposition::Fail => {
            println!("M3-07 live conformance: FAIL");
            ExitCode::from(2)
        }
    }
}
