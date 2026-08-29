use std::{env, path::PathBuf, process::ExitCode};

use workflow_testkit::conformance::{ConformanceStatus, write_conformance_report};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(path) = args.next().map(PathBuf::from) else {
        return usage();
    };
    let (Some(head), Some(tree), Some(status)) = (args.next(), args.next(), args.next()) else {
        return usage();
    };
    if args.next().is_some() {
        return usage();
    }
    let Some(status) = status.to_str().and_then(parse_status) else {
        return usage();
    };
    let (Some(head), Some(tree)) = (head.to_str(), tree.to_str()) else {
        return usage();
    };

    match write_conformance_report(&path, head, tree, status) {
        Ok(receipt) => {
            println!(
                "M1-15 conformance report: {} {}",
                receipt.path().display(),
                receipt.status().as_str()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("M1-15 conformance report failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn parse_status(status: &str) -> Option<ConformanceStatus> {
    match status {
        "PASS" => Some(ConformanceStatus::Pass),
        "FAIL" => Some(ConformanceStatus::Fail),
        _ => None,
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: m1-15-report <path> <head> <tree> <PASS|FAIL>");
    ExitCode::from(2)
}
