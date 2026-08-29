use std::{env, fs, path::PathBuf, process::ExitCode};

use workflow_testkit::conformance::{
    ConformanceStatus, ConformanceSubgate, documented_failure_matrix, write_conformance_report,
};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(first) = args.next() else {
        return usage();
    };
    if first == "--selectors" {
        if args.next().is_some() {
            return usage();
        }
        for class in documented_failure_matrix() {
            for probe in class.probes() {
                println!("{}", probe.selector());
            }
        }
        return ExitCode::SUCCESS;
    }
    let path = PathBuf::from(first);
    let (Some(head), Some(tree), Some(status), Some(evidence)) = (
        args.next(),
        args.next(),
        args.next(),
        args.next().map(PathBuf::from),
    ) else {
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
    let Ok(evidence) = fs::read_to_string(evidence) else {
        return ExitCode::from(1);
    };
    let mut subgates = Vec::new();
    for line in evidence.lines() {
        let Some((result, command)) = line.split_once('\t') else {
            return ExitCode::from(1);
        };
        let Some(result) = parse_status(result) else {
            return ExitCode::from(1);
        };
        subgates.push(ConformanceSubgate::new(command, result));
    }

    match write_conformance_report(&path, head, tree, status, &subgates) {
        Ok(receipt) => {
            println!(
                "M1-15 conformance report: {} {}",
                receipt.path().display(),
                receipt.status().as_str()
            );
            match receipt.status() {
                ConformanceStatus::Pass => ExitCode::SUCCESS,
                ConformanceStatus::Fail => ExitCode::from(1),
            }
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
