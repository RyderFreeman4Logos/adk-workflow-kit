use std::{env, path::PathBuf, process::ExitCode};

use workflow_testkit::conformance::{
    ConformanceStatus, documented_failure_matrix, execute_conformance_matrix,
    write_conformance_report,
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
    if args.next().is_some() {
        return usage();
    }
    let Ok(execution) = execute_conformance_matrix() else {
        return ExitCode::from(1);
    };

    match write_conformance_report(&path, &execution) {
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

fn usage() -> ExitCode {
    eprintln!("usage: m1-15-report <path>");
    ExitCode::from(2)
}
