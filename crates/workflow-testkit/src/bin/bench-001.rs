fn main() {
    let report = workflow_testkit::run_suite().expect("BENCH-001 synthetic suite must pass");
    let path = std::path::Path::new("artifacts/bench-001-baseline.json");
    report
        .write_json(path)
        .expect("BENCH-001 baseline report must be writable");
    println!("{}", path.display());
}
