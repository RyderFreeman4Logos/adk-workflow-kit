use std::{fs, process::Command};

fn workspace() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn documented_commands_smoke_the_real_adk_path() {
    let workspace = workspace();
    let readme = fs::read_to_string(workspace.join("README.md")).expect("README must be readable");
    for required in [
        "## Five-minute quickstart",
        "workflowctl run",
        "--profile",
        "workflowctl resume",
        "workflowctl replay",
        "implemented",
        "experimental",
        "planned",
        "deferred",
        "secrets",
        "workdir",
        "sandbox",
        "checkpoint",
    ] {
        assert!(readme.contains(required), "README must document {required}");
    }

    let help = Command::new(env!("CARGO_BIN_EXE_workflowctl"))
        .arg("--help")
        .output()
        .expect("workflowctl help must start");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("run <PATH>"));

    let root = std::env::temp_dir().join(format!("workflowctl-m1-16-docs-{}", std::process::id()));
    fs::create_dir(&root).expect("test root must be unique");
    let workflow = root.join("workflow.toml");
    let profile = root.join("profile.json");
    let workdir = root.join("runs");
    fs::write(
        &workflow,
        "schema_version = 1\n[workflow]\nid = \"m1-16-docs\"\nversion = \"1\"\nentry = \"agent\"\n[[nodes]]\nid = \"agent\"\nkind = \"agent\"\n[[nodes]]\nid = \"done\"\nkind = \"terminal\"\n[[edges]]\nfrom = \"agent\"\nto = \"done\"\n",
    )
    .expect("write workflow");
    fs::write(
        &profile,
        r#"{"schema_version":1,"model":{"provider":"fake","name":"docs","version":"1","model":"fake","responses":["done"]},"tool":{"name":"echo","result":{"ok":true},"required_capabilities":[]},"sandbox":{"capabilities":[]}}"#,
    )
    .expect("write profile");
    fs::create_dir(&workdir).expect("write workdir");

    let run = Command::new(env!("CARGO_BIN_EXE_workflowctl"))
        .args([
            "run",
            workflow.to_str().expect("UTF-8 workflow path"),
            "--profile",
            profile.to_str().expect("UTF-8 profile path"),
            "--input",
            r#"{"request":"public"}"#,
            "--workdir",
            workdir.to_str().expect("UTF-8 workdir path"),
        ])
        .output()
        .expect("documented ADK run must start");
    assert!(
        run.status.success(),
        "documented ADK run must succeed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn narrow_main_delegates_without_changing_cli_help() {
    let source = fs::read_to_string(workspace().join("crates/workflowctl/src/main.rs"))
        .expect("main source must be readable");
    assert_eq!(
        source,
        "mod cli;\nmod secure_open;\n\nfn main() {\n    cli::run();\n}\n"
    );

    let help = Command::new(env!("CARGO_BIN_EXE_workflowctl"))
        .arg("--help")
        .output()
        .expect("workflowctl help must start");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("skill test <PATH>"));
}

#[test]
fn linux_secure_open_remains_descriptor_relative_and_fail_closed() {
    let workspace = workspace();
    let secure_open = fs::read_to_string(workspace.join("crates/workflowctl/src/secure_open.rs"))
        .expect("secure-open module must be readable");
    assert!(secure_open.contains("#[cfg(target_os = \"linux\")]"));
    assert!(secure_open.contains("openat"));
    assert!(secure_open.contains("O_NOFOLLOW"));
    assert!(secure_open.contains("#[cfg(not(target_os = \"linux\"))]"));
    assert!(secure_open.contains("Err(failure)"));
}
