use std::{fs, path::Path, process::Command};

use sha2::{Digest, Sha256};

const CANARY_MANIFEST_55: &str = "CANARY_MANIFEST_55";
const CANARY_SCRIPT_55: &str = "CANARY_SCRIPT_55";
const SCHEMA: &str =
    r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#;

fn temp_skill(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir()
        .join(format!("workflowctl-cli-005-{name}-{}", std::process::id()))
        .join("canary-skill-55");
    fs::create_dir_all(&path).expect("create test skill directory");
    path
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
        .args(args)
        .output()
        .expect("run workflowctl")
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn write_valid_skill(path: &Path) {
    fs::write(
        path.join("SKILL.md"),
        "---\nname: canary-skill-55\ndescription: A test skill.\n---\n# Instructions\n",
    )
    .expect("write valid skill manifest");
    fs::create_dir_all(path.join("scripts")).expect("create script directory");
    fs::create_dir_all(path.join("references")).expect("create references directory");
    fs::write(path.join("references/schema.json"), SCHEMA).expect("write schema");
}

#[test]
fn invalid_manifest_fails_clearly_with_typed_redacted_diagnostic() {
    let path = temp_skill("manifest");
    fs::write(path.join("SKILL.md"), CANARY_MANIFEST_55).expect("write invalid manifest");

    let output = run(&["--json", "skill", "lint", path.to_str().expect("utf8 path")]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("skill.cli.invalid_manifest"));
    assert!(!stderr.contains(CANARY_MANIFEST_55));
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(path).expect("remove test skill directory");
}

#[test]
fn invalid_script_fails_clearly_with_typed_redacted_diagnostic() {
    let path = temp_skill("script");
    write_valid_skill(&path);
    let script = CANARY_SCRIPT_55.as_bytes();
    fs::write(path.join("scripts/check.py"), script).expect("write invalid script");
    let runtime_manifest = format!(
        "schema_version = 1\n\n[skill]\nid = \"canary-skill-55\"\nversion = \"1.0.0\"\n\n[[scripts]]\nid = \"check\"\npath = \"scripts/check.py\"\nruntime = \"python3\"\nsha256 = \"sha256:{}\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\n\n[[resources]]\nid = \"references/schema.json\"\nsha256 = \"{}\"\n",
        "0".repeat(64),
        digest(SCHEMA.as_bytes()),
    );
    fs::write(path.join("skill.runtime.toml"), runtime_manifest).expect("write runtime manifest");

    let output = run(&["--json", "skill", "test", path.to_str().expect("utf8 path")]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("skill.cli.invalid_script"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains(CANARY_SCRIPT_55));
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(path).expect("remove test skill directory");
}
