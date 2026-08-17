use std::{fmt::Display, path::Path};

use sha2::{Digest, Sha256};
use workflow_compiler::{
    activate_skill, DeclaredSkillResource, DeclaredSkillScript, RegistryCategory, RegistryEntry,
    RegistryNotFound, SkillActivationReceipt, SkillId, SkillManifest, SkillRegistry,
    SkillResourceId, SkillRuntimeLock, SkillRuntimeLockError, SkillRuntimeManifest,
    SkillRuntimeManifestError,
};
use workflow_runtime::{
    intersect_policy_capabilities, PolicyCapabilities, RequestedCapabilities, SandboxCapability,
};

struct TestSkillRegistry {
    manifest: SkillManifest,
}

impl SkillRegistry for TestSkillRegistry {
    type Implementation = SkillManifest;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        if (id, version) == ("valid-skill", "1.2.3") {
            Ok(RegistryEntry::new(&self.manifest, "valid-skill", "1.2.3"))
        } else {
            Err(RegistryNotFound::new(RegistryCategory::Skill, id, version))
        }
    }
}

fn skill_markdown() -> &'static [u8] {
    b"---\nname: valid-skill\ndescription: A bounded skill.\n---\n# Instructions\n"
}

fn registry() -> TestSkillRegistry {
    let parsed = match SkillManifest::parse(Path::new("valid-skill"), skill_markdown()) {
        Ok(manifest) => manifest,
        Err(error) => panic!("trusted SKILL.md fixture must parse: {error}"),
    };
    TestSkillRegistry { manifest: parsed }
}

fn activation(registry: &TestSkillRegistry) -> SkillActivationReceipt<'_> {
    let id = match SkillId::new("valid-skill") {
        Ok(id) => id,
        Err(error) => panic!("trusted skill ID must parse: {error}"),
    };
    match activate_skill(registry, &id, "1.2.3") {
        Ok(receipt) => receipt,
        Err(error) => panic!("trusted registry fixture must activate: {error}"),
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn resource_id(raw: &str) -> SkillResourceId {
    match SkillResourceId::new(raw) {
        Ok(id) => id,
        Err(error) => panic!("trusted resource ID must parse: {error}"),
    }
}

fn assert_private_error(error: impl Display, hostile_input: &str) {
    let rendered = error.to_string();
    assert_eq!(rendered.lines().count(), 1);
    assert!(!rendered.contains(hostile_input));
}

fn parse_runtime(
    receipt: &SkillActivationReceipt<'_>,
    document: impl AsRef<[u8]>,
) -> SkillRuntimeManifest {
    match SkillRuntimeManifest::parse_for_activation(receipt, document.as_ref()) {
        Ok(manifest) => manifest,
        Err(error) => panic!("trusted runtime manifest must parse: {error}"),
    }
}

fn runtime_manifest(scripts: &[(&str, &str, &str, &[&str])], resources: &[(&str, &str)]) -> String {
    let mut document =
        String::from("schema_version = 1\n\n[skill]\nid = \"valid-skill\"\nversion = \"1.2.3\"\n");
    for (id, path, sha256, capabilities) in scripts {
        document.push_str("\n[[scripts]]\n");
        document.push_str(&format!(
            "id = \"{id}\"\npath = \"{path}\"\nruntime = \"python3\"\nsha256 = \"{sha256}\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\ncapabilities = [",
        ));
        for (index, capability) in capabilities.iter().enumerate() {
            if index != 0 {
                document.push_str(", ");
            }
            document.push_str(&format!("\"{capability}\""));
        }
        document.push_str("]\n");
    }
    for (id, sha256) in resources {
        document.push_str("\n[[resources]]\n");
        document.push_str(&format!("id = \"{id}\"\nsha256 = \"{sha256}\"\n"));
    }
    document
}

const SCHEMA: &[u8] =
    br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#;

fn lock(
    manifest: &SkillRuntimeManifest,
    scripts: &[(&str, &[u8])],
    resources: &[(&SkillResourceId, &[u8])],
) -> SkillRuntimeLock {
    match SkillRuntimeLock::try_from_declared_bytes(
        manifest,
        skill_markdown(),
        scripts.iter().copied(),
        resources.iter().copied(),
    ) {
        Ok(lock) => lock,
        Err(error) => panic!("trusted declared bytes must lock: {error}"),
    }
}

#[test]
fn empty_hostile_and_unknown_manifest_fields_fail_closed_without_echo() {
    fn assert_manifest_error(
        receipt: &SkillActivationReceipt<'_>,
        document: &[u8],
        hostile_input: &str,
    ) {
        match SkillRuntimeManifest::parse_for_activation(receipt, document) {
            Err(error) => assert_private_error(error, hostile_input),
            Ok(_) => panic!("invalid runtime manifest must fail closed"),
        }
    }

    let registry = registry();
    let receipt = activation(&registry);
    assert_manifest_error(&receipt, b"", "hostile-empty");
    assert_manifest_error(
        &receipt,
        b"schema_version = 1\n[skill]\nid = \"valid-skill\"\nversion = \"1.2.3\"\nattacker-field = \"hostile-unknown-field\"\n[[resources]]\nid = \"references/schema.json\"\nsha256 = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n",
        "hostile-unknown-field",
    );
    assert_manifest_error(
        &receipt,
        b"schema_version = 1\n[skill]\nid = \"valid-skill\"\nversion = \"1.2.3\"\n[[scripts]]\nid = \"script\"\npath = \"scripts/script.py\"\nruntime = \"python3\"\nsha256 = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\ncapabilities = [\"hostile-unknown-capability\"]\n[[resources]]\nid = \"references/schema.json\"\nsha256 = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n",
        "hostile-unknown-capability",
    );
    assert_manifest_error(
        &receipt,
        b"schema_version = 1\n[skill]\nid = \"valid-skill\"\nversion = \"1.2.3\"\n",
        "valid-skill",
    );
    let _: Option<&DeclaredSkillScript> = None;
    let _: Option<&DeclaredSkillResource> = None;
}

#[test]
fn oversized_ids_paths_hashes_and_schemas_fail_closed_without_echo() {
    let registry = registry();
    let receipt = activation(&registry);

    let oversized_id = "a".repeat(65);
    let oversized_id_document = runtime_manifest(
        &[(&oversized_id, "scripts/ok.py", &digest(b"ok"), &[])],
        &[("references/schema.json", &digest(SCHEMA))],
    );
    match SkillRuntimeManifest::parse_for_activation(&receipt, oversized_id_document.as_bytes()) {
        Err(error) => assert_private_error(error, &oversized_id),
        Ok(_) => panic!("oversized script ID must fail closed"),
    }

    let oversized_path = format!("scripts/{}", "p".repeat(1_017));
    let oversized_path_document = runtime_manifest(
        &[("script", &oversized_path, &digest(b"ok"), &[])],
        &[("references/schema.json", &digest(SCHEMA))],
    );
    match SkillRuntimeManifest::parse_for_activation(&receipt, oversized_path_document.as_bytes()) {
        Err(error) => assert_private_error(error, &oversized_path),
        Ok(_) => panic!("oversized script path must fail closed"),
    }

    let hostile_hash = format!("sha256:{}", "A".repeat(64));
    let hostile_hash_document = runtime_manifest(
        &[("script", "scripts/ok.py", &hostile_hash, &[])],
        &[("references/schema.json", &digest(SCHEMA))],
    );
    match SkillRuntimeManifest::parse_for_activation(&receipt, hostile_hash_document.as_bytes()) {
        Err(error) => assert_private_error(error, &hostile_hash),
        Ok(_) => panic!("non-canonical digest must fail closed"),
    }

    let oversized_schema = vec![b'x'; 65_537];
    let oversized_schema_digest = digest(&oversized_schema);
    let document = runtime_manifest(
        &[("script", "scripts/ok.py", &digest(b"ok"), &[])],
        &[("references/schema.json", &oversized_schema_digest)],
    );
    let manifest = parse_runtime(&receipt, document);
    let schema_id = resource_id("references/schema.json");
    match SkillRuntimeLock::try_from_declared_bytes(
        &manifest,
        skill_markdown(),
        [("script", b"ok".as_slice())],
        [(&schema_id, oversized_schema.as_slice())],
    ) {
        Err(error) => assert_private_error(error, &"x".repeat(80)),
        Ok(_) => panic!("oversized schema must fail closed"),
    }
}

#[test]
fn permuted_declarations_produce_byte_identical_locks_without_execution() {
    let registry = registry();
    let receipt = activation(&registry);
    let alpha = b"alpha script\n".as_slice();
    let beta = b"beta script\n".as_slice();
    let asset = b"opaque asset".as_slice();
    let schema_digest = digest(SCHEMA);
    let alpha_digest = digest(alpha);
    let beta_digest = digest(beta);
    let asset_digest = digest(asset);

    let first_document = runtime_manifest(
        &[
            (
                "beta",
                "scripts/beta.py",
                &beta_digest,
                &["process.spawn", "network"],
            ),
            ("alpha", "scripts/alpha.py", &alpha_digest, &[]),
        ],
        &[
            ("assets/info.txt", &asset_digest),
            ("references/schema.json", &schema_digest),
        ],
    );
    let second_document = format!(
        "# equivalent comments and tables\n{}",
        runtime_manifest(
            &[
                ("alpha", "scripts/alpha.py", &alpha_digest, &[]),
                (
                    "beta",
                    "scripts/beta.py",
                    &beta_digest,
                    &["network", "process.spawn"]
                ),
            ],
            &[
                ("references/schema.json", &schema_digest),
                ("assets/info.txt", &asset_digest),
            ],
        )
    );
    let first = parse_runtime(&receipt, first_document);
    let second = parse_runtime(&receipt, second_document);
    assert!(first.script("alpha").is_some());
    assert!(first.script("missing").is_none());

    let schema_id = resource_id("references/schema.json");
    let asset_id = resource_id("assets/info.txt");
    let first_lock = lock(
        &first,
        &[("beta", beta), ("alpha", alpha)],
        &[(&asset_id, asset), (&schema_id, SCHEMA)],
    );
    let second_lock = lock(
        &second,
        &[("alpha", alpha), ("beta", beta)],
        &[(&schema_id, SCHEMA), (&asset_id, asset)],
    );
    let first_toml = match first_lock.to_toml() {
        Ok(toml) => toml,
        Err(error) => panic!("first lock must serialize: {error}"),
    };
    let second_toml = match second_lock.to_toml() {
        Ok(toml) => toml,
        Err(error) => panic!("second lock must serialize: {error}"),
    };

    assert_eq!(first_toml.as_bytes(), second_toml.as_bytes());
    assert!(first_toml.contains("capabilities = []"));
    assert!(first_toml.contains("capabilities = [\"network\", \"process.spawn\"]"));
    assert_eq!(first_toml.matches("[[scripts]]").count(), 2);
    assert_eq!(first_toml.matches("[[resources]]").count(), 2);
}

#[test]
fn capability_metadata_cannot_expand_policy_or_dispatch() {
    let registry = registry();
    let receipt = activation(&registry);
    let script = b"metadata only\n".as_slice();
    let document = runtime_manifest(
        &[(
            "metadata-only",
            "scripts/metadata.py",
            &digest(script),
            &["network", "process.spawn"],
        )],
        &[("references/schema.json", &digest(SCHEMA))],
    );
    let manifest = parse_runtime(&receipt, document);
    let schema_id = resource_id("references/schema.json");
    let runtime_lock = lock(
        &manifest,
        &[("metadata-only", script)],
        &[(&schema_id, SCHEMA)],
    );
    match runtime_lock.to_toml() {
        Ok(toml) => assert!(toml.contains("capabilities = [\"network\", \"process.spawn\"]")),
        Err(error) => panic!("metadata-only lock must serialize: {error}"),
    }

    let requested =
        RequestedCapabilities::new([SandboxCapability::Network, SandboxCapability::ProcessSpawn]);
    let policy = PolicyCapabilities::new(std::iter::empty::<SandboxCapability>());
    match intersect_policy_capabilities(&requested, &[policy]) {
        Err(_) => {}
        Ok(_) => panic!("runtime metadata must not authorize network or process spawning"),
    }
    let _: Result<String, SkillRuntimeLockError> = runtime_lock.to_toml();
    let _: Option<SkillRuntimeManifestError> = None;
}
