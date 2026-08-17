use std::{fmt::Display, path::Path};

use workflow_compiler::{
    activate_skill, RegistryCategory, RegistryEntry, RegistryNotFound, SkillActivationError,
    SkillId, SkillIdError, SkillManifest, SkillManifestError, SkillRegistry,
};
use workflow_runtime::{
    intersect_policy_capabilities, PolicyCapabilities, RequestedCapabilities, SandboxCapability,
};

struct TestSkillRegistry {
    lookup_id: &'static str,
    entry_id: &'static str,
    version: &'static str,
    manifest: SkillManifest,
}

impl SkillRegistry for TestSkillRegistry {
    type Implementation = SkillManifest;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        if (id, version) == (self.lookup_id, self.version) {
            Ok(RegistryEntry::new(
                &self.manifest,
                self.entry_id,
                self.version,
            ))
        } else {
            Err(RegistryNotFound::new(RegistryCategory::Skill, id, version))
        }
    }
}

fn valid_markdown(allowed_tools: &str) -> String {
    format!(
        "---\nname: valid-skill\ndescription: \"  A bounded skill description.  \"\nlicense: Apache-2.0\ncompatibility: \"  workflow-kit  \"\nmetadata:\n  version: \"ignored-frontmatter-version\"\n  owner: compiler\nallowed-tools: {allowed_tools}\n---\n# Instructions\n\nUse the explicit activation receipt only.\n"
    )
}

fn parsed_manifest(markdown: &str) -> SkillManifest {
    match SkillManifest::parse(Path::new("valid-skill"), markdown.as_bytes()) {
        Ok(manifest) => manifest,
        Err(error) => panic!("trusted fixture should parse: {error}"),
    }
}

fn valid_id() -> SkillId {
    match SkillId::new("valid-skill") {
        Ok(id) => id,
        Err(error) => panic!("trusted identifier should validate: {error}"),
    }
}

fn assert_private_error(error: impl Display, hostile_input: &str) {
    let rendered = error.to_string();
    assert_eq!(rendered.lines().count(), 1);
    assert!(!rendered.contains(hostile_input));
}

#[test]
fn valid_fixture_discovers_parses_and_activates_explicitly_without_dispatch() {
    let manifest = parsed_manifest(&valid_markdown("network process.spawn"));
    let discovery = manifest.discovery_metadata();
    assert_eq!(discovery.id().as_str(), "valid-skill");
    assert_eq!(discovery.description(), "A bounded skill description.");

    let registry = TestSkillRegistry {
        lookup_id: "valid-skill",
        entry_id: "valid-skill",
        version: "1.2.3",
        manifest,
    };
    let id = valid_id();
    let receipt = match activate_skill(&registry, &id, "1.2.3") {
        Ok(receipt) => receipt,
        Err(error) => panic!("exact registered skill should activate: {error}"),
    };
    assert_eq!(receipt.id().as_str(), "valid-skill");
    assert_eq!(receipt.version(), "1.2.3");
    assert_eq!(
        receipt.instructions(),
        "# Instructions\n\nUse the explicit activation receipt only.\n"
    );

    let missing = TestSkillRegistry {
        lookup_id: "other-skill",
        entry_id: "valid-skill",
        version: "1.2.3",
        manifest: parsed_manifest(&valid_markdown("read")),
    };
    match activate_skill(&missing, &id, "1.2.3") {
        Err(SkillActivationError::NotRegistered) => {}
        Ok(_) => panic!("an absent exact registry entry must not activate"),
        Err(error) => panic!("wrong activation error: {error}"),
    }

    let mismatched = TestSkillRegistry {
        lookup_id: "valid-skill",
        entry_id: "other-skill",
        version: "1.2.3",
        manifest: parsed_manifest(&valid_markdown("read")),
    };
    match activate_skill(&mismatched, &id, "1.2.3") {
        Err(SkillActivationError::RegistryIdentityMismatch) => {}
        Ok(_) => panic!("a registry identity mismatch must not activate"),
        Err(error) => panic!("wrong activation error: {error}"),
    }
}

#[test]
fn empty_or_malformed_manifest_fields_fail_closed() {
    let cases = [
        (
            "---\nname: \"\"\ndescription: present\n---\n",
            "skill manifest name is invalid: skill ID is empty",
        ),
        (
            "---\nname: valid-skill\ndescription: [not, a, string]\n---\n",
            "skill manifest frontmatter is invalid",
        ),
        (
            "---\nname: valid-skill\ndescription: 42\n---\n",
            "skill manifest frontmatter is invalid",
        ),
        (
            "---\nname: valid-skill\ndescription: \"present\"unescaped\"\n---\n",
            "skill manifest frontmatter is invalid",
        ),
        (
            "---\nname: valid-skill\ndescription: present\ncompatibility: \"   \"\n---\n",
            "skill manifest compatibility is invalid",
        ),
        (
            "---\nname: valid-skill\ndescription: present\nmetadata: []\n---\n",
            "skill manifest frontmatter is invalid",
        ),
        (
            "---\nname: valid-skill\nmetadata:\n  owner: compiler\ndescription: present\n  misplaced: value\n---\n",
            "skill manifest frontmatter is invalid",
        ),
        (
            "---\nname: valid-skill\ndescription: present\nunknown: value\n---\n",
            "skill manifest frontmatter is invalid",
        ),
        (
            "name: valid-skill\ndescription: present\n",
            "skill manifest is missing frontmatter",
        ),
        (
            "---\nname: valid-skill\ndescription: present\n",
            "skill manifest is missing frontmatter",
        ),
    ];

    for (markdown, expected) in cases {
        match SkillManifest::parse(Path::new("valid-skill"), markdown.as_bytes()) {
            Err(error) => assert_eq!(error.to_string(), expected),
            Ok(_) => panic!("malformed manifest must fail closed"),
        }
    }

    let invalid_utf8 = b"---\nname: valid-skill\ndescription: present\n---\n\xff";
    match SkillManifest::parse(Path::new("valid-skill"), invalid_utf8) {
        Err(SkillManifestError::InvalidUtf8) => {}
        Ok(_) => panic!("invalid UTF-8 must fail closed"),
        Err(error) => panic!("wrong UTF-8 error: {error}"),
    }
}

#[test]
fn hostile_or_directory_mismatched_skill_ids_are_rejected_without_echo() {
    for hostile_id in ["valid--skill", "Valid-skill", "valid-skill\nprivate-body"] {
        match SkillId::new(hostile_id) {
            Err(SkillIdError::InvalidSyntax) => {}
            Ok(_) => panic!("hostile ID must be rejected"),
            Err(error) => panic!("wrong ID error: {error}"),
        }
        match SkillManifest::parse(
            Path::new("valid-skill"),
            format!("---\nname: {hostile_id}\ndescription: present\n---\nprivate-body").as_bytes(),
        ) {
            Err(error) => assert_private_error(error, hostile_id),
            Ok(_) => panic!("hostile manifest ID must be rejected"),
        }
    }

    match SkillManifest::parse(
        Path::new("different-directory"),
        valid_markdown("read").as_bytes(),
    ) {
        Err(SkillManifestError::DirectoryNameMismatch) => {}
        Ok(_) => panic!("directory mismatch must be rejected"),
        Err(error) => panic!("wrong directory mismatch error: {error}"),
    }
    match SkillManifest::parse(Path::new(""), valid_markdown("read").as_bytes()) {
        Err(SkillManifestError::InvalidDirectoryName) => {}
        Ok(_) => panic!("missing directory name must be rejected"),
        Err(error) => panic!("wrong invalid directory error: {error}"),
    }
}

#[test]
fn oversized_name_description_or_skill_markdown_are_rejected_at_the_boundary() {
    let name = "a".repeat(65);
    let oversized_name = format!("---\nname: {name}\ndescription: present\n---\n");
    match SkillManifest::parse(Path::new(&name), oversized_name.as_bytes()) {
        Err(SkillManifestError::InvalidName(SkillIdError::TooLong)) => {}
        Ok(_) => panic!("oversized name must be rejected"),
        Err(error) => panic!("wrong oversized-name error: {error}"),
    }

    let description = "a".repeat(1_025);
    let oversized_description =
        format!("---\nname: valid-skill\ndescription: {description}\n---\n");
    match SkillManifest::parse(Path::new("valid-skill"), oversized_description.as_bytes()) {
        Err(SkillManifestError::InvalidDescription) => {}
        Ok(_) => panic!("oversized description must be rejected"),
        Err(error) => panic!("wrong oversized-description error: {error}"),
    }

    let oversized_markdown = vec![b'x'; 65_537];
    match SkillManifest::parse(Path::new("valid-skill"), &oversized_markdown) {
        Err(SkillManifestError::TooLarge) => {}
        Ok(_) => panic!("oversized skill markdown must be rejected"),
        Err(error) => panic!("wrong oversized-markdown error: {error}"),
    }
}

#[test]
fn activation_cannot_expand_policy_001_capabilities() {
    let manifest = parsed_manifest(&valid_markdown("network process.spawn"));
    let registry = TestSkillRegistry {
        lookup_id: "valid-skill",
        entry_id: "valid-skill",
        version: "1",
        manifest,
    };
    let id = valid_id();
    match activate_skill(&registry, &id, "1") {
        Ok(receipt) => assert!(receipt
            .instructions()
            .contains("explicit activation receipt")),
        Err(error) => panic!("skill should activate without interpreting allowed-tools: {error}"),
    }

    let requested =
        RequestedCapabilities::new([SandboxCapability::Network, SandboxCapability::ProcessSpawn]);
    let policy = PolicyCapabilities::new(std::iter::empty::<SandboxCapability>());
    match intersect_policy_capabilities(&requested, &[policy]) {
        Err(_) => {}
        Ok(_) => panic!("allowed-tools must not authorize network or process spawning"),
    }
}
