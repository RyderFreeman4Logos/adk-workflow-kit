use std::path::Path;

use workflow_compiler::{
    RegistryCategory, RegistryEntry, RegistryNotFound, SkillCapabilitySet, SkillDeclaration,
    SkillId, SkillManifest, SkillRegistry, retrieve_skill_candidates,
};

struct TestSkillRegistry {
    manifests: Vec<SkillManifest>,
}

impl SkillRegistry for TestSkillRegistry {
    type Implementation = SkillManifest;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        if version != "1.0.0" {
            return Err(RegistryNotFound::new(RegistryCategory::Skill, id, version));
        }
        for manifest in &self.manifests {
            let metadata = manifest.discovery_metadata();
            if metadata.id().as_str() == id {
                let canonical_id = match id {
                    "reader" => "reader",
                    "writer" => "writer",
                    _ => unreachable!("fixture ID is enumerated above"),
                };
                return Ok(RegistryEntry::new(manifest, canonical_id, "1.0.0"));
            }
        }
        Err(RegistryNotFound::new(RegistryCategory::Skill, id, version))
    }
}

fn manifest(directory: &str, description: &str) -> SkillManifest {
    let document = format!("---\nname: {directory}\ndescription: {description}\n---\n");
    SkillManifest::parse(Path::new(directory), document.as_bytes()).expect("valid fixture")
}

fn id(raw: &str) -> SkillId {
    SkillId::new(raw).expect("valid skill ID")
}

#[test]
fn retrieval_ranks_declared_skills_and_preserves_capabilities() {
    let registry = TestSkillRegistry {
        manifests: vec![
            manifest("writer", "write concise documents"),
            manifest("reader", "read source files"),
        ],
    };
    let declarations = vec![
        SkillDeclaration::new(id("reader"), "1.0.0"),
        SkillDeclaration::new(id("writer"), "1.0.0"),
    ];
    let capabilities = SkillCapabilitySet::new(["fs.read", "fs.write"]);

    let result = retrieve_skill_candidates(
        &registry,
        &declarations,
        "write documents",
        capabilities.clone(),
    );

    assert_eq!(result.capabilities(), &capabilities);
    assert_eq!(result.candidates()[0].id().as_str(), "writer");
    assert!(result.diagnostics().is_empty());
}
