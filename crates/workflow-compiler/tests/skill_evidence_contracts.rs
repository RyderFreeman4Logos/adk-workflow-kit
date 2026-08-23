use std::{num::NonZeroU64, path::Path};

use sha2::{Digest, Sha256};
use workflow_compiler::{
    activate_skill, RegistryCategory, RegistryEntry, RegistryNotFound, SkillActivationReceipt,
    SkillEvidence, SkillEvidenceKind, SkillEvidencePackage, SkillId, SkillManifest,
    SkillPlanningStage, SkillPromotion, SkillRegistry, SkillResourceId, SkillRuntimeLock,
    SkillRuntimeManifest,
};
use workflow_runtime::{ArtifactId, ArtifactStore, InMemoryArtifactStore};

struct TestSkillRegistry {
    manifest: SkillManifest,
    id: String,
    version: String,
}

impl SkillRegistry for TestSkillRegistry {
    type Implementation = SkillManifest;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        if (id, version) == (self.id.as_str(), self.version.as_str()) {
            Ok(RegistryEntry::new(&self.manifest, &self.id, &self.version))
        } else {
            Err(RegistryNotFound::new(RegistryCategory::Skill, id, version))
        }
    }
}

const SCHEMA: &[u8] =
    br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#;
const SCRIPT_BYTES: &[u8] = b"print('ok')\n";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn fixture() -> (SkillId, SkillRuntimeLock) {
    fixture_for("valid-skill")
}

fn fixture_for(skill_name: &str) -> (SkillId, SkillRuntimeLock) {
    let skill_id = SkillId::new(skill_name).expect("fixture Skill ID");
    let skill_markdown =
        format!("---\nname: {skill_name}\ndescription: A bounded skill.\n---\n# Instructions\n");
    let manifest = SkillManifest::parse(Path::new(skill_name), skill_markdown.as_bytes())
        .expect("fixture Skill manifest");
    let registry = TestSkillRegistry {
        manifest,
        id: skill_name.to_owned(),
        version: "1.2.3".to_owned(),
    };
    let receipt: SkillActivationReceipt<'_> =
        activate_skill(&registry, &skill_id, "1.2.3").expect("fixture activation");
    let schema_id = SkillResourceId::new("references/schema.json").expect("fixture schema ID");
    let script_id = SkillId::new("script").expect("fixture script ID");
    let runtime_manifest = format!(
        "schema_version = 1\n\n[skill]\nid = \"{skill_name}\"\nversion = \"1.2.3\"\n\n[[scripts]]\nid = \"script\"\npath = \"scripts/normalize.py\"\nruntime = \"python3\"\nsha256 = \"{}\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\ncapabilities = []\n\n[[resources]]\nid = \"references/schema.json\"\nsha256 = \"{}\"\n",
        digest(SCRIPT_BYTES),
        digest(SCHEMA)
    );
    let runtime_manifest =
        SkillRuntimeManifest::parse_for_activation(&receipt, runtime_manifest.as_bytes())
            .expect("fixture runtime manifest");
    let lock = SkillRuntimeLock::try_from_declared_bytes(
        &runtime_manifest,
        skill_markdown.as_bytes(),
        [(script_id.as_str(), SCRIPT_BYTES)],
        [(&schema_id, SCHEMA)],
    )
    .expect("fixture runtime lock");
    (skill_id, lock)
}

fn artifact() -> ArtifactId {
    let mut store = InMemoryArtifactStore::new(
        NonZeroU64::new(1024).expect("positive content limit"),
        NonZeroU64::new(1024).expect("positive page limit"),
    );
    store.put(b"redacted evidence").expect("fixture artifact")
}

fn valid_document(runtime_lock: &SkillRuntimeLock, artifact: &ArtifactId) -> String {
    format!(
        r#"{{
            "schema_version": 1,
            "skill": {{"id": "valid-skill", "version": "1.2.3"}},
            "runtime": {{
                "skill_markdown_sha256": "{}",
                "runtime_manifest_sha256": "{}"
            }},
            "scope_ref": "scope:tenant-a",
            "evidence": [{{
                "kind": "successful_run",
                "artifact_ref": "{}",
                "run_ref": "run-1"
            }}],
            "promotion": {{
                "stage": "candidate",
                "owner_ref": "owner:team-a",
                "review_refs": ["review:one"]
            }}
        }}"#,
        runtime_lock.skill_markdown_sha256(),
        runtime_lock.runtime_manifest_sha256(),
        artifact.as_str(),
    )
}

#[test]
fn redacted_evidence_fixture_validates() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);

    let package = SkillEvidencePackage::parse(
        document.as_bytes(),
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect("redacted evidence fixture must validate");

    assert_eq!(package.skill_id(), &skill_id);
    assert_eq!(package.skill_version(), "1.2.3");
    assert_eq!(package.scope_ref(), "scope:tenant-a");
    assert_eq!(package.evidence().len(), 1);
    let _: &[SkillEvidence] = package.evidence();
    assert_eq!(
        package.evidence()[0].kind(),
        SkillEvidenceKind::SuccessfulRun
    );
    assert_eq!(package.evidence()[0].artifact_ref(), &artifact);
    assert_eq!(
        package.evidence()[0].run_ref().map(|run| run.as_str()),
        Some("run-1")
    );
    assert_eq!(package.promotion().stage(), SkillPlanningStage::Candidate);
    let _: &SkillPromotion = package.promotion();
    assert_eq!(package.promotion().owner_ref(), "owner:team-a");
    assert_eq!(package.promotion().review_refs()[0], "review:one");
    let rendered = format!("{package:?}");
    for marker in ["scope:tenant-a", "owner:team-a", "run-1", artifact.as_str()] {
        assert!(!rendered.contains(marker));
    }
}

#[test]
fn unknown_raw_payload_fields_are_rejected() {
    let (skill_id, runtime_lock) = fixture();
    let error = SkillEvidencePackage::parse(
        br#"{"prompt":"SECRET_PROMPT"}"#,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        &[],
    )
    .expect_err("raw prompt fields must be rejected");

    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::UnknownPayloadField
    );
    assert!(!error.to_string().contains("SECRET_PROMPT"));
    assert!(!format!("{error:?}").contains("SECRET_PROMPT"));
}

#[test]
fn scope_and_evidence_are_required() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);

    let mut missing_scope: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    missing_scope
        .as_object_mut()
        .expect("fixture object")
        .remove("scope_ref");
    let missing_scope = serde_json::to_vec(&missing_scope).expect("scope fixture JSON");
    let error = SkillEvidencePackage::parse(
        &missing_scope,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("scope_ref is required");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::InvalidScopeRef
    );

    let mut empty_evidence: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    empty_evidence["evidence"] = serde_json::Value::Array(Vec::new());
    let empty_evidence = serde_json::to_vec(&empty_evidence).expect("evidence fixture JSON");
    let error = SkillEvidencePackage::parse(
        &empty_evidence,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("evidence must not be empty");
    assert_eq!(error, workflow_compiler::SkillEvidenceError::EmptyEvidence);
}

#[test]
fn unknown_kind_stage_and_schema_version_fail_closed() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);

    let mut unknown_kind: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    unknown_kind["evidence"][0]["kind"] = serde_json::Value::String("hostile-kind".to_owned());
    let unknown_kind = serde_json::to_vec(&unknown_kind).expect("kind fixture JSON");
    let error = SkillEvidencePackage::parse(
        &unknown_kind,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("unknown evidence kind must fail closed");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::UnknownEvidenceKind
    );

    let mut unknown_stage: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    unknown_stage["promotion"]["stage"] = serde_json::Value::String("hostile-stage".to_owned());
    let unknown_stage = serde_json::to_vec(&unknown_stage).expect("stage fixture JSON");
    let error = SkillEvidencePackage::parse(
        &unknown_stage,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("unknown planning stage must fail closed");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::UnknownPlanningStage
    );

    let mut unknown_schema: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    unknown_schema["schema_version"] = serde_json::Value::Number(99.into());
    let unknown_schema = serde_json::to_vec(&unknown_schema).expect("schema fixture JSON");
    let error = SkillEvidencePackage::parse(
        &unknown_schema,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("unsupported schema version must fail closed");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::UnsupportedSchemaVersion
    );
}

#[test]
fn owner_review_run_and_artifact_refs_fail_closed() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);

    let mut invalid_owner: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    invalid_owner["promotion"]["owner_ref"] = serde_json::Value::String(String::new());
    let invalid_owner = serde_json::to_vec(&invalid_owner).expect("owner JSON");
    let error = SkillEvidencePackage::parse(
        &invalid_owner,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("owner reference must be non-empty and opaque");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::InvalidOwnerRef
    );

    let mut invalid_review: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    invalid_review["promotion"]["review_refs"][0] =
        serde_json::Value::String("review/hostile".to_owned());
    let invalid_review = serde_json::to_vec(&invalid_review).expect("review JSON");
    let error = SkillEvidencePackage::parse(
        &invalid_review,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("review reference must be opaque");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::InvalidReviewRef
    );

    let mut invalid_run: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    invalid_run["evidence"][0]["run_ref"] = serde_json::Value::String(String::new());
    let invalid_run = serde_json::to_vec(&invalid_run).expect("run JSON");
    let error = SkillEvidencePackage::parse(
        &invalid_run,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("run reference must be non-empty");
    assert_eq!(error, workflow_compiler::SkillEvidenceError::InvalidRunRef);

    let mut unknown_artifact: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    unknown_artifact["evidence"][0]["artifact_ref"] =
        serde_json::Value::String("deadbeef".to_owned());
    let unknown_artifact = serde_json::to_vec(&unknown_artifact).expect("artifact JSON");
    let error = SkillEvidencePackage::parse(
        &unknown_artifact,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("unknown artifact reference must fail closed");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::UnknownArtifactRef
    );
}

#[test]
fn run_refs_use_the_conservative_opaque_grammar() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);

    for run_ref in [
        "/tmp/demo".to_owned(),
        "rm -rf".to_owned(),
        "run ref".to_owned(),
        "run\nref".to_owned(),
        "payload".repeat(64),
    ] {
        let mut hostile: serde_json::Value =
            serde_json::from_str(&document).expect("valid fixture JSON");
        hostile["evidence"][0]["run_ref"] = serde_json::Value::String(run_ref);
        let hostile = serde_json::to_vec(&hostile).expect("run fixture JSON");
        let error = SkillEvidencePackage::parse(
            &hostile,
            &skill_id,
            "1.2.3",
            &runtime_lock,
            std::slice::from_ref(&artifact),
        )
        .expect_err("run references must remain bounded opaque identifiers");
        assert_eq!(error, workflow_compiler::SkillEvidenceError::InvalidRunRef);
    }
}

#[test]
fn skill_and_runtime_lock_identity_must_match() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);

    let mut mismatched_skill: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    mismatched_skill["skill"]["version"] = serde_json::Value::String("9.9.9".to_owned());
    let mismatched_skill = serde_json::to_vec(&mismatched_skill).expect("skill JSON");
    let error = SkillEvidencePackage::parse(
        &mismatched_skill,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("Skill version mismatch must fail closed");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::SkillIdentityMismatch
    );

    let mut mismatched_lock: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    mismatched_lock["runtime"]["skill_markdown_sha256"] =
        serde_json::Value::String("sha256:wrong".to_owned());
    let mismatched_lock = serde_json::to_vec(&mismatched_lock).expect("runtime JSON");
    let error = SkillEvidencePackage::parse(
        &mismatched_lock,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("runtime lock digest mismatch must fail closed");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::RuntimeIdentityMismatch
    );
}

#[test]
fn split_skill_and_runtime_lock_identities_fail_closed() {
    let (skill_a, _) = fixture();
    let (_, lock_b) = fixture_for("other-skill");
    let artifact = artifact();
    let document = valid_document(&lock_b, &artifact);

    let error = SkillEvidencePackage::parse(
        document.as_bytes(),
        &skill_a,
        "1.2.3",
        &lock_b,
        std::slice::from_ref(&artifact),
    )
    .expect_err("a Skill A package must not accept Skill B runtime digests");

    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::SkillIdentityMismatch
    );
}

#[test]
fn scope_refs_use_a_conservative_opaque_grammar() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);
    let mut hostile_scope: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    hostile_scope["scope_ref"] = serde_json::Value::String("/host/path".to_owned());
    let hostile_scope = serde_json::to_vec(&hostile_scope).expect("scope JSON");
    let error = SkillEvidencePackage::parse(
        &hostile_scope,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("host paths are not opaque scope references");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::InvalidScopeRef
    );
}

#[test]
fn opaque_refs_reject_traversal_and_reserved_segments_everywhere() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);

    for value in [
        ".",
        "..",
        "scope:..",
        "GLOBAL",
        "scope:DEFAULT",
        "scope.global",
    ] {
        let mut scope: serde_json::Value =
            serde_json::from_str(&document).expect("valid fixture JSON");
        scope["scope_ref"] = serde_json::Value::String(value.to_owned());
        let scope = serde_json::to_vec(&scope).expect("scope fixture JSON");
        assert_eq!(
            SkillEvidencePackage::parse(
                &scope,
                &skill_id,
                "1.2.3",
                &runtime_lock,
                std::slice::from_ref(&artifact),
            ),
            Err(workflow_compiler::SkillEvidenceError::InvalidScopeRef)
        );

        let mut owner: serde_json::Value =
            serde_json::from_str(&document).expect("valid fixture JSON");
        owner["promotion"]["owner_ref"] = serde_json::Value::String(value.to_owned());
        let owner = serde_json::to_vec(&owner).expect("owner fixture JSON");
        assert_eq!(
            SkillEvidencePackage::parse(
                &owner,
                &skill_id,
                "1.2.3",
                &runtime_lock,
                std::slice::from_ref(&artifact),
            ),
            Err(workflow_compiler::SkillEvidenceError::InvalidOwnerRef)
        );

        let mut review: serde_json::Value =
            serde_json::from_str(&document).expect("valid fixture JSON");
        review["promotion"]["review_refs"][0] = serde_json::Value::String(value.to_owned());
        let review = serde_json::to_vec(&review).expect("review fixture JSON");
        assert_eq!(
            SkillEvidencePackage::parse(
                &review,
                &skill_id,
                "1.2.3",
                &runtime_lock,
                std::slice::from_ref(&artifact),
            ),
            Err(workflow_compiler::SkillEvidenceError::InvalidReviewRef)
        );

        let mut run: serde_json::Value =
            serde_json::from_str(&document).expect("valid fixture JSON");
        run["evidence"][0]["run_ref"] = serde_json::Value::String(value.to_owned());
        let run = serde_json::to_vec(&run).expect("run fixture JSON");
        assert_eq!(
            SkillEvidencePackage::parse(
                &run,
                &skill_id,
                "1.2.3",
                &runtime_lock,
                std::slice::from_ref(&artifact),
            ),
            Err(workflow_compiler::SkillEvidenceError::InvalidRunRef)
        );
    }
}

#[test]
fn malformed_oversized_and_unbounded_collections_fail_closed() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let oversized = vec![b' '; 65_537];
    let error = SkillEvidencePackage::parse(
        &oversized,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("oversized input must fail before JSON parsing");
    assert_eq!(error, workflow_compiler::SkillEvidenceError::TooLarge);

    let malformed = b"{not-json";
    let error = SkillEvidencePackage::parse(
        malformed,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("malformed JSON must fail closed");
    assert_eq!(error, workflow_compiler::SkillEvidenceError::InvalidJson);
}

#[test]
fn evidence_and_review_collections_are_bounded() {
    let (skill_id, runtime_lock) = fixture();
    let artifact = artifact();
    let document = valid_document(&runtime_lock, &artifact);

    let mut too_many_evidence: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    let evidence = too_many_evidence["evidence"]
        .as_array_mut()
        .expect("fixture evidence array");
    let evidence_item = evidence[0].clone();
    evidence.extend((0..64).map(|_| evidence_item.clone()));
    let too_many_evidence = serde_json::to_vec(&too_many_evidence).expect("evidence JSON");
    let error = SkillEvidencePackage::parse(
        &too_many_evidence,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("evidence collection must be bounded");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::TooManyEvidence
    );

    let mut too_many_reviews: serde_json::Value =
        serde_json::from_str(&document).expect("valid fixture JSON");
    let reviews = too_many_reviews["promotion"]["review_refs"]
        .as_array_mut()
        .expect("fixture review array");
    reviews.extend((0..64).map(|_| serde_json::Value::String("review:extra".to_owned())));
    let too_many_reviews = serde_json::to_vec(&too_many_reviews).expect("review JSON");
    let error = SkillEvidencePackage::parse(
        &too_many_reviews,
        &skill_id,
        "1.2.3",
        &runtime_lock,
        std::slice::from_ref(&artifact),
    )
    .expect_err("review collection must be bounded");
    assert_eq!(
        error,
        workflow_compiler::SkillEvidenceError::TooManyReviewRefs
    );
}
