use std::{
    fmt::Display,
    num::{NonZeroU64, NonZeroUsize},
    path::Path,
};

use workflow_compiler::{
    activate_skill, ActivatedSkillResources, RegistryCategory, RegistryEntry, RegistryNotFound,
    SkillId, SkillManifest, SkillRegistry, SkillResourceError, SkillResourceId,
    SkillResourceIdError, SkillResourceInput, SkillResourceLimits,
};
use workflow_runtime::{
    intersect_policy_capabilities, EffectiveCapabilities, PageRequest, PolicyCapabilities,
    RequestedCapabilities, SandboxCapability,
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
        if (id, version) == ("resource-skill", "1") {
            Ok(RegistryEntry::new(&self.manifest, "resource-skill", "1"))
        } else {
            Err(RegistryNotFound::new(RegistryCategory::Skill, id, version))
        }
    }
}

fn manifest(allowed_tools: &str) -> SkillManifest {
    let allowed_tools = if allowed_tools.is_empty() {
        String::new()
    } else {
        format!("allowed-tools: {allowed_tools}\n")
    };
    let source = format!(
        "---\nname: resource-skill\ndescription: bounded resources\n{allowed_tools}---\nDo not dispatch.\n"
    );
    match SkillManifest::parse(Path::new("resource-skill"), source.as_bytes()) {
        Ok(manifest) => manifest,
        Err(error) => panic!("trusted fixture must parse: {error}"),
    }
}

fn activate(registry: &TestSkillRegistry) -> workflow_compiler::SkillActivationReceipt<'_> {
    let id = match SkillId::new("resource-skill") {
        Ok(id) => id,
        Err(error) => panic!("trusted fixture ID must validate: {error}"),
    };
    match activate_skill(registry, &id, "1") {
        Ok(receipt) => receipt,
        Err(error) => panic!("trusted fixture must activate: {error}"),
    }
}

fn effective(capabilities: &[SandboxCapability]) -> EffectiveCapabilities {
    let requested = RequestedCapabilities::new(capabilities.iter().copied());
    let policy = PolicyCapabilities::new(capabilities.iter().copied());
    match intersect_policy_capabilities(&requested, &[policy]) {
        Ok(effective) => effective,
        Err(error) => panic!("trusted policy must authorize its requested set: {error}"),
    }
}

fn nonzero_usize(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value) {
        Some(value) => value,
        None => panic!("trusted test limit must be nonzero"),
    }
}

fn nonzero_u64(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(value) => value,
        None => panic!("trusted test limit must be nonzero"),
    }
}

fn limits(
    max_resources: usize,
    max_resource_bytes: u64,
    max_page_bytes: u64,
    max_total_read_bytes: u64,
) -> SkillResourceLimits {
    SkillResourceLimits::new(
        nonzero_usize(max_resources),
        nonzero_u64(max_resource_bytes),
        nonzero_u64(max_page_bytes),
        nonzero_u64(max_total_read_bytes),
    )
}

fn resource_id(value: &str) -> SkillResourceId {
    match SkillResourceId::new(value) {
        Ok(id) => id,
        Err(error) => panic!("trusted resource ID must validate: {error}"),
    }
}

fn attach<'a>(
    receipt: &'a workflow_compiler::SkillActivationReceipt<'a>,
    capabilities: &EffectiveCapabilities,
    limits: SkillResourceLimits,
    resources: impl IntoIterator<Item = SkillResourceInput>,
) -> ActivatedSkillResources<'a> {
    match receipt.attach_resources(capabilities, limits, resources) {
        Ok(resources) => resources,
        Err(error) => panic!("trusted resources must attach: {error}"),
    }
}

fn assert_private_error(error: impl Display, hostile_input: &str) {
    let rendered = error.to_string();
    assert_eq!(rendered.lines().count(), 1);
    assert!(!rendered.contains(hostile_input));
}

#[test]
fn bounded_list_and_paged_read_require_activation_without_dispatch() {
    let registry = TestSkillRegistry {
        manifest: manifest("network process.spawn"),
    };
    let receipt = activate(&registry);
    let capabilities = effective(&[SandboxCapability::FilesystemRead]);
    let guide = resource_id("references/guide.md");
    let logo = resource_id("assets/logo.bin");
    let mut resources = attach(
        &receipt,
        &capabilities,
        limits(2, 8, 3, 8),
        [
            SkillResourceInput::file(guide.clone(), b"abcd".to_vec()),
            SkillResourceInput::file(logo.clone(), b"xy".to_vec()),
        ],
    );

    let listed = resources.list_skill_resources();
    assert_eq!(listed.resources().len(), 2);
    assert_eq!(listed.resources()[0].id().as_str(), "assets/logo.bin");
    assert_eq!(listed.resources()[1].id().as_str(), "references/guide.md");
    assert_eq!(listed.resources()[1].byte_len(), 4);
    assert_eq!(listed.resources()[1].artifact_id().as_str().len(), 64);

    let first = match resources.read_skill_resource(&guide, PageRequest::new(0, nonzero_u64(8))) {
        Ok(read) => read,
        Err(error) => panic!("first page must read: {error}"),
    };
    assert_eq!(first.metadata().id(), &guide);
    assert_eq!(first.page().bytes(), b"abc");
    assert_eq!(first.page().next_offset(), Some(3));
    let second = match resources.read_skill_resource(&guide, PageRequest::new(3, nonzero_u64(8))) {
        Ok(read) => read.into_page(),
        Err(error) => panic!("terminal page must read: {error}"),
    };
    assert_eq!(second.bytes(), b"d");
    assert_eq!(second.next_offset(), None);

    let terminal = match resources.read_skill_resource(&guide, PageRequest::new(4, nonzero_u64(8)))
    {
        Ok(read) => read.into_page(),
        Err(error) => panic!("payload-end page must read: {error}"),
    };
    assert!(terminal.bytes().is_empty());
    assert_eq!(terminal.next_offset(), None);

    let missing = resource_id("references/missing=do-not-echo");
    match resources.read_skill_resource(&missing, PageRequest::new(0, nonzero_u64(8))) {
        Err(error @ SkillResourceError::ResourceNotFound) => {
            assert_private_error(error, "do-not-echo")
        }
        Ok(_) => panic!("missing resource must fail closed"),
        Err(error) => panic!("wrong missing-resource error: {error}"),
    }
    match resources.read_skill_resource(&guide, PageRequest::new(5, nonzero_u64(8))) {
        Err(error @ SkillResourceError::PageOutOfBounds) => {
            assert_private_error(error, "do-not-echo")
        }
        Ok(_) => panic!("past-end page must fail closed"),
        Err(error) => panic!("wrong past-end page error: {error}"),
    }
}

#[test]
fn traversal_absolute_and_invalid_resource_ids_fail_closed() {
    let cases = [
        ("", SkillResourceIdError::Empty),
        ("/assets/logo", SkillResourceIdError::Absolute),
        ("references/../secret", SkillResourceIdError::Traversal),
        ("references//secret", SkillResourceIdError::InvalidComponent),
        (
            "references/./secret",
            SkillResourceIdError::InvalidComponent,
        ),
        (
            "assets/secret\u{7f}",
            SkillResourceIdError::ControlCharacter,
        ),
        ("SKILL.md", SkillResourceIdError::DisallowedPrefix),
        ("scripts/install.sh", SkillResourceIdError::DisallowedPrefix),
        ("skill.runtime.toml", SkillResourceIdError::DisallowedPrefix),
        ("other/path", SkillResourceIdError::DisallowedPrefix),
    ];
    for (raw, expected) in cases {
        match SkillResourceId::new(raw) {
            Err(error) => assert_eq!(error, expected),
            Ok(_) => panic!("invalid resource ID must fail closed"),
        }
    }
    let oversized = format!("assets/{}", "x".repeat(1_018));
    match SkillResourceId::new(&oversized) {
        Err(SkillResourceIdError::TooLong) => {}
        Ok(_) => panic!("oversized resource ID must fail closed"),
        Err(error) => panic!("wrong oversized-resource error: {error}"),
    }
}

#[test]
fn symlink_escape_is_rejected_without_echoing_target() {
    let registry = TestSkillRegistry {
        manifest: manifest("network"),
    };
    let receipt = activate(&registry);
    let capabilities = effective(&[SandboxCapability::FilesystemRead]);
    let target = "../../private/credential=do-not-echo";
    let result = receipt.attach_resources(
        &capabilities,
        limits(1, 8, 8, 8),
        [SkillResourceInput::symlink(
            resource_id("references/link"),
            target.to_owned(),
        )],
    );
    match result {
        Err(SkillResourceError::SymlinkRejected) => {
            assert_private_error(SkillResourceError::SymlinkRejected, target)
        }
        Ok(_) => panic!("every symlink must be rejected"),
        Err(error) => panic!("wrong symlink error: {error}"),
    }
}

#[test]
fn oversized_payload_and_total_read_budget_fail_closed() {
    struct TooManyResourcesCanary {
        pulled: usize,
    }

    impl Iterator for TooManyResourcesCanary {
        type Item = SkillResourceInput;

        fn next(&mut self) -> Option<Self::Item> {
            self.pulled += 1;
            match self.pulled {
                1 => Some(SkillResourceInput::file(
                    resource_id("assets/first"),
                    b"one".to_vec(),
                )),
                2 => Some(SkillResourceInput::file(
                    resource_id("assets/too-many=do-not-echo"),
                    b"two".to_vec(),
                )),
                _ => panic!("resource iterator was read past max_resources + 1"),
            }
        }
    }

    let registry = TestSkillRegistry {
        manifest: manifest(""),
    };
    let receipt = activate(&registry);
    let capabilities = effective(&[SandboxCapability::FilesystemRead]);

    let too_many = receipt.attach_resources(
        &capabilities,
        limits(1, 4, 2, 3),
        TooManyResourcesCanary { pulled: 0 },
    );
    match too_many {
        Err(error @ SkillResourceError::TooManyResources) => {
            assert_private_error(error, "do-not-echo")
        }
        Ok(_) => panic!("resource count over the limit must fail closed"),
        Err(error) => panic!("wrong resource-count error: {error}"),
    }

    let duplicate_id = resource_id("assets/duplicate=do-not-echo");
    let duplicate = receipt.attach_resources(
        &capabilities,
        limits(2, 4, 2, 3),
        [
            SkillResourceInput::file(duplicate_id.clone(), b"one".to_vec()),
            SkillResourceInput::file(duplicate_id, b"two".to_vec()),
        ],
    );
    match duplicate {
        Err(error @ SkillResourceError::DuplicateResource) => {
            assert_private_error(error, "do-not-echo")
        }
        Ok(_) => panic!("duplicate resource IDs must fail closed"),
        Err(error) => panic!("wrong duplicate-resource error: {error}"),
    }

    let empty = receipt.attach_resources(
        &capabilities,
        limits(1, 4, 2, 3),
        [SkillResourceInput::file(
            resource_id("assets/empty=do-not-echo"),
            Vec::new(),
        )],
    );
    match empty {
        Err(error @ SkillResourceError::EmptyPayload) => assert_private_error(error, "do-not-echo"),
        Ok(_) => panic!("empty resource payload must fail closed"),
        Err(error) => panic!("wrong empty-payload error: {error}"),
    }

    let oversized = receipt.attach_resources(
        &capabilities,
        limits(1, 4, 2, 3),
        [SkillResourceInput::file(
            resource_id("assets/large"),
            b"12345".to_vec(),
        )],
    );
    match oversized {
        Err(SkillResourceError::PayloadTooLarge) => {}
        Ok(_) => panic!("oversized payload must fail closed"),
        Err(error) => panic!("wrong oversized-payload error: {error}"),
    }

    let id = resource_id("assets/readable");
    let mut resources = attach(
        &receipt,
        &capabilities,
        limits(1, 4, 2, 3),
        [SkillResourceInput::file(id.clone(), b"abcd".to_vec())],
    );
    let first = match resources.read_skill_resource(&id, PageRequest::new(0, nonzero_u64(4))) {
        Ok(read) => read.into_page(),
        Err(error) => panic!("page bounded by the artifact store must read: {error}"),
    };
    assert_eq!(first.bytes(), b"ab");
    let over_budget = resources.read_skill_resource(&id, PageRequest::new(0, nonzero_u64(4)));
    match over_budget {
        Err(SkillResourceError::TotalReadExceeded) => {}
        Ok(_) => panic!("over-budget read must fail atomically"),
        Err(error) => panic!("wrong total-budget error: {error}"),
    }
    let remaining = match resources.read_skill_resource(&id, PageRequest::new(2, nonzero_u64(1))) {
        Ok(read) => read.into_page(),
        Err(error) => panic!("failed read must not consume the remaining budget: {error}"),
    };
    assert_eq!(remaining.bytes(), b"c");
}

#[test]
fn resource_access_cannot_expand_policy_001_capabilities() {
    let registry = TestSkillRegistry {
        manifest: manifest("network process.spawn"),
    };
    let receipt = activate(&registry);
    let filesystem_read = effective(&[SandboxCapability::FilesystemRead]);
    let id = resource_id("references/only-read");
    let mut resources = attach(
        &receipt,
        &filesystem_read,
        limits(1, 8, 8, 8),
        [SkillResourceInput::file(id.clone(), b"safe".to_vec())],
    );
    assert_eq!(
        filesystem_read.capabilities(),
        &[SandboxCapability::FilesystemRead]
    );
    match resources.read_skill_resource(&id, PageRequest::new(0, nonzero_u64(8))) {
        Ok(_) => {}
        Err(error) => panic!("filesystem-read policy must permit resource reads: {error}"),
    }
    assert_eq!(
        filesystem_read.capabilities(),
        &[SandboxCapability::FilesystemRead]
    );

    let no_filesystem_read = effective(&[SandboxCapability::Network]);
    let denied = receipt.attach_resources(
        &no_filesystem_read,
        limits(1, 8, 8, 8),
        [SkillResourceInput::file(id, b"safe".to_vec())],
    );
    match denied {
        Err(SkillResourceError::CapabilityDenied) => {}
        Ok(_) => panic!("instruction claims must not grant filesystem read"),
        Err(error) => panic!("wrong capability error: {error}"),
    }
}
