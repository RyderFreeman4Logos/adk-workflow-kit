use workflow_runtime::{
    intersect_policy_capabilities, CapabilityPolicyDenied, EffectiveCapabilities,
    PolicyCapabilities, RequestedCapabilities, SandboxCapability,
};

const ALL_CAPABILITIES: [SandboxCapability; 15] = [
    SandboxCapability::FilesystemRead,
    SandboxCapability::FilesystemWrite,
    SandboxCapability::Network,
    SandboxCapability::ProcessSpawn,
    SandboxCapability::MaximumPids,
    SandboxCapability::CpuTime,
    SandboxCapability::WallTime,
    SandboxCapability::IdleTime,
    SandboxCapability::Memory,
    SandboxCapability::OutputBytes,
    SandboxCapability::OpenFiles,
    SandboxCapability::EnvironmentVariables,
    SandboxCapability::SyscallProfile,
    SandboxCapability::UserGroupIdentity,
    SandboxCapability::DeviceAccess,
];

fn capabilities(mask: u16) -> Vec<SandboxCapability> {
    ALL_CAPABILITIES
        .iter()
        .enumerate()
        .filter_map(|(index, capability)| (mask & (1 << index) != 0).then_some(*capability))
        .collect()
}

fn sorted(mut capabilities: Vec<SandboxCapability>) -> Vec<SandboxCapability> {
    capabilities.sort_unstable_by_key(SandboxCapability::as_str);
    capabilities
}

#[test]
fn common_requested_capabilities_are_authorized() {
    let requested = RequestedCapabilities::new([
        SandboxCapability::Network,
        SandboxCapability::FilesystemRead,
    ]);
    let policy_layers = [
        PolicyCapabilities::new([
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::Network,
        ]),
        PolicyCapabilities::new([
            SandboxCapability::FilesystemRead,
            SandboxCapability::Network,
            SandboxCapability::ProcessSpawn,
        ]),
    ];

    match intersect_policy_capabilities(&requested, &policy_layers) {
        Ok(effective) => assert_eq!(
            effective.capabilities(),
            &[
                SandboxCapability::FilesystemRead,
                SandboxCapability::Network
            ]
        ),
        Err(denied) => panic!("common capabilities must be authorized: {denied}"),
    }
}

#[test]
fn one_layer_veto_denies_the_complete_request() {
    let requested = RequestedCapabilities::new([
        SandboxCapability::Network,
        SandboxCapability::ProcessSpawn,
        SandboxCapability::Network,
    ]);
    let policy_layers = [
        PolicyCapabilities::new([SandboxCapability::Network, SandboxCapability::ProcessSpawn]),
        PolicyCapabilities::new([SandboxCapability::Network]),
    ];

    match intersect_policy_capabilities(&requested, &policy_layers) {
        Ok(effective) => panic!(
            "a vetoed request must not be partially authorized: {:?}",
            effective.capabilities()
        ),
        Err(denied) => assert_eq!(denied.missing(), &[SandboxCapability::ProcessSpawn]),
    }
}

#[test]
fn zero_policy_layers_deny_by_default() {
    let requested = RequestedCapabilities::new([
        SandboxCapability::Network,
        SandboxCapability::FilesystemRead,
        SandboxCapability::Network,
    ]);

    match intersect_policy_capabilities(&requested, &[]) {
        Ok(effective) => panic!(
            "zero policy layers must not authorize: {:?}",
            effective.capabilities()
        ),
        Err(denied) => assert_eq!(
            denied.missing(),
            &[
                SandboxCapability::FilesystemRead,
                SandboxCapability::Network
            ]
        ),
    }
}

#[test]
fn an_empty_layer_denies_a_nonempty_request() {
    let requested = RequestedCapabilities::new([SandboxCapability::Network]);
    let policy_layers = [
        PolicyCapabilities::new([SandboxCapability::Network]),
        PolicyCapabilities::new([]),
    ];

    match intersect_policy_capabilities(&requested, &policy_layers) {
        Ok(effective) => panic!(
            "an empty policy layer must deny: {:?}",
            effective.capabilities()
        ),
        Err(denied) => assert_eq!(denied.missing(), &[SandboxCapability::Network]),
    }
}

#[test]
fn empty_requests_are_typed_denials() {
    let requested = RequestedCapabilities::new([]);
    let policy_layers = [PolicyCapabilities::new([SandboxCapability::Network])];
    let result: Result<EffectiveCapabilities, CapabilityPolicyDenied> =
        intersect_policy_capabilities(&requested, &policy_layers);

    match result {
        Ok(effective) => panic!(
            "an empty request must not yield effective capabilities: {:?}",
            effective.capabilities()
        ),
        Err(denied) => assert!(denied.missing().is_empty()),
    }
}

#[test]
fn effective_capabilities_never_expand_privilege_over_a_deterministic_corpus() {
    let all_mask = (1 << ALL_CAPABILITIES.len()) - 1;
    let policy_masks = [0, all_mask, 0b0101_0101_0101_0101, 0b0011_0011_0011_0011];

    for requested_mask in 0..=all_mask {
        let requested_capabilities = capabilities(requested_mask);
        let requested = RequestedCapabilities::new(requested_capabilities.iter().copied());

        for first_policy_mask in policy_masks {
            for second_policy_mask in policy_masks {
                let first_policy = capabilities(first_policy_mask);
                let second_policy = capabilities(second_policy_mask);
                let policy_layers = [
                    PolicyCapabilities::new(first_policy.iter().copied()),
                    PolicyCapabilities::new(second_policy.iter().copied()),
                ];
                let expected_effective = sorted(
                    requested_capabilities
                        .iter()
                        .copied()
                        .filter(|capability| {
                            first_policy.contains(capability) && second_policy.contains(capability)
                        })
                        .collect(),
                );

                match intersect_policy_capabilities(&requested, &policy_layers) {
                    Ok(effective) => {
                        assert!(!effective.capabilities().is_empty());
                        assert_eq!(effective.capabilities(), expected_effective);
                        assert!(effective
                            .capabilities()
                            .iter()
                            .all(|capability| requested_capabilities.contains(capability)));
                        assert!(effective
                            .capabilities()
                            .iter()
                            .all(|capability| first_policy.contains(capability)));
                        assert!(effective
                            .capabilities()
                            .iter()
                            .all(|capability| second_policy.contains(capability)));
                    }
                    Err(denied) => {
                        let expected_missing = sorted(
                            requested_capabilities
                                .iter()
                                .copied()
                                .filter(|capability| !expected_effective.contains(capability))
                                .collect(),
                        );
                        assert_eq!(denied.missing(), expected_missing);
                    }
                }
            }
        }
    }
}
