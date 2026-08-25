use std::fmt;

use crate::PureTransformBinding;

/// A development-only immutable package publisher.
pub struct DevelopmentHotReload {
    current: PureTransformBinding,
}

impl DevelopmentHotReload {
    /// Starts a publisher with the package used by new runs.
    pub fn new(initial: PureTransformBinding) -> Self {
        Self { current: initial }
    }

    /// Returns the package identity currently used by new runs.
    pub fn current(&self) -> &PureTransformBinding {
        &self.current
    }

    /// Captures an immutable package identity for an in-flight run.
    pub fn start_run(&self) -> PureTransformBinding {
        self.current.clone()
    }

    /// Publishes a new package without changing identities already captured by runs.
    pub fn reload(
        &mut self,
        expected_current_digest: &str,
        workflow_id: impl Into<String>,
        workflow_version: impl Into<String>,
        module_digest: impl Into<String>,
        module: Option<&[u8]>,
    ) -> Result<PureTransformBinding, HotReloadError> {
        if self.current.module_digest() != expected_current_digest {
            return Err(HotReloadError::new(HotReloadErrorKind::IdentityDrift));
        }
        let module =
            module.ok_or_else(|| HotReloadError::new(HotReloadErrorKind::MissingPackage))?;
        let replacement =
            PureTransformBinding::new(workflow_id, workflow_version, module_digest, module)
                .map_err(|_| HotReloadError::new(HotReloadErrorKind::InvalidPackage))?;
        if replacement.module_digest() == self.current.module_digest() {
            return Err(HotReloadError::new(HotReloadErrorKind::IdentityDrift));
        }
        self.current = replacement.clone();
        Ok(replacement)
    }
}

/// Typed failure for a hot-reload bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotReloadErrorKind {
    /// Production profile/bind is never reloadable.
    ProductionReloadForbidden,
    /// No replacement package was supplied.
    MissingPackage,
    /// Replacement package identity or bytes are invalid.
    InvalidPackage,
    /// The publisher's expected identity is stale or unchanged.
    IdentityDrift,
}

/// Privacy-safe hot-reload diagnostic.
pub struct HotReloadError {
    kind: HotReloadErrorKind,
}

impl HotReloadError {
    pub(crate) const fn new(kind: HotReloadErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable typed failure category.
    pub const fn kind(&self) -> HotReloadErrorKind {
        self.kind
    }
}

impl fmt::Debug for HotReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HotReloadError")
            .field("kind", &self.kind)
            .field("package", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for HotReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self.kind {
            HotReloadErrorKind::ProductionReloadForbidden => "production_reload_forbidden",
            HotReloadErrorKind::MissingPackage => "missing_package",
            HotReloadErrorKind::InvalidPackage => "invalid_package",
            HotReloadErrorKind::IdentityDrift => "identity_drift",
        };
        write!(formatter, "hot reload rejected <redacted> ({code})")
    }
}

impl std::error::Error for HotReloadError {}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::{DevelopmentHotReload, HotReloadErrorKind};
    use crate::{
        ProductionProfile, PureTransformBinding, PureTransformPlanV1, RequestedCapabilities, RunId,
        SandboxCapability,
    };

    fn digest(module: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(module))
    }

    fn binding(version: &str, module: &[u8]) -> PureTransformBinding {
        PureTransformBinding::new("workflow", version, digest(module), module)
            .expect("canary package must be valid")
    }

    #[test]
    fn canary_hotreload_80_publishes_new_immutable_bind() {
        let old = b"CANARY_HOTRELOAD_80_A";
        let new = b"CANARY_HOTRELOAD_80_B";
        let mut publisher = DevelopmentHotReload::new(binding("1", old));
        let old_run = publisher.start_run();
        let replacement = publisher
            .reload(
                digest(old).as_str(),
                "workflow",
                "2",
                digest(new),
                Some(new),
            )
            .expect("development reload must bind a changed package");
        assert_eq!(old_run.module_digest(), digest(old));
        assert_eq!(replacement.module_digest(), digest(new));
        assert_eq!(publisher.current().module_digest(), digest(new));
    }

    #[test]
    fn canary_inflight_old_pkg_80_remains_on_old_package() {
        let old = b"CANARY_INFLIGHT_OLD_PKG_80_A";
        let new = b"CANARY_INFLIGHT_OLD_PKG_80_B";
        let mut publisher = DevelopmentHotReload::new(binding("1", old));
        let in_flight = publisher.start_run();
        publisher
            .reload(
                "not-the-current-digest",
                "workflow",
                "2",
                digest(new),
                Some(new),
            )
            .expect_err("stale reload must fail closed");
        assert_eq!(in_flight.module_bytes(), old);
        assert_eq!(publisher.current().module_bytes(), old);
        let replacement = publisher
            .reload(
                digest(old).as_str(),
                "workflow",
                "2",
                digest(new),
                Some(new),
            )
            .expect("changed package must publish");
        assert_eq!(replacement.module_bytes(), new);
        assert_eq!(in_flight.module_bytes(), old);
        let explanation = PureTransformPlanV1::new(
            in_flight,
            json!({"value": 7}),
            RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
        )
        .expect("captured binding must remain explainable")
        .render();
        assert!(explanation.contains(&format!("module_digest={}", digest(old))));
    }

    #[test]
    fn typed_missing_invalid_and_identity_failures_are_distinct() {
        let old = b"CANARY_PROD_NO_RELOAD_80";
        let mut publisher = DevelopmentHotReload::new(binding("1", old));
        assert_eq!(
            publisher
                .reload(digest(old).as_str(), "workflow", "2", digest(old), None)
                .expect_err("missing package must fail")
                .kind(),
            HotReloadErrorKind::MissingPackage
        );
        assert_eq!(
            publisher
                .reload(
                    digest(old).as_str(),
                    "workflow",
                    "2",
                    "bad",
                    Some(b"invalid")
                )
                .expect_err("invalid package must fail")
                .kind(),
            HotReloadErrorKind::InvalidPackage
        );
        assert_eq!(
            publisher
                .reload("stale", "workflow", "2", digest(b"new"), Some(b"new"))
                .expect_err("identity drift must fail")
                .kind(),
            HotReloadErrorKind::IdentityDrift
        );
    }

    #[test]
    fn canary_prod_no_reload_80_fails_closed_with_typed_diagnostic() {
        let base = std::env::temp_dir().join(format!(
            "workflow-runtime-production-reload-80-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).expect("production test base must be created");
        let profile = ProductionProfile::new(&base).expect("production profile must bind");
        let run_id = RunId::new(String::from("CANARY_PROD_NO_RELOAD_80"))
            .expect("canary run ID must be valid");
        let binding = profile.bind(&run_id).expect("production bind must succeed");
        let module = b"production-reload-module";
        let digest = digest(module);
        assert_eq!(
            binding
                .reload("current", "workflow", "1", digest, Some(module))
                .expect_err("production hot reload must be forbidden")
                .kind(),
            HotReloadErrorKind::ProductionReloadForbidden
        );
        let _ = std::fs::remove_dir_all(base);
    }
}
