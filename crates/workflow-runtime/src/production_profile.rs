use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

/// The fixed profile name for production Verbatim execution.
pub const PRODUCTION_PROFILE_NAME: &str = "production";

/// Allocates isolated workdirs for production Verbatim workflows.
pub struct ProductionProfile {
    workdirs: WorkdirManager,
}

impl ProductionProfile {
    /// Creates a production profile over a caller-managed workdir base.
    pub fn new(base: impl AsRef<Path>) -> Result<Self, ProductionProfileError> {
        WorkdirManager::new(base)
            .map(|workdirs| Self { workdirs })
            .map_err(|_| {
                ProductionProfileError::new(
                    ProductionProfileErrorKind::WorkdirIsolationBreach,
                    None,
                )
            })
    }

    /// Binds a production workdir without a source-truth path.
    pub fn bind(&self, run_id: &RunId) -> Result<ProductionProfileBinding, ProductionProfileError> {
        let workdir = self.workdirs.allocate(run_id).map_err(|_| {
            ProductionProfileError::new(ProductionProfileErrorKind::WorkdirIsolationBreach, None)
        })?;
        Ok(ProductionProfileBinding {
            workdir,
            source_root: None,
        })
    }

    /// Binds a production workdir while retaining the source-truth boundary.
    pub fn bind_with_source(
        &self,
        run_id: &RunId,
        source_root: impl AsRef<Path>,
    ) -> Result<ProductionProfileBinding, ProductionProfileError> {
        let source_root = source_root.as_ref();
        if !source_root.is_absolute() {
            return Err(ProductionProfileError::new(
                ProductionProfileErrorKind::SourceTruthViolation,
                None,
            ));
        }
        let source_root = fs::canonicalize(source_root).map_err(|_| {
            ProductionProfileError::new(ProductionProfileErrorKind::SourceTruthViolation, None)
        })?;
        if self.workdirs.base_path().starts_with(&source_root) {
            return Err(ProductionProfileError::new(
                ProductionProfileErrorKind::SourceTruthViolation,
                None,
            ));
        }
        let workdir = self.workdirs.allocate(run_id).map_err(|_| {
            ProductionProfileError::new(ProductionProfileErrorKind::WorkdirIsolationBreach, None)
        })?;
        Ok(ProductionProfileBinding {
            workdir,
            source_root: Some(source_root),
        })
    }
}

/// A successfully bound production profile.
pub struct ProductionProfileBinding {
    workdir: RunWorkdir,
    source_root: Option<PathBuf>,
}

impl ProductionProfileBinding {
    /// Returns the stable profile name.
    pub const fn profile_name(&self) -> &'static str {
        PRODUCTION_PROFILE_NAME
    }

    /// Returns the capabilities granted to the sandbox bind.
    pub fn requested(&self) -> RequestedCapabilities {
        RequestedCapabilities::new([
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
        ])
    }

    /// Rejects paths that would replace or write Verbatim source truth.
    pub fn validate_source_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), ProductionProfileError> {
        let Some(source_root) = &self.source_root else {
            return Err(ProductionProfileError::new(
                ProductionProfileErrorKind::SourceTruthViolation,
                None,
            ));
        };
        let path = path.as_ref();
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(ProductionProfileError::new(
                ProductionProfileErrorKind::SourceTruthViolation,
                None,
            ));
        }
        let Ok(canonical_path) = fs::canonicalize(path) else {
            return Err(ProductionProfileError::new(
                ProductionProfileErrorKind::SourceTruthViolation,
                None,
            ));
        };
        if canonical_path.starts_with(source_root) {
            Err(ProductionProfileError::new(
                ProductionProfileErrorKind::SourceTruthViolation,
                None,
            ))
        } else {
            Ok(())
        }
    }

    /// Requires writes to stay inside the allocated production workdir.
    pub fn validate_workdir_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), ProductionProfileError> {
        let path = path.as_ref();
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            Err(ProductionProfileError::new(
                ProductionProfileErrorKind::WorkdirIsolationBreach,
                None,
            ))
        } else {
            let mut existing_prefix = path.to_path_buf();
            while fs::symlink_metadata(&existing_prefix).is_err() {
                if !existing_prefix.pop() {
                    return Err(ProductionProfileError::new(
                        ProductionProfileErrorKind::WorkdirIsolationBreach,
                        None,
                    ));
                }
            }
            let Ok(canonical_prefix) = fs::canonicalize(existing_prefix) else {
                return Err(ProductionProfileError::new(
                    ProductionProfileErrorKind::WorkdirIsolationBreach,
                    None,
                ));
            };
            if canonical_prefix.starts_with(self.workdir.root())
                && !self
                    .source_root
                    .as_ref()
                    .is_some_and(|source_root| canonical_prefix.starts_with(source_root))
            {
                Ok(())
            } else {
                Err(ProductionProfileError::new(
                    ProductionProfileErrorKind::WorkdirIsolationBreach,
                    None,
                ))
            }
        }
    }

    /// Returns the isolated run workdir.
    pub fn workdir(&self) -> &RunWorkdir {
        &self.workdir
    }
}

/// A registry that refuses to substitute another profile for production.
#[derive(Default)]
pub struct ProductionProfileRegistry {
    production: Option<ProductionProfile>,
}

impl ProductionProfileRegistry {
    /// Registers the sole production profile.
    pub fn with_production(profile: ProductionProfile) -> Self {
        Self {
            production: Some(profile),
        }
    }

    /// Selects a named profile and fails closed when production is absent.
    pub fn select(&self, name: &str) -> Result<&ProductionProfile, ProductionProfileError> {
        if name == PRODUCTION_PROFILE_NAME {
            self.production.as_ref().ok_or_else(|| {
                ProductionProfileError::new(
                    ProductionProfileErrorKind::MissingProductionProfile,
                    None,
                )
            })
        } else {
            Err(ProductionProfileError::new(
                ProductionProfileErrorKind::MissingProductionProfile,
                None,
            ))
        }
    }
}

/// Typed diagnostics for production profile binding failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionProfileErrorKind {
    /// No production profile was registered for a production selection.
    MissingProductionProfile,
    /// A source-truth or adapter ACL boundary would be crossed.
    SourceTruthViolation,
    /// A path is outside the isolated production workdir.
    WorkdirIsolationBreach,
}

/// A privacy-safe production profile error.
pub struct ProductionProfileError {
    kind: ProductionProfileErrorKind,
}

impl ProductionProfileError {
    fn new(kind: ProductionProfileErrorKind, _path: Option<&Path>) -> Self {
        Self { kind }
    }

    /// Returns the stable error category.
    pub const fn kind(&self) -> ProductionProfileErrorKind {
        self.kind
    }
}

impl fmt::Debug for ProductionProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionProfileError")
            .field("kind", &self.kind)
            .field("path", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for ProductionProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self.kind {
            ProductionProfileErrorKind::MissingProductionProfile => "missing_production_profile",
            ProductionProfileErrorKind::SourceTruthViolation => "source_truth_violation",
            ProductionProfileErrorKind::WorkdirIsolationBreach => "workdir_isolation_breach",
        };
        write!(formatter, "production profile rejected <redacted> ({code})")
    }
}

impl std::error::Error for ProductionProfileError {}

use crate::{
    HotReloadError, HotReloadErrorKind, PureTransformBinding, RequestedCapabilities, RunId,
    RunWorkdir, SandboxCapability, WorkdirManager,
};

impl ProductionProfileBinding {
    /// Rejects hot reload so production cannot gain a live-reload path.
    pub fn reload(
        &self,
        _expected_current_digest: &str,
        _workflow_id: impl Into<String>,
        _workflow_version: impl Into<String>,
        _module_digest: impl Into<String>,
        _module: Option<&[u8]>,
    ) -> Result<PureTransformBinding, HotReloadError> {
        Err(HotReloadError::new(
            HotReloadErrorKind::ProductionReloadForbidden,
        ))
    }
}
