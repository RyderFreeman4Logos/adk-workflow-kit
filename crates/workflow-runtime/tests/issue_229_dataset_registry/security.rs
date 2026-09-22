use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::*;

struct CountingSource(AtomicUsize);

impl ByteSource for CountingSource {
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(DatasetSourceIdentity::local_fixture(
            "memory://smoke-fixture",
            SMOKE_SHA256,
        ))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let offset = usize::try_from(offset).expect("fixture offset");
        if offset >= SMOKE_BYTES.len() {
            return Ok(0);
        }
        let count = buf.len().min(SMOKE_BYTES.len() - offset);
        buf[..count].copy_from_slice(&SMOKE_BYTES[offset..offset + count]);
        Ok(count)
    }

    fn len(&self) -> Result<u64, DatasetError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(SMOKE_BYTES.len() as u64)
    }
}

#[test]
fn unsafe_warm_cache_descendants_are_rejected_before_fetch_or_manual_reuse() {
    for (label, component, mode) in [
        ("id-group", "id", 0o770),
        ("revision-world", "revision", 0o707),
    ] {
        for (reuse, offline, manual) in [
            ("fetch-online", false, false),
            ("fetch-offline", true, false),
            ("manual-warm", false, true),
        ] {
            let root = TestRoot::new(&format!("{label}-{reuse}"));
            let cache = root.0.join("cache");
            let source = CountingSource(AtomicUsize::new(0));
            let manual_manifest =
                DatasetManifest::parse_str(&gated_toml("manual", "9f3c1aa", false))
                    .expect("manual manifest");
            let fetch_manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
            let manual_path = root.0.join("manual.txt");
            let (manifest, suite, id, source_path) = if manual {
                fs::write(&manual_path, SMOKE_BYTES).expect("manual fixture");
                super::prepare(
                    &manual_manifest,
                    &cache,
                    &source,
                    Call {
                        id: "gated",
                        suite: EvalSuite::Formal,
                        offline: false,
                        license_accepted: false,
                        manual_path: Some(manual_path.as_path()),
                    },
                )
                .expect("seed verified manual cache");
                (
                    &manual_manifest,
                    EvalSuite::Formal,
                    "gated",
                    Some(manual_path.as_path()),
                )
            } else {
                super::prepare(
                    &fetch_manifest,
                    &cache,
                    &source,
                    Call {
                        id: "smoke-fixture",
                        suite: EvalSuite::Smoke,
                        offline: false,
                        license_accepted: false,
                        manual_path: None,
                    },
                )
                .expect("seed verified fetch cache");
                (&fetch_manifest, EvalSuite::Smoke, "smoke-fixture", None)
            };

            let id_path = cache.join(id);
            let revision = if manual { "9f3c1aa" } else { "1.0.0" };
            let revision_path = id_path.join(revision);
            assert!(revision_path.join("artifact").is_file());
            assert!(revision_path.join("artifact.identity").is_file());
            let unsafe_path = if component == "id" {
                &id_path
            } else {
                &revision_path
            };
            fs::set_permissions(unsafe_path, fs::Permissions::from_mode(mode))
                .expect("make warm cache ancestor unsafe");
            let witness = root.0.join("external-witness");
            fs::write(&witness, b"unchanged").expect("external witness");
            source.0.store(0, Ordering::SeqCst);

            let result = super::prepare(
                manifest,
                &cache,
                &source,
                Call {
                    id,
                    suite,
                    offline,
                    license_accepted: false,
                    manual_path: source_path,
                },
            );
            assert_eq!(
                result
                    .expect_err("unsafe warm cache must fail closed")
                    .kind(),
                DatasetErrorKind::Io,
                "{label} {reuse}"
            );
            assert_eq!(source.0.load(Ordering::SeqCst), 0, "{label} {reuse}");
            assert_eq!(fs::read(&witness).expect("witness"), b"unchanged");
        }
    }
}
