use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    sync::atomic::{AtomicUsize, Ordering},
};

use super::*;

#[test]
fn root_link_target_hop_cannot_redirect_resumed_partial() {
    struct SwapSource<'a> {
        source: &'a ScriptedSource,
        hop: &'a Path,
        outside: &'a Path,
    }
    impl ByteSource for SwapSource<'_> {
        fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
            self.source.identity()
        }
        fn len(&self) -> Result<u64, DatasetError> {
            fs::remove_file(self.hop).expect("replace target-chain link at source boundary");
            symlink(self.outside, self.hop).expect("redirect target-chain link");
            self.source.len()
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
            self.source.read_at(offset, buf)
        }
    }

    let root = TestRoot::new("root-link-hop");
    let cache = root.0.join("configured");
    let hop_parent = root.0.join("hop-parent");
    let hop = hop_parent.join("hop");
    let safe = root.0.join("safe");
    let outside = root.0.join("outside");
    fs::create_dir(&hop_parent).expect("hop parent");
    fs::create_dir(&safe).expect("safe cache");
    fs::create_dir(&outside).expect("outside witness root");
    symlink(&safe, &hop).expect("nested target link");
    symlink(&hop, &cache).expect("configured root link");
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let call = || Call {
        id: "smoke-fixture",
        suite: EvalSuite::Smoke,
        offline: false,
        license_accepted: false,
        manual_path: None,
    };
    let interrupted = ScriptedSource::short_eof_after(SMOKE_BYTES, 8, 8);
    assert_eq!(
        super::prepare(&manifest, &cache, &interrupted, call())
            .expect_err("seed interrupted partial through trusted nested links")
            .kind(),
        DatasetErrorKind::Interrupted
    );
    let relative = Path::new("smoke-fixture/1.0.0/artifact.partial");
    let witness = outside.join(relative);
    fs::create_dir_all(witness.parent().expect("witness parent")).expect("witness parents");
    fs::copy(safe.join(relative), &witness).expect("single-link outside witness");
    fs::copy(
        safe.join("smoke-fixture/1.0.0/artifact.partial.identity"),
        outside.join("smoke-fixture/1.0.0/artifact.partial.identity"),
    )
    .expect("authentic identity for external partial");

    let source = ScriptedSource::new(SMOKE_BYTES, SMOKE_BYTES.len());
    let swapped = SwapSource {
        source: &source,
        hop: &hop,
        outside: &outside,
    };
    let prepared = super::prepare(&manifest, &cache, &swapped, call())
        .expect("validated cache root remains bound after link replacement");
    assert_eq!(prepared.checksum(), SMOKE_SHA256);
    assert_eq!(
        fs::read(&witness).expect("outside witness"),
        &SMOKE_BYTES[..8]
    );
    assert!(!outside.join("smoke-fixture/1.0.0/artifact").exists());
    assert_eq!(
        fs::read(safe.join("smoke-fixture/1.0.0/artifact")).expect("safe artifact"),
        SMOKE_BYTES
    );
}

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
fn hard_linked_partial_cannot_append_to_external_witness() {
    let root = TestRoot::new("hard-linked-partial");
    let cache = root.0.join("cache");
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let prefix_source = ScriptedSource::short_eof_after(SMOKE_BYTES, 8, 8);
    let call = || Call {
        id: "smoke-fixture",
        suite: EvalSuite::Smoke,
        offline: false,
        license_accepted: false,
        manual_path: None,
    };
    assert_eq!(
        super::prepare(&manifest, &cache, &prefix_source, call())
            .expect_err("seed a resumable partial")
            .kind(),
        DatasetErrorKind::Interrupted
    );
    let partial = cache.join("smoke-fixture/1.0.0/artifact.partial");
    let identity = cache.join("smoke-fixture/1.0.0/artifact.partial.identity");
    assert!(
        identity.is_file(),
        "retain matching source identity metadata"
    );
    let witness = root.0.join("external-witness");
    fs::rename(&partial, &witness).expect("move authentic eight-byte partial outside cache");
    fs::hard_link(&witness, &partial).expect("alias external witness into cache");
    assert_eq!(fs::metadata(&partial).expect("partial").nlink(), 2);
    assert_eq!(fs::read(&witness).expect("witness"), &SMOKE_BYTES[..8]);

    let source = ScriptedSource::new(SMOKE_BYTES, SMOKE_BYTES.len());
    let result = super::prepare(&manifest, &cache, &source, call());
    assert_eq!(
        fs::read(&witness).expect("external witness"),
        &SMOKE_BYTES[..8]
    );
    assert_eq!(
        result
            .expect_err("hard-linked partial must fail closed")
            .kind(),
        DatasetErrorKind::Io
    );
    assert!(source.served.lock().expect("served").is_empty());
    assert!(!cache.join("smoke-fixture/1.0.0/artifact").exists());
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
