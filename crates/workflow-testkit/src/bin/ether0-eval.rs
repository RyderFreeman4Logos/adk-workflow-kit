//! Fixed, license-gated FutureHouse ether0 benchmark smoke command.
use std::{env, fs, os::unix::fs::DirBuilderExt, path::Path};
use workflow_runtime::{DatasetManifest, HttpByteSource};

const MANIFEST: &str = include_str!("../../../../config/datasets.toml");
const URL: &str = "https://huggingface.co/datasets/futurehouse/ether0-benchmark/resolve/c7d5e59960087f360bc32a5006bb994324b38c35/data/test-00000-of-00001.parquet";
const REVISION: &str = "c7d5e59960087f360bc32a5006bb994324b38c35";
const SHA: &str = "sha256:c53213a37ef319aa7f733751b93748db960cce33355c1d44124108e7f15c5bbc";

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5
        || !matches!(args[2].as_str(), "accept-cc-by-4.0" | "deny")
        || !matches!(args[3].as_str(), "online" | "offline")
    {
        return Err(
            "usage: ether0-eval CACHE_DIR accept-cc-by-4.0|deny online|offline CASES(1..8)".into(),
        );
    }
    if args[2] != "accept-cc-by-4.0" {
        return Err("dataset license acceptance is required".into());
    }
    let limit: usize = args[4].parse().map_err(|_| "invalid case limit")?;
    if !(1..=8).contains(&limit) {
        return Err("invalid case limit".into());
    }
    let manifest = DatasetManifest::parse_str(MANIFEST).map_err(|error| error.to_string())?;
    let entry = manifest.dataset("ether0").ok_or("missing pinned dataset")?;
    if entry.url() != URL
        || entry.revision() != REVISION
        || entry.sha256() != SHA
        || entry.license() != "CC-BY-4.0"
        || !entry.license_acceptance_required()
    {
        return Err("committed dataset pin mismatch".into());
    }
    let source =
        HttpByteSource::new(URL, REVISION, SHA, 100_000).map_err(|error| error.to_string())?;
    let requested = Path::new(&args[1]);
    let leaf = requested
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid cache directory")?;
    if leaf.is_empty()
        || !leaf
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("invalid cache directory".into());
    }
    let allowed = Path::new(&env::var("HOME").map_err(|_| "HOME is required")?)
        .join("tmp")
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if requested
        .parent()
        .ok_or("invalid cache directory")?
        .canonicalize()
        .map_err(|error| error.to_string())?
        != allowed
    {
        return Err("cache must be a direct child of ~/tmp".into());
    }
    let cache = allowed.join(leaf);
    match fs::symlink_metadata(&cache) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err("unsafe cache directory".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&cache)
                .map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    let path = workflow_testkit::run_dataset_product(
        &manifest,
        "ether0",
        &source,
        &cache,
        true,
        args[3] == "offline",
        limit,
    )?;
    println!("{}", path.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
