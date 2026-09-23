//! Pinned dataset evaluation and durable benchmark-compatible report composition.
use crate::{EvalEnvelope, EvalFixture, EvalInput, compile_eval};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use workflow_runtime::{
    ByteSource, DatasetManifest, EvalSuite, PrepareRequest, decode_parquet_cases, prepare_dataset,
    validated_dataset_cache_root,
};

#[derive(Serialize)]
struct ProductReport<'a> {
    schema_version: u32,
    dataset: ProductDataset<'a>,
    cases: Vec<ProductCase>,
}

#[derive(Serialize)]
struct ProductDataset<'a> {
    id: &'a str,
    family: &'a str,
    language: &'a str,
    attribution: &'static str,
    source_revision: &'a str,
    source_url: &'a str,
    checksum: &'a str,
    adapter_version: &'a str,
    derivation_hash: &'a str,
}

#[derive(Serialize)]
struct ProductCase {
    case_id: String,
    evaluation: EvalEnvelope,
}

/// Runs admitted Parquet cases through the deterministic trajectory fixture
/// boundary. This acknowledges fixture execution; it does not score answers.
/// The only report destination is `<cache>/ether0-report.json`.
pub fn run_dataset_product(
    manifest: &DatasetManifest,
    id: &str,
    source: &dyn ByteSource,
    cache: &Path,
    license_accepted: bool,
    offline: bool,
    limit: usize,
) -> Result<PathBuf, String> {
    if id != "ether0" || !(1..=8).contains(&limit) {
        return Err("unsupported dataset or case limit".into());
    }
    let entry = manifest.dataset(id).ok_or("dataset is not registered")?;
    if entry.family() != "futurehouse"
        || entry.language() != "en"
        || entry.license() != "CC-BY-4.0"
        || !entry.license_acceptance_required()
    {
        return Err("dataset license or split metadata mismatch".into());
    }
    if !license_accepted {
        return Err("dataset license acceptance is required".into());
    }
    let cache = validated_dataset_cache_root(cache).map_err(|error| error.to_string())?;
    let prepared = prepare_dataset(
        manifest,
        id,
        &PrepareRequest {
            cache_dir: &cache,
            source,
            suite: EvalSuite::Regression,
            offline,
            license_accepted,
            manual_path: None,
        },
    )
    .map_err(|error| error.to_string())?;
    let path = cache.join(id).join(entry.revision()).join("artifact");
    if fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len()
        > 1_048_576
    {
        return Err("dataset artifact exceeds adapter limit".into());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let cases = decode_parquet_cases(&prepared, &bytes, limit)
        .map_err(|error| format!("dataset adapter: {error:?}"))?;
    let evaluated = cases
        .into_iter()
        .map(|case| {
            let payload = case
                .problem
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            let evaluation = compile_eval(EvalInput::trajectory(EvalFixture::new(
                case.id.clone(),
                payload,
            )))
            .map_err(|error| error.to_string())?;
            Ok(ProductCase {
                case_id: case.id,
                evaluation,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let provenance = prepared.report();
    let report = ProductReport {
        schema_version: 1,
        dataset: ProductDataset {
            id,
            family: entry.family(),
            language: entry.language(),
            attribution: "FutureHouse ©2025 ether0-benchmark, CC BY 4.0; selected rows adapted by adk-workflow-kit",
            source_revision: provenance.source_revision(),
            source_url: entry.url(),
            checksum: provenance.checksum(),
            adapter_version: provenance.adapter_version(),
            derivation_hash: provenance.derivation_hash(),
        },
        cases: evaluated,
    };
    let encoded = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    if encoded.len() > 65_536 {
        return Err("report exceeds byte limit".into());
    }
    let dest = cache.join("ether0-report.json");
    if fs::symlink_metadata(&dest)
        .is_ok_and(|meta| !meta.is_file() || meta.file_type().is_symlink())
    {
        return Err("unsafe report destination".into());
    }
    let temporary = cache.join("ether0-report.json.partial");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    let result = output
        .write_all(&encoded)
        .and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.sync_all());
    drop(output);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    fs::rename(&temporary, &dest).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        error.to_string()
    })?;
    Ok(dest)
}
