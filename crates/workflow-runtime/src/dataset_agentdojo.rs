//! Two pinned archived AgentDojo episodes; source outcomes grant no Firewall authority.
use super::{
    ByteSource, DatasetError, DatasetErrorKind, DatasetManifest, DatasetProvenance, DatasetReport,
    DatasetSourceIdentity, EvalSuite, PrepareRequest, artifact_path, digest_bytes,
    prepare_dataset_with_limit, validated_dataset_cache_root,
};
use crate::{TrustDomain, firewall::ToolProposal};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{cell::Cell, collections::BTreeMap, fmt, fs, io::Read, path::Path};

const LIMIT: usize = 1_048_576;
const ADAPTER: &str = "agentdojo-archive-v1";
const PIN: &str = "089ed468cf3ed0322acc66b0211f26d9d90dbf60";
const GROUP: &str = "agentdojo@089ed468cf3ed0322acc66b0211f26d9d90dbf60/banking/user_task_0";
const ARTIFACTS: [(&str, &str); 3] = [
    ("agentdojo-archive-clean", "agentdojo-clean.json"),
    ("agentdojo-archive-attacked", "agentdojo-attacked.json"),
    ("sentinel-agentdojo-LICENSE", "agentdojo-LICENSE"),
];
const REGISTRY: &str = include_str!("../../../config/datasets.toml");

/// Closed, payload-free admission and native archive failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDojoDatasetError {
    LicenseRequired,
    Registry,
    Admission(DatasetErrorKind),
    Limit,
    Checksum,
    Schema,
    Composition,
}
impl fmt::Display for AgentDojoDatasetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentDojo dataset refusal: {self:?}")
    }
}
impl std::error::Error for AgentDojoDatasetError {}
impl From<DatasetError> for AgentDojoDatasetError {
    fn from(error: DatasetError) -> Self {
        if error.kind() == DatasetErrorKind::ArtifactTooLarge {
            Self::Limit
        } else {
            Self::Admission(error.kind())
        }
    }
}

/// Closed projection refusals; none implies a policy decision or execution permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDojoProjectionError {
    Index,
    UnsupportedCall,
    UnsupportedScalar,
    UnsupportedShape,
    MissingBinding,
    Provenance,
    Proposal,
}
impl fmt::Display for AgentDojoProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentDojo projection refusal: {self:?}")
    }
}
impl std::error::Error for AgentDojoProjectionError {}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeCall {
    function: String,
    #[serde(deserialize_with = "crate::firewall_types::unique_map")]
    args: BTreeMap<String, Value>,
    id: String,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Content {
    Text(String),
    Null(()),
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Calls {
    Present(Vec<NativeCall>),
    Null(()),
}
#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "lowercase", deny_unknown_fields)]
enum Message {
    System {
        #[serde(rename = "content")]
        _content: String,
    },
    User {
        #[serde(rename = "content")]
        _content: String,
    },
    Assistant {
        #[serde(rename = "content")]
        _content: Content,
        tool_calls: Calls,
    },
    Tool {
        #[serde(rename = "content")]
        _content: String,
        tool_call_id: String,
        tool_call: NativeCall,
        #[serde(rename = "error")]
        _error: (),
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    pipeline_name: String,
    suite_name: String,
    user_task_id: String,
    attack_type: Content,
    injection_task_id: Content,
    #[serde(rename = "injections")]
    _injections: BTreeMap<String, Value>,
    messages: Vec<Message>,
    utility: bool,
    security: bool,
    duration: f64,
    #[serde(rename = "error")]
    _error: (),
}
struct Binding {
    message: usize,
    slot: usize,
    result: Option<usize>,
}

/// Opaque checked archive. Raw messages, argument values and native IDs remain private.
/// Canonical output contains closed metadata/digests only; outcomes have unknown evaluator
/// polarity and are never action labels. The application supplies all host authority.
pub struct AgentDojoEpisode {
    archive: Archive,
    bindings: Vec<Binding>,
    source: DatasetReport,
    notice: DatasetReport,
    episode_id: String,
}
impl fmt::Debug for AgentDojoEpisode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentDojoEpisode")
            .field("episode_id", &self.episode_id)
            .field("messages", &self.message_count())
            .field("calls", &self.call_count())
            .finish()
    }
}
impl AgentDojoEpisode {
    /// Payload-free native case identity; variant metadata is bound by this digest.
    pub fn episode_id(&self) -> &str {
        &self.episode_id
    }
    /// Both retained variants share this source-parent group; neither is a sealed holdout.
    pub fn family_group_id(&self) -> &str {
        GROUP
    }
    /// Number of retained archived messages.
    pub fn message_count(&self) -> usize {
        self.archive.messages.len()
    }
    /// Number of original native calls, including unsupported projections.
    pub fn call_count(&self) -> usize {
        self.bindings.len()
    }
    /// Number of validated one-to-one native result bindings.
    pub fn bound_result_count(&self) -> usize {
        self.bindings.iter().filter(|b| b.result.is_some()).count()
    }
    /// Native outcome only; evaluator polarity is unknown here.
    pub fn native_utility(&self) -> bool {
        self.archive.utility
    }
    /// Native outcome only; never host policy authority.
    pub fn native_security(&self) -> bool {
        self.archive.security
    }
    /// Actual source admission evidence, retaining Manual versus LocalFixture identity.
    pub fn source_report(&self) -> &DatasetReport {
        &self.source
    }
    /// Actual complete notice admission evidence; full notice bytes remain in cache.
    pub fn notice_report(&self) -> &DatasetReport {
        &self.notice
    }

    fn call(&self, index: usize) -> Result<(&Binding, &NativeCall), AgentDojoProjectionError> {
        let binding = self
            .bindings
            .get(index)
            .ok_or(AgentDojoProjectionError::Index)?;
        let Some(Message::Assistant {
            tool_calls: Calls::Present(calls),
            ..
        }) = self.archive.messages.get(binding.message)
        else {
            return Err(AgentDojoProjectionError::Index);
        };
        Ok((
            binding,
            calls
                .get(binding.slot)
                .ok_or(AgentDojoProjectionError::Index)?,
        ))
    }

    /// Versioned JSON-tuple hash binding complete source bytes, native ID/coordinates,
    /// function and recursively sorted native arguments. It carries no authority.
    pub fn call_fingerprint(&self, index: usize) -> Result<String, AgentDojoProjectionError> {
        let (binding, call) = self.call(index)?;
        Ok(hash_json(json!([
            ADAPTER,
            self.source.checksum(),
            self.episode_id,
            call.id,
            binding.message,
            binding.slot,
            call.function,
            native_arguments_digest(&call.args)
        ])))
    }

    /// Selects a reviewed host-owned mapping without copying raw native strings.
    /// Supports exactly read_file(file_path) and get_most_recent_transactions(n).
    /// Float monetary amounts remain private and return UnsupportedScalar. Host proposals
    /// must fit the existing 16 KiB decoder, bind this source and their own argument digest,
    /// and remain UntrustedContent. Call FirewallPolicy::evaluate separately with host authority.
    pub fn project_call<'a>(
        &self,
        index: usize,
        host: &'a BTreeMap<String, ToolProposal>,
    ) -> Result<&'a ToolProposal, AgentDojoProjectionError> {
        let (_, call) = self.call(index)?;
        if call
            .args
            .values()
            .any(|v| matches!(v, Value::Number(n) if !n.is_i64()))
        {
            return Err(AgentDojoProjectionError::UnsupportedScalar);
        }
        let shape = match call.function.as_str() {
            "read_file" => {
                call.args.len() == 1
                    && call
                        .args
                        .get("file_path")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.is_empty() && s.len() <= 256)
            }
            "get_most_recent_transactions" => {
                call.args.len() == 1
                    && call
                        .args
                        .get("n")
                        .and_then(Value::as_i64)
                        .is_some_and(|n| n >= 0)
            }
            _ => return Err(AgentDojoProjectionError::UnsupportedCall),
        };
        if !shape {
            return Err(AgentDojoProjectionError::UnsupportedShape);
        }
        let proposal = host
            .get(&self.call_fingerprint(index)?)
            .ok_or(AgentDojoProjectionError::MissingBinding)?;
        let source = self
            .source
            .checksum()
            .strip_prefix("sha256:")
            .ok_or(AgentDojoProjectionError::Provenance)?;
        if source.len() != 64
            || !source
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || proposal.provenance.source_digest != source
            || proposal.provenance.arguments_digest != proposal.arguments_digest()
            || proposal.provenance.trust_domain != TrustDomain::UntrustedContent
        {
            return Err(AgentDojoProjectionError::Provenance);
        }
        let encoded =
            serde_json::to_vec(proposal).map_err(|_| AgentDojoProjectionError::Proposal)?;
        ToolProposal::decode(&encoded).map_err(|_| AgentDojoProjectionError::Proposal)?;
        Ok(proposal)
    }

    /// Stable payload-free metadata and report bindings. Raw dialogue, thoughts, IDs,
    /// injection values and argument text are intentionally excluded, including Debug.
    pub fn canonical_json(&self) -> Result<Vec<u8>, AgentDojoDatasetError> {
        let calls = (0..self.call_count()).map(|index| {
            let (binding, call) = self.call(index).map_err(|_| AgentDojoDatasetError::Composition)?;
            let function = match call.function.as_str() { "read_file" => "read_file", "send_money" => "send_money", "get_most_recent_transactions" => "get_most_recent_transactions", _ => "unsupported" };
            Ok(json!({"fingerprint":self.call_fingerprint(index).map_err(|_| AgentDojoDatasetError::Composition)?,"message_index":binding.message,"call_index":binding.slot,"result_message_index":binding.result,"native_function":function,"native_arguments_sha256":native_arguments_digest(&call.args)}))
        }).collect::<Result<Vec<_>, AgentDojoDatasetError>>()?;
        let mut record = json!({"schema_version":1,"adapter_version":ADAPTER,"episode_id":self.episode_id,"family_group_id":GROUP,"upstream_revision_declared":PIN,"message_count":self.message_count(),"call_count":self.call_count(),"bound_result_count":self.bound_result_count(),"native_utility":self.native_utility(),"native_security":self.native_security(),"native_evaluator_polarity":"unknown","source_admission":report_record(&self.source),"license_admission":report_record(&self.notice),"calls":calls});
        record.sort_all_objects();
        serde_json::to_vec(&record).map_err(|_| AgentDojoDatasetError::Schema)
    }
    /// Hash of the stable payload-free canonical record, distinct from source/call/proposal hashes.
    pub fn canonical_sha256(&self) -> Result<String, AgentDojoDatasetError> {
        Ok(digest_bytes(&self.canonical_json()?))
    }
}

fn hash_json(mut value: Value) -> String {
    value.sort_all_objects();
    digest_bytes(value.to_string().as_bytes())
}
fn native_arguments_digest(args: &BTreeMap<String, Value>) -> String {
    hash_json(json!(args))
}
fn report_record(report: &DatasetReport) -> Value {
    let provenance = match report.source_identity().provenance() {
        DatasetProvenance::Manual => "manual",
        DatasetProvenance::LocalFixture => "local_fixture",
        DatasetProvenance::Upstream => "upstream",
    };
    json!({"provenance":provenance,"checksum":report.checksum(),"source_revision":report.source_revision(),"adapter_version":report.adapter_version(),"derivation_hash":report.derivation_hash()})
}
fn nullable(value: &Content) -> Value {
    match value {
        Content::Text(s) => json!(s),
        Content::Null(()) => Value::Null,
    }
}

fn decode_archive(
    bytes: &[u8],
    source: DatasetReport,
    notice: DatasetReport,
) -> Result<AgentDojoEpisode, AgentDojoDatasetError> {
    if bytes.len() > LIMIT {
        return Err(AgentDojoDatasetError::Limit);
    }
    if digest_bytes(bytes) != source.checksum() {
        return Err(AgentDojoDatasetError::Checksum);
    }
    let archive: Archive =
        serde_json::from_slice(bytes).map_err(|_| AgentDojoDatasetError::Schema)?;
    if archive.messages.is_empty()
        || archive.suite_name != "banking"
        || archive.user_task_id != "user_task_0"
        || archive.pipeline_name.is_empty()
        || archive.pipeline_name.len() > 256
        || !archive.duration.is_finite()
        || archive.duration < 0.0
    {
        return Err(AgentDojoDatasetError::Schema);
    }
    let mut bindings = Vec::<Binding>::new();
    let mut ids = BTreeMap::<&str, usize>::new();
    for (message, row) in archive.messages.iter().enumerate() {
        match row {
            Message::Assistant {
                tool_calls: Calls::Present(calls),
                ..
            } => {
                for (slot, call) in calls.iter().enumerate() {
                    if call.id.is_empty()
                        || call.id.len() > 256
                        || call.function.is_empty()
                        || call.function.len() > 256
                        || call.args.len() > 32
                    {
                        return Err(AgentDojoDatasetError::Schema);
                    }
                    if ids.insert(&call.id, bindings.len()).is_some() {
                        return Err(AgentDojoDatasetError::Composition);
                    }
                    bindings.push(Binding {
                        message,
                        slot,
                        result: None,
                    });
                }
            }
            Message::Tool {
                tool_call_id,
                tool_call,
                ..
            } => {
                let index = *ids
                    .get(tool_call_id.as_str())
                    .ok_or(AgentDojoDatasetError::Composition)?;
                let binding = bindings
                    .get_mut(index)
                    .ok_or(AgentDojoDatasetError::Composition)?;
                let Some(Message::Assistant {
                    tool_calls: Calls::Present(calls),
                    ..
                }) = archive.messages.get(binding.message)
                else {
                    return Err(AgentDojoDatasetError::Composition);
                };
                if binding.result.is_some() || calls.get(binding.slot) != Some(tool_call) {
                    return Err(AgentDojoDatasetError::Composition);
                }
                binding.result = Some(message);
            }
            _ => {}
        }
    }
    if bindings.iter().any(|b| b.result.is_none()) {
        return Err(AgentDojoDatasetError::Composition);
    }
    let episode_id = hash_json(json!([
        ADAPTER,
        PIN,
        archive.pipeline_name,
        archive.suite_name,
        archive.user_task_id,
        nullable(&archive.attack_type),
        nullable(&archive.injection_task_id)
    ]));
    Ok(AgentDojoEpisode {
        archive,
        bindings,
        source,
        notice,
        episode_id,
    })
}

#[derive(Default)]
struct DeniedSource(Cell<usize>);
impl ByteSource for DeniedSource {
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        self.0.set(self.0.get() + 1);
        Err(DatasetError::new(DatasetErrorKind::OfflineMiss))
    }
    fn len(&self) -> Result<u64, DatasetError> {
        self.0.set(self.0.get() + 1);
        Err(DatasetError::new(DatasetErrorKind::OfflineMiss))
    }
    fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize, DatasetError> {
        self.0.set(self.0.get() + 1);
        Err(DatasetError::new(DatasetErrorKind::OfflineMiss))
    }
}
fn read_artifact(path: &Path, report: &DatasetReport) -> Result<Vec<u8>, AgentDojoDatasetError> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| AgentDojoDatasetError::Admission(DatasetErrorKind::Io))?
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| AgentDojoDatasetError::Admission(DatasetErrorKind::Io))?;
    if bytes.len() > LIMIT {
        return Err(AgentDojoDatasetError::Limit);
    }
    if digest_bytes(&bytes) != report.checksum() {
        return Err(AgentDojoDatasetError::Checksum);
    }
    Ok(bytes)
}

/// Admits exactly two archived episodes plus the existing complete pinned MIT notice.
/// Fixed registry/license checks precede paths; Some imports fixed local names and None
/// requires verified cache hits. Reads are bounded at 1 MiB. All source reports remain
/// Manual content provenance; declared upstream lineage does not authenticate a fetch.
/// No model, tool, workflow, source-label inference or policy evaluation runs here.
pub fn prepare_agentdojo_episodes(
    manifest: &DatasetManifest,
    cache: &Path,
    source_dir: Option<&Path>,
    license_accepted: bool,
) -> Result<Vec<AgentDojoEpisode>, AgentDojoDatasetError> {
    if !license_accepted {
        return Err(AgentDojoDatasetError::LicenseRequired);
    }
    let expected = DatasetManifest::parse_str(REGISTRY)?;
    for (id, _) in ARTIFACTS {
        if manifest.dataset(id).is_none() || manifest.dataset(id) != expected.dataset(id) {
            return Err(AgentDojoDatasetError::Registry);
        }
    }
    let source_dir = source_dir.map(validated_dataset_cache_root).transpose()?;
    let cache = if fs::symlink_metadata(cache)
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        let parent =
            validated_dataset_cache_root(cache.parent().ok_or(AgentDojoDatasetError::Registry)?)?;
        validated_dataset_cache_root(
            &parent.join(cache.file_name().ok_or(AgentDojoDatasetError::Registry)?),
        )?
    } else {
        validated_dataset_cache_root(cache)?
    };
    let denied = DeniedSource::default();
    let mut artifacts = Vec::new();
    for (id, filename) in ARTIFACTS {
        let manual = source_dir.as_ref().map(|root| root.join(filename));
        if let Some(path) = &manual {
            let metadata = fs::metadata(path)
                .map_err(|_| AgentDojoDatasetError::Admission(DatasetErrorKind::Io))?;
            if !metadata.is_file() || metadata.len() > LIMIT as u64 {
                return Err(AgentDojoDatasetError::Limit);
            }
        }
        let prepared = prepare_dataset_with_limit(
            manifest,
            id,
            &PrepareRequest {
                cache_dir: &cache,
                source: &denied,
                suite: EvalSuite::Regression,
                offline: true,
                license_accepted,
                manual_path: manual.as_deref(),
            },
            Some(LIMIT),
        )?;
        if source_dir.is_none() && !prepared.from_cache() {
            return Err(AgentDojoDatasetError::Composition);
        }
        let report = prepared.report();
        let bytes = read_artifact(
            &artifact_path(
                &cache,
                manifest
                    .dataset(id)
                    .ok_or(AgentDojoDatasetError::Registry)?,
            )?,
            &report,
        )?;
        artifacts.push((bytes, report));
    }
    if denied.0.get() != 0 {
        return Err(AgentDojoDatasetError::Composition);
    }
    let (notice_bytes, notice) = artifacts.pop().ok_or(AgentDojoDatasetError::Composition)?;
    drop(notice_bytes);
    artifacts
        .into_iter()
        .map(|(bytes, report)| decode_archive(&bytes, report, notice.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{FirewallPolicy, FirewallReason, ToolArgument, TrustedGoal};
    use std::{
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const MARKER: &str = "ATTACKER_NATIVE_MARKER";
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let path = fs::canonicalize(
                PathBuf::from(std::env::var_os("HOME").expect("HOME")).join("tmp"),
            )
            .expect("SSD tmp")
            .join(format!(
                "issue-241-private-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("private root");
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct Fixture<'a>(&'a [u8]);
    impl ByteSource for Fixture<'_> {
        fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
            Ok(DatasetSourceIdentity::local_fixture(
                "memory://agentdojo-native-fixture",
                digest_bytes(self.0),
            ))
        }
        fn len(&self) -> Result<u64, DatasetError> {
            Ok(self.0.len() as u64)
        }
        fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, DatasetError> {
            let start =
                usize::try_from(offset).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
            let rest = self.0.get(start..).unwrap_or_default();
            let count = rest.len().min(output.len());
            output[..count].copy_from_slice(&rest[..count]);
            Ok(count)
        }
    }
    // Both report slots below carry genuine LocalFixture evidence, not public MIT admission.
    fn report(bytes: &[u8]) -> DatasetReport {
        let root = Root::new();
        let manifest = DatasetManifest::parse_str(&format!(
            r#"schema_version = 1
[[datasets]]
id = "native-fixture"
family = "synthetic"
language = "en"
revision = "1.0.0"
url = "memory://agentdojo-native-fixture"
sha256 = "{}"
license = "MIT"
license_acceptance_required = false
distribution = "fetch"
adapter_version = "agentdojo-archive-v1"
derivation = "synthetic-decoder-control"
suites = ["smoke"]
"#,
            digest_bytes(bytes)
        ))
        .expect("fixture manifest");
        let prepared = prepare_dataset_with_limit(
            &manifest,
            "native-fixture",
            &PrepareRequest {
                cache_dir: &root.0,
                source: &Fixture(bytes),
                suite: EvalSuite::Smoke,
                offline: false,
                license_accepted: false,
                manual_path: None,
            },
            Some(LIMIT),
        )
        .expect("real fixture admission");
        assert_eq!(
            prepared.report().source_identity().provenance(),
            DatasetProvenance::LocalFixture
        );
        prepared.report()
    }
    fn decode(bytes: &[u8]) -> Result<AgentDojoEpisode, AgentDojoDatasetError> {
        let source = report(bytes);
        decode_archive(bytes, source.clone(), source)
    }
    fn archive() -> Value {
        let first = json!({"function":"read_file","args":{"file_path":MARKER},"id":"call-one"});
        let second = json!({"function":"send_money","args":{"amount":1.25,"date":"synthetic-date","recipient":"synthetic-recipient","subject":"synthetic-subject"},"id":"call-two"});
        json!({"pipeline_name":"synthetic","suite_name":"banking","user_task_id":"user_task_0","attack_type":null,"injection_task_id":null,"injections":{},"utility":true,"security":true,"duration":0.25,"error":null,
        "messages":[{"role":"system","content":"synthetic system"},{"role":"user","content":"synthetic request"},
        {"role":"assistant","content":null,"tool_calls":[first.clone()]},{"role":"tool","content":"synthetic result","tool_call_id":"call-one","tool_call":first,"error":null},
        {"role":"assistant","content":null,"tool_calls":[second.clone()]},{"role":"tool","content":"synthetic result","tool_call_id":"call-two","tool_call":second,"error":null},
        {"role":"assistant","content":"done","tool_calls":null}]})
    }
    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("synthetic bytes")
    }
    fn oracle_hash(mut value: Value) -> String {
        use sha2::{Digest, Sha256};
        value.sort_all_objects();
        format!("sha256:{:x}", Sha256::digest(bytes(&value)))
    }
    fn golden() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/issue_241/agentdojo_goldens.json"
        ))
        .expect("independent host oracle")
    }
    fn proposal(episode: &AgentDojoEpisode) -> ToolProposal {
        let golden = golden();
        let mut proposal: ToolProposal = serde_json::from_value(
            golden["episodes"][0]["host_bindings"]
                .as_object()
                .expect("bindings")
                .values()
                .next()
                .expect("read mapping")
                .clone(),
        )
        .expect("host proposal");
        proposal.provenance.source_digest = episode
            .source
            .checksum()
            .trim_start_matches("sha256:")
            .to_owned();
        // Keep the independently specified host-oracle argument digest; only source identity changes.
        proposal
    }

    #[test]
    fn native_archive_preserves_call_result_bindings() {
        let episode = decode(&bytes(&archive())).expect("production native decoder");
        assert_eq!(
            episode.call_count(),
            2,
            "archive must retain both original native calls"
        );
        assert_eq!(
            (episode.message_count(), episode.bound_result_count()),
            (7, 2)
        );
        let (binding, call) = episode.call(0).expect("first call");
        assert_eq!(
            (binding.message, binding.slot, binding.result),
            (2, 0, Some(3))
        );
        assert_eq!(call.id, "call-one");
        assert_eq!(call.args.get("file_path"), Some(&json!(MARKER)));
        let (binding, call) = episode.call(1).expect("float call retained");
        assert_eq!(
            (binding.message, binding.slot, binding.result),
            (4, 0, Some(5))
        );
        assert!(
            call.args
                .get("amount")
                .and_then(Value::as_f64)
                .is_some_and(|amount| amount == 1.25)
        );
        assert_eq!(
            episode.project_call(1, &BTreeMap::new()).err(),
            Some(AgentDojoProjectionError::UnsupportedScalar)
        );
    }

    #[test]
    fn native_archive_rejects_duplicate_argument_keys() {
        let original = String::from_utf8(bytes(&archive())).expect("UTF8");
        let duplicated = original.replacen(
            "\"file_path\":\"ATTACKER_NATIVE_MARKER\"",
            "\"file_path\":\"ATTACKER_NATIVE_MARKER\",\"file_path\":\"second\"",
            1,
        );
        assert_ne!(duplicated, original);
        assert_eq!(
            decode(duplicated.as_bytes()).expect_err("literal duplicate argument"),
            AgentDojoDatasetError::Schema
        );
    }

    #[test]
    fn native_archive_rejects_invalid_call_result_bindings() {
        let mut cases = Vec::new();
        let mut value = archive();
        value["messages"][3]["tool_call_id"] = json!("missing");
        cases.push(value);
        let mut value = archive();
        value["messages"][3]["tool_call"]["args"]["file_path"] = json!("changed");
        cases.push(value);
        let mut value = archive();
        value["messages"][4]["tool_calls"][0]["id"] = json!("call-one");
        cases.push(value);
        let mut value = archive();
        value["messages"]
            .as_array_mut()
            .expect("messages")
            .remove(3);
        cases.push(value);
        let mut value = archive();
        let duplicate = value["messages"][3].clone();
        value["messages"]
            .as_array_mut()
            .expect("messages")
            .insert(4, duplicate);
        cases.push(value);
        for value in cases {
            assert_eq!(
                decode(&bytes(&value)).expect_err("native result mismatch"),
                AgentDojoDatasetError::Composition
            );
        }
    }

    #[test]
    fn native_archive_rejects_missing_and_unsupported_shapes() {
        for field in [
            "utility",
            "security",
            "messages",
            "attack_type",
            "injection_task_id",
        ] {
            let mut value = archive();
            value.as_object_mut().expect("archive").remove(field);
            assert_eq!(
                decode(&bytes(&value)).expect_err("required native field"),
                AgentDojoDatasetError::Schema
            );
        }
        let mut value = archive();
        value["utility"] = json!("true");
        assert_eq!(
            decode(&bytes(&value)).expect_err("native bool required"),
            AgentDojoDatasetError::Schema
        );
        let mut value = archive();
        value["messages"][2]["tool_calls"][0]
            .as_object_mut()
            .expect("native call")
            .remove("args");
        assert_eq!(
            decode(&bytes(&value)).expect_err("required native argument map"),
            AgentDojoDatasetError::Schema
        );
        for argument in [
            Value::Null,
            json!([]),
            json!({}),
            json!(""),
            json!("x".repeat(257)),
        ] {
            let mut value = archive();
            value["messages"][2]["tool_calls"][0]["args"]["file_path"] = argument.clone();
            value["messages"][3]["tool_call"]["args"]["file_path"] = argument;
            let episode = decode(&bytes(&value)).expect("retained unsupported native shape");
            assert_eq!(
                episode.project_call(0, &BTreeMap::new()).err(),
                Some(AgentDojoProjectionError::UnsupportedShape)
            );
        }
        let original = bytes(&archive());
        let source = report(&original);
        let mut tampered = original.clone();
        let offset = tampered
            .iter()
            .position(|b| *b == b's')
            .expect("ASCII byte");
        tampered[offset] = b't';
        assert_eq!(tampered.len(), original.len());
        assert_eq!(
            decode_archive(&tampered, source.clone(), source.clone())
                .expect_err("post-admission changed bytes"),
            AgentDojoDatasetError::Checksum
        );
        assert_eq!(
            decode_archive(&vec![b' '; LIMIT + 1], source.clone(), source.clone())
                .expect_err("parser size cap"),
            AgentDojoDatasetError::Limit
        );
        let root = Root::new();
        let path = root.0.join("admitted.json");
        fs::write(&path, &original).expect("admitted copy");
        assert_eq!(
            read_artifact(&path, &source).expect("same admitted bytes"),
            original
        );
        fs::write(&path, tampered).expect("same-size race control");
        assert_eq!(
            read_artifact(&path, &source),
            Err(AgentDojoDatasetError::Checksum)
        );
        fs::write(&path, vec![b' '; LIMIT + 1]).expect("over cap control");
        assert_eq!(
            read_artifact(&path, &source),
            Err(AgentDojoDatasetError::Limit)
        );
    }

    #[test]
    fn native_labels_do_not_authorize_host_proposals() {
        let first_bytes = bytes(&archive());
        let first = decode(&first_bytes).expect("first source");
        let mut changed = archive();
        changed["utility"] = json!(false);
        changed["security"] = json!(false);
        let second_bytes = bytes(&changed);
        let second = decode(&second_bytes).expect("independently admitted changed source");
        assert_ne!(digest_bytes(&first_bytes), digest_bytes(&second_bytes));
        let arguments = oracle_hash(json!({"file_path":MARKER}));
        let identity = oracle_hash(json!([
            ADAPTER,
            PIN,
            "synthetic",
            "banking",
            "user_task_0",
            null,
            null
        ]));
        for (episode, source) in [(&first, &first_bytes), (&second, &second_bytes)] {
            use sha2::{Digest, Sha256};
            let source_digest = format!("sha256:{:x}", Sha256::digest(source));
            assert_eq!(episode.source_report().checksum(), source_digest);
            assert_eq!(episode.episode_id(), identity);
            let independent = oracle_hash(json!([
                ADAPTER,
                source_digest,
                identity,
                "call-one",
                2,
                0,
                "read_file",
                arguments
            ]));
            assert_eq!(
                episode.call_fingerprint(0).expect("fingerprint"),
                independent
            );
        }
        let old = BTreeMap::from([(
            first.call_fingerprint(0).expect("first key"),
            proposal(&first),
        )]);
        assert_eq!(
            second.project_call(0, &old).err(),
            Some(AgentDojoProjectionError::MissingBinding)
        );
        let rebound = BTreeMap::from([(
            second.call_fingerprint(0).expect("second key"),
            proposal(&second),
        )]);
        let golden = golden();
        let policy: FirewallPolicy =
            serde_json::from_value(golden["host_policy"].clone()).expect("host policy");
        let goal: TrustedGoal =
            serde_json::from_value(golden["host_goal"].clone()).expect("host goal");
        let before = policy.evaluate(
            &goal,
            first.project_call(0, &old).expect("first host binding"),
        );
        let after = policy.evaluate(
            &goal,
            second
                .project_call(0, &rebound)
                .expect("rebound host binding"),
        );
        assert_eq!(before.reason(), FirewallReason::LowRisk);
        assert_eq!(
            (before.decision(), before.reason()),
            (after.decision(), after.reason())
        );
        assert_eq!(
            (first.native_utility(), second.native_utility()),
            (true, false)
        );
    }

    #[test]
    fn native_projection_preserves_closed_privacy_boundary() {
        assert!(
            serde_json::from_value::<ToolArgument>(json!(MARKER)).is_ok(),
            "token syntax alone is not content policy"
        );
        let episode = decode(&bytes(&archive())).expect("native archive");
        let key = episode.call_fingerprint(0).expect("key");
        assert_eq!(
            episode.project_call(9, &BTreeMap::new()).err(),
            Some(AgentDojoProjectionError::Index)
        );
        assert_eq!(
            episode.project_call(0, &BTreeMap::new()).err(),
            Some(AgentDojoProjectionError::MissingBinding)
        );
        let host = BTreeMap::from([(key.clone(), proposal(&episode))]);
        let projected = episode
            .project_call(0, &host)
            .expect("host-only symbolic proposal");
        let golden = golden();
        let policy: FirewallPolicy =
            serde_json::from_value(golden["host_policy"].clone()).expect("host policy");
        let goal: TrustedGoal =
            serde_json::from_value(golden["host_goal"].clone()).expect("host goal");
        for output in [
            serde_json::to_string(projected).expect("proposal"),
            policy
                .evaluate(&goal, projected)
                .render_json()
                .expect("decision"),
            String::from_utf8(episode.canonical_json().expect("canonical")).expect("UTF8"),
            format!("{episode:?}"),
        ] {
            for raw in [
                MARKER,
                "synthetic system",
                "synthetic result",
                "call-one",
                "call-two",
                "synthetic-recipient",
            ] {
                assert!(!output.contains(raw), "private native payload absent");
            }
        }
        for mutation in 0..5 {
            let mut bad = proposal(&episode);
            match mutation {
                0 => bad.provenance.source_digest = "0".repeat(64),
                1 => bad.provenance.arguments_digest = "0".repeat(64),
                2 => bad.provenance.trust_domain = TrustDomain::TrustedGoal,
                3 => bad.schema_version = 2,
                _ => bad.intent.tool_id = "x".repeat(17_000),
            };
            let expected = if mutation < 3 {
                AgentDojoProjectionError::Provenance
            } else {
                AgentDojoProjectionError::Proposal
            };
            assert_eq!(
                episode
                    .project_call(0, &BTreeMap::from([(key.clone(), bad)]))
                    .err(),
                Some(expected)
            );
        }
        let mut unknown = archive();
        unknown["messages"][2]["tool_calls"][0]["function"] = json!("unknown");
        unknown["messages"][3]["tool_call"]["function"] = json!("unknown");
        assert_eq!(
            decode(&bytes(&unknown))
                .expect("retained unsupported function")
                .project_call(0, &BTreeMap::new())
                .err(),
            Some(AgentDojoProjectionError::UnsupportedCall)
        );
    }
}
