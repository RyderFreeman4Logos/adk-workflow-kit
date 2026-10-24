//! Pinned reference engine and packaged model; no runtime network or path override.
use crate::{LanguageAttribution as A, SegmentationReason as E, SentinelLanguage as L};
use fasttext::FastText;
use sha2::{Digest, Sha256};
use std::{os::fd::AsRawFd, sync::OnceLock};

const MODEL: &[u8] = include_bytes!("../../assets/lid.176.ftz");
const SHA256: &str = "8f3472cfe8738a7b6099e8e999c3cbfae0dcd15696aac7d7738a8039db603e83";
static DETECTOR: OnceLock<Result<FastText, E>> = OnceLock::new();

fn load(bytes: &[u8]) -> Result<FastText, E> {
    if bytes.len() != 938_013 || format!("{:x}", Sha256::digest(bytes)) != SHA256 {
        return Err(E::LanguageModelUnavailable);
    }
    let file = crate::sealed_file::sealed_memfd(bytes).map_err(|_| E::LanguageModelUnavailable)?;
    let mut model = FastText::new();
    model
        .load_model(&format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| E::LanguageModelUnavailable)?;
    Ok(model)
}

pub(super) fn predict(text: &str) -> Result<A, E> {
    // predictLine consumes one line; regions must never hide a later line here.
    if text.contains(['\0', '\n', '\r']) {
        return Err(E::InvalidPolicy);
    }
    if text.len() > 65_536 {
        return Err(E::ResourceLimit);
    }
    let detector = DETECTOR
        .get_or_init(|| load(MODEL))
        .as_ref()
        .map_err(|error| *error)?;
    let ranked = detector
        .predict(text, 2, 0.0)
        .map_err(|_| E::LanguageModelUnavailable)?;
    #[cfg(test)]
    if let (Some(first), Some(second)) = (ranked.first(), ranked.get(1)) {
        eprintln!(
            "language_rank {}",
            serde_json::json!({"input_sha256":format!("{:x}", Sha256::digest(text)), "first":first.label,"rank":first.prob,"second":second.label,"second_rank":second.prob})
        );
    }
    classify_ranks(&ranked)
}

fn classify_ranks(ranked: &[fasttext::Prediction]) -> Result<A, E> {
    let (Some(first), Some(second)) = (ranked.first(), ranked.get(1)) else {
        return Err(E::LanguageModelUnavailable);
    };
    if !first.prob.is_finite()
        || !second.prob.is_finite()
        || first.prob < second.prob
        || second.prob < 0.0
    {
        return Err(E::LanguageModelUnavailable);
    }
    // These are engineering rank cutoffs, not calibrated correctness estimates.
    if first.prob < 0.8 || first.prob - second.prob < 0.2 {
        return Ok(A::Unattributed);
    }
    Ok(match first.label.as_str() {
        "__label__en" => A::Attributed(L::En),
        "__label__zh" => A::Attributed(L::Zh),
        "__label__ja" => A::Attributed(L::Ja),
        label if label.starts_with("__label__") => A::UnsupportedLanguage,
        _ => return Err(E::LanguageModelUnavailable),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_and_margin_keep_statistical_abstention_and_typed_errors() {
        for (first, second, expected) in [
            (0.79, 0.1, A::Unattributed),
            (0.8, 0.7, A::Unattributed),
            (0.9, 0.1, A::UnsupportedLanguage),
        ] {
            assert_eq!(
                classify_ranks(&[
                    fasttext::Prediction {
                        label: "__label__ko".into(),
                        prob: first
                    },
                    fasttext::Prediction {
                        label: "__label__en".into(),
                        prob: second
                    }
                ]),
                Ok(expected)
            );
        }
        assert_eq!(classify_ranks(&[]), Err(E::LanguageModelUnavailable));
        assert_eq!(
            classify_ranks(&[
                fasttext::Prediction {
                    label: "__label__ko".into(),
                    prob: f32::NAN
                },
                fasttext::Prediction {
                    label: "__label__en".into(),
                    prob: 0.1
                }
            ]),
            Err(E::LanguageModelUnavailable)
        );
    }

    #[test]
    fn packaged_model_loads_with_an_unrelated_working_directory() {
        let directory = std::env::temp_dir();
        assert!(!directory.starts_with(env!("CARGO_MANIFEST_DIR")));
        let output = std::process::Command::new("/usr/bin/timeout")
            .args(["--kill-after=2s", "20s"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "sentinel_language::detector::tests::production_language_resources_and_ambiguous_ranks", "--nocapture", "--test-threads=1"])
            .current_dir(directory)
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("language_resources"));
        println!(
            "packaged_model_child {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn decoded_language_uses_original_hex_quanta_and_all_allowlist_bits() {
        use crate::{
            CarrierLimits, CarrierMode, InMemoryArtifactStore, LanguagePolicy, NormalizationLimits,
            SegmentationLimits, SentinelPreparation, TextSegmentKind, prepare_untrusted_text,
        };
        let capacity = std::num::NonZeroU64::new(10_000).unwrap();
        let raw = "hex:546869732069732061206d657373616765";
        let mut store = InMemoryArtifactStore::new(capacity, capacity);
        let SentinelPreparation::Prepared(text) = prepare_untrusted_text(
            &mut store,
            raw.as_bytes(),
            NormalizationLimits::default(),
            std::time::Instant::now(),
        )
        .unwrap() else {
            panic!("prepared input required");
        };
        let carriers = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        let decoded = carriers.candidates()[0].decoded().unwrap();
        let segments = crate::sentinel_segments::segment_view(
            &text,
            decoded.text(),
            decoded.source_map(),
            SegmentationLimits::default(),
        )
        .unwrap();
        let spans: Vec<_> = segments
            .iter()
            .filter(|span| span.kind() == TextSegmentKind::NaturalLanguage)
            .map(|span| {
                assert_eq!(span.source().artifact_id(), text.original_id().as_str());
                (span.source().start(), span.source().end())
            })
            .collect();
        assert_eq!(spans, [(4, 12), (14, 18), (20, 22), (24, 38)]);
        assert_eq!(text.normalized(), raw);
        for mask in 0..8 {
            let policy = LanguagePolicy {
                en: mask & 1 != 0,
                zh: mask & 2 != 0,
                ja: mask & 4 != 0,
            };
            assert_eq!(
                carriers
                    .assess_language(policy, SegmentationLimits::default())
                    .unwrap(),
                if policy.en {
                    A::Attributed(L::En)
                } else {
                    A::UnsupportedLanguage
                }
            );
        }
        assert_eq!(
            carriers.assess_language(
                LanguagePolicy::default(),
                SegmentationLimits {
                    max_bytes: 65_536,
                    max_segments: 2
                }
            ),
            Err(E::ResourceLimit)
        );
    }

    #[test]
    fn pinned_asset_and_invalid_input_fail_before_prediction() {
        assert!(matches!(
            load(&MODEL[..MODEL.len() - 1]),
            Err(E::LanguageModelUnavailable)
        ));
        let mut changed = MODEL.to_vec();
        changed[0] ^= 1;
        assert!(matches!(load(&changed), Err(E::LanguageModelUnavailable)));
        assert_eq!(predict("first\0second"), Err(E::InvalidPolicy));
        assert_eq!(predict("first\nsecond"), Err(E::InvalidPolicy));
        assert_eq!(predict(&"x".repeat(65_537)), Err(E::ResourceLimit));
        assert!(super::super::SENTINEL_LANGUAGE_MODEL_ID.ends_with(SHA256));
    }

    #[test]
    fn production_language_resources_and_ambiguous_ranks() {
        use crate::{
            CarrierLimits, CarrierMode, InMemoryArtifactStore, LanguagePolicy, NormalizationLimits,
            SegmentationLimits, SentinelPreparation, prepare_untrusted_text,
        };
        use std::{num::NonZeroU64, time::Instant};
        let assess = |raw: &str, limits: SegmentationLimits| {
            let capacity = NonZeroU64::new(1_000_000).unwrap();
            let mut store = InMemoryArtifactStore::new(capacity, capacity);
            let started = Instant::now();
            let SentinelPreparation::Prepared(text) = prepare_untrusted_text(
                &mut store,
                raw.as_bytes(),
                NormalizationLimits::default(),
                started,
            )
            .unwrap() else {
                panic!("prepared input required");
            };
            let carriers = text
                .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
                .unwrap();
            let result = carriers.assess_language(LanguagePolicy::default(), limits);
            (result, started.elapsed())
        };
        let note =
            "Please review the attached report and send your comments before tomorrow morning.";
        let (cold, cold_time) = assess(note, SegmentationLimits::default());
        assert_eq!(cold.unwrap(), A::Attributed(L::En));
        let mut warm = std::time::Duration::ZERO;
        for _ in 0..16 {
            let (result, elapsed) = assess(note, SegmentationLimits::default());
            assert_eq!(result.unwrap(), A::Attributed(L::En));
            warm += elapsed;
        }
        for raw in ["東京 大阪 京都 奈良 横浜 神戸", "東京大阪京都奈良横浜神戸"]
        {
            let (result, elapsed) = assess(raw, SegmentationLimits::default());
            println!(
                "ambiguous_routing {}",
                serde_json::json!({"input_sha256":format!("{:x}", Sha256::digest(raw)),"outcome":result.unwrap(),"milliseconds":elapsed.as_secs_f64()*1000.0,"accuracy_credit":false})
            );
        }
        let mut too_many_segments =
            "Please review the attached document before the meeting ".repeat(1_400);
        too_many_segments.truncate(65_536);
        let limits = SegmentationLimits {
            max_bytes: 65_536,
            max_segments: 16_384,
        };
        assert_eq!(assess(&too_many_segments, limits).0, Err(E::ResourceLimit));
        let mut maximum =
            "Documentation verification internationalization configuration ".repeat(1_200);
        maximum.truncate(65_536);
        let (result, maximum_time) = assess(&maximum, limits);
        assert!(result.is_ok(), "{result:?}");
        assert!(maximum_time.as_millis() < 1_000);
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let peak = status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .unwrap();
        println!(
            "language_resources {}",
            serde_json::json!({"cold_ms":cold_time.as_secs_f64()*1000.0,"warm_mean_ms":warm.as_secs_f64()*1000.0/16.0,"maximum_bytes":maximum.len(),"maximum_ms":maximum_time.as_secs_f64()*1000.0,"peak_rss":peak,"model_sha256":SHA256})
        );
    }
}
