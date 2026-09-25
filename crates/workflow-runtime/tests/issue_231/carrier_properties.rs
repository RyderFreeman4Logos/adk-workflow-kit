use super::prepared;
use base64::{Engine, engine::general_purpose::STANDARD};
use workflow_runtime::{
    CarrierLimits, CarrierMode, CarrierReason, CarrierStatus, NormalizationLimits,
};

fn encoded(value: &str, kind: u32) -> String {
    match kind % 3 {
        0 => value.bytes().map(|b| format!("%{b:02X}")).collect(),
        1 => format!(
            "hex:{}",
            value
                .bytes()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        _ => format!("base64:{}", STANDARD.encode(value)),
    }
}

#[test]
fn deterministic_nested_utf8_corpus_composes_monotonic_original_evidence() {
    let mut seed = 0x231_ca77_u32;
    for case in 0..256 {
        let mut leaf = String::from("A中");
        for _ in 0..8 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if let Some(ch) = char::from_u32(0x80 + seed % 0x10ff80) {
                leaf.push(ch);
            }
        }
        let depth = 1 + case % 3;
        let mut nested = leaf.clone();
        for layer in 0..depth {
            nested = encoded(&nested, seed.wrapping_add(layer));
        }
        let raw = format!("前\u{200b} {nested}");
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let limits = CarrierLimits::default();
        let analysis = text.analyze_carriers(CarrierMode::Decode, limits).unwrap();
        let repeated = text.analyze_carriers(CarrierMode::Decode, limits).unwrap();
        assert_eq!(analysis.candidates(), repeated.candidates());
        assert_eq!(analysis.telemetry(), repeated.telemetry());
        assert_eq!(analysis.candidates().len(), depth as usize);
        assert_eq!(
            analysis
                .candidates()
                .last()
                .unwrap()
                .decoded()
                .unwrap()
                .text(),
            leaf
        );
        assert!(analysis.expanded_bytes() <= limits.max_expanded_bytes);
        assert!(analysis.work_units() <= limits.max_work_units);
        for (index, candidate) in analysis.candidates().iter().enumerate() {
            assert_eq!(candidate.status(), CarrierStatus::Decoded);
            assert_eq!(candidate.depth(), index + 1);
            assert_eq!(candidate.parent(), index.checked_sub(1));
            let view = candidate.decoded().unwrap();
            let mut next = 0;
            let mut previous = (0, 0);
            for span in view.source_map() {
                assert_eq!(span.normalized_start(), next);
                next = span.normalized_end();
                assert_eq!(
                    view.text()[span.normalized_start()..next].chars().count(),
                    1
                );
                let source = span.source();
                assert_eq!(source.artifact_id(), text.original_id().as_str());
                assert!(candidate.source().start() <= source.start());
                assert!(source.end() <= candidate.source().end());
                assert!(source.start() >= previous.0 && source.end() >= previous.1);
                assert!(
                    raw.get(source.start() as usize..source.end() as usize)
                        .is_some()
                );
                previous = (source.start(), source.end());
            }
            assert_eq!(next, view.text().len());
        }
    }
}

#[test]
fn base64_quantum_maps_cover_utf8_crossing_quantum_boundaries() {
    let text = prepared(b"base64:YeS4rWI=", NormalizationLimits::default());
    let analysis = text
        .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
        .unwrap();
    let view = analysis.candidates()[0].decoded().unwrap();
    assert_eq!(view.text(), "a中b");
    assert_eq!(
        view.source_map()
            .iter()
            .map(|m| (
                m.normalized_start(),
                m.normalized_end(),
                m.source().start(),
                m.source().end()
            ))
            .collect::<Vec<_>>(),
        [(0, 1, 7, 11), (1, 4, 7, 15), (4, 5, 11, 15),]
    );
}

#[test]
fn deterministic_malformed_fuzz_seeds_are_repeatable_and_bounded() {
    let atoms = [
        "%",
        "%GG",
        "<!--",
        "-->",
        "[//]: # (",
        ")",
        "base64:",
        "hex:",
        "\\x",
        "\\u",
        "中",
        "\u{200b}",
        "http://a/",
        "`",
        "~",
        "4142",
        "+",
        "=",
        "\n",
        " ",
    ];
    let mut seed = 0x231_f022_u32;
    for _ in 0..512 {
        let mut raw = String::from("fuzz ");
        for _ in 0..32 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            raw.push_str(atoms[seed as usize % atoms.len()]);
        }
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let limits = CarrierLimits {
            max_candidates: 16,
            max_depth: 2,
            max_expanded_bytes: 256,
            max_work_units: 1024,
            ..CarrierLimits::default()
        };
        for mode in [CarrierMode::AnnotateOnly, CarrierMode::Decode] {
            let a = text.analyze_carriers(mode, limits);
            let b = text.analyze_carriers(mode, limits);
            match (a, b) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a.candidates(), b.candidates());
                    assert_eq!(a.telemetry(), b.telemetry());
                    assert!(a.expanded_bytes() <= limits.max_expanded_bytes);
                    assert!(a.work_units() <= limits.max_work_units);
                    for c in a.candidates() {
                        assert!(c.source().start() < c.source().end());
                        assert!(
                            raw.get(c.source().start() as usize..c.source().end() as usize)
                                .is_some()
                        );
                    }
                }
                (Err(a), Err(b)) => {
                    assert_eq!(a, b);
                    assert_eq!(a, CarrierReason::ResourceLimit);
                }
                _ => panic!("nondeterministic analysis"),
            }
        }
    }
}

#[test]
fn budgets_include_siblings_intermediates_and_failed_attempts() {
    let text = prepared(b"hex:4142 hex:4142", NormalizationLimits::default());
    let limits = CarrierLimits {
        max_expanded_bytes: 3,
        ..CarrierLimits::default()
    };
    assert_eq!(
        text.analyze_carriers(CarrierMode::Decode, limits)
            .unwrap_err(),
        CarrierReason::ResourceLimit
    );
    let exact = CarrierLimits {
        max_expanded_bytes: 4,
        ..limits
    };
    let value = text.analyze_carriers(CarrierMode::Decode, exact).unwrap();
    assert_eq!(value.expanded_bytes(), 4);
    let work = value.work_units();
    assert!(
        text.analyze_carriers(
            CarrierMode::Decode,
            CarrierLimits {
                max_work_units: work,
                ..exact
            }
        )
        .is_ok()
    );
    assert_eq!(
        text.analyze_carriers(
            CarrierMode::Decode,
            CarrierLimits {
                max_work_units: work - 1,
                ..exact
            }
        )
        .unwrap_err(),
        CarrierReason::ResourceLimit
    );
    let invalid = prepared(b"hex:41gg hex:4142", NormalizationLimits::default());
    assert_eq!(
        invalid
            .analyze_carriers(
                CarrierMode::Decode,
                CarrierLimits {
                    max_expanded_bytes: 2,
                    ..exact
                }
            )
            .unwrap_err(),
        CarrierReason::ResourceLimit
    );
    let zero = CarrierLimits {
        max_expanded_bytes: 0,
        max_depth: 1,
        ..exact
    };
    assert!(
        text.analyze_carriers(CarrierMode::AnnotateOnly, zero)
            .is_ok()
    );
    assert!(serde_json::from_value::<CarrierLimits>(serde_json::json!({"max_input_bytes":10,"max_candidates":10,"max_depth":1,"max_expanded_bytes":10,"max_work_units":10,"trusted":true})).is_err());
}
