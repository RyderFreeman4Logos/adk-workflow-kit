//! Restricted carrier syntax and strict decoding. No rendering or evaluation.
use super::CarrierReason;
use crate::CarrierKind;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{ops::Range, time::Instant};

#[path = "html.rs"]
mod html;

const LABELS: [(&str, CarrierKind); 2] =
    [("base64:", CarrierKind::Base64), ("hex:", CarrierKind::Hex)];

pub(super) struct Candidate {
    pub kind: CarrierKind,
    pub span: Range<usize>,
    pub body: Range<usize>,
    pub closed: bool,
}

fn starts_url(text: &str) -> bool {
    ["https://", "http://", "ftp://", "www."]
        .iter()
        .any(|prefix| {
            text.get(..prefix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
        })
}

pub(super) fn literal_len(text: &str) -> Option<usize> {
    if starts_url(text) {
        return Some(
            text.find(|c: char| c.is_whitespace() || matches!(c, '<' | '>'))
                .unwrap_or(text.len()),
        );
    }
    let first = text.as_bytes().first().copied()?;
    if first == b'`' || text.starts_with("~~~") {
        let n = text.bytes().take_while(|b| *b == first).count();
        let delimiter = &text[..n];
        // ponytail: explicit literal delimiters only; no Markdown renderer.
        return Some(text[n..].find(delimiter).map_or(text.len(), |i| n + i + n));
    }
    None
}

pub(super) struct Recognition {
    pub len: usize,
    pub candidates: Vec<Candidate>,
    pub work_units: usize,
}
impl Recognition {
    fn single(kind: CarrierKind, len: usize, body: Range<usize>, closed: bool) -> Self {
        Self {
            len,
            candidates: vec![Candidate {
                kind,
                span: 0..len,
                body,
                closed,
            }],
            work_units: 0,
        }
    }
}

pub(super) fn recognize(
    text: &str,
    boundary: bool,
    remaining: usize,
) -> Result<Option<Recognition>, CarrierReason> {
    for (open, close, kind) in [
        ("<!--", "-->", CarrierKind::HtmlComment),
        ("[//]: # (", ")", CarrierKind::MarkdownComment),
    ] {
        if let Some(body) = text.strip_prefix(open) {
            let end = body.find(close);
            let body_end = open.len() + end.unwrap_or(body.len());
            return Ok(Some(Recognition::single(
                kind,
                body_end + end.map_or(0, |_| close.len()),
                open.len()..body_end,
                end.is_some(),
            )));
        }
    }
    if let Some(html) = html::recognize(text, remaining)? {
        return Ok(Some(html));
    }
    if !boundary {
        return Ok(None);
    }
    for (prefix, kind) in LABELS {
        if let Some(body) = text.strip_prefix(prefix) {
            let len = body
                .bytes()
                .take_while(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
                })
                .count();
            return Ok(Some(Recognition::single(
                kind,
                prefix.len() + len,
                prefix.len()..prefix.len() + len,
                len > 0,
            )));
        }
    }
    let Some(first) = text.chars().next() else {
        return Ok(None);
    };
    if !first.is_alphanumeric() && !matches!(first, '%' | '\\' | '&') {
        return Ok(None);
    }
    let mut previous_boundary = false;
    let len = text
        .char_indices()
        .find_map(|(offset, c)| {
            // Preserve walker precedence without rescanning any unconsumed suffix.
            let tail = &text[offset..];
            let stop = c.is_whitespace()
                || matches!(
                    c,
                    '<' | '>' | '"' | '\'' | '`' | '$' | '(' | ')' | '[' | ']' | '{' | '}'
                )
                || (offset > 0
                    && (starts_url(tail)
                        || tail.starts_with("~~~")
                        || (previous_boundary
                            && (tail.starts_with("base64:") || tail.starts_with("hex:")))));
            previous_boundary = !c.is_alphanumeric() && c != '_';
            stop.then_some(offset)
        })
        .unwrap_or(text.len());
    let token = &text[..len];
    let percent = token
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'%' && w[1].is_ascii_alphanumeric());
    let escape = token.contains(r"\x") || token.contains(r"\u");
    let entity = token
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'&' && (w[1] == b'#' || w[1].is_ascii_alphabetic()));
    let kind = match (percent, escape, entity) {
        (true, false, false) => Some(CarrierKind::Percent),
        (false, true, false) => Some(CarrierKind::Escape),
        (false, false, true) => Some(CarrierKind::HtmlEntity),
        (false, false, false) => None,
        _ => Some(CarrierKind::Escape),
    };
    // Consume an ordinary token once too; repeated suffix scans would be quadratic.
    Ok(Some(kind.map_or(
        Recognition {
            len,
            candidates: vec![],
            work_units: 0,
        },
        |kind| Recognition::single(kind, len, 0..len, true),
    )))
}

pub(super) struct Decoded {
    pub bytes: Vec<u8>,
    pub origins: Vec<Range<usize>>,
    pub valid: bool,
}
impl Decoded {
    fn push(
        &mut self,
        bytes: &[u8],
        range: Range<usize>,
        limit: usize,
    ) -> Result<(), CarrierReason> {
        if bytes.len() > limit.saturating_sub(self.bytes.len()) {
            return Err(CarrierReason::ResourceLimit);
        }
        self.bytes.extend_from_slice(bytes);
        self.origins.extend(std::iter::repeat_n(range, bytes.len()));
        Ok(())
    }
}

pub(super) fn decode(
    text: &str,
    kind: CarrierKind,
    closed: bool,
    limit: usize,
    deadline: Instant,
) -> Result<Decoded, CarrierReason> {
    let mut out = Decoded {
        bytes: Vec::new(),
        origins: Vec::new(),
        valid: closed,
    };
    if !closed {
        return Ok(out);
    }
    let mut offset = 0;
    while offset < text.len() {
        super::check_deadline(deadline)?;
        let tail = &text.as_bytes()[offset..];
        let (prefix, digits) = match kind {
            CarrierKind::HtmlComment
            | CarrierKind::MarkdownComment
            | CarrierKind::HtmlHidden
            | CarrierKind::HtmlAttribute => {
                out.push(&tail[..1], offset..offset + 1, limit)?;
                offset += 1;
                continue;
            }
            CarrierKind::Base64 => {
                let Some(chunk) = tail.get(..4) else {
                    out.valid = false;
                    break;
                };
                if tail.len() > 4 && chunk.contains(&b'=') {
                    out.valid = false;
                    break;
                }
                let mut bytes = [0u8; 3];
                let Ok(n) = STANDARD.decode_slice(chunk, &mut bytes) else {
                    out.valid = false;
                    break;
                };
                out.push(&bytes[..n], offset..offset + 4, limit)?;
                offset += 4;
                continue;
            }
            CarrierKind::Hex => (0, 2),
            CarrierKind::Percent | CarrierKind::Escape | CarrierKind::HtmlEntity => {
                if tail.starts_with(b"%") {
                    (1, 2)
                } else if tail.starts_with(br"\x") {
                    (2, 2)
                } else if tail.starts_with(br"\u") {
                    (2, 4)
                } else if tail.starts_with(b"&") {
                    let Some((ch, len)) = entity(&text[offset..]) else {
                        out.valid = false;
                        break;
                    };
                    let mut bytes = [0; 4];
                    out.push(
                        ch.encode_utf8(&mut bytes).as_bytes(),
                        offset..offset + len,
                        limit,
                    )?;
                    offset += len;
                    continue;
                } else {
                    let Some(ch) = text[offset..].chars().next() else {
                        out.valid = false;
                        break;
                    };
                    out.push(
                        &tail[..ch.len_utf8()],
                        offset..offset + ch.len_utf8(),
                        limit,
                    )?;
                    offset += ch.len_utf8();
                    continue;
                }
            }
            _ => {
                out.valid = false;
                break;
            }
        };
        let mut len = prefix + digits;
        let value = tail
            .get(prefix..len)
            .filter(|s| s.iter().all(u8::is_ascii_hexdigit))
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| u32::from_str_radix(s, 16).ok());
        let Some(mut value) = value else {
            out.valid = false;
            break;
        };
        if digits == 4 {
            if (0xd800..=0xdbff).contains(&value) {
                let low = tail
                    .get(len..len + 6)
                    .filter(|bytes| bytes.starts_with(br"\u"))
                    .and_then(|bytes| std::str::from_utf8(&bytes[2..]).ok())
                    .and_then(|digits| u32::from_str_radix(digits, 16).ok())
                    .filter(|low| (0xdc00..=0xdfff).contains(low));
                let Some(low) = low else {
                    out.valid = false;
                    break;
                };
                value = 0x10000 + (value - 0xd800) * 0x400 + (low - 0xdc00);
                len += 6;
            }
            let Some(ch) = char::from_u32(value) else {
                out.valid = false;
                break;
            };
            let mut bytes = [0u8; 4];
            out.push(
                ch.encode_utf8(&mut bytes).as_bytes(),
                offset..offset + len,
                limit,
            )?;
        } else {
            out.push(&[value as u8], offset..offset + len, limit)?;
        }
        offset += len;
    }
    super::check_deadline(deadline)?;
    Ok(out)
}

fn entity(text: &str) -> Option<(char, usize)> {
    let end = text.find(';')?;
    let name = text.get(1..end)?;
    let ch = match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => '\u{a0}',
        _ => {
            let value =
                if let Some(hex) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return None;
                    }
                    u32::from_str_radix(hex, 16).ok()?
                } else {
                    let decimal = name.strip_prefix('#')?;
                    if decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit()) {
                        return None;
                    }
                    decimal.parse::<u32>().ok()?
                };
            if value == 0 {
                return None;
            }
            char::from_u32(value)?
        }
    };
    Some((ch, end + 1))
}
