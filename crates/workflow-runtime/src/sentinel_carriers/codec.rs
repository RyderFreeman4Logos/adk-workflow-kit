//! Restricted carrier syntax and strict decoding. No rendering or evaluation.
use super::CarrierReason;
use crate::CarrierKind;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::ops::Range;

pub(super) struct Candidate {
    pub kind: CarrierKind,
    pub len: usize,
    pub body: Range<usize>,
    pub closed: bool,
}

pub(super) fn literal_len(text: &str) -> Option<usize> {
    if ["https://", "http://", "ftp://", "www."]
        .iter()
        .any(|prefix| {
            text.get(..prefix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
        })
    {
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

pub(super) fn recognize(text: &str, boundary: bool) -> Option<Candidate> {
    for (open, close, kind) in [
        ("<!--", "-->", CarrierKind::HtmlComment),
        ("[//]: # (", ")", CarrierKind::MarkdownComment),
    ] {
        if let Some(body) = text.strip_prefix(open) {
            let end = body.find(close);
            let body_end = open.len() + end.unwrap_or(body.len());
            return Some(Candidate {
                kind,
                len: body_end + end.map_or(0, |_| close.len()),
                body: open.len()..body_end,
                closed: end.is_some(),
            });
        }
    }
    if !boundary {
        return None;
    }
    for (prefix, kind) in [("base64:", CarrierKind::Base64), ("hex:", CarrierKind::Hex)] {
        if let Some(body) = text.strip_prefix(prefix) {
            let len = body
                .bytes()
                .take_while(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
                })
                .count();
            return Some(Candidate {
                kind,
                len: prefix.len() + len,
                body: prefix.len()..prefix.len() + len,
                closed: len > 0,
            });
        }
    }
    let kind = if text.starts_with('%')
        && text
            .as_bytes()
            .get(1)
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        CarrierKind::Percent
    } else if text.starts_with(r"\x") || text.starts_with(r"\u") {
        CarrierKind::Escape
    } else {
        return None;
    };
    let len = text
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'%' | b'\\'))
        .count();
    Some(Candidate {
        kind,
        len,
        body: 0..len,
        closed: true,
    })
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
        let tail = &text.as_bytes()[offset..];
        let (prefix, digits) = match kind {
            CarrierKind::HtmlComment | CarrierKind::MarkdownComment => {
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
            CarrierKind::Percent if tail.starts_with(b"%") => (1, 2),
            CarrierKind::Escape if tail.starts_with(br"\x") => (2, 2),
            CarrierKind::Escape if tail.starts_with(br"\u") => (2, 4),
            _ => {
                out.valid = false;
                break;
            }
        };
        let len = prefix + digits;
        let value = tail
            .get(prefix..len)
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| u32::from_str_radix(s, 16).ok());
        let Some(value) = value else {
            out.valid = false;
            break;
        };
        if digits == 4 {
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
    Ok(out)
}
