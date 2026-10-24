//! Finite inert HTML projection: attributes and explicitly hidden element bodies.
//! No DOM, CSS cascade, rendering, script evaluation or inferred visibility.
use super::{Candidate, CarrierKind, CarrierReason, LABELS, Recognition};

fn name_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
        .count()
}

// An unquoted '<' ends this malformed opener's lookahead. Otherwise repeated
// fallback at adjacent malformed tags could rescan every remaining suffix.
fn tag_end(text: &str, start: usize) -> (usize, bool) {
    let Some(bytes) = text.as_bytes().get(start..) else {
        return (text.len(), false);
    };
    let mut quote = None;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        match quote {
            Some(delimiter) if byte == delimiter => quote = None,
            Some(_) => (),
            None if matches!(byte, b'\'' | b'"') => quote = Some(byte),
            None if byte == b'>' => return (start + offset + 1, true),
            None if byte == b'<' => return (start + offset, false),
            None => (),
        }
    }
    (text.len(), false)
}

fn has_label(name: &str) -> bool {
    let mut boundary = true;
    name.char_indices().any(|(offset, ch)| {
        let labeled = boundary
            && LABELS.iter().any(|(prefix, _)| {
                name.get(offset..)
                    .is_some_and(|tail| tail.starts_with(prefix))
            });
        boundary = !ch.is_alphanumeric() && ch != '_';
        labeled
    })
}

fn closing(text: &str, name: &str, mut cursor: usize) -> Option<(usize, usize)> {
    let mut depth = 1usize;
    while let Some(next) = text.get(cursor..)?.find('<') {
        let start = cursor + next;
        if text[start..].starts_with("<!--") {
            cursor = start + 4 + text[start + 4..].find("-->")? + 3;
            continue;
        }
        let is_close = text[start..].starts_with("</");
        let name_start = start + if is_close { 2 } else { 1 };
        if !text
            .as_bytes()
            .get(name_start)
            .is_some_and(u8::is_ascii_alphabetic)
        {
            cursor = start + 1;
            continue;
        }
        let len = name_len(text.as_bytes().get(name_start..)?);
        let (end, closed) = tag_end(text, name_start + len);
        if !closed {
            return None;
        }
        if text
            .get(name_start..name_start + len)?
            .eq_ignore_ascii_case(name)
        {
            if is_close {
                depth -= 1;
                if depth == 0 {
                    return Some((start, end));
                }
            } else if !text[..end - 1].trim_end().ends_with('/') {
                depth += 1;
            }
        }
        cursor = end;
    }
    None
}

fn hidden_style(value: &str) -> bool {
    value
        .split(';')
        .filter_map(|declaration| declaration.split_once(':'))
        .any(|(name, value)| {
            let name = name.trim();
            let value = value.trim();
            (name.eq_ignore_ascii_case("display") && value.eq_ignore_ascii_case("none"))
                || (name.eq_ignore_ascii_case("visibility") && value.eq_ignore_ascii_case("hidden"))
        })
}

pub(super) fn recognize(
    text: &str,
    remaining: usize,
) -> Result<Option<Recognition>, CarrierReason> {
    if !text.starts_with('<') || !text.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic) {
        return Ok(None);
    }
    let name_end = 1 + name_len(&text.as_bytes()[1..]);
    let name = &text[1..name_end];
    let (len, closed) = tag_end(text, name_end);
    let opening_end = closed.then_some(len);
    // Decline the whole projection, including previously extracted values, if
    // opener bytes would hide a legacy carrier. Resume ordinary scanning after
    // '<', charging this bounded lookahead even when no HTML view is produced.
    let fallback = || {
        Ok(Some(Recognition {
            len: 1,
            candidates: vec![],
            work_units: len,
        }))
    };
    if has_label(name)
        || text
            .as_bytes()
            .get(name_end)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && !matches!(byte, b'>' | b'/'))
    {
        return fallback();
    }
    let mut result = Recognition {
        len,
        candidates: vec![],
        work_units: len,
    };
    let mut cursor = name_end;
    let mut hidden = false;
    while cursor < len {
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if matches!(text.as_bytes().get(cursor), Some(b'>') | None)
            || text.get(cursor..len) == Some("/>")
        {
            break;
        }
        let start = cursor;
        let size = name_len(&text.as_bytes()[cursor..]);
        if size == 0 {
            return fallback();
        }
        let attribute = &text[cursor..cursor + size];
        if has_label(attribute) {
            return fallback();
        }
        cursor += size;
        if attribute.eq_ignore_ascii_case("hidden") {
            hidden = true;
        }
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if text.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        let quote = text
            .as_bytes()
            .get(cursor)
            .copied()
            .filter(|b| matches!(b, b'\'' | b'"'));
        if quote.is_some() {
            cursor += 1;
        }
        let body_start = cursor;
        let body_end = if let Some(quote) = quote {
            text.as_bytes()[cursor..len]
                .iter()
                .position(|b| *b == quote)
                .map(|offset| cursor + offset)
        } else {
            Some(
                cursor
                    + text.as_bytes()[cursor..len]
                        .iter()
                        .take_while(|b| !b.is_ascii_whitespace() && **b != b'>')
                        .count(),
            )
        };
        let closed = body_end.is_some() && opening_end.is_some();
        let body_end = body_end.unwrap_or(len);
        cursor = body_end + usize::from(quote.is_some() && body_end < len);
        let value = &text[body_start..body_end];
        hidden |= (attribute.eq_ignore_ascii_case("aria-hidden")
            && value.eq_ignore_ascii_case("true"))
            || (attribute.eq_ignore_ascii_case("style") && hidden_style(value));
        if !value.is_empty() {
            if result.candidates.len() >= remaining {
                return Err(CarrierReason::ResourceLimit);
            }
            result.candidates.push(Candidate {
                kind: CarrierKind::HtmlAttribute,
                span: start..cursor,
                body: body_start..body_end,
                closed,
            });
        }
    }
    if hidden && opening_end.is_some() && !text[..len - 1].trim_end().ends_with('/') {
        let close = closing(text, name, len);
        let body_end = close.map_or(text.len(), |(start, _)| start);
        result.len = close.map_or(text.len(), |(_, end)| end);
        result.work_units += result.len - len;
        if result.candidates.len() >= remaining {
            return Err(CarrierReason::ResourceLimit);
        }
        result.candidates.push(Candidate {
            kind: CarrierKind::HtmlHidden,
            span: 0..result.len,
            body: len..body_end,
            closed: close.is_some(),
        });
    }
    Ok(Some(result))
}
