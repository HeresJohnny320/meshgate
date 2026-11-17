//! Helpers that make serde read and write JSON the way Go's encoding/json
//! does, so files and API bodies stay interchangeable with Go nodes.
//!
//! - `omitempty` fields: `#[serde(skip_serializing_if = "zero")]`.
//! - Go writes `null` for empty slices and maps that lack `omitempty`, and
//!   reads `null` as "empty": `#[serde(deserialize_with = "nullable")]`.
//! - Missing fields are zero values: every record has `#[serde(default)]`.

use serde::{Deserialize, Deserializer};

/// True for a type's zero value (Go `omitempty`).
pub fn zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// Reads JSON `null` as the type's zero value.
pub fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Go's strconv.Atoi: optional sign, decimal digits, fits in i64.
pub fn atoi(s: &str) -> Option<i64> {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v: i64 = digits.parse().ok()?;
    Some(if neg { -v } else { v })
}

/// Go's json.Marshal: compact, with `<`, `>`, `&`, U+2028 and U+2029
/// escaped like Go does. Used where bytes are compared or hashed.
pub fn marshal<T: serde::Serialize + ?Sized>(v: &T) -> Vec<u8> {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
    go_escape(&s).into_bytes()
}

/// Go's json.MarshalIndent(v, "", indent).
pub fn marshal_indent<T: serde::Serialize + ?Sized>(v: &T, indent: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let f = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, f);
    if v.serialize(&mut ser).is_err() {
        return b"null".to_vec();
    }
    go_escape(&String::from_utf8(out).unwrap_or_default()).into_bytes()
}

fn go_escape(s: &str) -> String {
    if !s.contains(['<', '>', '&', '\u{2028}', '\u{2029}']) {
        return s.to_string();
    }
    // Only inside strings can these characters appear in serde_json output.
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atoi_like_go() {
        assert_eq!(atoi("80"), Some(80));
        assert_eq!(atoi("+80"), Some(80));
        assert_eq!(atoi("-1"), Some(-1));
        assert_eq!(atoi(""), None);
        assert_eq!(atoi("8a"), None);
        assert_eq!(atoi(" 8"), None);
    }

    #[test]
    fn escapes_like_go() {
        assert_eq!(String::from_utf8(marshal("a<b>&")).unwrap(), "\"a\\u003cb\\u003e\\u0026\"");
        #[derive(serde::Serialize)]
        struct S {
            a: Vec<i32>,
        }
        assert_eq!(String::from_utf8(marshal_indent(&S { a: vec![1] }, " ")).unwrap(), "{\n \"a\": [\n  1\n ]\n}");
    }
}
