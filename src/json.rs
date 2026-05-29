//! A tiny, dependency-free JSON writer for the CLI's `--json` mode.
//!
//! The core crate carries no `serde` (it stays zero-dependency), so structured
//! output is built from this minimal value tree. It covers exactly the subset
//! the CLI emits — strings, integers, booleans, null, arrays, and string-keyed
//! objects — and renders compact single-line output suitable for piping into
//! `jq` or an agent's tool-use loop.

/// A JSON value. Object keys are `&'static str` because every key the CLI emits
/// is a fixed field name, never user-controlled data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl Json {
    /// Render to a compact, single-line JSON string.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Str(s) => write_string(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (i, (key, value)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

// Conveniences so callers can write leaves as `value.into()` instead of wrapping
// each one by hand.
impl From<&str> for Json {
    fn from(s: &str) -> Self {
        Json::Str(s.to_string())
    }
}
impl From<String> for Json {
    fn from(s: String) -> Self {
        Json::Str(s)
    }
}
impl From<bool> for Json {
    fn from(b: bool) -> Self {
        Json::Bool(b)
    }
}
impl From<i64> for Json {
    fn from(n: i64) -> Self {
        Json::Int(n)
    }
}

/// Write a JSON string literal, escaping per RFC 8259.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_scalars() {
        assert_eq!(Json::Null.render(), "null");
        assert_eq!(Json::Bool(true).render(), "true");
        assert_eq!(Json::Int(-7).render(), "-7");
        assert_eq!(Json::from("hi").render(), "\"hi\"");
    }

    #[test]
    fn escapes_strings() {
        let s = Json::from("a\"b\\c\nd\te");
        assert_eq!(s.render(), r#""a\"b\\c\nd\te""#);
    }

    #[test]
    fn escapes_control_chars_as_unicode() {
        // U+0001 has no shorthand, so it must render as a \uXXXX escape. The
        // expected value is built char-by-char to keep the escapes unambiguous.
        let rendered = Json::from(String::from('\u{0001}')).render();
        let expected: String = ['"', '\\', 'u', '0', '0', '0', '1', '"']
            .into_iter()
            .collect();
        assert_eq!(rendered, expected);
    }

    #[test]
    fn renders_nested_object_and_array() {
        let obj = Json::Object(vec![
            ("effect", "deny".into()),
            ("rule", Json::Int(5)),
            ("tags", Json::Array(vec!["a".into(), "b".into()])),
            ("matched", Json::Null),
        ]);
        assert_eq!(
            obj.render(),
            r#"{"effect":"deny","rule":5,"tags":["a","b"],"matched":null}"#
        );
    }
}
