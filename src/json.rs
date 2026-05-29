//! A tiny, dependency-free JSON writer for the CLI's `--json` mode.
//!
//! The core crate carries no `serde` (it stays zero-dependency), so structured
//! output is built from this minimal value tree. It covers exactly the subset
//! the CLI emits — strings, integers, booleans, null, arrays, and string-keyed
//! objects — and renders compact single-line output suitable for piping into
//! `jq` or an agent's tool-use loop.

/// A JSON value. Object keys are owned `String`s: the CLI builds objects from
/// fixed `&'static str` field names (via [`Json::object`]), while the parser
/// produces keys at runtime from the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Build an object from `&str` keys, the shape every CLI call site uses.
    /// Each key is a fixed field name, so the borrow-to-owned copy is free of
    /// surprises and keeps construction sites terse.
    pub fn object(fields: Vec<(&str, Json)>) -> Self {
        Json::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        )
    }

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

/// Parse one JSON value from `input`, rejecting trailing junk.
///
/// This is the inverse of [`Json::render`] for the subset warden cares about:
/// the value tree it produces feeds the CLI's stdin batch mode. It is a total
/// function — every input yields `Ok` or a one-line `Err`, never a panic — and
/// nesting is capped at [`MAX_DEPTH`] so a pathological `[[[[…` can't blow the
/// stack. Numbers are integers only: JSON allows fractions and exponents, but
/// [`Json`] is `Eq` and carries no float, so a non-integer number is a clean
/// error rather than a lossy coercion.
pub fn parse(input: &str) -> Result<Json, String> {
    let mut parser = Parser {
        chars: input.chars().collect(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos < parser.chars.len() {
        return Err(format!(
            "unexpected trailing character `{}`",
            parser.chars[parser.pos]
        ));
    }
    Ok(value)
}

/// Maximum array/object nesting depth. Generous for real policies' action
/// payloads, but bounded so input can't drive unbounded recursion.
const MAX_DEPTH: usize = 128;

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        match self.peek() {
            Some('{') => self.object(depth),
            Some('[') => self.array(depth),
            Some('"') => self.string().map(Json::Str),
            Some('t' | 'f') => self.boolean(),
            Some('n') => self.null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!("unexpected character `{c}`")),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        if depth >= MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH} levels"));
        }
        self.bump(); // consume '{'
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.bump();
            return Ok(Json::Object(fields));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err("expected a string key in object".to_string());
            }
            let key = self.string()?;
            self.skip_ws();
            if self.bump() != Some(':') {
                return Err(format!("expected `:` after key `{key}`"));
            }
            self.skip_ws();
            let value = self.value(depth + 1)?;
            fields.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => return Ok(Json::Object(fields)),
                _ => return Err("expected `,` or `}` in object".to_string()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        if depth >= MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH} levels"));
        }
        self.bump(); // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.bump();
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some(']') => return Ok(Json::Array(items)),
                _ => return Err("expected `,` or `]` in array".to_string()),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.bump(); // consume opening '"'
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err("unterminated string".to_string()),
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('b') => out.push('\u{0008}'),
                    Some('f') => out.push('\u{000c}'),
                    Some('u') => out.push(self.unicode_escape()?),
                    Some(c) => return Err(format!("invalid escape `\\{c}`")),
                    None => return Err("unterminated escape".to_string()),
                },
                Some(c) => out.push(c),
            }
        }
    }

    /// Decode the `XXXX` of a `\uXXXX` escape, pairing a high surrogate with a
    /// following low surrogate. Any malformed or lone surrogate degrades to the
    /// replacement character rather than failing — totality over strictness,
    /// since these strings are tool arguments, not a wire protocol.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let high = self.hex4()?;
        if (0xD800..=0xDBFF).contains(&high) {
            // Expect a `\uXXXX` low surrogate to complete the pair.
            if self.peek() == Some('\\') {
                self.bump();
                if self.peek() == Some('u') {
                    self.bump();
                    let low = self.hex4()?;
                    if (0xDC00..=0xDFFF).contains(&low) {
                        let combined = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                        return Ok(char::from_u32(combined).unwrap_or('\u{FFFD}'));
                    }
                }
            }
            return Ok('\u{FFFD}');
        }
        Ok(char::from_u32(high).unwrap_or('\u{FFFD}'))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let c = self.bump().ok_or("truncated \\u escape")?;
            let digit = c
                .to_digit(16)
                .ok_or_else(|| format!("`{c}` is not a hex digit in \\u escape"))?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.bump();
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.bump();
        }
        // A fraction or exponent means it isn't an integer; reject it rather
        // than truncate, because `Json` has no float variant.
        if matches!(self.peek(), Some('.' | 'e' | 'E')) {
            return Err("only integer numbers are supported".to_string());
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        text.parse::<i64>()
            .map(Json::Int)
            .map_err(|_| format!("`{text}` is not a valid integer"))
    }

    fn boolean(&mut self) -> Result<Json, String> {
        if self.consume_keyword("true") {
            Ok(Json::Bool(true))
        } else if self.consume_keyword("false") {
            Ok(Json::Bool(false))
        } else {
            Err("invalid literal".to_string())
        }
    }

    fn null(&mut self) -> Result<Json, String> {
        if self.consume_keyword("null") {
            Ok(Json::Null)
        } else {
            Err("invalid literal".to_string())
        }
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        // Keywords are ASCII, so byte length equals char count.
        let end = self.pos + keyword.len();
        if end <= self.chars.len()
            && self.chars[self.pos..end]
                .iter()
                .copied()
                .eq(keyword.chars())
        {
            self.pos = end;
            true
        } else {
            false
        }
    }
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
        let obj = Json::object(vec![
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

    #[test]
    fn parses_scalars() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse("true").unwrap(), Json::Bool(true));
        assert_eq!(parse("false").unwrap(), Json::Bool(false));
        assert_eq!(parse("-42").unwrap(), Json::Int(-42));
        assert_eq!(parse(r#""hi""#).unwrap(), Json::from("hi"));
    }

    #[test]
    fn parses_object_with_runtime_keys() {
        let parsed = parse(r#"  { "tool": "bash" , "path": null, "n": 3 }  "#).unwrap();
        assert_eq!(
            parsed,
            Json::object(vec![
                ("tool", "bash".into()),
                ("path", Json::Null),
                ("n", Json::Int(3)),
            ])
        );
    }

    #[test]
    fn parses_nested_arrays_and_empties() {
        assert_eq!(parse("[]").unwrap(), Json::Array(vec![]));
        assert_eq!(parse("{}").unwrap(), Json::Object(vec![]));
        assert_eq!(
            parse(r#"[1, ["a", false], {}]"#).unwrap(),
            Json::Array(vec![
                Json::Int(1),
                Json::Array(vec!["a".into(), Json::Bool(false)]),
                Json::Object(vec![]),
            ])
        );
    }

    #[test]
    fn render_then_parse_round_trips() {
        let value = Json::object(vec![
            ("effect", "deny".into()),
            ("rule", Json::Int(5)),
            ("tags", Json::Array(vec!["a".into(), "b\nc".into()])),
            ("matched", Json::Null),
        ]);
        assert_eq!(parse(&value.render()).unwrap(), value);
    }

    #[test]
    fn decodes_escapes_and_surrogate_pairs() {
        assert_eq!(parse(r#""a\"b\\c\nd""#).unwrap(), Json::from("a\"b\\c\nd"));
        // U+0041 'A' as a plain BMP escape.
        assert_eq!(parse(r#""A""#).unwrap(), Json::from("A"));
        // A surrogate pair for U+1F600.
        assert_eq!(parse(r#""😀""#).unwrap(), Json::from("\u{1F600}"));
        // A lone high surrogate degrades to the replacement char (totality).
        assert_eq!(parse(r#""\uD83D""#).unwrap(), Json::from("\u{FFFD}"));
    }

    #[test]
    fn rejects_non_integer_numbers() {
        assert!(parse("1.5").is_err());
        assert!(parse("1e10").is_err());
    }

    #[test]
    fn rejects_trailing_junk_and_truncation() {
        assert!(parse(r#"{"a":1} oops"#).is_err());
        assert!(parse(r#"{"a":"#).is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn depth_guard_keeps_parse_total() {
        // Far past MAX_DEPTH: this must return an error, never overflow the
        // stack. The bracket count dwarfs the guard so the bound is exercised.
        let deep = "[".repeat(10_000);
        assert!(parse(&deep).is_err());
    }
}
