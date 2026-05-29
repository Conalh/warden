//! Span-aware error reporting with a rustc-style caret underline.

/// A half-open byte range `[start, end)` into the source, plus 1-based
/// line/column of `start` for human-readable diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: u32,
    pub col: u32,
}

impl Span {
    pub fn new(start: usize, end: usize, line: u32, col: u32) -> Self {
        Span {
            start,
            end,
            line,
            col,
        }
    }
}

/// A single error. `warden` collects these rather than bailing on the first
/// one, so a malformed policy reports every problem in one pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub message: String,
    pub span: Span,
}

impl Diagnostic {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Diagnostic {
            message: message.into(),
            span,
        }
    }

    /// Render against the original source with an `error:` label, e.g.
    /// ```text
    /// error: unknown field `paht`
    ///  --> line 3, col 11
    ///   |
    /// 3 | allow tool("read") when paht matches "src/**"
    ///   |                         ^^^^
    /// ```
    pub fn render(&self, source: &str) -> String {
        self.render_labeled(source, "error")
    }

    /// Render with a caller-chosen severity label (e.g. `"error"`, `"warning"`).
    pub fn render_labeled(&self, source: &str, label: &str) -> String {
        let line_text = source
            .lines()
            .nth(self.span.line.saturating_sub(1) as usize)
            .unwrap_or("");
        let gutter = self.span.line.to_string();
        let pad = " ".repeat(gutter.len());
        let caret_pad = " ".repeat(self.span.col.saturating_sub(1) as usize);
        let caret_len = (self.span.end.saturating_sub(self.span.start)).max(1);
        let carets = "^".repeat(caret_len);
        format!(
            "{label}: {msg}\n{pad} --> line {line}, col {col}\n{pad} |\n{gutter} | {line_text}\n{pad} | {caret_pad}{carets}",
            msg = self.message,
            line = self.span.line,
            col = self.span.col,
        )
    }
}

/// Render a batch of diagnostics into one string.
pub fn render_all(source: &str, diags: &[Diagnostic]) -> String {
    diags
        .iter()
        .map(|d| d.render(source))
        .collect::<Vec<_>>()
        .join("\n\n")
}
