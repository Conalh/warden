//! Tokens produced by the lexer.

use crate::diagnostics::Span;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    // Effects
    Allow,
    Deny,
    Ask,
    // Keywords
    Default,
    Mode,
    Tool,
    When,
    Test,
    // Logical operators
    And,
    Or,
    Not,
    // Predicate operators
    Matches,
    Contains,
    // Punctuation
    LParen,
    RParen,
    // Literals / identifiers
    Str(String),
    Ident(String),
    // End of input
    Eof,
}

impl TokenKind {
    /// Human-readable name used in "expected X, found Y" diagnostics.
    pub fn describe(&self) -> String {
        match self {
            TokenKind::Allow => "`allow`".into(),
            TokenKind::Deny => "`deny`".into(),
            TokenKind::Ask => "`ask`".into(),
            TokenKind::Default => "`default`".into(),
            TokenKind::Mode => "`mode`".into(),
            TokenKind::Tool => "`tool`".into(),
            TokenKind::When => "`when`".into(),
            TokenKind::Test => "`test`".into(),
            TokenKind::And => "`and`".into(),
            TokenKind::Or => "`or`".into(),
            TokenKind::Not => "`not`".into(),
            TokenKind::Matches => "`matches`".into(),
            TokenKind::Contains => "`contains`".into(),
            TokenKind::LParen => "`(`".into(),
            TokenKind::RParen => "`)`".into(),
            TokenKind::Str(_) => "a string literal".into(),
            TokenKind::Ident(name) => format!("identifier `{name}`"),
            TokenKind::Eof => "end of input".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Token { kind, span }
    }
}
