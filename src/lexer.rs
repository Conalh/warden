//! Scanner. No regex, no lexer generator. Turns source text into a flat
//! token stream, tracking
//! byte offsets and line/column for diagnostics. Errors are collected, not
//! thrown, so the parser still receives a usable (if shorter) stream.

use crate::diagnostics::{Diagnostic, Span};
use crate::token::{Token, TokenKind};

pub struct Lexer<'a> {
    source: &'a str,
    chars: Vec<(usize, char)>,
    i: usize,
    line: u32,
    col: u32,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        Lexer {
            source,
            chars: source.char_indices().collect(),
            i: 0,
            line: 1,
            col: 1,
            diagnostics: Vec::new(),
        }
    }

    pub fn tokenize(mut self) -> (Vec<Token>, Vec<Diagnostic>) {
        let mut tokens = Vec::new();
        loop {
            self.skip_trivia();
            let start = self.cur_byte();
            let (line, col) = (self.line, self.col);
            let c = match self.peek() {
                Some(c) => c,
                None => {
                    tokens.push(Token::new(TokenKind::Eof, Span::new(start, start, line, col)));
                    break;
                }
            };
            match c {
                '(' => {
                    self.bump();
                    tokens.push(self.finish(TokenKind::LParen, start, line, col));
                }
                ')' => {
                    self.bump();
                    tokens.push(self.finish(TokenKind::RParen, start, line, col));
                }
                '"' => {
                    if let Some(tok) = self.lex_string(start, line, col) {
                        tokens.push(tok);
                    }
                }
                c if c.is_alphabetic() || c == '_' => {
                    tokens.push(self.lex_ident(start, line, col));
                }
                other => {
                    self.bump();
                    let span = Span::new(start, self.cur_byte(), line, col);
                    self.diagnostics
                        .push(Diagnostic::new(format!("unexpected character `{other}`"), span));
                }
            }
        }
        (tokens, self.diagnostics)
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).map(|&(_, c)| c)
    }

    fn cur_byte(&self) -> usize {
        self.chars.get(self.i).map(|&(b, _)| b).unwrap_or(self.source.len())
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn finish(&self, kind: TokenKind, start: usize, line: u32, col: u32) -> Token {
        Token::new(kind, Span::new(start, self.cur_byte(), line, col))
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some('#') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                _ => break,
            }
        }
    }

    fn lex_string(&mut self, start: usize, line: u32, col: u32) -> Option<Token> {
        self.bump(); // opening quote
        let mut value = String::new();
        loop {
            match self.peek() {
                None => {
                    let span = Span::new(start, self.cur_byte(), line, col);
                    self.diagnostics
                        .push(Diagnostic::new("unterminated string literal", span));
                    return None;
                }
                Some('"') => {
                    self.bump();
                    break;
                }
                Some('\\') => {
                    self.bump();
                    match self.peek() {
                        Some('"') => {
                            value.push('"');
                            self.bump();
                        }
                        Some('\\') => {
                            value.push('\\');
                            self.bump();
                        }
                        Some(other) => {
                            value.push('\\');
                            value.push(other);
                            self.bump();
                        }
                        None => {}
                    }
                }
                Some(c) => {
                    value.push(c);
                    self.bump();
                }
            }
        }
        Some(Token::new(TokenKind::Str(value), Span::new(start, self.cur_byte(), line, col)))
    }

    fn lex_ident(&mut self, start: usize, line: u32, col: u32) -> Token {
        let mut text = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' {
                text.push(c);
                self.bump();
            } else {
                break;
            }
        }
        let kind = match text.as_str() {
            "allow" => TokenKind::Allow,
            "deny" => TokenKind::Deny,
            "ask" => TokenKind::Ask,
            "default" => TokenKind::Default,
            "mode" => TokenKind::Mode,
            "tool" => TokenKind::Tool,
            "when" => TokenKind::When,
            "and" => TokenKind::And,
            "or" => TokenKind::Or,
            "not" => TokenKind::Not,
            "matches" => TokenKind::Matches,
            "contains" => TokenKind::Contains,
            _ => TokenKind::Ident(text),
        };
        Token::new(kind, Span::new(start, self.cur_byte(), line, col))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        let (toks, diags) = Lexer::new(src).tokenize();
        assert!(diags.is_empty(), "unexpected diagnostics: {diags:?}");
        toks.into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn lexes_a_rule() {
        let got = kinds(r#"allow tool("read") when path matches "src/**""#);
        assert_eq!(
            got,
            vec![
                TokenKind::Allow,
                TokenKind::Tool,
                TokenKind::LParen,
                TokenKind::Str("read".into()),
                TokenKind::RParen,
                TokenKind::When,
                TokenKind::Ident("path".into()),
                TokenKind::Matches,
                TokenKind::Str("src/**".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn lexes_mode_directive() {
        let got = kinds("mode deny_overrides");
        assert_eq!(
            got,
            vec![
                TokenKind::Mode,
                TokenKind::Ident("deny_overrides".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn skips_comments_and_tracks_lines() {
        let (toks, diags) = Lexer::new("# comment\ndeny").tokenize();
        assert!(diags.is_empty());
        assert_eq!(toks[0].kind, TokenKind::Deny);
        assert_eq!(toks[0].span.line, 2);
    }

    #[test]
    fn reports_unterminated_string() {
        let (_toks, diags) = Lexer::new("allow tool(\"oops").tokenize();
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("unterminated"));
    }

    #[test]
    fn handles_escaped_quote() {
        let got = kinds(r#""a\"b""#);
        assert_eq!(got, vec![TokenKind::Str("a\"b".into()), TokenKind::Eof]);
    }
}
