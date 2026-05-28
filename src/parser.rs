//! Hand-written parser. The rule grammar is plain recursive descent; the
//! `when` condition is parsed with a Pratt (precedence-climbing) loop so that
//! `or` binds looser than `and`, and `not` binds tightest.
//!
//! Precedence (loosest to tightest): `or` < `and` < `not` < predicate.
//!
//! Errors don't abort the whole parse: on a bad statement we record a
//! diagnostic and resynchronize to the next rule boundary, so one run can
//! surface every error in the file.

use crate::ast::{Effect, Expr, Field, Policy, Rule};
use crate::diagnostics::{Diagnostic, Span};
use crate::token::{Token, TokenKind};

// Binding powers for the infix logical operators.
const BP_OR: u8 = 1;
const BP_AND: u8 = 3;

pub fn parse_tokens(tokens: Vec<Token>) -> (Policy, Vec<Diagnostic>) {
    let mut parser = Parser { tokens, pos: 0, diagnostics: Vec::new() };
    let policy = parser.parse_policy();
    (policy, parser.diagnostics)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    diagnostics: Vec<Diagnostic>,
}

impl Parser {
    fn parse_policy(&mut self) -> Policy {
        let mut default = Effect::Ask;
        let mut rules = Vec::new();
        while !self.at_end() {
            let before = self.pos;
            let result = if *self.peek() == TokenKind::Default {
                self.parse_default().map(|eff| default = eff)
            } else {
                self.parse_rule().map(|rule| rules.push(rule))
            };
            if let Err(diag) = result {
                self.diagnostics.push(diag);
                self.synchronize();
            }
            // Guarantee forward progress even if recovery landed on a boundary.
            if self.pos == before {
                self.advance();
            }
        }
        Policy { default, rules }
    }

    fn parse_default(&mut self) -> Result<Effect, Diagnostic> {
        self.expect(TokenKind::Default)?;
        let (effect, _) = self.parse_effect()?;
        Ok(effect)
    }

    fn parse_rule(&mut self) -> Result<Rule, Diagnostic> {
        let (effect, start) = self.parse_effect()?;
        self.expect(TokenKind::Tool)?;
        self.expect(TokenKind::LParen)?;
        let tool = self.expect_string()?;
        self.expect(TokenKind::RParen)?;
        let condition = if *self.peek() == TokenKind::When {
            self.advance();
            Some(self.parse_expr(0)?)
        } else {
            None
        };
        Ok(Rule { effect, tool, condition, span: start })
    }

    /// Pratt loop over the logical operators.
    fn parse_expr(&mut self, min_bp: u8) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_prefix()?;
        loop {
            match self.peek() {
                TokenKind::Or if BP_OR >= min_bp => {
                    self.advance();
                    let rhs = self.parse_expr(BP_OR + 1)?;
                    lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
                }
                TokenKind::And if BP_AND >= min_bp => {
                    self.advance();
                    let rhs = self.parse_expr(BP_AND + 1)?;
                    lhs = Expr::And(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_prefix(&mut self) -> Result<Expr, Diagnostic> {
        if *self.peek() == TokenKind::Not {
            self.advance();
            let operand = self.parse_prefix()?;
            Ok(Expr::Not(Box::new(operand)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, Diagnostic> {
        let token = self.peek_token().clone();
        match token.kind {
            TokenKind::LParen => {
                self.advance();
                let inner = self.parse_expr(0)?;
                self.expect(TokenKind::RParen)?;
                Ok(inner)
            }
            TokenKind::Ident(name) => {
                self.advance();
                let field = Field::from_ident(&name).ok_or_else(|| {
                    Diagnostic::new(
                        format!("unknown field `{name}` (expected `path` or `command`)"),
                        token.span,
                    )
                })?;
                let op = self.peek_token().clone();
                match op.kind {
                    TokenKind::Matches => {
                        self.advance();
                        let (pattern, span) = self.expect_string_span()?;
                        Ok(Expr::Match { field, pattern, span })
                    }
                    TokenKind::Contains => {
                        self.advance();
                        let (needle, span) = self.expect_string_span()?;
                        Ok(Expr::Contains { field, needle, span })
                    }
                    _ => Err(Diagnostic::new(
                        format!(
                            "expected `matches` or `contains` after field `{name}`, found {}",
                            op.kind.describe()
                        ),
                        op.span,
                    )),
                }
            }
            _ => Err(Diagnostic::new(
                format!("expected a condition, found {}", token.kind.describe()),
                token.span,
            )),
        }
    }

    fn parse_effect(&mut self) -> Result<(Effect, Span), Diagnostic> {
        let token = self.peek_token().clone();
        let effect = match token.kind {
            TokenKind::Allow => Effect::Allow,
            TokenKind::Deny => Effect::Deny,
            TokenKind::Ask => Effect::Ask,
            _ => {
                return Err(Diagnostic::new(
                    format!(
                        "expected an effect (`allow`, `deny`, or `ask`), found {}",
                        token.kind.describe()
                    ),
                    token.span,
                ));
            }
        };
        self.advance();
        Ok((effect, token.span))
    }

    // --- token-stream helpers ---

    fn peek(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    fn peek_token(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn at_end(&self) -> bool {
        matches!(self.peek(), TokenKind::Eof)
    }

    fn advance(&mut self) -> Token {
        let token = self.tokens[self.pos].clone();
        if !self.at_end() {
            self.pos += 1;
        }
        token
    }

    fn expect(&mut self, kind: TokenKind) -> Result<Token, Diagnostic> {
        if *self.peek() == kind {
            Ok(self.advance())
        } else {
            let token = self.peek_token();
            Err(Diagnostic::new(
                format!("expected {}, found {}", kind.describe(), token.kind.describe()),
                token.span,
            ))
        }
    }

    fn expect_string(&mut self) -> Result<String, Diagnostic> {
        self.expect_string_span().map(|(s, _)| s)
    }

    fn expect_string_span(&mut self) -> Result<(String, Span), Diagnostic> {
        let token = self.peek_token().clone();
        if let TokenKind::Str(value) = token.kind {
            self.advance();
            Ok((value, token.span))
        } else {
            Err(Diagnostic::new(
                format!("expected a string literal, found {}", token.kind.describe()),
                token.span,
            ))
        }
    }

    fn synchronize(&mut self) {
        while !self.at_end() {
            match self.peek() {
                TokenKind::Allow
                | TokenKind::Deny
                | TokenKind::Ask
                | TokenKind::Default => return,
                _ => {
                    self.advance();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;

    fn parse(src: &str) -> Result<Policy, Vec<Diagnostic>> {
        let (tokens, lex_diags) = Lexer::new(src).tokenize();
        assert!(lex_diags.is_empty(), "lex errors: {lex_diags:?}");
        let (policy, diags) = parse_tokens(tokens);
        if diags.is_empty() { Ok(policy) } else { Err(diags) }
    }

    #[test]
    fn parses_default_and_rules() {
        let policy = parse(
            r#"
            default deny
            allow tool("read") when path matches "src/**"
            ask tool("write")
        "#,
        )
        .unwrap();
        assert_eq!(policy.default, Effect::Deny);
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].effect, Effect::Allow);
        assert_eq!(policy.rules[1].condition, None);
    }

    #[test]
    fn or_binds_looser_than_and() {
        // a or b and c  ==>  a or (b and c)
        let policy = parse(
            r#"deny tool("x") when path matches "a" or path matches "b" and path matches "c""#,
        )
        .unwrap();
        let cond = policy.rules[0].condition.clone().unwrap();
        match cond {
            Expr::Or(_, rhs) => assert!(matches!(*rhs, Expr::And(_, _))),
            other => panic!("expected top-level Or, got {other:?}"),
        }
    }

    #[test]
    fn not_binds_tightest() {
        // not a and b  ==>  (not a) and b
        let policy = parse(r#"deny tool("x") when not path matches "a" and path matches "b""#).unwrap();
        let cond = policy.rules[0].condition.clone().unwrap();
        match cond {
            Expr::And(lhs, _) => assert!(matches!(*lhs, Expr::Not(_))),
            other => panic!("expected top-level And, got {other:?}"),
        }
    }

    #[test]
    fn parens_override_precedence() {
        let policy =
            parse(r#"deny tool("x") when (path matches "a" or path matches "b") and command contains "rm""#)
                .unwrap();
        let cond = policy.rules[0].condition.clone().unwrap();
        match cond {
            Expr::And(lhs, _) => assert!(matches!(*lhs, Expr::Or(_, _))),
            other => panic!("expected top-level And, got {other:?}"),
        }
    }

    #[test]
    fn reports_unknown_field() {
        let err = parse(r#"allow tool("read") when paht matches "x""#).unwrap_err();
        assert_eq!(err.len(), 1);
        assert!(err[0].message.contains("unknown field"));
    }

    #[test]
    fn recovers_and_reports_multiple_errors() {
        // First rule is missing its closing paren+string; second rule is fine
        // but a third has a bad effect. Recovery should find both problems.
        let err = parse(
            r#"
            allow tool(
            deny tool("ok")
            banana tool("z")
        "#,
        )
        .unwrap_err();
        assert!(err.len() >= 2, "expected multiple diagnostics, got {err:?}");
    }
}
