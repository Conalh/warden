//! Glob matching for the `matches` operator.
//!
//! A backtracking glob whose treatment of `/` depends on the [`GlobScope`] of
//! the field being matched:
//!
//! - **Segmented** (`path`) follows the gitignore convention where `/` is a hard
//!   boundary: `*` matches a run **except** `/` (one path segment), `**` (a run
//!   of two or more `*`) matches any run **including** `/`, and `?` matches one
//!   character that is not `/`.
//! - **Flat** (`command`) treats `/` as an ordinary character — it carries no
//!   structural meaning in a shell command — so `*` and `?` cross it freely and
//!   the `*` vs `**` distinction collapses.
//!
//! So under segmented rules `src/*` matches `src/main.rs` but not `src/a/b.rs`,
//! while `src/**` matches both; under flat rules `git *` matches `git clone a/b`.
//! The matcher is a plain recursive backtracker memoized on `(pattern index,
//! text index)`, which bounds it to `O(pattern * text)` and lets `**` try every
//! split point — a single greedy star anchor cannot, because a later
//! segment-bounded `*` may force an earlier `**` to grow.
//!
//! The same module also answers a *static* question for the shadow analysis:
//! [`glob_subsumes`] decides whether one glob's match-set contains another's
//! (glob language inclusion), conservatively and under the same scope rules.

use crate::ast::GlobScope;

pub(crate) fn glob_match(pattern: &str, text: &str, scope: GlobScope) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    let flat = matches!(scope, GlobScope::Flat);
    let width = txt.len() + 1;
    // 0 = unexplored, 1 = matched, 2 = failed.
    let mut cache = vec![0u8; (pat.len() + 1) * width];
    matches(&pat, &txt, 0, 0, flat, &mut cache, width)
}

fn matches(
    pat: &[char],
    txt: &[char],
    pi: usize,
    ti: usize,
    flat: bool,
    cache: &mut [u8],
    width: usize,
) -> bool {
    let key = pi * width + ti;
    match cache[key] {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let result = compute(pat, txt, pi, ti, flat, cache, width);
    cache[key] = if result { 1 } else { 2 };
    result
}

fn compute(
    pat: &[char],
    txt: &[char],
    pi: usize,
    ti: usize,
    flat: bool,
    cache: &mut [u8],
    width: usize,
) -> bool {
    if pi == pat.len() {
        return ti == txt.len();
    }
    match pat[pi] {
        '*' => {
            // Collapse a run of consecutive stars: two or more means `**`
            // (crosses `/`), a lone `*` stays inside one segment — unless the
            // scope is flat, where every `*` crosses `/`.
            let mut end = pi;
            while end < pat.len() && pat[end] == '*' {
                end += 1;
            }
            let spans_slash = flat || end - pi >= 2;
            // Either the star run matches nothing and we resume after it,
            // or it swallows one more character (any char when it spans `/`,
            // a non-`/` char otherwise) and we stay parked on the run.
            if matches(pat, txt, end, ti, flat, cache, width) {
                return true;
            }
            ti < txt.len()
                && (spans_slash || txt[ti] != '/')
                && matches(pat, txt, pi, ti + 1, flat, cache, width)
        }
        '?' => {
            ti < txt.len()
                && (flat || txt[ti] != '/')
                && matches(pat, txt, pi + 1, ti + 1, flat, cache, width)
        }
        literal => {
            ti < txt.len()
                && txt[ti] == literal
                && matches(pat, txt, pi + 1, ti + 1, flat, cache, width)
        }
    }
}

/// A pattern token, the unit the subsumption check reasons over. A maximal run
/// of `*` collapses to one token: two or more stars become [`Tok::DStar`]
/// (spans `/`), a lone star [`Tok::Star`] (stays in a segment).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok {
    Lit(char),
    Any1,
    Star,
    DStar,
}

fn tokenize(pattern: &str) -> Vec<Tok> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                let start = i;
                while i < chars.len() && chars[i] == '*' {
                    i += 1;
                }
                toks.push(if i - start >= 2 {
                    Tok::DStar
                } else {
                    Tok::Star
                });
            }
            '?' => {
                toks.push(Tok::Any1);
                i += 1;
            }
            c => {
                toks.push(Tok::Lit(c));
                i += 1;
            }
        }
    }
    toks
}

/// Sound check: does glob `a` match **every** string that glob `b` matches —
/// i.e. is `L(a)` a superset of `L(b)`?
///
/// This is glob *language inclusion*, used by the shadow analysis to decide
/// when one rule's pattern already covers another's. It is deliberately
/// **conservative**: it may answer `false` when the true answer is `true`, but
/// never the reverse — a linter must not wrongly call a reachable rule dead.
/// The `scope` rules from [`glob_match`] carry over: under [`GlobScope::Segmented`]
/// a single `*`/`?` never spans `/` while `**` does; under [`GlobScope::Flat`]
/// every `*`/`?` spans `/`. Both globs are read under the same scope, since they
/// are patterns over the same field.
pub(crate) fn glob_subsumes(a: &str, b: &str, scope: GlobScope) -> bool {
    if a == b {
        return true;
    }
    let flat = matches!(scope, GlobScope::Flat);
    let at = tokenize(a);
    let bt = tokenize(b);
    let width = bt.len() + 1;
    let mut cache = vec![0u8; (at.len() + 1) * width];
    covers(&at, &bt, 0, 0, flat, &mut cache, width)
}

fn covers(
    a: &[Tok],
    b: &[Tok],
    ai: usize,
    bi: usize,
    flat: bool,
    cache: &mut [u8],
    width: usize,
) -> bool {
    let key = ai * width + bi;
    match cache[key] {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let result = covers_compute(a, b, ai, bi, flat, cache, width);
    cache[key] = if result { 1 } else { 2 };
    result
}

fn covers_compute(
    a: &[Tok],
    b: &[Tok],
    ai: usize,
    bi: usize,
    flat: bool,
    cache: &mut [u8],
    width: usize,
) -> bool {
    if ai == a.len() {
        // `a` can now only produce "", so it covers `b` iff `b` is also spent.
        return bi == b.len();
    }
    if bi == b.len() {
        // `b` produces only ""; `a` covers it iff its tail can be empty too.
        return a[ai..].iter().all(|t| matches!(t, Tok::Star | Tok::DStar));
    }
    match a[ai] {
        // A literal in `a` is only covered if `b` forces that exact char next.
        Tok::Lit(c) => match b[bi] {
            Tok::Lit(d) => c == d && covers(a, b, ai + 1, bi + 1, flat, cache, width),
            _ => false,
        },
        // `?` consumes exactly one char (non-`/` when segmented), so `b` must
        // produce exactly one — and not a `/` unless the scope is flat.
        Tok::Any1 => match b[bi] {
            Tok::Lit(d) => (flat || d != '/') && covers(a, b, ai + 1, bi + 1, flat, cache, width),
            Tok::Any1 => covers(a, b, ai + 1, bi + 1, flat, cache, width),
            _ => false,
        },
        // A single `*`: under flat scope it spans `/` exactly like `**`;
        // otherwise it matches only a run of non-`/` chars.
        Tok::Star if !flat => {
            if covers(a, b, ai + 1, bi, flat, cache, width) {
                return true;
            }
            let absorbable = match b[bi] {
                Tok::Lit(d) => d != '/',
                Tok::Any1 | Tok::Star => true,
                Tok::DStar => false,
            };
            absorbable && covers(a, b, ai, bi + 1, flat, cache, width)
        }
        // `**` (or any `*` under flat scope) matches anything: skip it, or
        // absorb any one `b` token.
        Tok::Star | Tok::DStar => {
            covers(a, b, ai + 1, bi, flat, cache, width)
                || covers(a, b, ai, bi + 1, flat, cache, width)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{glob_match, glob_subsumes};
    use crate::ast::GlobScope::{Flat, Segmented};

    #[test]
    fn literal() {
        assert!(glob_match("read", "read", Segmented));
        assert!(!glob_match("read", "write", Segmented));
    }

    #[test]
    fn star_stays_within_a_segment() {
        assert!(glob_match("src/*", "src/main", Segmented));
        assert!(glob_match("src/*", "src/", Segmented));
        assert!(glob_match("*.env", "prod.env", Segmented));
        // A single `*` must not cross a `/`.
        assert!(!glob_match("src/*", "src/a/b", Segmented));
        assert!(!glob_match("*.env", "deep/prod.env", Segmented));
        assert!(!glob_match("src/*", "lib/main", Segmented));
    }

    #[test]
    fn double_star_spans_segments() {
        assert!(glob_match("src/**", "src/a/b/c", Segmented));
        assert!(glob_match("**/.env", "a/b/.env", Segmented));
        assert!(glob_match("**/*.json", "a/b/c.json", Segmented));
        // The classic case a single greedy anchor gets wrong: the trailing
        // segment-bounded `*` forces the leading `**` to grow past a `/`.
        assert!(glob_match("**/*x", "a/b/cx", Segmented));
    }

    #[test]
    fn question_mark_is_one_non_slash_char() {
        assert!(glob_match("v?", "v1", Segmented));
        assert!(!glob_match("v?", "v12", Segmented));
        assert!(!glob_match("a?b", "a/b", Segmented));
    }

    #[test]
    fn star_matches_empty() {
        assert!(glob_match("a*b", "ab", Segmented));
        assert!(glob_match("*", "", Segmented));
        assert!(glob_match("**", "", Segmented));
        assert!(glob_match("**", "a/b/c", Segmented));
    }

    #[test]
    fn flat_scope_lets_a_lone_star_cross_slash() {
        // The command footgun: under flat scope `*` spans `/`, so `git *`
        // matches a git command whose arguments contain a path.
        assert!(glob_match("git *", "git clone a/b", Flat));
        assert!(glob_match("git *", "git status", Flat));
        // `?` is likewise an ordinary single char, `/` included.
        assert!(glob_match("a?b", "a/b", Flat));
        // The very same pattern under segmented scope would refuse the slash.
        assert!(!glob_match("git *", "git clone a/b", Segmented));
    }

    #[test]
    fn subsumes_reflexive_and_catch_all() {
        assert!(glob_subsumes("src/**", "src/**", Segmented));
        assert!(glob_subsumes("**", "src/**", Segmented));
        assert!(glob_subsumes("**", "anything/at/all.txt", Segmented));
        assert!(glob_subsumes("git*", "git status", Segmented));
    }

    #[test]
    fn subsumes_respects_segments() {
        // `**` reaches across `/`, a single `*` does not, so neither direction
        // of `*` vs `src/**` may be claimed.
        assert!(!glob_subsumes("*", "src/**", Segmented));
        assert!(!glob_subsumes("src/*", "src/a/b", Segmented));
        // The narrower pattern never subsumes the broader one.
        assert!(!glob_subsumes("src/**", "**", Segmented));
    }

    #[test]
    fn subsumes_literal_is_just_a_match() {
        // When `b` has no wildcards it denotes one string, so inclusion is a
        // plain match of `a` against it.
        assert!(glob_subsumes("src/**", "src/main.rs", Segmented));
        assert!(!glob_subsumes("src/*", "src/a/b.rs", Segmented));
    }

    #[test]
    fn flat_subsumption_ignores_slash_boundaries() {
        // Under flat scope a lone `*` covers a slashed literal, and the
        // distinction between `*` and `**` collapses.
        assert!(glob_subsumes("git *", "git clone a/b", Flat));
        assert!(glob_subsumes("a*", "a/b/c", Flat));
        assert!(glob_subsumes("*", "any/thing", Flat));
        // ...but the same claim is unsound under segmented scope.
        assert!(!glob_subsumes("git *", "git clone a/b", Segmented));
        assert!(!glob_subsumes("a*", "a/b/c", Segmented));
    }
}
