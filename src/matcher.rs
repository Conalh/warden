//! Glob matching for the `matches` operator.
//!
//! Segment-aware backtracking glob, following the gitignore/`.gitignore`
//! convention where `/` is a hard boundary:
//!
//! - `*`  matches any run of characters **except** `/` (one path segment),
//! - `**` (a run of two or more `*`) matches any run **including** `/`,
//! - `?`  matches exactly one character, again never `/`,
//! - any other character is a literal (so a `/` in the pattern matches a `/`).
//!
//! So `src/*` matches `src/main.rs` but not `src/a/b.rs`, while `src/**`
//! matches both. The matcher is a plain recursive backtracker memoized on
//! `(pattern index, text index)`, which bounds it to `O(pattern * text)` and
//! lets `**` try every split point — a single greedy star anchor cannot,
//! because a later segment-bounded `*` may force an earlier `**` to grow.
//!
//! The same module also answers a *static* question for the shadow analysis:
//! [`glob_subsumes`] decides whether one glob's match-set contains another's
//! (glob language inclusion), conservatively and with the same segment rules.

pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    let width = txt.len() + 1;
    // 0 = unexplored, 1 = matched, 2 = failed.
    let mut cache = vec![0u8; (pat.len() + 1) * width];
    matches(&pat, &txt, 0, 0, &mut cache, width)
}

fn matches(
    pat: &[char],
    txt: &[char],
    pi: usize,
    ti: usize,
    cache: &mut [u8],
    width: usize,
) -> bool {
    let key = pi * width + ti;
    match cache[key] {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let result = compute(pat, txt, pi, ti, cache, width);
    cache[key] = if result { 1 } else { 2 };
    result
}

fn compute(
    pat: &[char],
    txt: &[char],
    pi: usize,
    ti: usize,
    cache: &mut [u8],
    width: usize,
) -> bool {
    if pi == pat.len() {
        return ti == txt.len();
    }
    match pat[pi] {
        '*' => {
            // Collapse a run of consecutive stars: two or more means `**`
            // (crosses `/`), a lone `*` stays inside one segment.
            let mut end = pi;
            while end < pat.len() && pat[end] == '*' {
                end += 1;
            }
            let spans_slash = end - pi >= 2;
            // Either the star run matches nothing and we resume after it,
            // or it swallows one more character (any char for `**`, a
            // non-`/` char for a single `*`) and we stay parked on the run.
            if matches(pat, txt, end, ti, cache, width) {
                return true;
            }
            ti < txt.len()
                && (spans_slash || txt[ti] != '/')
                && matches(pat, txt, pi, ti + 1, cache, width)
        }
        '?' => ti < txt.len() && txt[ti] != '/' && matches(pat, txt, pi + 1, ti + 1, cache, width),
        literal => {
            ti < txt.len() && txt[ti] == literal && matches(pat, txt, pi + 1, ti + 1, cache, width)
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
/// The segment rules from [`glob_match`] carry over: a single `*`/`?` never
/// spans `/`, while `**` does.
pub(crate) fn glob_subsumes(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let at = tokenize(a);
    let bt = tokenize(b);
    let width = bt.len() + 1;
    let mut cache = vec![0u8; (at.len() + 1) * width];
    covers(&at, &bt, 0, 0, &mut cache, width)
}

fn covers(a: &[Tok], b: &[Tok], ai: usize, bi: usize, cache: &mut [u8], width: usize) -> bool {
    let key = ai * width + bi;
    match cache[key] {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let result = covers_compute(a, b, ai, bi, cache, width);
    cache[key] = if result { 1 } else { 2 };
    result
}

fn covers_compute(
    a: &[Tok],
    b: &[Tok],
    ai: usize,
    bi: usize,
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
            Tok::Lit(d) => c == d && covers(a, b, ai + 1, bi + 1, cache, width),
            _ => false,
        },
        // `?` consumes exactly one non-`/` char, so `b` must produce exactly one.
        Tok::Any1 => match b[bi] {
            Tok::Lit(d) => d != '/' && covers(a, b, ai + 1, bi + 1, cache, width),
            Tok::Any1 => covers(a, b, ai + 1, bi + 1, cache, width),
            _ => false,
        },
        // A single `*` matches a run of non-`/` chars: skip it, or let it
        // absorb one `b` token — but only one that can't yield a `/`.
        Tok::Star => {
            if covers(a, b, ai + 1, bi, cache, width) {
                return true;
            }
            let absorbable = match b[bi] {
                Tok::Lit(d) => d != '/',
                Tok::Any1 | Tok::Star => true,
                Tok::DStar => false,
            };
            absorbable && covers(a, b, ai, bi + 1, cache, width)
        }
        // `**` matches anything: skip it, or absorb any one `b` token.
        Tok::DStar => {
            covers(a, b, ai + 1, bi, cache, width) || covers(a, b, ai, bi + 1, cache, width)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{glob_match, glob_subsumes};

    #[test]
    fn literal() {
        assert!(glob_match("read", "read"));
        assert!(!glob_match("read", "write"));
    }

    #[test]
    fn star_stays_within_a_segment() {
        assert!(glob_match("src/*", "src/main"));
        assert!(glob_match("src/*", "src/"));
        assert!(glob_match("*.env", "prod.env"));
        // A single `*` must not cross a `/`.
        assert!(!glob_match("src/*", "src/a/b"));
        assert!(!glob_match("*.env", "deep/prod.env"));
        assert!(!glob_match("src/*", "lib/main"));
    }

    #[test]
    fn double_star_spans_segments() {
        assert!(glob_match("src/**", "src/a/b/c"));
        assert!(glob_match("**/.env", "a/b/.env"));
        assert!(glob_match("**/*.json", "a/b/c.json"));
        // The classic case a single greedy anchor gets wrong: the trailing
        // segment-bounded `*` forces the leading `**` to grow past a `/`.
        assert!(glob_match("**/*x", "a/b/cx"));
    }

    #[test]
    fn question_mark_is_one_non_slash_char() {
        assert!(glob_match("v?", "v1"));
        assert!(!glob_match("v?", "v12"));
        assert!(!glob_match("a?b", "a/b"));
    }

    #[test]
    fn star_matches_empty() {
        assert!(glob_match("a*b", "ab"));
        assert!(glob_match("*", ""));
        assert!(glob_match("**", ""));
        assert!(glob_match("**", "a/b/c"));
    }

    #[test]
    fn subsumes_reflexive_and_catch_all() {
        assert!(glob_subsumes("src/**", "src/**"));
        assert!(glob_subsumes("**", "src/**"));
        assert!(glob_subsumes("**", "anything/at/all.txt"));
        assert!(glob_subsumes("git*", "git status"));
    }

    #[test]
    fn subsumes_respects_segments() {
        // `**` reaches across `/`, a single `*` does not, so neither direction
        // of `*` vs `src/**` may be claimed.
        assert!(!glob_subsumes("*", "src/**"));
        assert!(!glob_subsumes("src/*", "src/a/b"));
        // The narrower pattern never subsumes the broader one.
        assert!(!glob_subsumes("src/**", "**"));
    }

    #[test]
    fn subsumes_literal_is_just_a_match() {
        // When `b` has no wildcards it denotes one string, so inclusion is a
        // plain match of `a` against it.
        assert!(glob_subsumes("src/**", "src/main.rs"));
        assert!(!glob_subsumes("src/*", "src/a/b.rs"));
    }
}
