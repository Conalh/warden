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

pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    let width = txt.len() + 1;
    // 0 = unexplored, 1 = matched, 2 = failed.
    let mut cache = vec![0u8; (pat.len() + 1) * width];
    matches(&pat, &txt, 0, 0, &mut cache, width)
}

fn matches(pat: &[char], txt: &[char], pi: usize, ti: usize, cache: &mut [u8], width: usize) -> bool {
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

fn compute(pat: &[char], txt: &[char], pi: usize, ti: usize, cache: &mut [u8], width: usize) -> bool {
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
        '?' => {
            ti < txt.len() && txt[ti] != '/' && matches(pat, txt, pi + 1, ti + 1, cache, width)
        }
        literal => {
            ti < txt.len() && txt[ti] == literal && matches(pat, txt, pi + 1, ti + 1, cache, width)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::glob_match;

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
}
