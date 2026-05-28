//! Glob matching for the `matches` operator.
//!
//! Classic backtracking glob: `*` matches any run of characters (including
//! empty), `?` matches exactly one. Consecutive `*` collapse naturally, so a
//! `**` written for readability behaves the same as `*` in v0. Segment-aware
//! `**` (not crossing `/`) is a planned v1 refinement.

pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Backtracking anchors: where the last `*` was, and how far we'd advanced
    // in the text when we hit it.
    let mut star: Option<usize> = None;
    let mut mark = 0usize;

    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == '?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(star_pi) = star {
            // Mismatch after a `*`: let the star swallow one more char.
            pi = star_pi + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }

    // Trailing `*`s can match the empty remainder.
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
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
    fn star() {
        assert!(glob_match("src/*", "src/main"));
        assert!(glob_match("src/*", "src/"));
        assert!(glob_match("*.env", "prod.env"));
        assert!(glob_match("src/**", "src/a/b/c"));
        assert!(!glob_match("src/*", "lib/main"));
    }

    #[test]
    fn question_mark() {
        assert!(glob_match("v?", "v1"));
        assert!(!glob_match("v?", "v12"));
    }

    #[test]
    fn star_matches_empty() {
        assert!(glob_match("a*b", "ab"));
        assert!(glob_match("*", ""));
    }
}
