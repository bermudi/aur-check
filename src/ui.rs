//! TTY-aware stderr reporter.

use std::io::IsTerminal;

use crate::classifier::Reporter;

/// Render untrusted candidate/provider text without terminal control bytes.
/// Raw evidence remains unchanged on disk; only presentation is escaped.
pub fn terminal_safe(text: &str) -> String {
    render_safe(text.as_bytes(), false)
}

/// Escape untrusted bytes while preserving patch line structure for paging.
pub fn document_safe(text: &str) -> String {
    document_safe_bytes(text.as_bytes())
}

pub fn document_safe_bytes(bytes: &[u8]) -> String {
    render_safe(bytes, true)
}

pub fn error(text: &str) {
    eprintln!("error: {}", terminal_safe(text));
}

fn render_safe(bytes: &[u8], preserve_newlines: bool) -> String {
    let mut safe = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b' '..=b'~' => safe.push(byte as char),
            b'\n' if preserve_newlines => safe.push('\n'),
            b'\n' => safe.push_str("\\n"),
            b'\r' => safe.push_str("\\r"),
            b'\t' => safe.push_str("\\t"),
            _ => safe.push_str(&format!("\\x{byte:02x}")),
        }
    }
    safe
}

pub struct StderrReporter {
    color: bool,
}

impl StderrReporter {
    pub fn new() -> Self {
        Self {
            color: std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    fn styled(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn hits(&self, label: &str, code: &str, tag: &str, hits: &[String], limit: usize) {
        eprintln!("  {} [{}]", self.styled(code, label), terminal_safe(tag));
        for hit in hits.iter().take(limit) {
            eprintln!("      {}", terminal_safe(hit));
        }
    }
}

impl Default for StderrReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for StderrReporter {
    fn block_hits(&mut self, tag: &str, hits: &[String], limit: usize) {
        self.hits("BLOCK", "1;31", tag, hits, limit);
    }

    fn review_hits(&mut self, tag: &str, hits: &[String], limit: usize) {
        self.hits("review", "1;33", tag, hits, limit);
    }

    fn review_msg(&mut self, msg: &str) {
        eprintln!("  {} {}", self.styled("1;33", "review"), terminal_safe(msg));
    }

    fn dim(&mut self, msg: &str) {
        eprintln!("{}", self.styled("2", &terminal_safe(msg)));
    }

    fn review_needed(&mut self, summary: &str, detail: &str) {
        eprintln!(
            "  {} {}",
            self.styled("1;33", "review needed —"),
            terminal_safe(summary)
        );
        eprintln!("      added: {}", terminal_safe(detail));
    }
}

#[cfg(test)]
mod tests {
    use super::{document_safe, document_safe_bytes, terminal_safe};

    #[test]
    fn terminal_output_escapes_control_and_non_ascii_bytes() {
        assert_eq!(
            terminal_safe("ok\x1b[2J\r\n\t\u{007f}\u{0080}"),
            "ok\\x1b[2J\\r\\n\\t\\x7f\\xc2\\x80"
        );
        assert_eq!(document_safe("a\n\x1bb"), "a\n\\x1bb");
        assert_eq!(document_safe_bytes(b"a\n\xffb"), "a\n\\xffb");
    }
}
