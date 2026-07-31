//! TTY-aware stderr reporter.

use std::io::IsTerminal;

use crate::classifier::Reporter;

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
        eprintln!("  {} [{tag}]", self.styled(code, label));
        for hit in hits.iter().take(limit) {
            eprintln!("      {hit}");
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
        eprintln!("  {} {msg}", self.styled("1;33", "review"));
    }

    fn dim(&mut self, msg: &str) {
        eprintln!("{}", self.styled("2", msg));
    }

    fn review_needed(&mut self, summary: &str, detail: &str) {
        eprintln!("  {} {summary}", self.styled("1;33", "review needed —"));
        eprintln!("      added: {detail}");
    }
}
