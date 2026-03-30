use serde::{Deserialize, Serialize};

/// Severity of an analyzer finding
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Healthy,
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn symbol(&self) -> &str {
        match self {
            Severity::Critical => "🔴 CRITICAL",
            Severity::Warning  => "⚠️  WARNING",
            Severity::Info     => "💡 INFO",
            Severity::Healthy  => "✅ HEALTHY",
        }
    }

    pub fn short_symbol(&self) -> &str {
        match self {
            Severity::Critical => "🔴",
            Severity::Warning  => "⚠️",
            Severity::Info     => "💡",
            Severity::Healthy  => "✅",
        }
    }
}

/// A single finding produced by an analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// Actionable hint shown in the summary (e.g. "Run: tdanalyzer contention <file>")
    pub hint: Option<String>,
}

impl Finding {
    pub fn critical(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Critical,
            title: title.into(),
            detail: detail.into(),
            hint: None,
        }
    }

    pub fn warning(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            title: title.into(),
            detail: detail.into(),
            hint: None,
        }
    }

    pub fn info(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            title: title.into(),
            detail: detail.into(),
            hint: None,
        }
    }

    pub fn healthy(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Healthy,
            title: title.into(),
            detail: detail.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}
