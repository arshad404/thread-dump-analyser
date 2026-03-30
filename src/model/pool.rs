use serde::{Deserialize, Serialize};

/// A detected thread pool with its activity breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPool {
    pub name: String,
    pub total: usize,
    pub active: usize,
    pub idle: usize,
    pub blocked: usize,
}

impl ThreadPool {
    pub fn idle_percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.idle as f64 / self.total as f64) * 100.0
        }
    }

    pub fn active_percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.active as f64 / self.total as f64) * 100.0
        }
    }

    pub fn is_saturated(&self) -> bool {
        self.active_percent() >= 80.0 && self.total >= 4
    }

    pub fn is_oversized(&self) -> bool {
        self.idle_percent() >= 80.0 && self.total >= 10
    }
}
