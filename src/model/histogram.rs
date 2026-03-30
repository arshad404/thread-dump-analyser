use serde::{Deserialize, Serialize};

/// A single entry from a jmap -histo output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoEntry {
    pub rank: usize,
    pub instances: u64,
    pub bytes: u64,
    pub class_name: String,
}

impl HistoEntry {
    pub fn bytes_mb(&self) -> f64 {
        self.bytes as f64 / (1024.0 * 1024.0)
    }

    /// True if this class is a known memory-leak-prone type
    pub fn is_suspicious(&self) -> bool {
        let known = &[
            "[B",                           // byte[]
            "[C",                           // char[]
            "java.lang.String",
            "java.util.HashMap$Entry",
            "java.util.concurrent.ConcurrentHashMap$Node",
            "java.lang.Object[]",
        ];
        known.iter().any(|&k| self.class_name == k)
    }
}

/// A full parsed heap histogram snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapSnapshot {
    pub entries: Vec<HistoEntry>,
    pub total_instances: u64,
    pub total_bytes: u64,
}

impl HeapSnapshot {
    pub fn total_bytes_mb(&self) -> f64 {
        self.total_bytes as f64 / (1024.0 * 1024.0)
    }

    pub fn top_by_bytes(&self, n: usize) -> Vec<&HistoEntry> {
        let mut sorted: Vec<&HistoEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        sorted.into_iter().take(n).collect()
    }

    pub fn top_by_instances(&self, n: usize) -> Vec<&HistoEntry> {
        let mut sorted: Vec<&HistoEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| b.instances.cmp(&a.instances));
        sorted.into_iter().take(n).collect()
    }
}

/// Growth diff between two heap snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoDiff {
    pub class_name: String,
    pub delta_instances: i64,
    pub delta_bytes: i64,
    pub instances_t1: u64,
    pub instances_t2: u64,
    pub bytes_t1: u64,
    pub bytes_t2: u64,
}

impl HistoDiff {
    pub fn delta_bytes_mb(&self) -> f64 {
        self.delta_bytes as f64 / (1024.0 * 1024.0)
    }

    pub fn is_growing_fast(&self) -> bool {
        // More than 50 MB growth or more than 50% increase
        self.delta_bytes > 50 * 1024 * 1024
            || (self.bytes_t1 > 0
                && (self.delta_bytes as f64 / self.bytes_t1 as f64) > 0.5)
    }
}
