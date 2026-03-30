use crate::model::{Finding, Thread, ThreadDump, ThreadState};
use std::collections::HashMap;

pub struct ContentionResult {
    pub hotspots: Vec<LockHotspot>,
    pub findings: Vec<Finding>,
}

pub struct LockHotspot {
    pub monitor_address: String,
    pub monitor_class: String,
    pub owner_thread: Option<String>,
    pub owner_state: Option<String>,
    pub waiters: Vec<String>,
}

impl LockHotspot {
    pub fn waiter_count(&self) -> usize {
        self.waiters.len()
    }
}

pub fn analyze(dump: &ThreadDump) -> ContentionResult {
    // Build map: monitor address → holder thread
    let mut holder_map: HashMap<String, &Thread> = HashMap::new();
    for thread in &dump.threads {
        for monitor in &thread.locked_monitors {
            holder_map.insert(monitor.clone(), thread);
        }
    }

    // Group BLOCKED threads by the monitor they're waiting on
    let mut waiter_map: HashMap<String, Vec<&Thread>> = HashMap::new();
    for thread in &dump.threads {
        if thread.state == ThreadState::Blocked {
            if let Some(ref monitor) = thread.waiting_to_lock {
                waiter_map.entry(monitor.clone()).or_default().push(thread);
            }
        }
    }

    // Build hotspots
    let mut hotspots: Vec<LockHotspot> = waiter_map
        .into_iter()
        .map(|(monitor, waiters)| {
            let owner = holder_map.get(&monitor);
            let monitor_class = extract_monitor_class(dump, &monitor);

            LockHotspot {
                monitor_address: monitor,
                monitor_class,
                owner_thread: owner.map(|t| t.name.clone()),
                owner_state: owner.map(|t| t.state.as_str().to_string()),
                waiters: waiters.iter().map(|t| t.name.clone()).collect(),
            }
        })
        .collect();

    // Sort by number of waiters descending
    hotspots.sort_by(|a, b| b.waiter_count().cmp(&a.waiter_count()));

    let findings = build_findings(&hotspots);

    ContentionResult { hotspots, findings }
}

/// Try to find the class name for a monitor address by scanning lock_info fields
fn extract_monitor_class(dump: &ThreadDump, monitor: &str) -> String {
    for thread in &dump.threads {
        for frame in &thread.stack_frames {
            if let Some(ref lock_info) = frame.lock_info {
                if lock_info.contains(monitor) {
                    // Extract class name from "- locked <0x...> (a java.lang.SomeClass)"
                    if let Some(start) = lock_info.find("(a ") {
                        let rest = &lock_info[start + 3..];
                        if let Some(end) = rest.find(')') {
                            return rest[..end].trim().to_string();
                        }
                    }
                    // Simpler form: "(java.lang.SomeClass)"
                    if let Some(start) = lock_info.find('(') {
                        let rest = &lock_info[start + 1..];
                        if let Some(end) = rest.find(')') {
                            return rest[..end].trim().to_string();
                        }
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

fn build_findings(hotspots: &[LockHotspot]) -> Vec<Finding> {
    if hotspots.is_empty() {
        return vec![Finding::healthy(
            "No lock contention detected",
            "No BLOCKED threads found waiting on monitors.",
        )];
    }

    let mut findings = Vec::new();
    for hotspot in hotspots {
        let severity = if hotspot.waiter_count() >= 5 {
            crate::model::Severity::Critical
        } else {
            crate::model::Severity::Warning
        };

        let owner_info = match &hotspot.owner_thread {
            Some(owner) => format!(" (held by \"{owner}\")"),
            None => " (holder unknown — may have been released)".to_string(),
        };

        findings.push(crate::model::Finding {
            severity,
            title: format!(
                "{} threads blocked on {} {}",
                hotspot.waiter_count(),
                hotspot.monitor_class,
                &hotspot.monitor_address
            ),
            detail: format!(
                "Lock {}{}\nWaiters: {}",
                hotspot.monitor_address,
                owner_info,
                hotspot.waiters.join(", ")
            ),
            hint: Some("Run: tdanalyzer contention <file>  for full details".to_string()),
        });
    }

    findings
}
