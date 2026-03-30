use crate::model::{Finding, Thread, ThreadDump, ThreadRole, ThreadState};
use std::collections::HashMap;

pub struct HotThreadsResult {
    pub groups: Vec<StackGroup>,
    pub findings: Vec<Finding>,
}

/// A group of threads sharing an identical stack signature
pub struct StackGroup {
    pub stack_signature: String,
    pub top_frames: Vec<String>,
    pub thread_names: Vec<String>,
    pub state: ThreadState,
}

pub fn analyze(dump: &ThreadDump) -> HotThreadsResult {
    // Group threads by identical stack signature
    let mut sig_map: HashMap<String, Vec<&Thread>> = HashMap::new();
    for thread in &dump.threads {
        if thread.role == ThreadRole::System || thread.stack_frames.is_empty() {
            continue;
        }
        sig_map
            .entry(thread.stack_signature())
            .or_default()
            .push(thread);
    }

    // Only report groups with 2+ threads (single thread with unique stack is uninteresting)
    let mut groups: Vec<StackGroup> = sig_map
        .into_iter()
        .filter(|(_, threads)| threads.len() >= 2)
        .map(|(sig, threads)| {
            let top_frames: Vec<String> = threads[0]
                .stack_frames
                .iter()
                .take(8)
                .map(|f| f.class_and_method.clone())
                .collect();
            let state = threads[0].state.clone();
            let thread_names = threads.iter().map(|t| t.name.clone()).collect();
            StackGroup {
                stack_signature: sig,
                top_frames,
                thread_names,
                state,
            }
        })
        .collect();

    // Sort by group size descending
    groups.sort_by(|a, b| b.thread_names.len().cmp(&a.thread_names.len()));

    let findings = build_findings(&groups);
    HotThreadsResult { groups, findings }
}

fn build_findings(groups: &[StackGroup]) -> Vec<Finding> {
    if groups.is_empty() {
        return vec![Finding::healthy(
            "No thread stack saturation detected",
            "No large groups of threads share an identical stack.",
        )];
    }

    let mut findings = Vec::new();
    for group in groups {
        let count = group.thread_names.len();
        let top = group.top_frames.first().map(String::as_str).unwrap_or("(empty)");
        let severity = if count >= 10 {
            crate::model::Severity::Warning
        } else {
            crate::model::Severity::Info
        };

        findings.push(crate::model::Finding {
            severity,
            title: format!("{count} threads share the same stack (possible saturation)"),
            detail: format!(
                "State: {}\nTop frame: {}\nThreads: {}",
                group.state.as_str(),
                top,
                group.thread_names.join(", ")
            ),
            hint: Some("Run: tdanalyzer hot <file>  for full stack details".to_string()),
        });
    }

    findings
}
