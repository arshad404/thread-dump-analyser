use crate::model::{Finding, HeapSnapshot, HistoDiff};

pub struct HeapAnalysisResult {
    pub top_by_bytes: Vec<String>,
    pub top_by_instances: Vec<String>,
    pub suspicious: Vec<String>,
    pub findings: Vec<Finding>,
}

pub struct HeapCompareResult {
    pub diffs: Vec<HistoDiff>,
    pub findings: Vec<Finding>,
}

pub fn analyze(snapshot: &HeapSnapshot) -> HeapAnalysisResult {
    let top_by_bytes: Vec<String> = snapshot
        .top_by_bytes(10)
        .iter()
        .map(|e| format!("{:.1} MB  {}  ({} instances)", e.bytes_mb(), e.class_name, e.instances))
        .collect();

    let top_by_instances: Vec<String> = snapshot
        .top_by_instances(10)
        .iter()
        .map(|e| format!("{}  {}  ({:.1} MB)", e.instances, e.class_name, e.bytes_mb()))
        .collect();

    let suspicious: Vec<String> = snapshot
        .top_by_bytes(50)
        .iter()
        .filter(|e| e.is_suspicious() && e.bytes_mb() > 100.0)
        .map(|e| format!("{} — {:.1} MB ({} instances)", e.class_name, e.bytes_mb(), e.instances))
        .collect();

    let findings = build_findings(snapshot, &suspicious);

    HeapAnalysisResult {
        top_by_bytes,
        top_by_instances,
        suspicious,
        findings,
    }
}

/// Compare two heap snapshots and return growth diffs
pub fn compare(snap1: &HeapSnapshot, snap2: &HeapSnapshot) -> HeapCompareResult {
    use std::collections::HashMap;

    let map1: HashMap<&str, &crate::model::HistoEntry> = snap1
        .entries
        .iter()
        .map(|e| (e.class_name.as_str(), e))
        .collect();

    let mut diffs: Vec<HistoDiff> = snap2
        .entries
        .iter()
        .map(|e2| {
            let (inst1, bytes1) = map1
                .get(e2.class_name.as_str())
                .map(|e1| (e1.instances, e1.bytes))
                .unwrap_or((0, 0));

            HistoDiff {
                class_name: e2.class_name.clone(),
                delta_instances: e2.instances as i64 - inst1 as i64,
                delta_bytes: e2.bytes as i64 - bytes1 as i64,
                instances_t1: inst1,
                instances_t2: e2.instances,
                bytes_t1: bytes1,
                bytes_t2: e2.bytes,
            }
        })
        .collect();

    // Sort by byte growth descending
    diffs.sort_by(|a, b| b.delta_bytes.cmp(&a.delta_bytes));

    let findings = build_compare_findings(&diffs);
    HeapCompareResult { diffs, findings }
}

fn build_findings(snapshot: &HeapSnapshot, suspicious: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let total_mb = snapshot.total_bytes_mb();
    if total_mb > 1024.0 {
        findings.push(Finding::warning(
            format!("Total heap usage is {total_mb:.0} MB"),
            "Heap usage exceeds 1 GB — consider investigating large object holders.",
        ));
    }

    for s in suspicious {
        findings.push(Finding::warning(
            format!("Potentially oversized object: {s}"),
            "This class is a known memory-pressure type and is using significant memory.",
        ));
    }

    if findings.is_empty() {
        findings.push(Finding::healthy(
            "Heap histogram looks normal",
            "No suspicious large object types detected.",
        ));
    }

    findings
}

fn build_compare_findings(diffs: &[HistoDiff]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for diff in diffs.iter().take(20) {
        if diff.is_growing_fast() {
            findings.push(
                Finding::warning(
                    format!(
                        "{} growing fast (+{:.1} MB)",
                        diff.class_name,
                        diff.delta_bytes_mb()
                    ),
                    format!(
                        "Instances: {} → {} (+{})\nBytes: {:.1} MB → {:.1} MB",
                        diff.instances_t1,
                        diff.instances_t2,
                        diff.delta_instances,
                        diff.bytes_t1 as f64 / (1024.0 * 1024.0),
                        diff.bytes_t2 as f64 / (1024.0 * 1024.0),
                    ),
                )
                .with_hint("Possible memory leak — monitor across multiple snapshots"),
            );
        }
    }

    if findings.is_empty() {
        findings.push(Finding::healthy(
            "No fast-growing classes detected",
            "Heap growth between snapshots looks normal.",
        ));
    }

    findings
}
