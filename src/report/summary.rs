use crate::analyzer::{
    contention::{self, ContentionResult},
    deadlock::{self, DeadlockResult},
    heap_analysis::{self, HeapAnalysisResult},
    hot_threads::{self, HotThreadsResult},
    thread_overview::{self, ThreadOverviewResult},
};
use crate::model::{Finding, HeapSnapshot, Severity, ThreadDump};
use chrono::Local;

pub struct SummaryReport {
    pub analyzed_at: String,
    pub thread_dump_file: String,
    pub histogram_file: Option<String>,
    pub thread_overview: ThreadOverviewResult,
    pub deadlock: DeadlockResult,
    pub contention: ContentionResult,
    pub hot_threads: HotThreadsResult,
    pub heap: Option<HeapAnalysisResult>,
    pub recommendations: Vec<String>,
}

impl SummaryReport {
    pub fn build(
        dump: &ThreadDump,
        heap: Option<&HeapSnapshot>,
        thread_dump_file: &str,
        histogram_file: Option<&str>,
    ) -> Self {
        let thread_overview = thread_overview::analyze(dump);
        let deadlock        = deadlock::analyze(dump);
        let contention      = contention::analyze(dump);
        let hot_threads     = hot_threads::analyze(dump);
        let heap_result     = heap.map(|h| heap_analysis::analyze(h));

        let recommendations = build_recommendations(
            &thread_overview,
            &deadlock,
            &contention,
            &hot_threads,
            heap_result.as_ref(),
        );

        SummaryReport {
            analyzed_at: Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string(),
            thread_dump_file: thread_dump_file.to_string(),
            histogram_file: histogram_file.map(str::to_string),
            thread_overview,
            deadlock,
            contention,
            hot_threads,
            heap: heap_result,
            recommendations,
        }
    }

    /// Collect all findings across all analyzers, sorted by severity (Critical first)
    pub fn all_findings(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = Vec::new();
        findings.extend(self.deadlock.findings.iter());
        findings.extend(self.contention.findings.iter());
        findings.extend(self.hot_threads.findings.iter());
        findings.extend(self.thread_overview.findings.iter());
        if let Some(ref heap) = self.heap {
            findings.extend(heap.findings.iter());
        }
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    pub fn highest_severity(&self) -> &Severity {
        self.all_findings()
            .first()
            .map(|f| &f.severity)
            .unwrap_or(&Severity::Healthy)
    }

    pub fn count_by_severity(&self, sev: &Severity) -> usize {
        self.all_findings()
            .iter()
            .filter(|f| &f.severity == sev)
            .count()
    }
}

fn build_recommendations(
    overview: &ThreadOverviewResult,
    deadlock: &DeadlockResult,
    contention: &ContentionResult,
    hot: &HotThreadsResult,
    heap: Option<&HeapAnalysisResult>,
) -> Vec<String> {
    let mut recs = Vec::new();

    if !deadlock.deadlocks.is_empty() {
        recs.push(format!(
            "🔴 URGENT: Resolve {} deadlock(s) — service may be partially frozen",
            deadlock.deadlocks.len()
        ));
    }

    if !contention.hotspots.is_empty() {
        let top = &contention.hotspots[0];
        recs.push(format!(
            "Investigate lock '{}' held by {:?} — {} threads are blocked waiting",
            top.monitor_class,
            top.owner_thread.as_deref().unwrap_or("unknown"),
            top.waiter_count()
        ));
    }

    let saturated: Vec<_> = overview.pools.iter().filter(|p| p.is_saturated()).collect();
    for pool in &saturated {
        recs.push(format!(
            "Pool '{}' is saturated ({}/{} active) — consider increasing pool size or reducing load",
            pool.name, pool.active, pool.total
        ));
    }

    let oversized: Vec<_> = overview.pools.iter().filter(|p| p.is_oversized()).collect();
    for pool in oversized {
        recs.push(format!(
            "Pool '{}' is oversized ({}/{} idle) — consider reducing pool size to free resources",
            pool.name, pool.idle, pool.total
        ));
    }

    if !hot.groups.is_empty() && hot.groups[0].thread_names.len() >= 5 {
        recs.push(format!(
            "{} threads share an identical stack — investigate possible pool exhaustion at: {}",
            hot.groups[0].thread_names.len(),
            hot.groups[0].top_frames.first().map(String::as_str).unwrap_or("unknown frame")
        ));
    }

    if let Some(heap) = heap {
        for s in &heap.suspicious {
            recs.push(format!("Heap: potential leak candidate — {s}"));
        }
    }

    if recs.is_empty() {
        recs.push("No immediate action required — system appears healthy.".to_string());
    }

    recs
}
