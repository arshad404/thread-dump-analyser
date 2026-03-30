use tdanalyzer::analyzer::{contention, deadlock, heap_analysis, hot_threads, thread_overview};
use tdanalyzer::parser::{heap_histogram, thread_dump};
use tdanalyzer::model::ThreadRole;

const SAMPLE_DUMP: &str = include_str!("fixtures/sample-thread-dump.txt");
const DEADLOCK_DUMP: &str = include_str!("fixtures/deadlock-thread-dump.txt");
const SAMPLE_HISTO: &str = include_str!("fixtures/sample-heap-histogram.txt");

// ─── Parser tests ─────────────────────────────────────────────────────────────

#[test]
fn test_parse_sample_thread_dump_succeeds() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("should parse sample dump");
    assert!(dump.threads.len() >= 7, "expected at least 7 threads");
}

#[test]
fn test_parse_detects_jvm_info() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("should parse");
    assert!(dump.jvm_info.is_some(), "expected JVM info line");
    assert!(dump.jvm_info.unwrap().contains("OpenJDK"));
}

#[test]
fn test_parse_heap_histogram_succeeds() {
    let snap = heap_histogram::parse(SAMPLE_HISTO).expect("should parse histogram");
    assert_eq!(snap.entries.len(), 10);
    assert_eq!(snap.entries[0].class_name, "[B");
    assert_eq!(snap.total_instances, 323100);
}

// ─── Thread overview tests ────────────────────────────────────────────────────

#[test]
fn test_thread_overview_counts() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("parse");
    let result = thread_overview::analyze(&dump);

    assert!(result.total >= 7);
    assert!(result.system >= 1, "GC thread should be system");
    assert!(result.idle >= 1, "idle http-nio threads should be detected");
    assert!(result.active >= 1, "active search workers should be detected");
}

#[test]
fn test_thread_overview_pools_detected() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("parse");
    let result = thread_overview::analyze(&dump);

    let pool_names: Vec<&str> = result.pools.iter().map(|p| p.name.as_str()).collect();
    assert!(pool_names.contains(&"http-nio-exec"), "http-nio pool should be detected");
    assert!(pool_names.contains(&"my-search-worker"), "my-search-worker pool should be detected");
}

#[test]
fn test_pool_idle_detection() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("parse");
    let result = thread_overview::analyze(&dump);

    let nio_pool = result.pools.iter().find(|p| p.name == "http-nio-exec");
    assert!(nio_pool.is_some(), "http-nio-exec pool should exist");
    let nio = nio_pool.unwrap();
    assert!(nio.idle >= 1, "http-nio threads should be idle");
}

// ─── Deadlock tests ────────────────────────────────────────────────────────────

#[test]
fn test_no_deadlock_in_sample_dump() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("parse");
    let result = deadlock::analyze(&dump);
    assert!(result.deadlocks.is_empty(), "sample dump should have no deadlocks");
}

#[test]
fn test_deadlock_detected_in_deadlock_dump() {
    let dump = thread_dump::parse(DEADLOCK_DUMP).expect("parse deadlock dump");
    let result = deadlock::analyze(&dump);
    assert!(!result.deadlocks.is_empty(), "deadlock should be detected");
    let cycle = &result.deadlocks[0];
    assert!(cycle.threads.iter().any(|t| t.contains("indexer-worker")));
}

#[test]
fn test_deadlock_finding_is_critical() {
    use tdanalyzer::model::Severity;
    let dump = thread_dump::parse(DEADLOCK_DUMP).expect("parse");
    let result = deadlock::analyze(&dump);
    assert!(result.findings.iter().any(|f| f.severity == Severity::Critical));
}

// ─── Contention tests ─────────────────────────────────────────────────────────

#[test]
fn test_no_contention_in_sample_dump() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("parse");
    let result = contention::analyze(&dump);
    // Sample dump has no BLOCKED threads waiting on a monitor
    assert!(result.hotspots.is_empty());
}

#[test]
fn test_contention_detected_in_deadlock_dump() {
    let dump = thread_dump::parse(DEADLOCK_DUMP).expect("parse");
    let result = contention::analyze(&dump);
    assert!(!result.hotspots.is_empty(), "deadlock dump has BLOCKED threads");
}

// ─── Hot threads tests ────────────────────────────────────────────────────────

#[test]
fn test_hot_threads_groups_identical_stacks() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("parse");
    let result = hot_threads::analyze(&dump);
    // my-search-worker-1 and -2 share an identical stack
    let search_group = result.groups.iter().find(|g| {
        g.thread_names.iter().any(|t| t.starts_with("my-search-worker"))
    });
    assert!(search_group.is_some(), "search workers with identical stacks should be grouped");
    assert_eq!(search_group.unwrap().thread_names.len(), 2);
}

// ─── Heap analysis tests ──────────────────────────────────────────────────────

#[test]
fn test_heap_analysis_top_by_bytes() {
    let snap = heap_histogram::parse(SAMPLE_HISTO).expect("parse histo");
    let result = heap_analysis::analyze(&snap);
    assert!(!result.top_by_bytes.is_empty());
    // [B (byte[]) is the biggest — should be first
    assert!(result.top_by_bytes[0].contains("[B"));
}

#[test]
fn test_heap_compare_detects_growth() {
    // Simulate snapshot 2 with more CacheEntry instances
    let snap1 = heap_histogram::parse(SAMPLE_HISTO).expect("parse snap1");
    // Build a synthetic snap2 with CacheEntry doubled
    let snap2_text = SAMPLE_HISTO
        .replace("          5100       81000000  com.example.cache.CacheEntry",
                 "         10200      162000000  com.example.cache.CacheEntry");
    let snap2 = heap_histogram::parse(&snap2_text).expect("parse snap2");

    let result = heap_analysis::compare(&snap1, &snap2);
    let cache_diff = result.diffs.iter()
        .find(|d| d.class_name.contains("CacheEntry"))
        .expect("CacheEntry diff should exist");
    assert!(cache_diff.delta_instances > 0, "CacheEntry should have grown");
    assert!(cache_diff.is_growing_fast(), "growth should be flagged as fast");
}

// ─── Role classification tests ────────────────────────────────────────────────

#[test]
fn test_gc_thread_classified_as_system() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("parse");
    let gc = dump.threads.iter().find(|t| t.name.starts_with("GC Thread"));
    assert!(gc.is_some(), "GC thread should be present");
    assert_eq!(gc.unwrap().role, ThreadRole::System);
}

#[test]
fn test_reactor_nio_thread_classified_as_idle() {
    let dump = thread_dump::parse(SAMPLE_DUMP).expect("parse");
    let reactor = dump.threads.iter().find(|t| t.name.starts_with("reactor-http-nio"));
    assert!(reactor.is_some(), "reactor-http-nio thread should be present");
    // EPoll.wait → idle
    assert_eq!(reactor.unwrap().role, ThreadRole::Idle);
}
