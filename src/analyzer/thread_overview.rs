use crate::model::{Finding, Thread, ThreadDump, ThreadPool, ThreadRole, ThreadState};
use std::collections::HashMap;

pub struct ThreadOverviewResult {
    pub total: usize,
    pub runnable: usize,
    pub blocked: usize,
    pub waiting: usize,
    pub timed_waiting: usize,
    pub active: usize,
    pub idle: usize,
    pub system: usize,
    pub pools: Vec<ThreadPool>,
    pub findings: Vec<Finding>,
}

pub fn analyze(dump: &ThreadDump) -> ThreadOverviewResult {
    let total = dump.threads.len();
    let runnable  = count_state(&dump.threads, &ThreadState::Runnable);
    let blocked   = count_state(&dump.threads, &ThreadState::Blocked);
    let waiting   = count_state(&dump.threads, &ThreadState::Waiting);
    let timed     = count_state(&dump.threads, &ThreadState::TimedWaiting);
    let active    = count_role(&dump.threads, &ThreadRole::Active);
    let idle      = count_role(&dump.threads, &ThreadRole::Idle);
    let system    = count_role(&dump.threads, &ThreadRole::System);

    let pools = build_pools(&dump.threads);
    let findings = build_findings(blocked, &pools);

    ThreadOverviewResult {
        total,
        runnable,
        blocked,
        waiting,
        timed_waiting: timed,
        active,
        idle,
        system,
        pools,
        findings,
    }
}

fn count_state(threads: &[Thread], state: &ThreadState) -> usize {
    threads.iter().filter(|t| &t.state == state).count()
}

fn count_role(threads: &[Thread], role: &ThreadRole) -> usize {
    threads.iter().filter(|t| &t.role == role).count()
}

fn build_pools(threads: &[Thread]) -> Vec<ThreadPool> {
    let mut map: HashMap<String, (usize, usize, usize, usize)> = HashMap::new();
    // (total, active, idle, blocked)

    for t in threads {
        if let Some(pool) = &t.pool_name {
            let entry = map.entry(pool.clone()).or_insert((0, 0, 0, 0));
            entry.0 += 1;
            match t.role {
                ThreadRole::Active  => entry.1 += 1,
                ThreadRole::Idle    => entry.2 += 1,
                ThreadRole::Blocked => entry.3 += 1,
                ThreadRole::System  => {}
            }
        }
    }

    let mut pools: Vec<ThreadPool> = map
        .into_iter()
        .map(|(name, (total, active, idle, blocked))| ThreadPool {
            name,
            total,
            active,
            idle,
            blocked,
        })
        .collect();

    // Sort by total descending so the biggest pools appear first
    pools.sort_by(|a, b| b.total.cmp(&a.total));
    pools
}

fn build_findings(blocked: usize, pools: &[ThreadPool]) -> Vec<Finding> {
    let mut findings = Vec::new();

    if blocked > 0 {
        findings.push(
            Finding::warning(
                format!("{blocked} thread(s) are BLOCKED on a lock"),
                "Blocked threads may indicate lock contention or a deadlock.",
            )
            .with_hint("Run: tdanalyzer contention <file>"),
        );
    }

    for pool in pools {
        if pool.is_saturated() {
            findings.push(
                Finding::warning(
                    format!("Pool '{}' is saturated ({}/{} active)", pool.name, pool.active, pool.total),
                    format!(
                        "{:.0}% of threads in this pool are actively working — it may be undersized.",
                        pool.active_percent()
                    ),
                )
                .with_hint("Run: tdanalyzer hot <file>"),
            );
        }

        if pool.is_oversized() {
            findings.push(
                Finding::info(
                    format!("Pool '{}' may be oversized ({}/{} idle)", pool.name, pool.idle, pool.total),
                    format!(
                        "{:.0}% of threads in this pool are idle — consider reducing pool size.",
                        pool.idle_percent()
                    ),
                ),
            );
        }
    }

    if findings.is_empty() {
        findings.push(Finding::healthy(
            "Thread pools look healthy",
            "No saturation or oversizing detected.",
        ));
    }

    findings
}
