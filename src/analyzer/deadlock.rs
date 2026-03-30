use crate::model::{Finding, ThreadDump};

pub struct DeadlockResult {
    pub deadlocks: Vec<DeadlockCycle>,
    pub findings: Vec<Finding>,
}

pub struct DeadlockCycle {
    pub threads: Vec<String>,
    pub description: String,
}

pub fn analyze(dump: &ThreadDump) -> DeadlockResult {
    let mut deadlocks = Vec::new();

    // 1. Use jstack's own deadlock section if present
    if let Some(ref section) = dump.deadlock_section {
        let cycles = parse_jstack_deadlock_section(section);
        deadlocks.extend(cycles);
    }

    // 2. Independently detect cycles via lock-wait graph (catches cases jstack misses)
    let graph_cycles = detect_graph_cycles(dump);
    for cycle in graph_cycles {
        let already_found = deadlocks.iter().any(|d: &DeadlockCycle| {
            d.threads.iter().all(|t| cycle.threads.contains(t))
        });
        if !already_found {
            deadlocks.push(cycle);
        }
    }

    let findings = build_findings(&deadlocks);

    DeadlockResult { deadlocks, findings }
}

/// Parse the "Found N deadlock(s)" section that jstack appends
fn parse_jstack_deadlock_section(section: &str) -> Vec<DeadlockCycle> {
    let mut cycles = Vec::new();
    let mut current_threads: Vec<String> = Vec::new();
    let mut current_desc = String::new();

    for line in section.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('"') {
            // New thread name in the deadlock chain
            if let Some(end) = trimmed[1..].find('"') {
                current_threads.push(trimmed[1..end + 1].to_string());
            }
            current_desc.push_str(line);
            current_desc.push('\n');
        } else if trimmed.is_empty() && !current_threads.is_empty() {
            // End of a deadlock block
            cycles.push(DeadlockCycle {
                threads: current_threads.clone(),
                description: current_desc.trim().to_string(),
            });
            current_threads.clear();
            current_desc.clear();
        } else {
            current_desc.push_str(line);
            current_desc.push('\n');
        }
    }

    // Flush last block
    if !current_threads.is_empty() {
        cycles.push(DeadlockCycle {
            threads: current_threads,
            description: current_desc.trim().to_string(),
        });
    }

    cycles
}

/// Build a lock-wait graph and detect cycles via DFS
/// Each node is a thread name; an edge A→B means "A is waiting for a lock held by B"
fn detect_graph_cycles(dump: &ThreadDump) -> Vec<DeadlockCycle> {
    use std::collections::HashMap;

    // Map monitor address → holder thread name
    let mut lock_holder: HashMap<String, String> = HashMap::new();
    for thread in &dump.threads {
        for monitor in &thread.locked_monitors {
            lock_holder.insert(monitor.clone(), thread.name.clone());
        }
    }

    // Map thread name → thread it's waiting on (if any)
    let mut waits_for: HashMap<String, String> = HashMap::new();
    for thread in &dump.threads {
        if let Some(ref monitor) = thread.waiting_to_lock {
            if let Some(holder) = lock_holder.get(monitor) {
                if holder != &thread.name {
                    waits_for.insert(thread.name.clone(), holder.clone());
                }
            }
        }
    }

    // DFS cycle detection
    let mut cycles = Vec::new();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();

    for start in waits_for.keys() {
        if visited.contains(start) {
            continue;
        }
        let mut path = Vec::new();
        let mut current = start.clone();
        let mut path_set: std::collections::HashSet<String> = std::collections::HashSet::new();

        loop {
            if path_set.contains(&current) {
                // Found a cycle — extract just the cycle portion
                let cycle_start = path.iter().position(|t| t == &current).unwrap_or(0);
                let cycle_threads: Vec<String> = path[cycle_start..].to_vec();
                let desc = format!(
                    "Deadlock cycle: {}",
                    cycle_threads.join(" → ")
                );
                cycles.push(DeadlockCycle {
                    threads: cycle_threads,
                    description: desc,
                });
                break;
            }

            visited.insert(current.clone());
            path_set.insert(current.clone());
            path.push(current.clone());

            if let Some(next) = waits_for.get(&current) {
                current = next.clone();
            } else {
                break;
            }
        }
    }

    cycles
}

fn build_findings(deadlocks: &[DeadlockCycle]) -> Vec<Finding> {
    if deadlocks.is_empty() {
        return vec![Finding::healthy("No deadlocks detected", "Lock-wait graph is acyclic.")];
    }

    deadlocks
        .iter()
        .map(|cycle| {
            Finding::critical(
                format!("Deadlock detected ({} threads)", cycle.threads.len()),
                format!("Threads involved: {}", cycle.threads.join(", ")),
            )
            .with_hint("Run: tdanalyzer deadlock <file>  for the full chain")
        })
        .collect()
}
