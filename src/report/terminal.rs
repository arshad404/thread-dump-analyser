use crate::model::Severity;
use crate::report::summary::SummaryReport;
use owo_colors::OwoColorize;

const WIDTH: usize = 60;

pub fn render(report: &SummaryReport) {
    print_header(report);
    print_thread_summary(report);
    print_pool_table(report);
    print_deadlock_section(report);
    print_contention_section(report);
    print_hot_threads_section(report);
    if report.heap.is_some() {
        print_heap_section(report);
    }
    print_findings_summary(report);
    print_recommendations(report);
}

fn divider(label: &str) {
    println!("\n{} {} {}", "─".repeat(3), label.bold(), "─".repeat(WIDTH.saturating_sub(label.len() + 5)));
}

fn print_header(report: &SummaryReport) {
    let top = "═".repeat(WIDTH);
    println!("\n{top}");
    println!("  {} Thread & Heap Analysis", "JVM Service".bold().cyan());
    println!("  File    : {}", report.thread_dump_file.dimmed());
    if let Some(ref hf) = report.histogram_file {
        println!("  Heap    : {}", hf.dimmed());
    }
    println!("  Analyzed: {}", report.analyzed_at.dimmed());
    println!("{top}");
}

fn print_thread_summary(report: &SummaryReport) {
    let ov = &report.thread_overview;
    divider("[1] Thread Overview");
    println!(
        "  Total: {}  │  Active: {}  │  Idle: {}  │  Blocked: {}  │  System: {}",
        ov.total.bold(),
        ov.active.to_string().green(),
        ov.idle.to_string().dimmed(),
        if ov.blocked > 0 { ov.blocked.to_string().red().to_string() } else { ov.blocked.to_string().green().to_string() },
        ov.system.to_string().dimmed(),
    );
    println!(
        "  State breakdown → RUNNABLE: {}  WAITING: {}  TIMED_WAITING: {}  BLOCKED: {}",
        ov.runnable,
        ov.waiting,
        ov.timed_waiting,
        if ov.blocked > 0 { ov.blocked.to_string().red().to_string() } else { "0".to_string() },
    );
}

fn print_pool_table(report: &SummaryReport) {
    let pools = &report.thread_overview.pools;
    if pools.is_empty() {
        return;
    }

    divider("[2] Thread Pool Breakdown");
    println!(
        "  {:<38} {:>6} {:>7} {:>6} {:>8}",
        "Pool".bold(), "Total".bold(), "Active".bold(), "Idle".bold(), "Status".bold()
    );
    println!("  {}", "─".repeat(70));

    for pool in pools {
        let status = if pool.is_saturated() {
            "⚠ saturated".red().to_string()
        } else if pool.is_oversized() {
            "💡 oversized".yellow().to_string()
        } else {
            "✅ ok".green().to_string()
        };

        println!(
            "  {:<38} {:>6} {:>7} {:>6}  {}",
            pool.name,
            pool.total,
            pool.active,
            pool.idle,
            status,
        );
    }
}

fn print_deadlock_section(report: &SummaryReport) {
    divider("[3] Deadlock Detection");
    if report.deadlock.deadlocks.is_empty() {
        println!("  {} No deadlocks detected", "✅".green());
    } else {
        for (i, cycle) in report.deadlock.deadlocks.iter().enumerate() {
            println!("  {} Deadlock #{} — {} threads involved:", "🔴".red(), i + 1, cycle.threads.len());
            for thread in &cycle.threads {
                println!("      → \"{}\"", thread.red());
            }
            println!();
            println!("  {}", cycle.description.dimmed());
        }
    }
}

fn print_contention_section(report: &SummaryReport) {
    divider("[4] Lock Contention");
    if report.contention.hotspots.is_empty() {
        println!("  {} No lock contention detected", "✅".green());
    } else {
        for (i, hs) in report.contention.hotspots.iter().enumerate() {
            let marker = if hs.waiter_count() >= 5 { "🔴" } else { "⚠️ " };
            println!(
                "  {} #{} — {} threads blocked on {} ({})",
                marker,
                i + 1,
                hs.waiter_count().to_string().red(),
                hs.monitor_class.bold(),
                hs.monitor_address.dimmed(),
            );
            if let Some(ref owner) = hs.owner_thread {
                println!("       Owner: \"{}\" [{}]", owner, hs.owner_state.as_deref().unwrap_or("?"));
            } else {
                println!("       Owner: (unknown)");
            }
            let preview: Vec<_> = hs.waiters.iter().take(5).collect();
            println!("       Waiting: {}", preview.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", "));
            if hs.waiters.len() > 5 {
                println!("       ... and {} more", hs.waiters.len() - 5);
            }
        }
    }
}

fn print_hot_threads_section(report: &SummaryReport) {
    divider("[5] Hot / Saturated Threads");
    if report.hot_threads.groups.is_empty() {
        println!("  {} No thread stack saturation detected", "✅".green());
    } else {
        for (i, group) in report.hot_threads.groups.iter().enumerate() {
            println!(
                "  ⚠️  Group #{} — {} threads share this stack [{}]:",
                i + 1,
                group.thread_names.len().to_string().yellow(),
                group.state.as_str().dimmed(),
            );
            for frame in group.top_frames.iter().take(5) {
                println!("       {}", frame.dimmed());
            }
            if group.top_frames.len() > 5 {
                println!("       ... ({} more frames)", group.top_frames.len() - 5);
            }
            let preview: Vec<_> = group.thread_names.iter().take(4).collect();
            println!("    Threads: {}", preview.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            if group.thread_names.len() > 4 {
                println!("             ... and {} more", group.thread_names.len() - 4);
            }
        }
    }
}

fn print_heap_section(report: &SummaryReport) {
    let heap = match &report.heap {
        Some(h) => h,
        None => return,
    };
    divider("[6] Heap Histogram");
    println!("  Top 5 by bytes:");
    for (i, entry) in heap.top_by_bytes.iter().take(5).enumerate() {
        println!("    {}. {}", i + 1, entry);
    }
    if !heap.suspicious.is_empty() {
        println!("\n  {} Suspicious large objects:", "⚠️".yellow());
        for s in &heap.suspicious {
            println!("    • {}", s.yellow());
        }
    } else {
        println!("\n  {} No suspicious large objects", "✅".green());
    }
}

fn print_findings_summary(report: &SummaryReport) {
    let all = report.all_findings();
    let critical = report.count_by_severity(&Severity::Critical);
    let warning  = report.count_by_severity(&Severity::Warning);
    let info     = report.count_by_severity(&Severity::Info);

    let border = "═".repeat(WIDTH);
    println!("\n{border}");
    println!("  {}", "FINDINGS SUMMARY".bold());
    println!("{border}");
    println!("  {} ({critical})", "🔴 CRITICAL".red().bold());
    println!("  {} ({warning})",  "⚠️  WARNING".yellow().bold());
    println!("  {} ({info})",     "💡 INFO".cyan().bold());
    println!();

    for finding in all.iter().filter(|f| f.severity != Severity::Healthy) {
        let sym = finding.severity.short_symbol();
        println!("  {sym} {}", finding.title.bold());
        for line in finding.detail.lines() {
            println!("       {}", line.dimmed());
        }
        if let Some(ref hint) = finding.hint {
            println!("       → {}", hint.cyan());
        }
        println!();
    }
}

fn print_recommendations(report: &SummaryReport) {
    let border = "═".repeat(WIDTH);
    println!("{border}");
    println!("  {}", "RECOMMENDED NEXT STEPS".bold());
    println!("{border}");
    for (i, rec) in report.recommendations.iter().enumerate() {
        println!("  {}. {}", i + 1, rec);
    }
    println!();
}
