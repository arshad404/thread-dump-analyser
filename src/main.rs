use clap::{Parser, Subcommand};
use std::fs;
use std::io::Write;
use std::process;

mod analyzer;
mod model;
mod parser;
mod report;

use report::summary::SummaryReport;

/// JVM thread dump and heap histogram analyzer
#[derive(Parser)]
#[command(
    name = "tdanalyzer",
    version = "0.1.0",
    about = "Analyze JVM thread dumps and heap histograms from jstack/jmap",
    long_about = "tdanalyzer parses jstack thread dumps and jmap heap histograms,\n\
                  detects deadlocks, lock contention, idle/saturated thread pools,\n\
                  and produces a ranked findings report."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all analyzers and produce a full ranked summary (recommended starting point)
    Summary {
        /// Path to the jstack thread dump file
        thread_dump: String,
        /// Path to the jmap -histo heap histogram file (optional)
        #[arg(long)]
        histogram: Option<String>,
        /// Output format: terminal (default) or json
        #[arg(long, default_value = "terminal")]
        format: String,
        /// Write output to this file instead of stdout (useful for json output)
        #[arg(long, short = 'o')]
        output: Option<String>,
    },

    /// Show thread count breakdown by state and role, with pool-level idle/active stats
    Threads {
        /// Path to the jstack thread dump file
        thread_dump: String,
        /// Output format: terminal or json
        #[arg(long, default_value = "terminal")]
        format: String,
        /// Write output to this file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },

    /// Detect deadlock cycles in the thread dump
    Deadlock {
        /// Path to the jstack thread dump file
        thread_dump: String,
        /// Output format: terminal or json
        #[arg(long, default_value = "terminal")]
        format: String,
        /// Write output to this file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },

    /// Show lock contention hotspots (BLOCKED threads grouped by monitor)
    Contention {
        /// Path to the jstack thread dump file
        thread_dump: String,
        /// Output format: terminal or json
        #[arg(long, default_value = "terminal")]
        format: String,
        /// Write output to this file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },

    /// Identify hot/saturated thread pools and groups of threads with identical stacks
    Hot {
        /// Path to the jstack thread dump file
        thread_dump: String,
        /// Output format: terminal or json
        #[arg(long, default_value = "terminal")]
        format: String,
        /// Write output to this file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },

    /// Analyze a jmap heap histogram for large objects and suspicious classes
    Histogram {
        /// Path to the jmap -histo output file
        histogram: String,
        /// Output format: terminal or json
        #[arg(long, default_value = "terminal")]
        format: String,
        /// Write output to this file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },

    /// Compare two jmap heap histograms to detect memory growth between snapshots
    Compare {
        /// Path to the first (older) histogram file
        histogram1: String,
        /// Path to the second (newer) histogram file
        histogram2: String,
        /// Output format: terminal or json
        #[arg(long, default_value = "terminal")]
        format: String,
        /// Write output to this file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Summary { thread_dump, histogram, format, output } => {
            let dump = load_thread_dump(&thread_dump);
            let heap_snap = histogram.as_ref().map(|p| load_histogram(p));
            let report = SummaryReport::build(
                &dump,
                heap_snap.as_ref(),
                &thread_dump,
                histogram.as_deref(),
            );
            match format.as_str() {
                "json" => write_output(&report::json::render(&report), output.as_deref()),
                _ => {
                    if output.is_some() {
                        // For terminal format to file, capture via a string buffer isn't trivial;
                        // recommend json for file output
                        eprintln!("Tip: use --format json when writing to a file for clean output.");
                    }
                    report::terminal::render(&report);
                }
            }
        }

        Commands::Threads { thread_dump, format, output } => {
            let dump = load_thread_dump(&thread_dump);
            let result = analyzer::thread_overview::analyze(&dump);
            match format.as_str() {
                "json" => {
                    use serde_json::json;
                    let pools: Vec<_> = result.pools.iter().map(|p| json!({
                        "name": p.name, "total": p.total, "active": p.active,
                        "idle": p.idle, "blocked": p.blocked,
                        "idle_percent": format!("{:.1}", p.idle_percent()),
                        "saturated": p.is_saturated(), "oversized": p.is_oversized(),
                    })).collect();
                    write_output(&serde_json::to_string_pretty(&json!({
                        "total": result.total, "runnable": result.runnable,
                        "blocked": result.blocked, "waiting": result.waiting,
                        "timed_waiting": result.timed_waiting,
                        "active": result.active, "idle": result.idle, "system": result.system,
                        "pools": pools,
                        "findings": result.findings.iter().map(|f| json!({
                            "severity": format!("{:?}", f.severity),
                            "title": f.title, "detail": f.detail,
                        })).collect::<Vec<_>>(),
                    })).unwrap(), output.as_deref());
                }
                _ => {
                    use owo_colors::OwoColorize;
                    println!("\n{}", "Thread Overview".bold());
                    println!("  Total: {}  Active: {}  Idle: {}  Blocked: {}  System: {}",
                        result.total.bold(),
                        result.active.to_string().green(),
                        result.idle,
                        if result.blocked > 0 { result.blocked.to_string().red().to_string() } else { "0".to_string() },
                        result.system,
                    );
                    println!("\n{}", "Thread Pool Breakdown".bold());
                    println!("  {:<38} {:>6} {:>7} {:>6} {:>8}", "Pool", "Total", "Active", "Idle", "Status");
                    println!("  {}", "─".repeat(65));
                    for pool in &result.pools {
                        let status = if pool.is_saturated() { "⚠ saturated".to_string() }
                            else if pool.is_oversized() { "💡 oversized".to_string() }
                            else { "✅ ok".to_string() };
                        println!("  {:<38} {:>6} {:>7} {:>6}  {}", pool.name, pool.total, pool.active, pool.idle, status);
                    }
                }
            }
        }

        Commands::Deadlock { thread_dump, format, output } => {
            let dump = load_thread_dump(&thread_dump);
            let result = analyzer::deadlock::analyze(&dump);
            match format.as_str() {
                "json" => {
                    use serde_json::json;
                    write_output(&serde_json::to_string_pretty(&json!({
                        "deadlock_count": result.deadlocks.len(),
                        "deadlocks": result.deadlocks.iter().map(|d| json!({
                            "threads": d.threads,
                            "description": d.description,
                        })).collect::<Vec<_>>(),
                        "findings": result.findings.iter().map(|f| json!({
                            "severity": format!("{:?}", f.severity),
                            "title": f.title,
                        })).collect::<Vec<_>>(),
                    })).unwrap(), output.as_deref());
                }
                _ => {
                    use owo_colors::OwoColorize;
                    if result.deadlocks.is_empty() {
                        println!("\n  {} No deadlocks detected", "✅".green());
                    } else {
                        for (i, cycle) in result.deadlocks.iter().enumerate() {
                            println!("\n  {} Deadlock #{} ({} threads):", "🔴".red(), i + 1, cycle.threads.len());
                            for t in &cycle.threads {
                                println!("    → \"{}\"", t.red());
                            }
                            println!("\n{}", cycle.description.dimmed());
                        }
                    }
                }
            }
        }

        Commands::Contention { thread_dump, format, output } => {
            let dump = load_thread_dump(&thread_dump);
            let result = analyzer::contention::analyze(&dump);
            match format.as_str() {
                "json" => {
                    use serde_json::json;
                    write_output(&serde_json::to_string_pretty(&json!({
                        "hotspot_count": result.hotspots.len(),
                        "hotspots": result.hotspots.iter().map(|h| json!({
                            "monitor": h.monitor_address,
                            "class": h.monitor_class,
                            "owner": h.owner_thread,
                            "waiter_count": h.waiter_count(),
                            "waiters": h.waiters,
                        })).collect::<Vec<_>>(),
                    })).unwrap(), output.as_deref());
                }
                _ => {
                    use owo_colors::OwoColorize;
                    if result.hotspots.is_empty() {
                        println!("\n  {} No lock contention detected", "✅".green());
                    } else {
                        for (i, hs) in result.hotspots.iter().enumerate() {
                            println!("\n  #{}: {} threads blocked on {} ({})",
                                i + 1, hs.waiter_count().to_string().red(), hs.monitor_class.bold(), hs.monitor_address.dimmed());
                            if let Some(ref owner) = hs.owner_thread {
                                println!("     Owner: \"{}\"", owner);
                            }
                            for w in &hs.waiters {
                                println!("     Waiter: \"{}\"", w);
                            }
                        }
                    }
                }
            }
        }

        Commands::Hot { thread_dump, format, output } => {
            let dump = load_thread_dump(&thread_dump);
            let result = analyzer::hot_threads::analyze(&dump);
            match format.as_str() {
                "json" => {
                    use serde_json::json;
                    write_output(&serde_json::to_string_pretty(&json!({
                        "group_count": result.groups.len(),
                        "groups": result.groups.iter().map(|g| json!({
                            "thread_count": g.thread_names.len(),
                            "state": g.state.as_str(),
                            "top_frames": g.top_frames,
                            "threads": g.thread_names,
                        })).collect::<Vec<_>>(),
                    })).unwrap(), output.as_deref());
                }
                _ => {
                    use owo_colors::OwoColorize;
                    if result.groups.is_empty() {
                        println!("\n  {} No thread stack saturation detected", "✅".green());
                    } else {
                        for (i, g) in result.groups.iter().enumerate() {
                            println!("\n  Group #{} — {} threads [{}]:", i + 1, g.thread_names.len().to_string().yellow(), g.state.as_str());
                            for frame in g.top_frames.iter().take(6) {
                                println!("    {}", frame.dimmed());
                            }
                            println!("  Threads: {}", g.thread_names.iter().take(5).cloned().collect::<Vec<_>>().join(", "));
                            if g.thread_names.len() > 5 {
                                println!("           ... and {} more", g.thread_names.len() - 5);
                            }
                        }
                    }
                }
            }
        }

        Commands::Histogram { histogram, format, output } => {
            let snap = load_histogram(&histogram);
            let result = analyzer::heap_analysis::analyze(&snap);
            match format.as_str() {
                "json" => {
                    use serde_json::json;
                    write_output(&serde_json::to_string_pretty(&json!({
                        "top_by_bytes": result.top_by_bytes,
                        "top_by_instances": result.top_by_instances,
                        "suspicious": result.suspicious,
                        "findings": result.findings.iter().map(|f| json!({
                            "severity": format!("{:?}", f.severity),
                            "title": f.title,
                        })).collect::<Vec<_>>(),
                    })).unwrap(), output.as_deref());
                }
                _ => {
                    use owo_colors::OwoColorize;
                    println!("\n{}", "Top 10 by Bytes".bold());
                    for (i, e) in result.top_by_bytes.iter().enumerate() {
                        println!("  {}. {}", i + 1, e);
                    }
                    println!("\n{}", "Top 10 by Instances".bold());
                    for (i, e) in result.top_by_instances.iter().enumerate() {
                        println!("  {}. {}", i + 1, e);
                    }
                    if !result.suspicious.is_empty() {
                        println!("\n{}", "⚠️  Suspicious Large Objects".yellow().bold());
                        for s in &result.suspicious {
                            println!("  • {}", s.yellow());
                        }
                    }
                }
            }
        }

        Commands::Compare { histogram1, histogram2, format, output } => {
            let snap1 = load_histogram(&histogram1);
            let snap2 = load_histogram(&histogram2);
            let result = analyzer::heap_analysis::compare(&snap1, &snap2);
            match format.as_str() {
                "json" => {
                    use serde_json::json;
                    write_output(&serde_json::to_string_pretty(&json!({
                        "diffs": result.diffs.iter().take(20).map(|d| json!({
                            "class": d.class_name,
                            "delta_instances": d.delta_instances,
                            "delta_bytes": d.delta_bytes,
                            "delta_bytes_mb": format!("{:.1}", d.delta_bytes_mb()),
                            "growing_fast": d.is_growing_fast(),
                        })).collect::<Vec<_>>(),
                        "findings": result.findings.iter().map(|f| json!({
                            "severity": format!("{:?}", f.severity),
                            "title": f.title,
                        })).collect::<Vec<_>>(),
                    })).unwrap(), output.as_deref());
                }
                _ => {
                    use owo_colors::OwoColorize;
                    println!("\n{}", "Heap Growth Report (snapshot 1 → snapshot 2)".bold());
                    println!("  {:<60} {:>15} {:>10}", "Class".bold(), "Δ Bytes (MB)".bold(), "Δ Instances".bold());
                    println!("  {}", "─".repeat(90));
                    for diff in result.diffs.iter().take(20) {
                        let flag = if diff.is_growing_fast() { " 🔴" } else { "" };
                        println!("  {:<60} {:>+14.1} {:>+10}{}", diff.class_name, diff.delta_bytes_mb(), diff.delta_instances, flag);
                    }
                }
            }
        }
    }
}

fn load_thread_dump(path: &str) -> model::ThreadDump {
    let content = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Error reading thread dump '{}': {}", path, e);
        process::exit(1);
    });
    parser::thread_dump::parse(&content).unwrap_or_else(|e| {
        eprintln!("Error parsing thread dump: {}", e);
        process::exit(1);
    })
}

fn load_histogram(path: &str) -> model::HeapSnapshot {
    let content = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Error reading histogram '{}': {}", path, e);
        process::exit(1);
    });
    parser::heap_histogram::parse(&content).unwrap_or_else(|e| {
        eprintln!("Error parsing histogram: {}", e);
        process::exit(1);
    })
}

/// Write `content` to `path` if provided, otherwise print to stdout.
fn write_output(content: &str, path: Option<&str>) {
    match path {
        Some(p) => {
            let mut file = std::fs::File::create(p).unwrap_or_else(|e| {
                eprintln!("Error creating output file '{}': {}", p, e);
                process::exit(1);
            });
            file.write_all(content.as_bytes()).unwrap_or_else(|e| {
                eprintln!("Error writing to '{}': {}", p, e);
                process::exit(1);
            });
            eprintln!("Output written to: {}", p);
        }
        None => print!("{}", content),
    }
}
