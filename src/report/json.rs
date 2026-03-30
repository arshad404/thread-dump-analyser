use crate::model::{Finding, Severity};
use crate::report::summary::SummaryReport;
use serde_json::{json, Value};

/// Render the full summary report as machine-readable JSON
pub fn render(report: &SummaryReport) -> String {
    let findings: Vec<Value> = report
        .all_findings()
        .iter()
        .map(|f| finding_to_json(f))
        .collect();

    let pools: Vec<Value> = report
        .thread_overview
        .pools
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "total": p.total,
                "active": p.active,
                "idle": p.idle,
                "blocked": p.blocked,
                "idle_percent": format!("{:.1}", p.idle_percent()),
                "active_percent": format!("{:.1}", p.active_percent()),
                "saturated": p.is_saturated(),
                "oversized": p.is_oversized(),
            })
        })
        .collect();

    let counts = count_by_severity(report.all_findings());

    let obj = json!({
        "version": "1.0",
        "analyzed_at": report.analyzed_at,
        "thread_dump_file": report.thread_dump_file,
        "histogram_file": report.histogram_file,
        "thread_summary": {
            "total": report.thread_overview.total,
            "runnable": report.thread_overview.runnable,
            "blocked": report.thread_overview.blocked,
            "waiting": report.thread_overview.waiting,
            "timed_waiting": report.thread_overview.timed_waiting,
            "active": report.thread_overview.active,
            "idle": report.thread_overview.idle,
            "system": report.thread_overview.system,
        },
        "pools": pools,
        "findings": findings,
        "finding_counts": {
            "critical": counts.0,
            "warning": counts.1,
            "info": counts.2,
            "healthy": counts.3,
        },
        "recommendations": report.recommendations,
    });

    serde_json::to_string_pretty(&obj).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

fn finding_to_json(f: &Finding) -> Value {
    json!({
        "severity": format!("{:?}", f.severity),
        "title": f.title,
        "detail": f.detail,
        "hint": f.hint,
    })
}

fn count_by_severity(findings: Vec<&Finding>) -> (usize, usize, usize, usize) {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let warning  = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let info     = findings.iter().filter(|f| f.severity == Severity::Info).count();
    let healthy  = findings.iter().filter(|f| f.severity == Severity::Healthy).count();
    (critical, warning, info, healthy)
}
