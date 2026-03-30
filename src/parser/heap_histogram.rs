use crate::model::{HeapSnapshot, HistoEntry};

/// Parse the output of `jmap -histo` or `jmap -histo:live`
///
/// Expected format (two variants):
///   num     #instances         #bytes  class name
///   1:         123456      987654321  [B
/// or (without header):
///   1          123456      987654321  [B
pub fn parse(input: &str) -> Result<HeapSnapshot, String> {
    let mut entries = Vec::new();
    let mut total_instances: u64 = 0;
    let mut total_bytes: u64 = 0;

    for line in input.lines() {
        let line = line.trim();

        // Skip header / blank / totals lines
        if line.is_empty()
            || line.starts_with("num")
            || line.starts_with("Num")
            || line.starts_with("---")
            || line.starts_with("Total")
        {
            // Parse the "Total" line for overall stats if present
            if line.starts_with("Total") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    total_instances = parts[1].replace(',', "").parse().unwrap_or(0);
                    total_bytes = parts[2].replace(',', "").parse().unwrap_or(0);
                }
            }
            continue;
        }

        if let Some(entry) = parse_line(line) {
            if total_instances == 0 {
                total_instances += entry.instances;
                total_bytes += entry.bytes;
            }
            entries.push(entry);
        }
    }

    // If we parsed totals from data lines (no Total row), sum them up
    if total_instances == 0 && !entries.is_empty() {
        total_instances = entries.iter().map(|e| e.instances).sum();
        total_bytes = entries.iter().map(|e| e.bytes).sum();
    }

    if entries.is_empty() {
        return Err("No histogram entries found — is this a valid jmap -histo output?".into());
    }

    Ok(HeapSnapshot {
        entries,
        total_instances,
        total_bytes,
    })
}

fn parse_line(line: &str) -> Option<HistoEntry> {
    // Strip leading rank number with optional colon: "1:" or "1"
    let line = line.trim_start_matches(|c: char| c.is_whitespace());
    let parts: Vec<&str> = line.split_whitespace().collect();

    // Need at least: rank instances bytes class_name
    if parts.len() < 4 {
        return None;
    }

    // rank may have a trailing colon
    let rank_str = parts[0].trim_end_matches(':');
    let rank: usize = rank_str.parse().ok()?;
    let instances: u64 = parts[1].replace(',', "").parse().ok()?;
    let bytes: u64 = parts[2].replace(',', "").parse().ok()?;
    // class name is remainder (handles array types like "[Ljava.lang.String;")
    let class_name = parts[3..].join(" ");

    Some(HistoEntry {
        rank,
        instances,
        bytes,
        class_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_histogram() {
        let input = r#"
 num     #instances         #bytes  class name
----------------------------------------------
   1:        100000      800000000  [B
   2:         50000      400000000  java.lang.String
   3:          1000        8000000  com.example.Foo
Total        151000     1208000000
"#;
        let snap = parse(input).unwrap();
        assert_eq!(snap.entries.len(), 3);
        assert_eq!(snap.entries[0].class_name, "[B");
        assert_eq!(snap.entries[0].instances, 100000);
        assert_eq!(snap.entries[0].bytes, 800000000);
        assert_eq!(snap.total_instances, 151000);
        assert_eq!(snap.total_bytes, 1208000000);
    }

    #[test]
    fn test_top_by_bytes() {
        let input = r#"
   1:        100000      800000000  [B
   2:         50000      400000000  java.lang.String
   3:          1000        8000000  com.example.Foo
"#;
        let snap = parse(input).unwrap();
        let top = snap.top_by_bytes(2);
        assert_eq!(top[0].class_name, "[B");
        assert_eq!(top[1].class_name, "java.lang.String");
    }
}
