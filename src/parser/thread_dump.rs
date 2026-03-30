use crate::model::{StackFrame, Thread, ThreadDump, ThreadRole, ThreadState};
use regex::Regex;

/// Known idle/parking stack frame signatures — a thread whose top frames match
/// any of these is considered idle (parked in a pool, not doing work).
const IDLE_FRAMES: &[&str] = &[
    "sun.misc.Unsafe.park",
    "jdk.internal.misc.Unsafe.park",
    "java.lang.Object.wait",
    "java.lang.Thread.sleep",
    "java.lang.Thread.sleep0",
    "sun.nio.ch.EPoll.wait",
    "sun.nio.ch.KQueue.poll",
    "io.netty.channel.epoll.Native.epollWait",
    "io.netty.channel.kqueue.Native.keventWait",
    "java.util.concurrent.locks.LockSupport.park",
    "jdk.internal.vm.Continuation.run",
];

/// Known system/JVM thread name prefixes
const SYSTEM_THREAD_PREFIXES: &[&str] = &[
    "GC Thread",
    "G1 ",
    "VM Thread",
    "VM Periodic Task Thread",
    "Finalizer",
    "Reference Handler",
    "Signal Dispatcher",
    "C2 CompilerThread",
    "C1 CompilerThread",
    "Compiler Thread",
    "Sweeper thread",
    "Service Thread",
    "Common-Cleaner",
    "Monitor Ctrl-Break",
    "Attach Listener",
    "DestroyJavaVM",
    "process reaper",
];

/// Derive a canonical pool name from a raw thread name.
///
/// Strategy (in order):
/// 1. Strip a trailing `-<digits>` suffix → "http-nio-8080-exec-42" → "http-nio-8080-exec"
///    Then normalise known noisy port segments: "http-nio-8080-exec" → "http-nio-exec"
/// 2. Strip a trailing `-<digits>` preceded by another segment if the name ends with a
///    known pool suffix keyword (WorkersThread, ElasticExecutorsThread, etc.)
/// 3. Use the full thread name as the pool name if multiple threads share it exactly
///    (e.g. 1000 threads all named "tcs-client-threads")
///
/// This is intentionally generic — it does NOT require a hardcoded list of pool names.
pub fn derive_pool_name(name: &str) -> String {
    // Step 1: strip trailing -<digits>
    let stripped = strip_trailing_number(name);

    // Step 2: normalise port numbers embedded in the pool name
    //   e.g. "http-nio-8080-exec" → "http-nio-exec"
    //        "http-nio-8092-exec" → "http-nio-exec"
    let normalised = normalise_port_segments(&stripped);

    normalised
}

/// Strip ALL trailing numeric segments (separated by `-`, `_`, or space), recursively.
/// "http-nio-8080-exec-42"          → "http-nio-8080-exec"
/// "lettuce-nioEventLoop-4-1"       → "lettuce-nioEventLoop"  (strips -1 then -4)
/// "tcs-client-threads"             → "tcs-client-threads"    (no number suffix)
/// "TaskRunner 9"                   → "TaskRunner"
fn strip_trailing_number(name: &str) -> String {
    let mut current = name.to_string();
    loop {
        let stripped = strip_one_trailing_number(&current);
        if stripped == current {
            break;
        }
        current = stripped;
    }
    current
}

fn strip_one_trailing_number(name: &str) -> String {
    // Try dash-separated
    if let Some(pos) = name.rfind('-') {
        let suffix = &name[pos + 1..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            return name[..pos].to_string();
        }
    }
    // Try underscore-separated
    if let Some(pos) = name.rfind('_') {
        let suffix = &name[pos + 1..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            return name[..pos].to_string();
        }
    }
    // Try space-separated (e.g. "TaskRunner 9")
    if let Some(pos) = name.rfind(' ') {
        let suffix = &name[pos + 1..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            return name[..pos].to_string();
        }
    }
    name.to_string()
}

/// Remove embedded port numbers from pool names.
/// "http-nio-8080-exec" → "http-nio-exec"
/// "lettuce-nioEventLoop-4-1" → "lettuce-nioEventLoop"  (already stripped by caller)
fn normalise_port_segments(name: &str) -> String {
    // Split on '-', filter out pure-numeric segments that look like ports (4-5 digits)
    let parts: Vec<&str> = name.split('-').collect();
    let filtered: Vec<&str> = parts
        .iter()
        .filter(|&&p| {
            let is_port = p.chars().all(|c| c.is_ascii_digit()) && p.len() >= 4;
            !is_port
        })
        .copied()
        .collect();
    if filtered.is_empty() {
        name.to_string()
    } else {
        filtered.join("-")
    }
}

/// Parse the full output of `jstack <pid>` into a ThreadDump
pub fn parse(input: &str) -> Result<ThreadDump, String> {
    let (jvm_info, thread_blocks, deadlock_section) = split_sections(input);

    let mut threads = Vec::new();
    for block in thread_blocks {
        if let Some(thread) = parse_thread_block(&block) {
            threads.push(thread);
        }
    }

    if threads.is_empty() {
        return Err(
            "No threads found — is this a valid jstack output?".into()
        );
    }

    Ok(ThreadDump {
        threads,
        deadlock_section,
        jvm_info,
    })
}

/// Split raw jstack output into (jvm_info, thread_blocks, deadlock_section)
fn split_sections(input: &str) -> (Option<String>, Vec<String>, Option<String>) {
    let mut jvm_info: Option<String> = None;
    let mut blocks: Vec<String> = Vec::new();
    let mut deadlock: Option<String> = None;
    let mut current_block = String::new();
    let mut in_deadlock = false;

    for line in input.lines() {
        if jvm_info.is_none() && !line.trim().is_empty() && !line.starts_with('"') {
            jvm_info = Some(line.to_string());
            continue;
        }

        if line.contains("Found") && line.contains("deadlock") {
            if !current_block.trim().is_empty() {
                blocks.push(current_block.trim().to_string());
                current_block = String::new();
            }
            in_deadlock = true;
            deadlock = Some(String::new());
        }

        if in_deadlock {
            if let Some(ref mut d) = deadlock {
                d.push_str(line);
                d.push('\n');
            }
            continue;
        }

        if line.starts_with('"') && !current_block.is_empty() {
            blocks.push(current_block.trim().to_string());
            current_block = String::new();
        }

        current_block.push_str(line);
        current_block.push('\n');
    }

    if !current_block.trim().is_empty() {
        blocks.push(current_block.trim().to_string());
    }

    (jvm_info, blocks, deadlock)
}

/// Parse a single thread block into a Thread struct
fn parse_thread_block(block: &str) -> Option<Thread> {
    let mut lines = block.lines();

    let header = lines.next()?;
    if !header.starts_with('"') {
        return None;
    }

    let name = extract_thread_name(header)?;
    let tid = extract_hex_field(header, "tid=");
    let nid = extract_hex_field(header, "nid=");
    let java_priority = extract_int_field(header, "prio=");
    let os_priority = extract_int_field(header, "os_prio=");

    let mut state = ThreadState::Unknown("UNKNOWN".to_string());
    let mut stack_frames: Vec<StackFrame> = Vec::new();
    let mut waiting_to_lock: Option<String> = None;
    let mut locked_monitors: Vec<String> = Vec::new();

    let state_re = Regex::new(r"java\.lang\.Thread\.State:\s+(\S+)").ok()?;
    let at_re = Regex::new(r"^\s+at\s+(.+)\((.+)\)").ok()?;
    let lock_re = Regex::new(r"^\s+-\s+(.+)").ok()?;
    let monitor_re = Regex::new(r"<(0x[0-9a-f]+)>").ok()?;

    for line in lines {
        let trimmed = line.trim();

        if let Some(caps) = state_re.captures(trimmed) {
            state = ThreadState::from_str(&caps[1]);
            continue;
        }

        if let Some(caps) = at_re.captures(line) {
            stack_frames.push(StackFrame {
                class_and_method: caps[1].trim().to_string(),
                source_location: Some(caps[2].trim().to_string()),
                lock_info: None,
            });
            continue;
        }

        if let Some(caps) = lock_re.captures(line) {
            let lock_info = caps[1].trim().to_string();

            if let Some(frame) = stack_frames.last_mut() {
                frame.lock_info = Some(lock_info.clone());
            }

            if lock_info.contains("waiting to lock") {
                if let Some(addr_caps) = monitor_re.captures(&lock_info) {
                    waiting_to_lock = Some(addr_caps[1].to_string());
                }
            } else if lock_info.contains("locked") {
                if let Some(addr_caps) = monitor_re.captures(&lock_info) {
                    locked_monitors.push(addr_caps[1].to_string());
                }
            }
        }
    }

    let is_system = SYSTEM_THREAD_PREFIXES.iter().any(|p| name.starts_with(p));

    // Every non-system thread gets a pool name — derived generically from the thread name
    let pool_name = if is_system {
        None
    } else {
        Some(derive_pool_name(&name))
    };

    let role = determine_role(&state, &stack_frames, is_system);

    Some(Thread {
        name,
        tid,
        nid,
        os_priority,
        java_priority,
        state,
        role,
        stack_frames,
        pool_name,
        waiting_to_lock,
        locked_monitors,
    })
}

fn extract_thread_name(header: &str) -> Option<String> {
    let start = header.find('"')? + 1;
    let rest = &header[start..];
    let end = rest.rfind('"')?;
    Some(rest[..end].to_string())
}

fn extract_hex_field(line: &str, field: &str) -> Option<String> {
    let pos = line.find(field)? + field.len();
    let rest = &line[pos..];
    let end = rest.find(|c: char| c.is_whitespace() || c == ']').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn extract_int_field(line: &str, field: &str) -> Option<i32> {
    let pos = line.find(field)? + field.len();
    let rest = &line[pos..];
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn determine_role(
    state: &ThreadState,
    frames: &[StackFrame],
    is_system: bool,
) -> ThreadRole {
    if is_system {
        return ThreadRole::System;
    }

    if *state == ThreadState::Blocked {
        return ThreadRole::Blocked;
    }

    let top_frames: Vec<&str> = frames
        .iter()
        .take(5)
        .map(|f| f.class_and_method.as_str())
        .collect();

    let is_idle = IDLE_FRAMES.iter().any(|idle_frame| {
        top_frames.iter().any(|f| f.starts_with(idle_frame))
    });

    let is_waiting = matches!(state, ThreadState::Waiting | ThreadState::TimedWaiting);

    if is_idle || (is_waiting && top_frames.iter().any(|f| {
        f.contains("park") || f.contains("wait") || f.contains("sleep") || f.contains("poll")
    })) {
        ThreadRole::Idle
    } else {
        ThreadRole::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DUMP: &str = r#"Full thread dump OpenJDK 64-Bit Server VM (21.0.1+12-LTS mixed mode, sharing):

"http-nio-8080-exec-1" #42 daemon prio=5 os_prio=0 cpu=123.45ms elapsed=3600.00s tid=0x00007f1234 nid=0x1234 waiting on condition [0x00007f5678]
   java.lang.Thread.State: TIMED_WAITING (parking)
	at sun.misc.Unsafe.park(Native Method)
	- parking to wait for  <0x00000006c1234abc> (a java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject)
	at java.util.concurrent.locks.LockSupport.parkNanos(LockSupport.java:252)

"my-search-worker-1" #100 daemon prio=5 os_prio=0 tid=0x00007f9999 nid=0x9999 runnable [0x00007faabb]
   java.lang.Thread.State: RUNNABLE
	at com.example.search.service.SearchService.executeQuery(SearchService.java:123)
	at com.example.search.service.SearchService.search(SearchService.java:80)

"tcs-client-threads" #200 daemon prio=5 os_prio=0 tid=0x00007f0001 nid=0x0001 waiting on condition [0x00007fa001]
   java.lang.Thread.State: WAITING (parking)
	at jdk.internal.misc.Unsafe.park(Native Method)
	at java.util.concurrent.locks.LockSupport.park(LockSupport.java:211)

"tcs-client-threads" #201 daemon prio=5 os_prio=0 tid=0x00007f0002 nid=0x0002 waiting on condition [0x00007fa002]
   java.lang.Thread.State: WAITING (parking)
	at jdk.internal.misc.Unsafe.park(Native Method)
	at java.util.concurrent.locks.LockSupport.park(LockSupport.java:211)

"GC Thread#0" os_prio=0 cpu=450.00ms elapsed=10000.00s tid=0x00007faaaa nid=0xaaaa runnable

"Finalizer" #3 daemon prio=8 os_prio=0 tid=0x00007fbbbb nid=0xbbbb in Object.wait()  [0x00007fcccc]
   java.lang.Thread.State: WAITING (on object monitor)
	at java.lang.Object.wait(Object.java:552)
"#;

    #[test]
    fn test_parse_thread_count() {
        let dump = parse(SAMPLE_DUMP).unwrap();
        assert!(dump.threads.len() >= 5);
    }

    #[test]
    fn test_idle_thread_detection() {
        let dump = parse(SAMPLE_DUMP).unwrap();
        let exec1 = dump.threads.iter().find(|t| t.name == "http-nio-8080-exec-1").unwrap();
        assert_eq!(exec1.role, ThreadRole::Idle);
        assert_eq!(exec1.pool_name.as_deref(), Some("http-nio-exec"));
    }

    #[test]
    fn test_active_thread_detection() {
        let dump = parse(SAMPLE_DUMP).unwrap();
        let worker = dump.threads.iter().find(|t| t.name == "my-search-worker-1").unwrap();
        assert_eq!(worker.role, ThreadRole::Active);
        assert_eq!(worker.pool_name.as_deref(), Some("my-search-worker"));
    }

    #[test]
    fn test_system_thread_detection() {
        let dump = parse(SAMPLE_DUMP).unwrap();
        let gc = dump.threads.iter().find(|t| t.name.starts_with("GC Thread")).unwrap();
        assert_eq!(gc.role, ThreadRole::System);
        assert_eq!(gc.pool_name, None);
    }

    #[test]
    fn test_exact_name_threads_get_pool() {
        // "tcs-client-threads" has no trailing number — should use full name as pool
        let dump = parse(SAMPLE_DUMP).unwrap();
        let tcs: Vec<_> = dump.threads.iter().filter(|t| t.name == "tcs-client-threads").collect();
        assert_eq!(tcs.len(), 2);
        assert_eq!(tcs[0].pool_name.as_deref(), Some("tcs-client-threads"));
        assert_eq!(tcs[1].pool_name.as_deref(), Some("tcs-client-threads"));
    }

    #[test]
    fn test_pool_name_derivation() {
        assert_eq!(derive_pool_name("http-nio-8080-exec-42"), "http-nio-exec");
        assert_eq!(derive_pool_name("http-nio-8092-exec-1"),  "http-nio-exec");
        assert_eq!(derive_pool_name("my-search-worker-7"), "my-search-worker");
        assert_eq!(derive_pool_name("tcs-client-threads"),    "tcs-client-threads");
        assert_eq!(derive_pool_name("media-indexer-client-threads"), "media-indexer-client-threads");
        assert_eq!(derive_pool_name("eventWorkersThread-99"), "eventWorkersThread");
        assert_eq!(derive_pool_name("TaskRunner 9"),          "TaskRunner");
        assert_eq!(derive_pool_name("ForkJoinPool.commonPool-worker-3"), "ForkJoinPool.commonPool-worker");
        assert_eq!(derive_pool_name("lettuce-nioEventLoop-4-1"), "lettuce-nioEventLoop");
    }
}
