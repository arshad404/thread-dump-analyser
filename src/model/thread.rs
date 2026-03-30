use serde::{Deserialize, Serialize};

/// JVM thread state as reported by jstack
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadState {
    Runnable,
    Blocked,
    Waiting,
    TimedWaiting,
    New,
    Terminated,
    Unknown(String),
}

impl ThreadState {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "RUNNABLE" => ThreadState::Runnable,
            "BLOCKED" => ThreadState::Blocked,
            "WAITING" => ThreadState::Waiting,
            "TIMED_WAITING" => ThreadState::TimedWaiting,
            "NEW" => ThreadState::New,
            "TERMINATED" => ThreadState::Terminated,
            other => ThreadState::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ThreadState::Runnable => "RUNNABLE",
            ThreadState::Blocked => "BLOCKED",
            ThreadState::Waiting => "WAITING",
            ThreadState::TimedWaiting => "TIMED_WAITING",
            ThreadState::New => "NEW",
            ThreadState::Terminated => "TERMINATED",
            ThreadState::Unknown(s) => s.as_str(),
        }
    }
}

/// High-level role of a thread, derived from its stack
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadRole {
    /// Actively executing application work
    Active,
    /// Sitting idle in a thread pool (parked, sleeping, waiting for tasks)
    Idle,
    /// Stuck on a lock
    Blocked,
    /// JVM/GC/JIT internal thread
    System,
}

/// A single stack frame from a thread's stack trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub class_and_method: String,
    pub source_location: Option<String>,
    /// Lock info: "- locked <0x...> (class)", "- waiting to lock <0x...>", etc.
    pub lock_info: Option<String>,
}

/// A parsed JVM thread
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    pub name: String,
    pub tid: Option<String>,
    pub nid: Option<String>,
    pub os_priority: Option<i32>,
    pub java_priority: Option<i32>,
    pub state: ThreadState,
    pub role: ThreadRole,
    pub stack_frames: Vec<StackFrame>,
    /// Name of the thread pool this thread belongs to (detected heuristically)
    pub pool_name: Option<String>,
    /// Monitor address this thread is waiting to lock (if BLOCKED)
    pub waiting_to_lock: Option<String>,
    /// Monitor addresses this thread holds
    pub locked_monitors: Vec<String>,
}

impl Thread {
    /// Returns true if the thread has an identical stack to another (for grouping)
    pub fn stack_signature(&self) -> String {
        self.stack_frames
            .iter()
            .map(|f| f.class_and_method.as_str())
            .collect::<Vec<_>>()
            .join("|")
    }
}

/// The full parsed thread dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadDump {
    pub threads: Vec<Thread>,
    /// Raw deadlock section from jstack output (if present)
    pub deadlock_section: Option<String>,
    /// JVM info line (e.g. "OpenJDK 64-Bit Server VM ...")
    pub jvm_info: Option<String>,
}
