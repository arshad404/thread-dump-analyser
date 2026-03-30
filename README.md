# tdanalyzer — JVM Thread Dump & Heap Histogram Analyzer

A fast, single-binary Rust CLI tool that parses `jstack` thread dumps and
`jmap -histo` heap histograms and produces ranked, actionable findings.

Works with any JVM service — Spring Boot, Dropwizard, Tomcat, Netty, and more.

---

## Quick Start

```bash
# Build (requires Rust 1.75+)
cargo build --release

# One-shot full analysis (recommended starting point)
./target/release/tdanalyzer summary build/dump/thread-dump.txt \
    --histogram build/dump/heap-histogram.txt

# JSON output for scripting / agent consumption
./target/release/tdanalyzer summary build/dump/thread-dump.txt --format json
```

---

## Sub-commands

| Command | Description |
|---------|-------------|
| `summary` ⭐ | **Start here.** Runs all analyzers and produces a ranked report with recommendations. |
| `threads` | Thread count by state + per-pool idle/active/blocked breakdown. |
| `deadlock` | Detect deadlock cycles (uses jstack section + independent graph analysis). |
| `contention` | Lock contention hotspots — BLOCKED threads grouped by the monitor they wait on. |
| `hot` | Saturated thread pools and groups of threads sharing identical stack traces. |
| `histogram` | Top-N classes by bytes/instances, suspicious large-object detection. |
| `compare` | Diff two heap snapshots to detect memory growth between captures. |

---

## Example Workflow

### Step 1 — Capture (using the `heap-thread-dump` skill)

```bash
# Thread dump
jstack <pid> > build/dump/thread-dump.txt

# Heap histogram
jmap -histo:live <pid> > build/dump/heap-histogram.txt
```

### Step 2 — Analyze

```bash
./target/release/tdanalyzer summary build/dump/thread-dump.txt \
    --histogram build/dump/heap-histogram.txt
```

### Step 3 — Drill down on findings

```bash
# If contention was flagged:
./target/release/tdanalyzer contention build/dump/thread-dump.txt

# If deadlock was flagged:
./target/release/tdanalyzer deadlock build/dump/thread-dump.txt

# If heap growth is suspected:
./target/release/tdanalyzer compare dump-t1.txt dump-t2.txt
```

---

## Sample Output

```
════════════════════════════════════════════════════════════
  JVM Thread & Heap Analysis
  File    : build/dump/thread-dump.txt
  Analyzed: 2026-03-30 12:10:02 UTC
════════════════════════════════════════════════════════════

─── [1] Thread Overview ───────────────────────────────────
  Total: 312  │  Active: 55  │  Idle: 198  │  Blocked: 7  │  System: 52

─── [2] Thread Pool Breakdown ─────────────────────────────
  Pool                                    Total  Active   Idle    Status
  ──────────────────────────────────────────────────────────────────────
  http-nio                                  100      12     88  💡 oversized
  my-search-worker                     20      18      2  ⚠ saturated
  reactor-http-nio                           32       8     24  ✅ ok
  scheduler                                   8       2      6  ✅ ok

─── [3] Deadlock Detection ────────────────────────────────
  ✅ No deadlocks detected

─── [4] Lock Contention ───────────────────────────────────
  ⚠️  5 threads blocked on ReentrantReadWriteLock <0x00000006c1a2b3c4>
       Owner: "indexer-worker-1" [RUNNABLE]

════════════════════════════════════════════════════════════
  FINDINGS SUMMARY
════════════════════════════════════════════════════════════
  🔴 CRITICAL (0)
  ⚠️  WARNING  (2)
  💡 INFO     (1)

  ⚠️  my-search-worker pool is saturated (18/20 active)
       → Run: tdanalyzer hot <file>
  ⚠️  5 threads blocked on ReentrantReadWriteLock
       → Run: tdanalyzer contention <file>
  💡  http-nio pool may be oversized (88/100 idle)

════════════════════════════════════════════════════════════
  RECOMMENDED NEXT STEPS
════════════════════════════════════════════════════════════
  1. Investigate lock held by "indexer-worker-1" — 5 threads waiting
  2. Pool my-search-worker saturated — consider increasing size
  3. Pool http-nio oversized — consider reducing from 100 → 30
```

---

## Severity Model

| Symbol | Severity | Triggered by |
|--------|----------|--------------|
| 🔴 | CRITICAL | Deadlock detected, complete pool exhaustion |
| ⚠️  | WARNING  | Lock contention, pool saturation ≥80%, large heap objects |
| 💡 | INFO     | Oversized idle pools (≥80% idle, ≥10 threads), minor tuning opportunities |
| ✅ | HEALTHY  | Analyzer ran clean |

---

## Thread Pool Detection

The analyzer uses a **fully generic, zero-configuration** approach to pool detection:

1. **Strip trailing numbers** — `my-worker-42` → `my-worker`, `lettuce-nioEventLoop-4-1` → `lettuce-nioEventLoop`
2. **Strip embedded port numbers** — `http-nio-8080-exec` → `http-nio-exec`
3. **Use full name as pool** — threads named exactly `tcs-client-threads` (no number suffix) are grouped under that name

This means **any** thread pool is automatically detected — no hardcoded list needed.

**Common framework pools detected automatically:**

**Spring / Tomcat**
- `http-nio-*`, `https-nio-*`, `tomcat-handler-*`, `tomcat-exec-*`

**Reactor / Netty**
- `reactor-http-nio-*`, `reactor-http-epoll-*`
- `boundedElastic-*`, `parallel-*`

**OpenSearch Client**
- `opensearch-client-worker-*`, `opensearch-transport-worker-*`

**Other**
- `scheduler-*`, `pool-*`, `ForkJoinPool-*`
- Any `*-<number>` thread name → pool name is derived by stripping the trailing number

**Idle Detection** — a thread is classified as idle if its top stack frames contain any of:
- `sun.misc.Unsafe.park` / `jdk.internal.misc.Unsafe.park`
- `java.lang.Object.wait`
- `java.lang.Thread.sleep`
- `sun.nio.ch.EPoll.wait` / `sun.nio.ch.KQueue.poll`
- `io.netty.channel.epoll.Native.epollWait`
- `java.util.concurrent.locks.LockSupport.park`

---

## Building

```bash
# Debug build (faster compile, slower binary)
cargo build

# Release build (optimised, stripped)
cargo build --release

# Run tests
cargo test

# Run with a real dump
cargo run -- summary path/to/thread-dump.txt --histogram path/to/heap-histogram.txt
```

Requires **Rust 1.75+**. Install via [rustup.rs](https://rustup.rs).

---

## Project Structure

```
src/
├── main.rs               # CLI entry point (clap sub-commands)
├── lib.rs                # Library surface
├── model/                # Data types (Thread, ThreadPool, Finding, HeapSnapshot, ...)
├── parser/               # jstack + jmap -histo parsers
├── analyzer/             # Analysis logic (deadlock, contention, hot_threads, ...)
└── report/               # Output rendering (terminal, json, summary orchestrator)

tests/
├── fixtures/             # Real-world-shaped jstack + jmap sample files
└── integration_test.rs   # End-to-end tests across parser + analyzer layers
```
