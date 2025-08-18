## process-exporter

macOS process exporter. Exposes per-process metrics in Prometheus text format over HTTP.

## Build
```
zig build -Doptimize=ReleaseSafe

./zig-out/bin/process-exporter --help
```

## Run
Default:

```sh
# listening on 0.0.0.0:9256, metrics at /metrics
./process-exporter
```
## Examples
```sh
# Custom port and include only postgres processes
./process-exporter --port 9257 --include-pattern postgres

# Exclude kernel-style names and use a longer interval
./process-exporter --exclude-pattern "^kernel" --interval 30

# Bind to loopback only
./process-exporter --bind 127.0.0.1

# Print help
./process-exporter --help
```
## Metrics

All metric names are prefixed with `process_`

Gauges (one sample per group unless noted):

* `cpu_usage_percent` — instantaneous CPU% normalized by logical cores, computed from deltas between scrapes.
* `memory_rss_bytes`, `memory_vms_bytes`
* `open_fds`
* `threads` — per group emitted twice with state="total" and state="running".
* `priority`
* `phys_footprint_bytes`
* `start_time_seconds` — earliest start time among members of the group (if any).

Counters (monotonic):
* `cpu_seconds_total{mode="user"|"system"}` — accumulated CPU seconds split by mode.
* Disk I/O: `diskio_bytes_read_total`, `diskio_bytes_write_total`
* Scheduler/syscalls/messages: `context_switches_total`, `syscalls_mach_total`, `syscalls_unix_total`, `messages_sent_total`, `messages_received_total`
* Network: `net_receive_bytes_total`, `net_transmit_bytes_total`, `net_receive_packets_total`, `net_transmit_packets_total`
* Memory faults: `cow_faults_total`, `faults_total`, `pageins_total`


Additional helper gauge:
* `process_num_procs` — number of processes in the group.

Labels on all samples:
* `groupname` — grouping key (see below)
* `name` — representative process name (first member of the group)
* `user` — representative username
* `mode` — only on cpu_seconds_total
* `state` — only on process_threads (total or running)

## Process grouping

Controlled by `Config.grouping`:
* `by_name` (default `true`)
* `by_user` (default `false`)
* `by_cmdline` (default `false`, first token only)
* `custom_grouper` (optional function hook)

Keys are borrowed (no allocation) when grouping by a single stable slice (name/user/first cmd token). Composite keys are built in a reusable buffer and duped so the map owns them.

The representative process for labels is the first seen member of the group.

## Filtering

`Config.include_patterns` / `Config.exclude_patterns` are applied to process names (not cmdline). Current implementation is substring match (case-sensitive), not full regex.

If include_patterns is non-empty, only names containing at least one include pattern are kept (post exclude check).

`exclude_patterns` are applied first; matching names are dropped.

## Network accounting

Network totals are built from NetworkStatistics per-socket absolute counters:

* The exporter subscribes to all TCP and UDP sources.
* Deltas are computed per socket (keyed by UUID) and then summed per PID.
* On macOS versions where counts are not available for a source, totals for that socket may remain zero until counts are reported.
* Closed/TimeWait sockets are purged from the per-socket baseline to bound memory.
* Per-PID aggregates are monotonic for the exporter lifetime (they do not persist across restarts).

## Library

### Init and run your own server

```Zig
const std = @import("std");
const exporter_lib = @import("lib.zig");
const Config = exporter_lib.Config;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // macOS guard
    try exporter_lib.init();

    // Configure
    var cfg = Config{
        .port = 0, // not used when you host your own endpoint
        .metrics_path = "/metrics",
        .grouping = .{ .by_name = true, .by_user = false, .by_cmdline = false },
        .include_patterns = &.{}, // substring matches
        .exclude_patterns = &.{},
        .collect_fd = true,
        .include_threads = true,
        .collection_interval = 15,
    };

    const exp = try exporter_lib.createExporter(alloc, cfg);
    defer exp.deinit();

    // Example: integrate with your HTTP stack
    // On each request to /metrics:
    const body = try exp.collectOnce();
    // NOTE: `body` aliases an internal buffer and is valid until the next collect.
    // Write it directly to the response; copy if you need to retain it.
    // Also set Content-Type: text/plain; version=0.0.4; charset=utf-8
}
```

### Start the built-in server

If you just want to serve `/metrics` with the provided server:
```zig
const exporter_lib = @import("lib.zig");
const Config = exporter_lib.Config;

pub fn main() !void {
    try exporter_lib.init();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const exp = try exporter_lib.createExporter(gpa.allocator(), .{});
    defer exp.deinit();

    // Blocks; handles /metrics and scrapes at the configured interval.
    try exp.run();
}
```

### Contract notes
* `collectOnce()` returns a slice that aliases an internal buffer; do not keep it past the next collect (copy if you must retain).

* `Exporter.deinit()` must be called to release resources.

* `init()` returns UnsupportedPlatform on non-macOS targets.

## Notes
* Memory Allocation strategy
    * Reused PID buffer for enumeration.
    * Generation-swept caches for process names, usernames, cmdlines.
    * String interning pool to deduplicate common strings.
    * Formatter keeps a large [ArrayList(u8)](https://ziglang.org/documentation/master/std/#std.ArrayList) and calls clearRetainingCapacity() each scrape.

* CPU%
    * Computed from deltas of microsecond counters between scrapes and normalized by CPU count.
    * If counters regress (PID reuse or restart), the sample is zero for that interval.
* Thread metrics
    * Emitted as two samples (total, running) per group.
* The exporter provides an unauthenticated HTTP endpoint. Prefer binding to `127.0.0.1` and use a reverse proxy for remote access.
* Some per-process calls can fail due to permissions. The collector treats AccessDenied/InvalidPid as non-fatal and skips those processes.
* Network statistics rely on a private framework availability/behavior may vary by macOS version but should be stable since 10.x versions atleast