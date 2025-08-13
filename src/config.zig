const std = @import("std");

pub const Config = struct {
    /// Process name patterns to include (regex)
    include_patterns: []const []const u8 = &.{},

    /// Process name patterns to exclude (regex)
    exclude_patterns: []const []const u8 = &.{},

    /// Whether to track child processes
    track_children: bool = true,

    /// Collection interval in seconds
    collection_interval: u64 = 15,

    /// HTTP server port
    port: u16 = 9256,

    /// HTTP server bind address
    bind_address: []const u8 = "0.0.0.0",

    /// Path for metrics endpoint
    metrics_path: []const u8 = "/metrics",

    /// Whether to include threads in process count
    include_threads: bool = false,

    /// Whether to collect file descriptor counts
    collect_fd: bool = true,

    /// Whether to collect memory mappings
    collect_memory_maps: bool = false,

    /// Process grouping configuration
    grouping: ProcessGrouping = .{},
};

pub const ProcessGrouping = struct {
    /// Group by process name
    by_name: bool = true,

    /// Group by command line
    by_cmdline: bool = false,

    /// Group by username
    by_user: bool = false,

    /// Custom grouping function
    custom_grouper: ?*const fn (proc: ProcessInfo) []const u8 = null,
};

pub const ProcessInfo = struct {
    pid: i32,
    ppid: u32,
    name: []const u8,
    cmdline: []const u8,
    username: []const u8,
    state: ProcessState,

    cpu_usage_percent: f64,
    cpu_time_user: u64,
    cpu_time_system: u64,

    memory_rss: u64,
    memory_vms: u64,

    diskio_bytes_read: u64,
    diskio_bytes_write: u64,

    num_fds: u32,
    num_threads: u32,
    num_threads_running: u32,

    context_switches: i32,

    syscalls_mach: i32,
    syscalls_unix: i32,

    messages_sent: i32,
    messages_received: i32,
    
    net_rx_bytes: u64,
    net_tx_bytes: u64,
    net_rx_packets: u64,
    net_tx_packets: u64,

    cow_faults: i32,
    faults: i32,
    pageins: u64,
    priority: i32,

    phys_footprint: u64,

    start_time: i64,

    pub fn deinit(self: *ProcessInfo, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};

pub const ProcessState = enum {
    running,
    sleeping,
    waiting,
    zombie,
    stopped,
    idle,
    unknown,

    pub fn toString(self: ProcessState) []const u8 {
        return switch (self) {
            .running => "running",
            .sleeping => "sleeping",
            .waiting => "waiting",
            .zombie => "zombie",
            .stopped => "stopped",
            .idle => "idle",
            .unknown => "unknown",
        };
    }
};

pub const MetricType = enum {
    cpu_usage_percent,
    cpu_seconds_total,
    memory_rss,
    memory_vms,
    diskio_bytes_read_total,
    diskio_bytes_write_total,
    num_fds,
    num_threads,
    context_switches_total,
    syscalls_mach_total,
    syscalls_unix_total,
    messages_sent_total,
    messages_received_total,
    net_receive_bytes_total,
    net_transmit_bytes_total,
    net_receive_packets_total,
    net_transmit_packets_total,
    cow_faults_total,
    faults_total,
    pageins_total,
    priority,
    phys_footprint_bytes,
    start_time,

    pub fn getName(self: MetricType) []const u8 {
        return switch (self) {
            .cpu_usage_percent => "cpu_usage_percent",
            .cpu_seconds_total => "cpu_seconds_total",
            .memory_rss => "memory_rss_bytes",
            .memory_vms => "memory_vms_bytes",
            .diskio_bytes_read_total => "diskio_bytes_read_total",
            .diskio_bytes_write_total => "diskio_bytes_write_total",
            .num_fds => "open_fds",
            .num_threads => "threads",
            .context_switches_total => "context_switches_total",
            .syscalls_mach_total => "syscalls_mach_total",
            .syscalls_unix_total => "syscalls_unix_total",
            .messages_sent_total => "messages_sent_total",
            .messages_received_total => "messages_received_total",
            .net_receive_bytes_total => "net_receive_bytes_total",
            .net_transmit_bytes_total => "net_transmit_bytes_total",
            .net_receive_packets_total => "net_receive_packets_total",
            .net_transmit_packets_total => "net_transmit_packets_total",
            .cow_faults_total => "cow_faults_total",
            .faults_total => "faults_total",
            .pageins_total => "pageins_total",
            .priority => "priority",
            .phys_footprint_bytes => "phys_footprint_bytes",
            .start_time => "start_time_seconds",
        };
    }

    pub fn getHelp(self: MetricType) []const u8 {
        return switch (self) {
            .cpu_usage_percent => "CPU usage percentage",
            .cpu_seconds_total => "Total accumulated CPU time in seconds (split by mode=user|system)",
            .memory_rss => "Resident set size in bytes",
            .memory_vms => "Virtual memory size in bytes",
            .diskio_bytes_read_total => "Total bytes read from disk",
            .diskio_bytes_write_total => "Total bytes written to disk",
            .num_fds => "Number of open file descriptors",
            .num_threads => "Number of threads",
            .context_switches_total => "Total number of context switches",
            .syscalls_mach_total => "Total number of Mach system calls",
            .syscalls_unix_total => "Total number of Unix system calls",
            .messages_sent_total => "Total number of Mach messages sent",
            .messages_received_total => "Total number of Mach messages received",
            .net_receive_bytes_total => "Total bytes received on all sockets",
            .net_transmit_bytes_total => "Total bytes transmitted on all sockets",
            .net_receive_packets_total => "Total packets received on all sockets",
            .net_transmit_packets_total => "Total packets transmitted on all sockets",
            .cow_faults_total => "Total number of copy-on-write faults",
            .faults_total => "Total number of page faults",
            .pageins_total => "Total number of page-ins",
            .phys_footprint_bytes => "Physical footprint in bytes",
            .priority => "Process priority",
            .start_time => "Process start time in seconds since epoch",
        };
    }

    pub fn getType(self: MetricType) []const u8 {
        return switch (self) {
            .cpu_usage_percent => "gauge",
            .cpu_seconds_total => "counter",
            .memory_rss, .memory_vms => "gauge",
            .num_fds, .num_threads => "gauge",
            .diskio_bytes_read_total, .diskio_bytes_write_total => "counter",
            .context_switches_total => "counter",
            .syscalls_mach_total, .syscalls_unix_total => "counter",
            .messages_sent_total, .messages_received_total => "counter",
            .net_receive_bytes_total, .net_transmit_bytes_total => "counter",
            .net_receive_packets_total, .net_transmit_packets_total => "counter",
            .cow_faults_total, .faults_total => "counter",
            .pageins_total => "counter",
            .priority => "gauge",
            .phys_footprint_bytes => "gauge",
            .start_time => "gauge",
        };
    }
};

test "ProcessState string conversion" {
    try std.testing.expectEqualStrings("running", ProcessState.running.toString());
    try std.testing.expectEqualStrings("zombie", ProcessState.zombie.toString());
}

test "MetricType properties" {
    try std.testing.expectEqualStrings("cpu_seconds_total", MetricType.cpu_seconds_total.getName());
    try std.testing.expectEqualStrings("counter", MetricType.cpu_seconds_total.getType());
    try std.testing.expectEqualStrings("gauge", MetricType.memory_rss.getType());
}
