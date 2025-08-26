const std = @import("std");
const config = @import("config.zig");

const ProcessInfo = config.ProcessInfo;
const MetricType = config.MetricType;
const Config = config.Config;

// Format Prometheus metrics from a snapshot of ProcessInfo
// Reuses an internal byte buffer across scrapes (buffer.clearRetainingCapacity) to avoid per-request allocations for the output string
// Groups are built per scrape using a temporary HashMap. Groups keys follow a borrowing strategy to minimize allpactions:
//     * If the grouping key is a single, stable slice (e.g. name, username,
//       or the first token of cmdline), we borrow that slice as the map key.
//     * If the key is composite (e.g. name:user or includes cmdline), we
//       build it in key_buffer and dupe it so the HashMap owns a stable copy.
//   Owned keys are tracked and freed in freeGroups.
pub const MetricsFormatter = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),
    key_buffer: []u8,

    // No thoughts behind these numbers, just a reasonable size to start with
    const KEY_BUFFER_SIZE = 64 * 1024;
    const INITIAL_BUFFER_SIZE = 1 * 1024 * 1024;

    pub fn init(allocator: std.mem.Allocator) !MetricsFormatter {
        var buffer = std.ArrayList(u8).init(allocator);
        try buffer.ensureTotalCapacity(INITIAL_BUFFER_SIZE);

        return .{
            .allocator = allocator,
            .buffer = buffer,
            .key_buffer = try allocator.alloc(u8, KEY_BUFFER_SIZE),
        };
    }

    pub fn deinit(self: *MetricsFormatter) void {
        self.buffer.deinit();
        self.allocator.free(self.key_buffer);
    }

    pub fn format(self: *MetricsFormatter, processes: []const ProcessInfo, cfg: Config) ![]const u8 {
        // clear buffer but keep allocated memory
        self.buffer.clearRetainingCapacity();

        const writer = self.buffer.writer();

        var groups = try self.groupProcesses(processes, cfg);
        defer self.freeGroups(&groups);

        const scalar_metrics = [_]MetricType{
            .cpu_usage_percent,
            .memory_rss,
            .memory_vms,
            .diskio_bytes_read_total,
            .diskio_bytes_write_total,
            .num_fds,
            .context_switches_total,
            .syscalls_mach_total,
            .syscalls_unix_total,
            .messages_sent_total,
            .messages_received_total,
            .net_receive_bytes_total,
            .net_transmit_bytes_total,
            .net_receive_packets_total,
            .net_transmit_packets_total,
            .cow_faults_total,
            .faults_total,
            .pageins_total,
            .phys_footprint_bytes,
            .priority,
            .start_time,
        };

        const composite_metrics = [_]MetricType{
            .cpu_seconds_total,
        };

        inline for (scalar_metrics) |metric_type| {
            try self.writeScalarMetric(writer, metric_type, groups, cfg, processes);
        }

        inline for (composite_metrics) |metric_type| switch (metric_type) {
            .cpu_seconds_total => try self.writeCpuSecondsTotal(writer, groups, cfg, processes),
            else => unreachable,
        };

        try self.writeProcessCounts(writer, groups, processes);
        try self.writeThreadMetrics(writer, groups, processes);
        try self.writeProcessInfo(writer, processes);

        return self.buffer.items;
    }

    const ProcessGroupAgg = struct { repr_idx: usize, count: usize = 0, sums: Sums = .{}, owned_key: bool = false };

    const GroupMap = std.StringHashMap(ProcessGroupAgg);

    fn groupProcesses(self: *MetricsFormatter, processes: []const ProcessInfo, cfg: Config) !GroupMap {
        var groups = GroupMap.init(self.allocator);
        // worst case: every process is its own group
        const expected = std.math.cast(u32, processes.len) orelse std.math.maxInt(u32);
        try groups.ensureTotalCapacity(expected);
        errdefer self.freeGroups(&groups);

        for (processes, 0..) |proc, idx| {
            const gk = try self.getGroupKey(proc, cfg.grouping);

            const result = try groups.getOrPut(gk.key);
            if (!result.found_existing) {
                if (gk.needs_dup) {
                    const dup = try self.allocator.dupe(u8, gk.key);
                    result.key_ptr.* = dup;
                    result.value_ptr.* = .{ .repr_idx = idx, .owned_key = true, .sums = .{} };
                } else {
                    // borrow a stable slice (name/username/first cmd token)
                    result.key_ptr.* = gk.key;
                    result.value_ptr.* = .{ .repr_idx = idx, .owned_key = false, .sums = .{} };
                }
            }

            result.value_ptr.sums.add(proc);
            result.value_ptr.count += 1;
        }

        return groups;
    }

    fn getGroupKey(self: *MetricsFormatter, proc: ProcessInfo, grouping: config.ProcessGrouping) !struct { key: []const u8, needs_dup: bool } {
        if (grouping.custom_grouper) |grouper| {
            return .{ .key = grouper(proc), .needs_dup = true };
        }

        if (grouping.by_name and !grouping.by_user and !grouping.by_cmdline) {
            return .{ .key = proc.name, .needs_dup = false };
        }

        if (!grouping.by_name and grouping.by_user and !grouping.by_cmdline) {
            return .{ .key = proc.username, .needs_dup = false };
        }

        if (!grouping.by_name and !grouping.by_user and grouping.by_cmdline) {
            var it = std.mem.tokenizeAny(u8, proc.cmdline, " ");
            const tok = it.next() orelse proc.cmdline[0..0];
            return .{ .key = tok, .needs_dup = false };
        }

        var fbs = std.io.fixedBufferStream(self.key_buffer);
        const writer = fbs.writer();

        var first = true;

        if (grouping.by_name) {
            try writer.writeAll(proc.name);
            first = false;
        }

        if (grouping.by_user) {
            if (!first) try writer.writeByte(':');
            try writer.writeAll(proc.username);
            first = false;
        }

        if (grouping.by_cmdline) {
            if (!first) try writer.writeByte(':');
            var iter = std.mem.tokenizeAny(u8, proc.cmdline, " ");
            if (iter.next()) |cmd| {
                try writer.writeAll(cmd);
            }
        }

        const written = fbs.getWritten();

        if (written.len == 0) {
            return .{ .key = proc.name, .needs_dup = false };
        }

        return .{ .key = written, .needs_dup = true };
    }

    fn freeGroups(self: *MetricsFormatter, groups: *GroupMap) void {
        var it = groups.iterator();

        while (it.next()) |entry| {
            if (entry.value_ptr.owned_key) {
                self.allocator.free(entry.key_ptr.*);
            }
        }
        groups.deinit();
    }

    fn writeScalarMetric(self: *MetricsFormatter, writer: anytype, metric_type: MetricType, groups: GroupMap, cfg: Config, processes: []const ProcessInfo) !void {
        _ = cfg;
        _ = self;

        const metric_name = metric_type.getName();
        const metric_help = metric_type.getHelp();
        const metric_prom_type = metric_type.getType();

        try writer.print("# HELP process_{s} {s}\n", .{ metric_name, metric_help });
        try writer.print("# TYPE process_{s} {s}\n", .{ metric_name, metric_prom_type });

        var it = groups.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const procs = entry.value_ptr.*;

            const value = valueFor(metric_type, procs);

            if (value) |v| {
                const repr_proc = processes[procs.repr_idx];

                try writer.print(
                    "process_{s}{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\"}} {d}\n",
                    .{ metric_name, group_name, repr_proc.name, repr_proc.username, v },
                );
            }
        }

        try writer.writeByte('\n');
    }

    fn valueFor(metric_type: MetricType, g: ProcessGroupAgg) ?f64 {
        return switch (metric_type) {
            .cpu_usage_percent => g.sums.cpu_usage_percent,
            .memory_rss => @floatFromInt(g.sums.memory_rss),
            .memory_vms => @floatFromInt(g.sums.memory_vms),
            .diskio_bytes_read_total => @floatFromInt(g.sums.diskio_bytes_read),
            .diskio_bytes_write_total => @floatFromInt(g.sums.diskio_bytes_write),
            .num_fds => @floatFromInt(g.sums.num_fds),
            .context_switches_total => @floatFromInt(g.sums.context_switches),
            .syscalls_mach_total => @floatFromInt(g.sums.syscalls_mach),
            .syscalls_unix_total => @floatFromInt(g.sums.syscalls_unix),
            .messages_sent_total => @floatFromInt(g.sums.messages_sent),
            .messages_received_total => @floatFromInt(g.sums.messages_received),
            .net_receive_bytes_total => @floatFromInt(g.sums.net_rx_bytes),
            .net_transmit_bytes_total => @floatFromInt(g.sums.net_tx_bytes),
            .net_receive_packets_total => @floatFromInt(g.sums.net_rx_packets),
            .net_transmit_packets_total => @floatFromInt(g.sums.net_tx_packets),
            .cow_faults_total => @floatFromInt(g.sums.cow_faults),
            .faults_total => @floatFromInt(g.sums.faults),
            .pageins_total => @floatFromInt(g.sums.pageins),
            .phys_footprint_bytes => @floatFromInt(g.sums.phys_footprint),
            .priority => @floatFromInt(g.sums.priority),
            .start_time => if (g.sums.start_time_min == std.math.maxInt(i64)) null else @floatFromInt(g.sums.start_time_min),
            .cpu_seconds_total, .num_threads => unreachable,
        };
    }

    fn writeCpuSecondsTotal(self: *MetricsFormatter, writer: anytype, groups: GroupMap, cfg: Config, processes: []const ProcessInfo) !void {
        _ = self;
        _ = cfg;

        try writer.writeAll("# HELP process_cpu_seconds_total Total accumulated CPU time in seconds (split by mode=user|system)\n");
        try writer.writeAll("# TYPE process_cpu_seconds_total counter\n");

        var it = groups.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const procs = entry.value_ptr.*;
            const repr = processes[procs.repr_idx];

            const total_user: f64 = @as(f64, @floatFromInt(procs.sums.cpu_time_user_us)) / 1_000_000.0;
            const total_sys: f64 = @as(f64, @floatFromInt(procs.sums.cpu_time_sys_us)) / 1_000_000.0;

            try writer.print(
                "process_cpu_seconds_total{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\",mode=\"user\"}} {d}\n",
                .{ group_name, repr.name, repr.username, total_user },
            );
            try writer.print(
                "process_cpu_seconds_total{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\",mode=\"system\"}} {d}\n",
                .{ group_name, repr.name, repr.username, total_sys },
            );
        }

        try writer.writeByte('\n');
    }

    fn writeProcessCounts(self: *MetricsFormatter, writer: anytype, groups: GroupMap, processes: []const ProcessInfo) !void {
        _ = self;

        try writer.writeAll("# HELP process_num_procs Number of processes in this group\n");
        try writer.writeAll("# TYPE process_num_procs gauge\n");

        var it = groups.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const procs = entry.value_ptr.*;
            const repr_proc = processes[procs.repr_idx];

            try writer.print(
                "process_num_procs{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\"}} {d}\n",
                .{ group_name, repr_proc.name, repr_proc.username, procs.count },
            );
        }

        try writer.writeByte('\n');
    }

    fn writeThreadMetrics(self: *MetricsFormatter, writer: anytype, groups: GroupMap, processes: []const ProcessInfo) !void {
        _ = self;

        try writer.writeAll("# HELP process_threads Number of threads\n");
        try writer.writeAll("# TYPE process_threads gauge\n");

        var it = groups.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const procs = entry.value_ptr.*;

            const repr_proc = processes[procs.repr_idx];
            const total_threads: u64 = @intCast(procs.sums.threads_total);
            const running_threads: u64 = @intCast(procs.sums.threads_running);

            try writer.print(
                "process_threads{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\",state=\"total\"}} {d}\n",
                .{ group_name, repr_proc.name, repr_proc.username, total_threads },
            );

            try writer.print(
                "process_threads{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\",state=\"running\"}} {d}\n",
                .{ group_name, repr_proc.name, repr_proc.username, running_threads },
            );
        }
        try writer.writeByte('\n');
    }

    fn writeProcessInfo(self: *MetricsFormatter, writer: anytype, processes: []const ProcessInfo) !void {
        _ = self;

        try writer.writeAll("# HELP process_info Process metadata (pid, ppid, uid, gid, user, state)\n");
        try writer.writeAll("# TYPE process_info gauge\n");

        for (processes) |p| {
            const state = p.state.toString();

            try writer.print(
                "process_info{{pid=\"{d}\",ppid=\"{d}\",uid=\"{d}\",gid=\"{d}\",name=\"{s}\",user=\"{s}\",state=\"{s}\",priority=\"{d}\",start_time=\"{d}\"}} 1\n",
                .{ p.pid, p.ppid, p.uid, p.gid, p.name, p.username, state, p.priority, p.start_time },
            );
        }
        try writer.writeByte('\n');
    }

    const Sums = struct {
        // running totals
        cpu_usage_percent: f64 = 0,
        cpu_time_user_us: u64 = 0,
        cpu_time_sys_us: u64 = 0,
        memory_rss: u64 = 0,
        memory_vms: u64 = 0,
        diskio_bytes_read: u64 = 0,
        diskio_bytes_write: u64 = 0,
        num_fds: u64 = 0,
        context_switches: i64 = 0,
        syscalls_mach: i64 = 0,
        syscalls_unix: i64 = 0,
        messages_sent: i64 = 0,
        messages_received: i64 = 0,
        net_rx_bytes: u64 = 0,
        net_tx_bytes: u64 = 0,
        net_rx_packets: u64 = 0,
        net_tx_packets: u64 = 0,
        cow_faults: i64 = 0,
        faults: i64 = 0,
        pageins: u64 = 0,
        phys_footprint: u64 = 0,
        priority: i64 = 0,
        threads_total: u64 = 0,
        threads_running: u64 = 0,
        start_time_min: i64 = std.math.maxInt(i64),

        fn add(self: *Sums, p: ProcessInfo) void {
            self.cpu_usage_percent += p.cpu_usage_percent;
            self.cpu_time_user_us += @as(u64, p.cpu_time_user);
            self.cpu_time_sys_us += @as(u64, p.cpu_time_system);
            self.memory_rss += @as(u64, p.memory_rss);
            self.memory_vms += @as(u64, p.memory_vms);
            self.diskio_bytes_read += @as(u64, p.diskio_bytes_read);
            self.diskio_bytes_write += @as(u64, p.diskio_bytes_write);
            self.num_fds += @as(u64, p.num_fds);
            self.context_switches += @as(i64, p.context_switches);
            self.syscalls_mach += @as(i64, p.syscalls_mach);
            self.syscalls_unix += @as(i64, p.syscalls_unix);
            self.messages_sent += @as(i64, p.messages_sent);
            self.messages_received += @as(i64, p.messages_received);
            self.net_rx_bytes += @as(u64, p.net_rx_bytes);
            self.net_tx_bytes += @as(u64, p.net_tx_bytes);
            self.net_rx_packets += @as(u64, p.net_rx_packets);
            self.net_tx_packets += @as(u64, p.net_tx_packets);
            self.cow_faults += @as(i64, p.cow_faults);
            self.faults += @as(i64, p.faults);
            self.pageins += @as(u64, p.pageins);
            self.phys_footprint += @as(u64, p.phys_footprint);
            self.priority += @as(i64, p.priority);
            self.threads_total += @as(u64, p.num_threads);
            self.threads_running += @as(u64, p.num_threads_running);
            if (p.start_time < self.start_time_min) self.start_time_min = p.start_time;
        }
    };
};

test "metrics formatter" {
    const allocator = std.testing.allocator;

    var formatter = try MetricsFormatter.init(allocator);
    defer formatter.deinit();

    var processes = [_]ProcessInfo{
        .{
            .pid = 123,
            .ppid = 1,
            .name = try allocator.dupe(u8, "test_app"),
            .cmdline = try allocator.dupe(u8, "test_app --flag"),
            .username = try allocator.dupe(u8, "testuser"),
            .state = .running,
            .cpu_usage_percent = 25.5,
            .cpu_time_user = 1000000,
            .cpu_time_system = 500000,
            .memory_rss = 1024 * 1024 * 100,
            .memory_vms = 1024 * 1024 * 200,
            .num_fds = 15,
            .num_threads = 4,
            .context_switches = 12345,
            .priority = 20,
            .start_time = 1234567890,
        },
    };

    defer {
        for (&processes) |*proc| {
            allocator.free(proc.name);
            allocator.free(proc.cmdline);
            allocator.free(proc.username);
        }
    }

    const cfg = Config{};
    const output = try formatter.format(&processes, cfg);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "# HELP process_cpu_usage_percent") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "# TYPE process_cpu_usage_percent gauge") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "process_cpu_usage_percent{") != null);

    // Test that buffer retains capacity after format
    const old_capacity = formatter.buffer.capacity;
    const output2 = try formatter.format(&processes, cfg);

    defer allocator.free(output2);

    // Capacity should be the same or larger, but not smaller
    try std.testing.expect(formatter.buffer.capacity >= old_capacity);
}
