const std = @import("std");
const config = @import("config.zig");

const ProcessInfo = config.ProcessInfo;
const MetricType = config.MetricType;
const Config = config.Config;

pub const MetricsFormatter = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MetricsFormatter {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MetricsFormatter) void {
        _ = self;
    }

    pub fn format(self: *MetricsFormatter, processes: []const ProcessInfo, cfg: Config) ![]const u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();

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
            try self.writeScalarMetric(&buffer, metric_type, groups, cfg);
        }

        inline for (composite_metrics) |metric_type| switch (metric_type) {
            .cpu_seconds_total => try self.writeCpuSecondsTotal(&buffer, groups, cfg),
            else => unreachable,
        };

        try self.writeProcessCounts(&buffer, groups);

        try self.writeThreadMetrics(&buffer, groups);

        return buffer.toOwnedSlice();
    }

    const ProcessGroup = struct {
        key: []const u8,
        processes: std.ArrayList(ProcessInfo),

        fn deinit(self: *ProcessGroup, allocator: std.mem.Allocator) void {
            allocator.free(self.key);
            self.processes.deinit();
        }
    };

    const GroupMap = std.StringHashMap(std.ArrayList(ProcessInfo));

    fn groupProcesses(self: *MetricsFormatter, processes: []const ProcessInfo, cfg: Config) !GroupMap {
        var groups = GroupMap.init(self.allocator);
        errdefer self.freeGroups(&groups);

        for (processes) |proc| {
            const group_key = try self.getGroupKey(proc, cfg.grouping);
            defer self.allocator.free(group_key);

            const result = try groups.getOrPut(group_key);
            if (!result.found_existing) {
                result.key_ptr.* = try self.allocator.dupe(u8, group_key);
                result.value_ptr.* = std.ArrayList(ProcessInfo).init(self.allocator);
            }

            try result.value_ptr.append(proc);
        }

        return groups;
    }

    fn getGroupKey(self: *MetricsFormatter, proc: ProcessInfo, grouping: config.ProcessGrouping) ![]u8 {
        if (grouping.custom_grouper) |grouper| {
            return self.allocator.dupe(u8, grouper(proc));
        }

        var key_parts = std.ArrayList([]const u8).init(self.allocator);
        defer key_parts.deinit();

        if (grouping.by_name) {
            try key_parts.append(proc.name);
        }

        if (grouping.by_user) {
            try key_parts.append(proc.username);
        }

        if (grouping.by_cmdline) {
            var iter = std.mem.tokenizeAny(u8, proc.cmdline, " ");
            if (iter.next()) |cmd| {
                try key_parts.append(cmd);
            }
        }

        if (key_parts.items.len == 0) {
            return self.allocator.dupe(u8, proc.name);
        }

        var key = std.ArrayList(u8).init(self.allocator);
        for (key_parts.items, 0..) |part, i| {
            if (i > 0) try key.append(':');
            try key.appendSlice(part);
        }
        return key.toOwnedSlice();
    }

    fn freeGroups(self: *MetricsFormatter, groups: *GroupMap) void {
        var it = groups.iterator();

        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        groups.deinit();
    }

    fn writeScalarMetric(self: *MetricsFormatter, buffer: *std.ArrayList(u8), metric_type: MetricType, groups: GroupMap, cfg: Config) !void {
        _ = cfg;

        const metric_name = metric_type.getName();
        const metric_help = metric_type.getHelp();
        const metric_prom_type = metric_type.getType();

        try buffer.writer().print("# HELP process_{s} {s}\n", .{ metric_name, metric_help });
        try buffer.writer().print("# TYPE process_{s} {s}\n", .{ metric_name, metric_prom_type });

        var it = groups.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const procs = entry.value_ptr.*;

            const value = try self.aggregateScalarMetric(metric_type, procs.items);

            if (value) |v| {
                const repr_proc = procs.items[0];

                try buffer.writer().print(
                    "process_{s}{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\"}} {d}\n",
                    .{ metric_name, group_name, repr_proc.name, repr_proc.username, v },
                );
            }
        }

        try buffer.append('\n');
    }

    fn aggregateScalarMetric(self: *MetricsFormatter, metric_type: MetricType, processes: []const ProcessInfo) !?f64 {
        _ = self;

        if (processes.len == 0) return null;

        var sum: f64 = 0;
        var count: usize = 0;

        for (processes) |proc| {
            const value: ?f64 = switch (metric_type) {
                .cpu_usage_percent => proc.cpu_usage_percent,
                .cpu_seconds_total => unreachable, // never called from composites
                .memory_rss => @floatFromInt(proc.memory_rss),
                .memory_vms => @floatFromInt(proc.memory_vms),
                .diskio_bytes_read_total => @floatFromInt(proc.diskio_bytes_read),
                .diskio_bytes_write_total => @floatFromInt(proc.diskio_bytes_write),
                .num_fds => @floatFromInt(proc.num_fds),
                .num_threads => unreachable,
                .context_switches_total => @floatFromInt(proc.context_switches),
                .syscalls_mach_total => @floatFromInt(proc.syscalls_mach),
                .syscalls_unix_total => @floatFromInt(proc.syscalls_unix),
                .messages_sent_total => @floatFromInt(proc.messages_sent),
                .messages_received_total => @floatFromInt(proc.messages_received),
                .cow_faults_total => @floatFromInt(proc.cow_faults),
                .faults_total => @floatFromInt(proc.faults),
                .pageins_total => @floatFromInt(proc.pageins),
                .phys_footprint_bytes => @floatFromInt(proc.phys_footprint),
                .priority => @floatFromInt(proc.priority),
                .start_time => @floatFromInt(proc.start_time),
            };

            if (value) |v| {
                sum += v;
                count += 1;
            }
        }

        if (count == 0) return null;

        // For most metrics, sum across processes in a group
        // For start_time, just take the minimum (earliest)
        return switch (metric_type) {
            .start_time => blk: {
                var min: i64 = std.math.maxInt(i64);
                for (processes) |proc| {
                    if (proc.start_time < min) {
                        min = proc.start_time;
                    }
                }
                break :blk @floatFromInt(min);
            },
            .cpu_usage_percent => sum,
            else => sum,
        };
    }

    fn writeCpuSecondsTotal(self: *MetricsFormatter, buffer: *std.ArrayList(u8), groups: GroupMap, cfg: Config) !void {
        _ = self;
        _ = cfg;

        try buffer.writer().print("# HELP process_cpu_seconds_total Total accumulated CPU time in seconds (split by mode=user|system)\n", .{});
        try buffer.writer().print("# TYPE process_cpu_seconds_total counter\n", .{});

        var it = groups.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const procs = entry.value_ptr.*;

            var total_user: f64 = 0;
            var total_sys: f64 = 0;

            for (procs.items) |p| {
                total_user += @as(f64, @floatFromInt(p.cpu_time_user)) / 1_000_000.0;
                total_sys += @as(f64, @floatFromInt(p.cpu_time_system)) / 1_000_000.0;
            }

            const repr = procs.items[0];
            try buffer.writer().print(
                "process_cpu_seconds_total{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\",mode=\"user\"}} {d}\n",
                .{ group_name, repr.name, repr.username, total_user },
            );
            try buffer.writer().print(
                "process_cpu_seconds_total{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\",mode=\"system\"}} {d}\n",
                .{ group_name, repr.name, repr.username, total_sys },
            );
        }

        try buffer.append('\n');
    }

    fn writeProcessCounts(self: *MetricsFormatter, buffer: *std.ArrayList(u8), groups: GroupMap) !void {
        _ = self;

        try buffer.appendSlice("# HELP process_num_procs Number of processes in this group\n");
        try buffer.appendSlice("# TYPE process_num_procs gauge\n");

        var it = groups.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const procs = entry.value_ptr.*;
            const repr_proc = procs.items[0];

            try buffer.writer().print(
                "process_num_procs{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\"}} {d}\n",
                .{ group_name, repr_proc.name, repr_proc.username, procs.items.len },
            );
        }

        try buffer.append('\n');
    }

    fn writeThreadMetrics(self: *MetricsFormatter, buffer: *std.ArrayList(u8), groups: GroupMap) !void {
        _ = self;

        try buffer.appendSlice("# HELP process_threads Number of threads\n");
        try buffer.appendSlice("# TYPE process_threads gauge\n");

        var it = groups.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const procs = entry.value_ptr.*;

            var total_threads: u64 = 0;
            var running_threads: u64 = 0;

            for (procs.items) |proc| {
                total_threads += proc.num_threads;
                running_threads += proc.num_threads_running;
            }

            const repr_proc = procs.items[0];

            try buffer.writer().print(
                "process_threads{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\",state=\"total\"}} {d}\n",
                .{ group_name, repr_proc.name, repr_proc.username, total_threads },
            );

            try buffer.writer().print(
                "process_threads{{groupname=\"{s}\",name=\"{s}\",user=\"{s}\",state=\"running\"}} {d}\n",
                .{ group_name, repr_proc.name, repr_proc.username, running_threads },
            );
        }
        try buffer.append('\n');
    }
};

test "metrics formatter" {
    const allocator = std.testing.allocator;

    var formatter = MetricsFormatter.init(allocator);
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
}
