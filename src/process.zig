const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");

const darwin = switch (builtin.os.tag) {
    .macos => struct {
        pub const sysctl = @import("platform/sysctl.zig");
        pub const proc_info = @import("platform/proc_info.zig");
        pub const mach = @import("platform/mach.zig");
    },
    else => @compileError("Unsupported platform"),
};

const ProcessInfo = config.ProcessInfo;
const ProcessState = config.ProcessState;
const Config = config.Config;

pub const ProcessCollector = struct {
    allocator: std.mem.Allocator,
    config: Config,
    cpu_count: u32,
    // page_size: u32,
    boot_time: i64,
    last_collection: ?CollectionState = null,

    const CollectionState = struct {
        time: i64,
        processes: std.AutoHashMap(i32, ProcessSnapshot),

        fn deinit(self: *CollectionState) void {
            self.processes.deinit();
        }
    };

    const ProcessSnapshot = struct {
        cpu_user_us: u64,
        cpu_sys_us: u64,
        timestamp: i64,
    };

    const CollectionStats = struct {
        total_pids: usize = 0,
        collected: usize = 0,
        full_quality: usize = 0,
        degraded_quality: usize = 0,
        skipped: usize = 0,
    };

    pub fn init(allocator: std.mem.Allocator, cfg: Config) !ProcessCollector {
        return ProcessCollector{
            .allocator = allocator,
            .config = cfg,
            .cpu_count = try darwin.sysctl.getCpuCount(),
            // .page_size = std.c.getpagesize(),
            .boot_time = try darwin.sysctl.getBootTime(),
        };
    }

    pub fn deinit(self: *ProcessCollector) void {
        if (self.last_collection) |*collection| {
            collection.deinit();
        }
    }

    pub fn collect(self: *ProcessCollector) ![]ProcessInfo {
        const pids = try darwin.sysctl.getAllPids(self.allocator);
        defer self.allocator.free(pids);

        var stats = CollectionStats{ .total_pids = pids.len };

        var processes = std.ArrayList(ProcessInfo).init(self.allocator);
        errdefer {
            for (processes.items) |*proc| {
                proc.deinit(self.allocator);
            }
            processes.deinit();
        }

        const current_time = std.time.timestamp();
        var new_collection = CollectionState{
            .time = current_time,
            .processes = std.AutoHashMap(i32, ProcessSnapshot).init(self.allocator),
        };

        errdefer new_collection.deinit();

        for (pids) |pid| {
            const proc_info = try self.collectProcessHybrid(pid, current_time, &new_collection, &stats);

            if (proc_info) |info| {
                if (try self.shouldIncludeProcess(info)) {
                    try processes.append(info);
                    stats.collected += 1;
                } else {
                    var mut_info = info;
                    mut_info.deinit(self.allocator);
                }
            } else {
                stats.skipped += 1;
            }
        }

        // std.log.info("Process collection: {}/{} collected ({} full, {} degraded, {} skipped)", .{ stats.collected, stats.total_pids, stats.full_quality, stats.degraded_quality, stats.skipped });

        if (self.last_collection) |*old| {
            old.deinit();
        }
        self.last_collection = new_collection;

        return processes.toOwnedSlice();
    }

    fn collectProcessHybrid(self: *ProcessCollector, pid: i32, current_time: i64, new_collection: *CollectionState, stats: *CollectionStats) !?ProcessInfo {
        if (self.collectProcess(pid, current_time, new_collection)) |info| {
            stats.full_quality += 1;
            return info;
        } else |err| switch (err) {
            error.AccessDenied => {
                if (self.collectProcessDegraded(pid, current_time, new_collection)) |info| {
                    stats.degraded_quality += 1;
                    return info;
                } else |fallback_err| {
                    std.log.debug("Failed degraded collection for PID {}: {s}", .{ pid, @errorName(fallback_err) });
                    return null;
                }
            },
            error.InvalidPid => return null,
            else => return err,
        }
    }

    fn collectProcess(self: *ProcessCollector, pid: i32, current_time: i64, new_collection: *CollectionState) !?ProcessInfo {
        const basic_info = try darwin.proc_info.getBasicInfo(pid);

        if (basic_info.pbi_flags & 0x4 != 0) {
            return null;
        }

        const name = try darwin.proc_info.getProcessName(self.allocator, pid);
        errdefer self.allocator.free(name);

        const cmdline = darwin.proc_info.getProcessCmdline(self.allocator, pid) catch |err| blk: {
            switch (err) {
                error.SystemError => break :blk try self.allocator.dupe(u8, name),
                else => return err,
            }
        };
        errdefer self.allocator.free(cmdline);

        const username = try self.getUserName(basic_info.pbi_uid);
        errdefer self.allocator.free(username);

        const cpu_info = try darwin.mach.getTaskCpuInfo(pid);
        const cpu_percent = self.calculateCpuPercent(pid, cpu_info.user_time, cpu_info.system_time, current_time);

        const mem_info = try darwin.mach.getTaskMemoryInfo(pid);

        const task_info = try darwin.proc_info.getTaskInfo(pid);

        const rusage_info = darwin.proc_info.getRusageInfo(pid) catch |err| blk: {
            std.log.debug("Failed to get rusage for PID {}: {s}", .{ pid, @errorName(err) });
            break :blk null;
        };

        const diskio_read = if (rusage_info) |r| r.ri_diskio_bytesread else 0;
        const diskio_written = if (rusage_info) |r| r.ri_diskio_byteswritten else 0;
        const phys_footprint = if (rusage_info) |r| r.ri_phys_footprint else 0;
        const pageins = if (rusage_info) |r| r.ri_pageins else 0;

        const fd_count = if (self.config.collect_fd)
            darwin.proc_info.getFdCount(pid) catch 0
        else
            0;

        const thread_count = darwin.proc_info.getThreadCount(pid) catch 1;

        try new_collection.processes.put(pid, ProcessSnapshot{
            .cpu_user_us = cpu_info.user_time,
            .cpu_sys_us = cpu_info.system_time,
            .timestamp = current_time,
        });

        return ProcessInfo{
            .pid = pid,
            .ppid = basic_info.pbi_ppid,
            .name = name,
            .cmdline = cmdline,
            .username = username,
            .state = self.getProcessState(basic_info.pbi_status),
            .cpu_usage_percent = cpu_percent,
            .cpu_time_user = cpu_info.user_time,
            .cpu_time_system = cpu_info.system_time,
            .memory_rss = mem_info.resident_size,
            .memory_vms = mem_info.virtual_size,
            .diskio_bytes_read = diskio_read,
            .diskio_bytes_write = diskio_written,
            .num_fds = fd_count,
            .num_threads = thread_count,
            .num_threads_running = @intCast(task_info.pti_numrunning),
            .context_switches = task_info.pti_csw,
            .syscalls_mach = task_info.pti_syscalls_mach,
            .syscalls_unix = task_info.pti_syscalls_unix,
            .messages_sent = task_info.pti_messages_sent,
            .messages_received = task_info.pti_messages_received,
            .cow_faults = task_info.pti_cow_faults,
            .faults = task_info.pti_faults,
            .pageins = pageins,
            .phys_footprint = phys_footprint,
            .priority = @intCast(task_info.pti_priority),
            .start_time = @intCast(basic_info.pbi_start_tvsec),
        };
    }

    fn collectProcessDegraded(self: *ProcessCollector, pid: i32, current_time: i64, new_collection: *CollectionState) !?ProcessInfo {
        const basic_info = try darwin.proc_info.getBasicInfo(pid);

        // skip kernel threads
        if (basic_info.pbi_flags & 0x4 != 0) {
            return null;
        }

        const name = try darwin.proc_info.getProcessName(self.allocator, pid);
        errdefer self.allocator.free(name);

        const cmdline = darwin.proc_info.getProcessCmdline(self.allocator, pid) catch
            try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(cmdline);

        const username = try self.getUserName(basic_info.pbi_uid);
        errdefer self.allocator.free(username);

        const task_info_result = try darwin.proc_info.getTaskInfoWithFallback(pid);

        const fd_count = if (self.config.collect_fd)
            darwin.proc_info.getFdCount(pid) catch 0
        else
            0;

        if (task_info_result.info) |task_info| {
            const cpu_percent = self.calculateCpuPercent(pid, task_info.pti_total_user, task_info.pti_total_system, current_time);

            const rusage_info = darwin.proc_info.getRusageInfo(pid) catch null;
            const diskio_read = if (rusage_info) |r| r.ri_diskio_bytesread else 0;
            const diskio_written = if (rusage_info) |r| r.ri_diskio_byteswritten else 0;
            const phys_footprint = if (rusage_info) |r| r.ri_phys_footprint else 0;
            const pageins = if (rusage_info) |r| r.ri_pageins else 0;

            try new_collection.processes.put(pid, .{ .cpu_user_us = task_info.pti_total_user, .cpu_sys_us = task_info.pti_total_system, .timestamp = current_time });
            return ProcessInfo{
                .pid = pid,
                .ppid = basic_info.pbi_ppid,
                .name = name,
                .cmdline = cmdline,
                .username = username,
                .state = self.getProcessState(basic_info.pbi_status),
                .cpu_usage_percent = cpu_percent,
                .cpu_time_user = task_info.pti_total_user,
                .cpu_time_system = task_info.pti_total_system,
                .memory_rss = task_info.pti_resident_size,
                .memory_vms = task_info.pti_virtual_size,
                .diskio_bytes_read = diskio_read,
                .diskio_bytes_write = diskio_written,
                .num_fds = fd_count,
                .num_threads = @intCast(task_info.pti_threadnum),
                .num_threads_running = @intCast(task_info.pti_numrunning),
                .context_switches = task_info.pti_csw,
                .syscalls_mach = task_info.pti_syscalls_mach,
                .syscalls_unix = task_info.pti_syscalls_unix,
                .messages_sent = task_info.pti_messages_sent,
                .messages_received = task_info.pti_messages_received,
                .cow_faults = task_info.pti_cow_faults,
                .faults = task_info.pti_faults,
                .pageins = pageins,
                .phys_footprint = phys_footprint,
                .priority = @intCast(task_info.pti_priority),
                .start_time = @intCast(basic_info.pbi_start_tvsec),
            };
        } else {
            try new_collection.processes.put(pid, .{ .cpu_user_us = 0, .cpu_sys_us = 0, .timestamp = current_time });

            return ProcessInfo{
                .pid = pid,
                .ppid = basic_info.pbi_ppid,
                .name = name,
                .cmdline = cmdline,
                .username = username,
                .state = self.getProcessState(basic_info.pbi_status),
                .cpu_usage_percent = 0,
                .cpu_time_user = 0,
                .cpu_time_system = 0,
                .memory_rss = 0,
                .memory_vms = 0,
                .diskio_bytes_read = 0,
                .diskio_bytes_write = 0,
                .num_fds = fd_count,
                .num_threads = 0,
                .num_threads_running = 0,
                .context_switches = 0,
                .syscalls_mach = 0,
                .syscalls_unix = 0,
                .messages_sent = 0,
                .messages_received = 0,
                .cow_faults = 0,
                .faults = 0,
                .pageins = 0,
                .phys_footprint = 0,
                .priority = 0,
                .start_time = @intCast(basic_info.pbi_start_tvsec),
            };
        }
    }

    fn calculateCpuPercent(self: *ProcessCollector, pid: i32, user_us: u64, sys_us: u64, now: i64) f64 {
        const last_state = self.last_collection orelse return 0;
        const prev = last_state.processes.get(pid) orelse return 0;

        const elapsed = now - last_state.time;
        if (elapsed <= 0) return 0;

        const cur_total = @as(u128, user_us) + @as(u128, sys_us);
        const prev_total = @as(u128, prev.cpu_user_us) + @as(u128, prev.cpu_sys_us);

        if (cur_total <= prev_total) return 0; //counter went backwards (maybe proc restarted)
        const diff_us = cur_total - prev_total;

        const sec = @as(f64, @floatFromInt(elapsed));
        const cores = @as(f64, @floatFromInt(self.cpu_count));
        return (@as(f64, @floatFromInt(diff_us)) / 1_000_000.0) / sec * 100.0 / cores;
    }

    fn getProcessState(self: *ProcessCollector, status: u32) ProcessState {
        _ = self;
        return switch ((status)) {
            1 => .idle, //SIDL
            2 => .running, //SRUN
            3 => .sleeping, //SSLEEP
            4 => .stopped, //SSTOP
            5 => .zombie, //SZOMB
            else => .unknown,
        };
    }

    fn getUserName(self: *ProcessCollector, uid: u32) ![]u8 {
        const c = @cImport({
            @cInclude("pwd.h");
        });

        const pwd = c.getpwuid(uid);
        if (pwd == null) {
            return std.fmt.allocPrint(self.allocator, "{d}", .{uid});
        }

        const name_len = std.mem.len(pwd.*.pw_name);
        return self.allocator.dupe(u8, pwd.*.pw_name[0..name_len]);
    }

    fn shouldIncludeProcess(self: *ProcessCollector, proc: ProcessInfo) !bool {
        for (self.config.exclude_patterns) |pattern| {
            if (try self.matchesPattern(proc.name, pattern)) {
                return false;
            }
        }

        if (self.config.include_patterns.len > 0) {
            for (self.config.include_patterns) |pattern| {
                if (try self.matchesPattern(proc.name, pattern)) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    fn matchesPattern(self: *ProcessCollector, name: []const u8, pattern: []const u8) !bool {
        _ = self;

        //TODO: (umegbewe) implement proper regex matching
        return std.mem.indexOf(u8, name, pattern) != null;
    }

    pub fn freeProcessList(self: *ProcessCollector, processes: []ProcessInfo) void {
        for (processes) |*proc| {
            proc.deinit(self.allocator);
        }
        self.allocator.free(processes);
    }
};

test "process collector initialization" {
    const allocator = std.testing.allocator;
    const cfg = Config{};

    var collector = try ProcessCollector.init(allocator, cfg);
    defer collector.deinit();

    try std.testing.expect(collector.cpu_count > 0);
}

test "process collection" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .collection_interval = 1,
    };

    var collector = try ProcessCollector.init(allocator, cfg);
    defer collector.deinit();

    const processes = try collector.collect();
    defer collector.freeProcessList(processes);

    try std.testing.expect(processes.len > 0);

    // Find our own process
    const our_pid = std.c.getpid();
    var found = false;
    for (processes) |proc| {
        if (proc.pid == our_pid) {
            found = true;
            try std.testing.expect(proc.memory_rss > 0);
            try std.testing.expect(proc.num_threads > 0);
            break;
        }
    }
    try std.testing.expect(found);
}
