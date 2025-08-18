const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const cache = @import("cache.zig");

const darwin = switch (builtin.os.tag) {
    .macos => struct {
        pub const sysctl = @import("platform/sysctl.zig");
        pub const proc_info = @import("platform/proc_info.zig");
        pub const mach = @import("platform/mach.zig");
        pub const net = @import("platform/nstat.zig");
    },
    else => @compileError("Unsupported platform"),
};

const ProcessInfo = config.ProcessInfo;
const ProcessState = config.ProcessState;
const Config = config.Config;

// High-level collector for taking a point-in-time snapshot of 
// process state and formatting it for metrics. The collector is deliberately
// stateful to compute CPU usages from deltas between scrapes and
// preserve caches that reduce per-scrape syscalls and allocations
pub const ProcessCollector = struct {
    allocator: std.mem.Allocator,
    config: Config,
    cpu_count: u32,
    boot_time: i64,
    name_cache: ProcessNameCache,
    user_cache: ProcessUsernameCache,
    cmd_cache: ProcessCmdlineCache,
    string_pool: StringPool,
    // Previous scrape snapshot used to compute CPU deltas, replaced automatically
    // at the end of eac successful collect()
    last_collection: ?CollectionState = null,
    // Reusable pid buffer to avoid per-scrape allocations
    pid_buf: []i32 = &.{},
    pid_capacity: usize = 0,

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

    pub fn init(allocator: std.mem.Allocator, cfg: Config) !ProcessCollector {
        try darwin.net.initNetworkStats(allocator);

        return ProcessCollector{
            .allocator = allocator,
            .config = cfg,
            .cpu_count = try darwin.sysctl.getCpuCount(),
            // .page_size = std.c.getpagesize(),
            .boot_time = try darwin.sysctl.getBootTime(),
            .name_cache = ProcessNameCache.init(allocator),
            .user_cache = ProcessUsernameCache.init(allocator),
            .cmd_cache = ProcessCmdlineCache.init(allocator),
            .string_pool = StringPool.init(allocator),
        };
    }

    // Frees caches and any reused buffers. Safe to call after partial failure
    pub fn deinit(self: *ProcessCollector) void {
        if (self.last_collection) |*collection| {
            collection.deinit();
        }
        self.name_cache.deinit();
        self.user_cache.deinit();
        self.cmd_cache.deinit(); //no-op for values (already interned)
        self.string_pool.deinit();
        if (self.pid_capacity != 0) self.allocator.free(self.pid_buf);
        darwin.net.deinitNetworkStats();
    }

    // Takes a single snapshot of all processes visible to the caller
    // Uses caches to minimize syscalls and reuses internal buffers
    // Returns an owned slice, freed at freeProcessList
    pub fn collect(self: *ProcessCollector) ![]ProcessInfo {
        darwin.net.sweepStaleSocketStats(60 * std.time.ns_per_s);

        self.cmd_cache.beginRound();
        defer self.cmd_cache.sweep();

        self.name_cache.beginRound();
        defer self.name_cache.sweep();

        const pids = try darwin.sysctl.listAllPids(self.allocator, &self.pid_buf, &self.pid_capacity);

        var processes = std.ArrayList(ProcessInfo).init(self.allocator);
        try processes.ensureTotalCapacityPrecise(pids.len);

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
        try new_collection.processes.ensureTotalCapacity(@intCast(pids.len));
        errdefer new_collection.deinit();

        for (pids) |pid| {
            const proc_info = try self.collectProcess(pid, current_time, &new_collection);

            if (proc_info) |info| {
                if (try self.shouldIncludeProcess(info)) {
                    try processes.append(info);
                } else {
                    var mut_info = info;
                    mut_info.deinit(self.allocator);
                }
            }
        }

        if (self.last_collection) |*old| {
            old.deinit();
        }
        
        self.last_collection = new_collection;

        return processes.toOwnedSlice();
    }

    // Wrapper that treats common errors as "not present" rather than failing the scrape
    fn collectProcess(self: *ProcessCollector, pid: i32, current_time: i64, new_collection: *CollectionState) !?ProcessInfo {
        return self.collectProcessProcInfo(pid, current_time, new_collection) catch |err| switch (err) {
            error.AccessDenied, error.InvalidPid => null,
            else => return err,
        };
    }

    // Primary data path using libproc/proc_pidinfo with graceful fallback
    // when some fields are unavailable. Populates new_collections so later
    // scrapes can compute CPU usage deltas
    fn collectProcessProcInfo(self: *ProcessCollector, pid: i32, current_time: i64, new_collection: *CollectionState) !?ProcessInfo {
        const basic_info = try darwin.proc_info.getBasicInfo(pid);

        // skip kernel threads, uninteresting for process-level accounting
        if (basic_info.pbi_flags & 0x4 != 0) {
            return null;
        }

        const upid = Upid{
            .pid = pid,
            .start_sec = @as(i64, @intCast(basic_info.pbi_start_tvsec)),
            .start_usec = @as(i64, @intCast(basic_info.pbi_start_tvusec)),
        };

        const name: []const u8 = blk: {
            if (self.name_cache.get(upid)) |n| break :blk n;

            var buf: [darwin.proc_info.MaxProcNameLen]u8 = undefined;
            const slice = try darwin.proc_info.getProcessName(pid, &buf);
            const interned = try self.string_pool.intern(slice);
            try self.name_cache.put(upid, interned);
            break :blk interned;
        };

        const cmdline: []const u8 = blk: {
            if (self.cmd_cache.get(upid)) |s| break :blk s;

            const tmp = darwin.proc_info.getProcessCmdline(self.allocator, pid) catch
                try self.allocator.dupe(u8, name);

            try self.cmd_cache.put(upid, tmp);
            break :blk tmp;
        };

        const username = try getUserName(&self.user_cache, basic_info.pbi_uid);

        const task_info_result = try darwin.proc_info.getTaskInfoWithFallback(pid);

        const fd_count = if (self.config.collect_fd)
            darwin.proc_info.getFdCount(pid) catch 0
        else
            0;

        if (task_info_result.info) |task_info| {
            const cpu_percent = self.calculateCpuPercent(pid, task_info.pti_total_user, task_info.pti_total_system, current_time);

            const rusage_info = darwin.proc_info.getRusageInfo(pid) catch null;
            const net = darwin.net.getProcessNetworkStats(pid) catch darwin.net.ProcessNetworkStats{
                .pid = pid,
                .rx_bytes = 0,
                .tx_bytes = 0,
                .rx_packets = 0,
                .tx_packets = 0,
            };
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
                .net_rx_bytes = net.rx_bytes,
                .net_tx_bytes = net.tx_bytes,
                .net_rx_packets = net.rx_packets,
                .net_tx_packets = net.tx_packets,
                .cow_faults = task_info.pti_cow_faults,
                .faults = task_info.pti_faults,
                .pageins = pageins,
                .phys_footprint = phys_footprint,
                .priority = @intCast(task_info.pti_priority),
                .start_time = @intCast(basic_info.pbi_start_tvsec),
            };
        } else {
            // No info available (e.g permission), Record a zeroed
            // snapshot so CPU deltas remain well-defined on next scrape
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
                .net_rx_bytes = 0,
                .net_tx_bytes = 0,
                .net_rx_packets = 0,
                .net_tx_packets = 0,
                .cow_faults = 0,
                .faults = 0,
                .pageins = 0,
                .phys_footprint = 0,
                .priority = 0,
                .start_time = @intCast(basic_info.pbi_start_tvsec),
            };
        }
    }

    // Alternative Mach-based path kept for reference/experimentation
    // Requires task_for_pid which oftens fails without priviledges. Not used
    // by collect(), see collectProcessProcInfo for the production
    fn collectProcessMach(self: *ProcessCollector, pid: i32, current_time: i64, new_collection: *CollectionState) !?ProcessInfo {
        const basic_info = try darwin.proc_info.getBasicInfo(pid);

        if (basic_info.pbi_flags & 0x4 != 0) {
            return null;
        }

        // get process name and intern it
        const name_tmp = try darwin.proc_info.getProcessName(self.allocator, pid);
        defer self.allocator.free(name_tmp);
        const name = try self.string_pool.intern(name_tmp);

        const cmdline = darwin.proc_info.getProcessCmdline(self.allocator, pid) catch |err| blk: {
            switch (err) {
                error.SystemError => break :blk try self.allocator.dupe(u8, name_tmp),
                else => return err,
            }
        };
        errdefer self.allocator.free(cmdline);

        const username = try self.user_cache.getUserName(basic_info.pbi_uid);

        const cpu_info = try darwin.mach.getTaskCpuInfo(pid);
        const cpu_percent = self.calculateCpuPercent(pid, cpu_info.user_time, cpu_info.system_time, current_time);

        const mem_info = try darwin.mach.getTaskMemoryInfo(pid);

        const net = darwin.net.getProcessNetworkStats(pid) catch darwin.net.ProcessNetworkStats{
            .pid = pid,
            .rx_bytes = 0,
            .tx_bytes = 0,
            .rx_packets = 0,
            .tx_packets = 0,
        };

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

        // Duplicate the username string for this ProcessInfo
        // we need to do this because ProcessInfo owns its strings
        const username_dup = try self.allocator.dupe(u8, username);
        errdefer self.allocator.free(username_dup);

        return ProcessInfo{
            .pid = pid,
            .ppid = basic_info.pbi_ppid,
            .name = name,
            .cmdline = cmdline,
            .username = username_dup,
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
            .net_rx_bytes = net.rx_bytes,
            .net_tx_bytes = net.tx_bytes,
            .net_rx_packets = net.rx_packets,
            .net_tx_packets = net.tx_packets,
            .cow_faults = task_info.pti_cow_faults,
            .faults = task_info.pti_faults,
            .pageins = pageins,
            .phys_footprint = phys_footprint,
            .priority = @intCast(task_info.pti_priority),
            .start_time = @intCast(basic_info.pbi_start_tvsec),
        };
    }

    // Computes CPU usage percentage across scrapes using per process user+sys
    // microsecond counters and elapsed wall time. Normalized by core count
    // Returns 0 when elasped <= 0 or counters regressed e.g PID reuse
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

    // Apply include/exclude name filters. Note: current matching is a simple
    // substring test, not full regex
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

    // Frees all owned strings in a collected list and then the list itself
    // Safe today because ProcessInfo.deinit is a no-op, if that changes
    // the loop still delegates ownership to that method
    pub fn freeProcessList(self: *ProcessCollector, processes: []ProcessInfo) void {
        for (processes) |*proc| {
            proc.deinit(self.allocator);
        }
        self.allocator.free(processes);
    }
};

// Looks up a username for a UID and caches the results
// Returns an owned slice lifetime is managed by ProcessUsernameCache
pub fn getUserName(self: *ProcessUsernameCache, uid: u32) ![]const u8 {
    if (self.get(uid)) |name| {
        return name;
    }

    const c = @cImport({
        @cInclude("pwd.h");
    });

    const pwd = c.getpwuid(uid);
    const name = if (pwd == null) blk: {
        // User not found, use numeric ID
        break :blk try std.fmt.allocPrint(self.allocator, "{d}", .{uid});
    } else blk: {
        // Copy username from passwd struct
        const name_len = std.mem.len(pwd.*.pw_name);
        break :blk try self.allocator.dupe(u8, pwd.*.pw_name[0..name_len]);
    };

    try self.put(uid, name);
    return name;
}

const Upid = struct { 
    pid: i32, 
    start_sec: i64, 
    start_usec: i64 
};

// Names are interned in string_pool need to rethink this
const ProcessNameCache = cache.Cache(Upid, []const u8, null);

// Usernames are owned here, free on sweep/deinit
const ProcessUsernameCache = cache.Cache(u32, []const u8, freeOwnedSlice);

// Cmdlines are owned here, free on sweep/deinit
const ProcessCmdlineCache = cache.Cache(Upid, []const u8, freeOwnedSlice);

// Helper to free owned slices
fn freeOwnedSlice(allocator: std.mem.Allocator, s: []const u8) void {
    allocator.free(s);
}

//Deduplicates common strings (process names, cmdlines) to reduce memory churn
const StringPool = struct {
    strings: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StringPool {
        return .{ .strings = std.StringHashMap([]const u8).init(allocator), .allocator = allocator };
    }

    pub fn deinit(self: *StringPool) void {
        var iter = self.strings.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.strings.deinit();
    }

    // Returns a stable, interned copy of str. If an identical slice
    // exists, it is reused (pointer equality is valid across scrapes).
    pub fn intern(self: *StringPool, str: []const u8) ![]const u8 {
        if (self.strings.get(str)) |existing| {
            return existing;
        }
        const copy = try self.allocator.dupe(u8, str);
        try self.strings.put(copy, copy);
        return copy;
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
