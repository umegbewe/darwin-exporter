const std = @import("std");
const objc = @import("objc");
const c = @cImport({
    @cInclude("dispatch/dispatch.h");
    @cInclude("CoreFoundation/CoreFoundation.h");
});

const NStatManagerRef = *opaque {};
const NStatSourceRef = *opaque {};

extern "c" fn NStatManagerCreate(
    allocator: c.CFAllocatorRef,
    queue: c.dispatch_queue_t,
    callback: *anyopaque,
) NStatManagerRef;

extern "c" fn NStatManagerAddAllTCPWithFilter(
    manager: NStatManagerRef,
    filter: c_int,
    filter2: c_int,
) c_int;

extern "c" fn NStatManagerAddAllUDPWithFilter(
    manager: NStatManagerRef,
    filter: c_int,
    filter2: c_int,
) c_int;

extern "c" fn NStatManagerSetFlags(
    manager: NStatManagerRef,
    flags: c_int,
) c_int;

extern "c" fn NStatSourceSetDescriptionBlock(
    source: NStatSourceRef,
    block: *anyopaque,
) void;

extern "c" fn NStatSourceSetCountsBlock(
    source: NStatSourceRef,
    block: *anyopaque,
) void;

extern "c" fn NStatSourceQueryDescription(
    source: NStatSourceRef,
) void;

extern "c" fn NStatSourceQueryCounts(
    source: NStatSourceRef,
) void;

// NetworkStatistics.framework keys
extern "c" const kNStatSrcKeyPID: c.CFStringRef;
extern "c" const kNStatSrcKeyProcessName: c.CFStringRef;
extern "c" const kNStatSrcKeyRxBytes: c.CFStringRef;
extern "c" const kNStatSrcKeyTxBytes: c.CFStringRef;
extern "c" const kNStatSrcKeyRxPackets: c.CFStringRef;
extern "c" const kNStatSrcKeyTxPackets: c.CFStringRef;
extern "c" const kNStatSrcKeyProvider: c.CFStringRef;
extern "c" const kNStatSrcKeyUUID: c.CFStringRef;
extern "c" const kNStatSrcKeyTCPState: c.CFStringRef;

pub const NetworkStatsError = error{
    CreateManagerFailed,
    AddTCPFailed,
    AddUDPFailed,
    InvalidPID,
};

pub const ProcessNetworkStats = struct {
    pid: i32,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
};

const SocketStats = struct {
    pid: i32,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
};

// Block signatures for NetworkStatistics callbacks
const SourceAddedBlock = objc.Block(struct {}, .{ NStatSourceRef, ?*anyopaque }, void);

const DescriptionBlock = objc.Block(struct {}, .{c.CFDictionaryRef}, void);

const CountsBlock = objc.Block(struct {}, .{c.CFDictionaryRef}, void);

var g_network_stats: ?*NetworkStatsManager = null;
var g_stats_mutex = std.Thread.Mutex{};

const NetworkStatsManager = struct {
    allocator: std.mem.Allocator,
    // per process aggregated stats
    stats_map: std.AutoHashMap(i32, ProcessNetworkStats),
    //per socket stats for delta calculation key is UUID string
    socket_map: std.StringHashMap(SocketStats),
    manager: NStatManagerRef,
    // Blocks must be kept alive, stores contexts we copy
    source_added_block: SourceAddedBlock.Context,
    description_blocks: std.ArrayList(*DescriptionBlock.Context),
    counts_blocks: std.ArrayList(*CountsBlock.Context),

    pub fn deinit(self: *NetworkStatsManager) void {
        for (self.description_blocks.items) |block| {
            DescriptionBlock.release(block);
        }
        self.description_blocks.deinit();

        for (self.counts_blocks.items) |block| {
            CountsBlock.release(block);
        }
        self.counts_blocks.deinit();

        // Clean up socket map keys we own the strings
        var iter = self.socket_map.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.socket_map.deinit();

        self.stats_map.deinit();
        self.allocator.destroy(self);
    }
};

// Helper to get u64 from CFNumber
fn getCFNumberValue(dict: c.CFDictionaryRef, key: c.CFStringRef) u64 {
    const num = c.CFDictionaryGetValue(dict, key);

    if (num == null) return 0;

    var value: i64 = 0;
    _ = c.CFNumberGetValue(@ptrCast(num), c.kCFNumberSInt64Type, &value);
    return @intCast(@max(0, value));
}

// Helper to get string from CFString
fn getCFStringValue(allocator: std.mem.Allocator, dict: c.CFDictionaryRef, key: c.CFStringRef) ![]u8 {
    const str = c.CFDictionaryGetValue(dict, key);
    if (str == null) return allocator.dupe(u8, "<unknown>");

    var buffer: [256]u8 = undefined;

    const success = c.CFStringGetCString(@ptrCast(str), &buffer, buffer.len, c.kCFStringEncodingUTF8);

    if (success == 0) return allocator.dupe(u8, "<unknown>");

    const len = std.mem.indexOfScalar(u8, &buffer, 0) orelse buffer.len;
    return allocator.dupe(u8, buffer[0..len]);
}

// Description callback, handles metadata updates
fn descriptionCallbackImpl(_: *const DescriptionBlock.Context, dict: c.CFDictionaryRef) callconv(.C) void {
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return;

    // If TCPState present and Closed/TimeWait remove from socket_map
    const state = getCFStringValue(manager.allocator, dict, kNStatSrcKeyTCPState) catch return;
    defer manager.allocator.free(state);

    if (std.mem.eql(u8, state, "Closed") or std.mem.eql(u8, state, "TimeWait")) {
        const uuid = getCFStringValue(manager.allocator, dict, kNStatSrcKeyUUID) catch return;
        defer manager.allocator.free(uuid);

        if (manager.socket_map.fetchRemove(uuid)) |kv| {
            manager.allocator.free(kv.key);
        }
    }
}

fn countsCallbackImpl(ctx: *const CountsBlock.Context, dict: c.CFDictionaryRef) callconv(.C) void {
    _ = ctx;

    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return;

    const uuid = getCFStringValue(manager.allocator, dict, kNStatSrcKeyUUID) catch return;
    defer manager.allocator.free(uuid);

    const pid_raw = getCFNumberValue(dict, kNStatSrcKeyPID);
    if (pid_raw == 0) return;
    const pid: i32 = @intCast(pid_raw);

    const curr_rx_bytes = getCFNumberValue(dict, kNStatSrcKeyRxBytes);
    const curr_tx_bytes = getCFNumberValue(dict, kNStatSrcKeyTxBytes);
    const curr_rx_packets = getCFNumberValue(dict, kNStatSrcKeyRxPackets);
    const curr_tx_packets = getCFNumberValue(dict, kNStatSrcKeyTxPackets);

    var delta_rx_bytes: u64 = curr_rx_bytes;
    var delta_tx_bytes: u64 = curr_tx_bytes;
    var delta_rx_packets: u64 = curr_rx_packets;
    var delta_tx_packets: u64 = curr_tx_packets;

    if (manager.socket_map.get(uuid)) |prev| {
        // calulate delta and handle potential counter resets
        if (curr_rx_bytes >= prev.rx_bytes) {
            delta_rx_bytes = curr_rx_bytes - prev.rx_bytes;
        }
        if (curr_tx_bytes >= prev.tx_bytes) {
            delta_tx_bytes = curr_tx_bytes - prev.tx_bytes;
        }
        if (curr_rx_packets >= prev.rx_packets) {
            delta_rx_packets = curr_rx_packets - prev.rx_packets;
        }
        if (curr_tx_packets >= prev.tx_packets) {
            delta_tx_packets = curr_tx_packets - prev.tx_packets;
        }
    }

    const gop = manager.socket_map.getOrPut(uuid) catch |err| {
        std.log.debug("Failed to get or put socket stats: {s}", .{@errorName(err)});
        return;
    };

    if (!gop.found_existing) {
        gop.key_ptr.* = manager.allocator.dupe(u8, uuid) catch |err| {
            _ = manager.socket_map.remove(uuid);
            std.log.debug("Failed to allocate socket key: {s}", .{@errorName(err)});
            return;
        };
    }

    gop.value_ptr.* = SocketStats{
        .pid = pid,
        .rx_bytes = curr_rx_bytes,
        .tx_bytes = curr_tx_bytes,
        .rx_packets = curr_rx_packets,
        .tx_packets = curr_tx_packets,
    };

    const existing = manager.stats_map.get(pid) orelse ProcessNetworkStats{
        .pid = pid,
        .rx_bytes = 0,
        .tx_bytes = 0,
        .rx_packets = 0,
        .tx_packets = 0,
    };

    manager.stats_map.put(pid, ProcessNetworkStats{
        .pid = pid,
        .rx_bytes = existing.rx_bytes + delta_rx_bytes,
        .tx_bytes = existing.tx_bytes + delta_tx_bytes,
        .rx_packets = existing.rx_packets + delta_rx_packets,
        .tx_packets = existing.tx_packets + delta_tx_packets,
    }) catch |err| {
        std.log.debug("Failed to update process stats for PID {}: {s}", .{ pid, @errorName(err) });
    };
}

fn sourceAddedCallbackImpl(_: *const SourceAddedBlock.Context, source: NStatSourceRef, context: ?*anyopaque) callconv(.C) void {
    // context is not reliably passed through the block, so we use global state
    _ = context;

    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return;

    const desc_block_context = DescriptionBlock.init(.{}, &descriptionCallbackImpl);

    // Copy the block to heap, it needs to persist
    const desc_block = DescriptionBlock.copy(&desc_block_context) catch |err| {
        std.log.err("Failed to copy description block: {s}", .{@errorName(err)});
        return;
    };

    // Track the block so we can clean it up later
    manager.description_blocks.append(desc_block) catch |err| {
        std.log.err("Failed to track description block: {s}", .{@errorName(err)});
        DescriptionBlock.release(desc_block);
        return;
    };

    _ = NStatSourceSetDescriptionBlock(source, @ptrCast(desc_block));

    const count_block_context = CountsBlock.init(.{}, &countsCallbackImpl);
    const counts_block = CountsBlock.copy(&count_block_context) catch |err| {
        std.log.err("Failed to copy counts block: {s}", .{@errorName(err)});
        return;
    };
    manager.counts_blocks.append(counts_block) catch |err| {
        std.log.err("Failed to track counts block: {s}", .{@errorName(err)});
        CountsBlock.release(counts_block);
        return;
    };

    _ = NStatSourceSetCountsBlock(source, @ptrCast(counts_block));

    // Query initial description to get first snapshot
    _ = NStatSourceQueryDescription(source);

    // Try to query counts (available on macOS 14+)
    // This may fail on older versions, but that's okay
    _ = NStatSourceQueryCounts(source);
}

pub fn initNetworkStats(allocator: std.mem.Allocator) !void {
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    if (g_network_stats != null) return;

    const manager = try allocator.create(NetworkStatsManager);
    errdefer allocator.destroy(manager);

    manager.* = NetworkStatsManager{
        .allocator = allocator,
        .stats_map = std.AutoHashMap(i32, ProcessNetworkStats).init(allocator),
        .socket_map = std.StringHashMap(SocketStats).init(allocator),
        .manager = undefined,
        .source_added_block = undefined,
        .description_blocks = std.ArrayList(*DescriptionBlock.Context).init(allocator),
        .counts_blocks = std.ArrayList(*CountsBlock.Context).init(allocator),
    };

    errdefer manager.stats_map.deinit();
    errdefer manager.socket_map.deinit();
    errdefer manager.description_blocks.deinit();
    errdefer manager.counts_blocks.deinit();

    manager.source_added_block = SourceAddedBlock.init(.{}, &sourceAddedCallbackImpl);

    const queue = c.dispatch_get_global_queue(c.DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    manager.manager = NStatManagerCreate(
        c.kCFAllocatorDefault,
        queue,
        @ptrCast(&manager.source_added_block),
    );

    if (@intFromPtr(manager.manager) == 0) {
        return NetworkStatsError.CreateManagerFailed;
    }

    _ = NStatManagerSetFlags(manager.manager, 0);

    _ = NStatManagerAddAllTCPWithFilter(manager.manager, 0, 0);
    _ = NStatManagerAddAllUDPWithFilter(manager.manager, 0, 0);

    g_network_stats = manager;
}

pub fn deinitNetworkStats() void {
    g_stats_mutex.lock();

    defer g_stats_mutex.unlock();

    if (g_network_stats) |manager| {
        manager.deinit();
        g_network_stats = null;
    }
}

pub fn getProcessNetworkStats(pid: i32) !ProcessNetworkStats {
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return NetworkStatsError.InvalidPID;

    if (manager.stats_map.get(pid)) |stats| {
        return stats;
    }

    // Return zero stats if not found
    return ProcessNetworkStats{
        .pid = pid,
        .rx_bytes = 0,
        .tx_bytes = 0,
        .rx_packets = 0,
        .tx_packets = 0,
    };
}

pub fn resetProcessNetworkStats(pid: i32) void {
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return;

    _ = manager.stats_map.remove(pid);

    // because i like the word, synonym is "remove"
    var obliterate = std.ArrayList([]const u8).init(manager.allocator);
    defer obliterate.deinit();

    var iter = manager.socket_map.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.pid == pid) {
            obliterate.append(entry.key_ptr.*) catch continue;
        }
    }

    for (obliterate.items) |key| {
        if (manager.socket_map.fetchRemove(key)) |kv| {
            manager.allocator.free(kv.key);
        }
    }
}

pub fn getAllNetworkStats(allocator: std.mem.Allocator) ![]ProcessNetworkStats {
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return &[_]ProcessNetworkStats{};

    var stats_list = std.ArrayList(ProcessNetworkStats).init(allocator);
    errdefer stats_list.deinit();

    var iter = manager.stats_map.iterator();
    while (iter.next()) |entry| {
        try stats_list.append(entry.value_ptr.*);
    }

    return stats_list.toOwnedSlice();
}
