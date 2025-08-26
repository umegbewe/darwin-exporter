const std = @import("std");
const objc = @import("objc");
const c = @cImport({
    @cInclude("dispatch/dispatch.h");
    @cInclude("CoreFoundation/CoreFoundation.h");
});

// Thin wrapper around NetworkStatistics.framework to accumulate per-PID
// network counters. We subscribe to all TCP/UDP sockets, compute deltas
// per socket (keyed by UUID) and aggregate them per process
// The aggregated values are intended to be exported as monotonic Prometheus
// counters (since exporter start)
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

// NOTE: Keys are CFString identifiers used in dictionary payloads from the
// framework. Presence/format can vary across macOS versions but should be stable since 10.x
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

// Public, per process view od accumulated network activity since init
pub const ProcessNetworkStats = struct {
    pid: i32,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
};

// Internal per socket snapshot used to compute deltas. We store the latest
// absolute counters from the framework and the last seen time to prune
// sockets e.g closed connections that no longer emit updates
const SocketStats = struct {
    pid: i32,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    last_seen_ns: u64 
};

// Block signatures for NetworkStatistics callbacks
const SourceAddedBlock = objc.Block(struct {}, .{ NStatSourceRef, ?*anyopaque }, void);

const DescriptionBlock = objc.Block(struct {}, .{c.CFDictionaryRef}, void);

const CountsBlock = objc.Block(struct {}, .{c.CFDictionaryRef}, void);

// Global manager guarded by g_stats_mutex, the framework expects a
// singleton-style lifecycle for the manager/callbacks
var g_network_stats: ?*NetworkStatsManager = null;
var g_stats_mutex = std.Thread.Mutex{};

const NetworkStatsManager = struct {
    allocator: std.mem.Allocator,
    // Per process aggregated stats
    stats_map: std.AutoHashMap(i32, ProcessNetworkStats),
    //Per socket stats for delta calculation key is UUID string
    socket_map: std.AutoHashMap(Uuid16, SocketStats),
    manager: NStatManagerRef,
    source_added_block: SourceAddedBlock.Context,

    pub fn deinit(self: *NetworkStatsManager) void {


        self.socket_map.deinit();

        self.stats_map.deinit();

        if (@intFromPtr(self.manager) != 0) {
            // Manager is a CFType, release our retain
            c.CFRelease(@as(c.CFTypeRef, @ptrCast(self.manager)));
        }
        self.allocator.destroy(self);
    }
};

// Helper to read a signed 64 bit CFNumber and clamp <0 to 0 (framework may
// report negative values transiently)
fn getCFNumberValue(dict: c.CFDictionaryRef, key: c.CFStringRef) u64 {
    const num = c.CFDictionaryGetValue(dict, key);

    if (num == null) return 0;

    var value: i64 = 0;
    _ = c.CFNumberGetValue(@ptrCast(num), c.kCFNumberSInt64Type, &value);
    return @intCast(@max(0, value));
}

// Helper to copy a CFString value from the dictionary into buf as UTF-8
// Returns a slice into buf or nulll if absent or too large
fn getCFStringValue(buf: []u8, dict: c.CFDictionaryRef, key: c.CFStringRef) ?[]const u8 {
    const str = c.CFDictionaryGetValue(dict, key);
    if (str == null) return null;

    if (c.CFStringGetCString(@ptrCast(str), buf.ptr, @intCast(buf.len), c.kCFStringEncodingUTF8) == 0) return null;
    const n = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    return buf[0..n];
}

// Description callback, handles metadata updates
// When a socket transitions to a terminal state, purge it from socket_map
// to stop holding stale baselines for delta computation
fn descriptionCallbackImpl(_: *const DescriptionBlock.Context, dict: c.CFDictionaryRef) callconv(.C) void {
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return;

    // If TCPState present and Closed/TimeWait remove from socket_map
    var state_buf: [32]u8 = undefined;

    if (getCFStringValue(&state_buf, dict, kNStatSrcKeyTCPState)) |state| {
        if (std.mem.eql(u8, state, "Closed") or std.mem.eql(u8, state, "TimeWait")) {
            var uuid_buf: [64]u8 = undefined;
            const uuid = getCFStringValue(&uuid_buf, dict, kNStatSrcKeyUUID) orelse return;
            const key = parseUuid16(uuid) orelse return;
            _ = manager.socket_map.remove(key);
        }
    }
}

// Counts callback converts absolute per-socket counters to per-interval deltas
// and aggregates them into per-PID totals, counter regressions (PID/socket
// restarts) are treated as zero delta
fn countsCallbackImpl(ctx: *const CountsBlock.Context, dict: c.CFDictionaryRef) callconv(.C) void {
    _ = ctx;

    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return;

    var uuid_buf: [64]u8 = undefined;
    const uuid = getCFStringValue(&uuid_buf, dict, kNStatSrcKeyUUID) orelse return;
    const uuid_key = parseUuid16(uuid) orelse return;

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

    if (manager.socket_map.get(uuid_key)) |prev| {
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

    const gop = manager.socket_map.getOrPut(uuid_key) catch |err| {
        std.log.debug("Failed to get or put socket stats: {s}", .{@errorName(err)});
        return;
    };

    // monotonic timestamp for stale socket pruning
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());

    gop.value_ptr.* = SocketStats{ .pid = pid, .rx_bytes = curr_rx_bytes, .tx_bytes = curr_tx_bytes, .rx_packets = curr_rx_packets, .tx_packets = curr_tx_packets, .last_seen_ns = now_ns };

    const s = manager.stats_map.getOrPut(pid) catch |err| {
        std.log.debug("Failed to update process stats for PID {}: {s}", .{ pid, @errorName(err) });
        return;
    };

    if (!s.found_existing) {
        s.value_ptr.* = ProcessNetworkStats{
            .pid = pid,
            .rx_bytes = 0,
            .tx_bytes = 0,
            .rx_packets = 0,
            .tx_packets = 0,
        };
    }
    s.value_ptr.rx_bytes += delta_rx_bytes;
    s.value_ptr.tx_bytes += delta_tx_bytes;
    s.value_ptr.rx_packets += delta_rx_packets;
    s.value_ptr.tx_packets += delta_tx_packets;
}

// Called by the framework when a new source is observed. We attach our 
// descripition and counts blocks to the source and issue an immediate query
// to seed initial state. Blocks are copied to the heap and retained
fn sourceAddedCallbackImpl(_: *const SourceAddedBlock.Context, source: NStatSourceRef, context: ?*anyopaque) callconv(.C) void {
    // context is not reliably passed through the block, so we use global state
    _ = context;

    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();


    const desc_block_context = DescriptionBlock.init(.{}, &descriptionCallbackImpl);
    const desc_block = DescriptionBlock.copy(&desc_block_context) catch |err| {
        std.log.err("Failed to copy description block: {s}", .{@errorName(err)});
        return;
    };

    _ = NStatSourceSetDescriptionBlock(source, @ptrCast(desc_block));
    DescriptionBlock.release(desc_block);

    const count_block_context = CountsBlock.init(.{}, &countsCallbackImpl);
    const counts_block = CountsBlock.copy(&count_block_context) catch |err| {
        std.log.err("Failed to copy counts block: {s}", .{@errorName(err)});
        return;
    };
    _ = NStatSourceSetCountsBlock(source, @ptrCast(counts_block));
    CountsBlock.release(counts_block);

    // Query initial description to get first snapshot
    _ = NStatSourceQueryDescription(source);

    // Try to query counts (available on macOS 14+)
    // This may fail on older versions, but that's okay
    _ = NStatSourceQueryCounts(source);
}

// Initializes the global NetworkStatistics manager once
// Pre-sizes maps to reduce rehashing, registers blocks and subscribes
// all TCP/UDP sources (filters set to 0 = no filtering)
pub fn initNetworkStats(allocator: std.mem.Allocator) !void {
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    if (g_network_stats != null) return;

    const manager = try allocator.create(NetworkStatsManager);
    errdefer allocator.destroy(manager);

    manager.* = NetworkStatsManager{
        .allocator = allocator,
        .stats_map = std.AutoHashMap(i32, ProcessNetworkStats).init(allocator),
        .socket_map = std.AutoHashMap(Uuid16, SocketStats).init(allocator),
        .manager = undefined,
        .source_added_block = undefined,
    };

    errdefer manager.stats_map.deinit();
    errdefer manager.socket_map.deinit();

    // Presized to reduce rehash churn
    try manager.stats_map.ensureTotalCapacity(512);
    try manager.socket_map.ensureTotalCapacity(4096);

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

// Tears down the global manager and releases retained blocks/CF objecsts
pub fn deinitNetworkStats() void {
    g_stats_mutex.lock();

    defer g_stats_mutex.unlock();

    if (g_network_stats) |manager| {
        manager.deinit();
        g_network_stats = null;
    }
}

// Returns the current accumulated stats for a PID. If no activity has been
// observed for pid, returns a zeroed struct. Errors if the manager is unset
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

// Remove sockets that have not been seen for max_age_ns. This keeps the
// per-socket baseline table bounded, per-process totals remain intact
pub fn sweepStaleSocketStats(max_age_ns: u64) void {
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return;
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());

    var to_remove = std.ArrayList(Uuid16).init(manager.allocator);
    defer to_remove.deinit();
    to_remove.ensureTotalCapacity(manager.socket_map.count()) catch {};

    var iter = manager.socket_map.iterator();
    while (iter.next()) |entry| {
        if (now_ns - entry.value_ptr.last_seen_ns > max_age_ns) {
            to_remove.append(entry.key_ptr.*) catch {};
        }
    }

    for (to_remove.items) |key| {
        _ = manager.socket_map.remove(key);
    }
}

// Returns a snapshot array of all per-PID aggragtes. Caller owns the slice
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

const Uuid16 = [16]u8;

// Hex nibble helper for UUID parsing
fn hexNibble(cu: u8) ?u8 {
    return switch (cu) {
        '0'...'9' => cu - '0',
        'a'...'f' => cu - 'a' + 10,
        'A'...'F' => cu - 'A' + 10,
        else => null,
    };
}

// Parses a UUID with or without dashes into 16 raw bytes
// Returns null if the string is malformed
fn parseUuid16(s: []const u8) ?Uuid16 {
    var out: Uuid16 = undefined;
    var i: usize = 0;
    var j: usize = 0;

    while (i < s.len and j < 16) {
        if (s[i] == '-') {
            i += 1;
            continue;
        }

        if (i + 1 >= s.len) return null;
        const hi = hexNibble(s[i]) orelse return null;
        const lo = hexNibble(s[i + 1]) orelse return null;
        out[j] = (hi << 4) | lo;
        j += 1;
        i += 2;
    }
    if (j != 16) return null;
    while (i < s.len) : (i += 1) if (s[i] != '-') return null;
    return out;
}
