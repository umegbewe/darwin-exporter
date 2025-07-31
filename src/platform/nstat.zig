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

extern "c" fn NStatSourceSetDescriptionBlock(
    source: NStatSourceRef,
    block: *anyopaque,
) void;

extern "c" fn NStatSourceQueryDescription(
    source: NStatSourceRef,
) c.CFDictionaryRef;

// NetworkStatistics.framework keys
extern "c" const kNStatSrcKeyPID: c.CFStringRef;
extern "c" const kNStatSrcKeyProcessName: c.CFStringRef;
extern "c" const kNStatSrcKeyRxBytes: c.CFStringRef;
extern "c" const kNStatSrcKeyTxBytes: c.CFStringRef;
extern "c" const kNStatSrcKeyRxPackets: c.CFStringRef;
extern "c" const kNStatSrcKeyTxPackets: c.CFStringRef;
extern "c" const kNStatSrcKeyProvider: c.CFStringRef;

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

// Block signatures for NetworkStatistics callbacks
const SourceAddedBlock = objc.Block(
    struct {},
    .{ NStatSourceRef, ?*anyopaque },
    void
);

const DescriptionBlock = objc.Block(
    struct {},
    .{c.CFDictionaryRef},
    void
);

var g_network_stats: ?*NetworkStatsManager = null;
var g_stats_mutex = std.Thread.Mutex{};

const NetworkStatsManager = struct {
    allocator: std.mem.Allocator,
    stats_map: std.AutoHashMap(i32, ProcessNetworkStats),
    manager: NStatManagerRef,
    source_added_block: SourceAddedBlock.Context,
    description_blocks: std.ArrayList(*DescriptionBlock.Context),

    pub fn deinit(self: *NetworkStatsManager) void {
        for (self.description_blocks.items) |block| {
            DescriptionBlock.release(block);
        }

        self.description_blocks.deinit();

        self.stats_map.deinit();
        // We don't need to release source_added_block since it's stack allocated
        // and copied by the runtime
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
    if (str == null) return allocator.dupe(u8, "<unknown");

    var buffer: [256]u8 = undefined;

    const success = c.CFStringGetCString(@ptrCast(str), &buffer, buffer.len, c.kCFStringEncodingUTF8);

    if (success == 0) return allocator.dupe(u8, "<unknown");

    const len = std.mem.indexOfScalar(u8, &buffer, 0) orelse buffer.len;
    return allocator.dupe(u8, buffer[0..len]);
}

// Description callback that gets network stats
fn descriptionCallbackImpl(ctx: *const DescriptionBlock.Context, dict: c.CFDictionaryRef) callconv(.C) void {
    _ = ctx;
    g_stats_mutex.lock();
    defer g_stats_mutex.unlock();

    const manager = g_network_stats orelse return;

    const pid_raw = getCFNumberValue(dict, kNStatSrcKeyPID);
    if (pid_raw == 0) return;

    const pid: i32 = @intCast(pid_raw);
    const stats = ProcessNetworkStats{
        .pid = pid,
        .rx_bytes = getCFNumberValue(dict, kNStatSrcKeyRxBytes),
        .tx_bytes = getCFNumberValue(dict, kNStatSrcKeyTxBytes),
        .rx_packets = getCFNumberValue(dict, kNStatSrcKeyRxPackets),
        .tx_packets = getCFNumberValue(dict, kNStatSrcKeyTxPackets),
    };

    manager.stats_map.put(pid, stats) catch |err| {
        std.log.debug("Failed to update network stats for PID {}: {s}", .{ pid, @errorName(err) });
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

    NStatSourceSetDescriptionBlock(source, @ptrCast(desc_block));

    // Query initial description to get first snapshot
    _ = NStatSourceQueryDescription(source);
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
        .manager = undefined,
        .source_added_block = undefined,
        .description_blocks = std.ArrayList(*DescriptionBlock.Context).init(allocator),

    };

    errdefer manager.stats_map.deinit();
    errdefer manager.description_blocks.deinit();

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
