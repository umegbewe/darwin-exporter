const std = @import("std");

// A tiny generation-based cache with mark-and-sweep semantics.
// Call beginRound() before a scan, touch entries via get/put,
// then sweep() to drop untouched entries.
pub fn Cache(comptime Key: type, comptime Value: type, comptime deinitFn: ?fn (std.mem.Allocator, Value) void) type {
    return struct {
        const Self = @This();
        const Entry = struct { value: Value, gen: u32 = 0 }; // gen marks last-touch round

        cache: std.AutoHashMap(Key, Entry),
        allocator: std.mem.Allocator,
        gen: u32 = 0,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .cache = std.AutoHashMap(Key, Entry).init(allocator), .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            if (deinitFn) |val| {
                var iter = self.cache.iterator();
                while (iter.next()) |entry| val(self.allocator, entry.value_ptr.value);
            }
            self.cache.deinit();
        }

        pub fn beginRound(self: *Self) void {
            // Advances the "current" generation; touches will be updated.
            self.gen += 1;
        }

        pub fn sweep(self: *Self) void {
            var to_remove = std.ArrayList(Key).init(self.allocator);
            defer to_remove.deinit();

            var it = self.cache.iterator();

            while (it.next()) |e| {
                if (e.value_ptr.gen != self.gen) {
                    to_remove.append(e.key_ptr.*) catch {};
                }
            }

            if (deinitFn) |f| {
                for (to_remove.items) |k| {
                    if (self.cache.fetchRemove(k)) |kv| {
                        f(self.allocator, kv.value.value);
                    }
                }
            } else {
                for (to_remove.items) |k| _ = self.cache.remove(k);
            }
        }

        pub fn get(self: *Self, key: Key) ?Value {
            // Touch on read so the entry survives the next sweep()
            if (self.cache.getPtr(key)) |entry| {
                entry.gen = self.gen;
                return entry.value;
            }
            return null;
        }

        pub fn put(self: *Self, key: Key, value: Value) !void {
            // Inserts/updates at the current generation
            try self.cache.put(key, .{ .value = value, .gen = self.gen });
        }
    };
}
