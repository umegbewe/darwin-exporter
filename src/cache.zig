const std = @import("std");

pub fn Cache(comptime Key: type, comptime Value: type, comptime deinitFn: ?fn (std.mem.Allocator, Value) void) type {
    return struct {
        const Self = @This();
        const Entry = struct { value: Value, gen: u32 = 0 };

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
            self.gen += 1;
        }

        pub fn sweep(self: *Self) void {
            var iter = self.cache.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.gen != self.gen) {
                    _ = self.cache.remove(entry.key_ptr.*);
                }
            }
        }

        pub fn get(self: *Self, key: Key) ?Value {
            if (self.cache.getPtr(key)) |entry| {
                entry.gen = self.gen;
                return entry.value;
            }
            return null;
        }

        pub fn put(self: *Self, key: Key, value: Value) !void {
            try self.cache.put(key, .{ 
                .value = value, 
                .gen = self.gen 
            });
        }
    };
}
