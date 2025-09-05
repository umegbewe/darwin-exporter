const std = @import("std");

pub const HandlerFn = *const fn (context: *anyopaque, req: *std.http.Server.Request, target: []const u8) anyerror![]const u8;

const Route = struct {
    path: []const u8,
    handler: HandlerFn,
    context: *anyopaque,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    bind_address: []const u8,
    port: u16,
    routes: std.ArrayList(Route),

    pub fn init(allocator: std.mem.Allocator, bind_address: []const u8, port: u16) !Server {
        return Server{
            .allocator = allocator,
            .bind_address = bind_address,
            .port = port,
            .routes = std.ArrayList(Route).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        self.routes.deinit();
    }

    pub fn addRoute(self: *Server, path: []const u8, handler: HandlerFn, context: *anyopaque) !void {
        try self.routes.append(.{
            .path = path,
            .handler = handler,
            .context = context,
        });
    }

    pub fn run(self: *Server) !void {
        const address = try std.net.Address.parseIp4(self.bind_address, self.port);
        var server = try address.listen(.{
            .reuse_address = true
        });
        defer server.deinit();

        std.log.info("listening on {s}:{d}", .{ self.bind_address, self.port });

        while (true) {
            var conn = try server.accept();
            defer conn.stream.close();

            var read_buffer: [4096]u8 = undefined;
            var http_server = std.http.Server.init(conn, &read_buffer);

            var request = http_server.receiveHead() catch |err| switch (err) {
                error.HttpConnectionClosing => continue,
                else => {
                    std.log.err("error receiving head: {}", .{err});
                    continue;
                },
            };

            const prom_headers = [_]std.http.Header{
                .{ .name = "Content-Type", .value = "text/plain; version=0.0.4; charset=utf-8" },
            };

            var matched: ?*const Route = null;
            for (self.routes.items) |*r| {
                if (std.mem.eql(u8, request.head.target, r.path)) {
                    matched = r;
                    break;
                }
            }

            if (matched) |r| {
                const response_body = r.handler(r.context, &request, request.head.target) catch |err| {
                    std.log.err("handler error: {}", .{err});
                    request.respond("Internal Server Error", .{
                        .status = .internal_server_error,
                        .extra_headers = &prom_headers,
                    }) catch {};
                    continue;
                };
                request.respond(response_body, .{
                    .status = .ok,
                    .extra_headers = &prom_headers,
                }) catch |err| {
                    std.log.err("respond error: {}", .{err});
                };
            } else {
                request.respond("Not Found", .{
                    .status = .not_found,
                    .extra_headers = &prom_headers,
                }) catch |err| {
                    std.log.err("respond error: {}", .{err});
                };
            }
        }
    }
};
