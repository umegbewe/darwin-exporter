const std = @import("std");
const builtin = @import("builtin");

pub const config = @import("config.zig");
pub const process = @import("process.zig");
pub const metrics = @import("metrics.zig");
pub const server = @import("server.zig");

pub const Config = config.Config;
pub const ProcessInfo = config.ProcessInfo;
pub const ProcessState = config.ProcessState;
pub const MetricType = config.MetricType;
pub const ProcessCollector = process.ProcessCollector;
pub const MetricsFormatter = metrics.MetricsFormatter;
pub const Server = server.Server;

pub const Error = error{
    SystemError,
    PermissionDenied,
    ProcessNotFound,
    UnsupportedPlatform,
    ConfigurationError,
    ServerError,
    SystemResources,
    InvalidArgument,
    UnknownError,
    TimerUnsupported,
    CreateManagerFailed,
    AddTCPFailed,
    AddUDPFailed,
    InvalidPID,
} || std.mem.Allocator.Error;

pub fn init() Error!void {
    if (builtin.os.tag != .macos) {
        return Error.UnsupportedPlatform;
    }
}

pub fn createExporter(allocator: std.mem.Allocator, cfg: Config) Error!*Exporter {
    const exporter = try allocator.create(Exporter);
    exporter.* = Exporter{
        .allocator = allocator,
        .config = cfg,
        .collector = try ProcessCollector.init(allocator, cfg),
        .formatter = MetricsFormatter.init(allocator),
        .server = null,
    };
    return exporter;
}

pub const Exporter = struct {
    allocator: std.mem.Allocator,
    config: Config,
    collector: ProcessCollector,
    formatter: MetricsFormatter,
    server: ?Server,

    pub fn deinit(self: *Exporter) void {
        if (self.server) |*srv| {
            srv.deinit();
        }
        self.formatter.deinit();
        self.collector.deinit();
        self.allocator.destroy(self);
    }

    pub fn startServer(self: *Exporter) anyerror!void {
        self.server = try Server.init(
            self.allocator,
            self.config.bind_address,
            self.config.port,
        );

        const srv = &self.server.?;
        try srv.addRoute(self.config.metrics_path, metricsHandler, self);
        try srv.run();
    }

    pub fn collectOnce(self: *Exporter) anyerror![]const u8 {
        const processes = try self.collector.collect();
        defer self.collector.freeProcessList(processes);

        return try self.formatter.format(processes, self.config);
    }

    pub fn run(self: *Exporter) anyerror!void {
        if (self.server == null) {
            try self.startServer();
        }

        var timer = try std.time.Timer.start();

        while (true) {
            _ = self.collectOnce() catch |err| {
                std.log.err("Failed to collect metrics: {s}", .{@errorName(err)});
            };

            // Wait for next collection interval
            const elapsed = timer.read();
            const interval_ns = self.config.collection_interval * std.time.ns_per_s;
            if (elapsed < interval_ns) {
                std.time.sleep(interval_ns - elapsed);
            }
            timer.reset();
        }
    }
};

fn metricsHandler(context: *anyopaque, req: *std.http.Server.Request, target: []const u8) anyerror![]const u8 {
    _ = req;
    _ = target;

    const exporter = @as(*Exporter, @ptrCast(@alignCast(context)));
    return try exporter.collectOnce();
}

test "exporter library initialization" {
    if (builtin.os.tag == .macos) {
        try init();
    } else {
        try std.testing.expectError(Error.UnsupportedPlatform, init());
    }
}

test "exporter creation" {
    if (builtin.os.tag != .macos) return;

    const allocator = std.testing.allocator;
    const cfg = Config{};

    const exporter = try createExporter(allocator, cfg);
    defer exporter.deinit();

    try std.testing.expect(exporter.config.port == 9256);
}
