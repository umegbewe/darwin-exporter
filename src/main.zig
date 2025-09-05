const std = @import("std");
const posix = std.posix;
const darwin_exporter = @import("lib.zig");
const Config = darwin_exporter.Config;
const build_options = @import("build_options");
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config = Config{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }
            config.port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--bind") or std.mem.eql(u8, arg, "-b")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }
            config.bind_address = args[i];
        } else if (std.mem.eql(u8, arg, "--path")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }
            config.metrics_path = args[i];
        } else if (std.mem.eql(u8, arg, "--interval") or std.mem.eql(u8, arg, "-i")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }
            config.collection_interval = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--include-pattern")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }

            var patterns = try allocator.alloc([]const u8, 1);
            patterns[0] = args[i];
            config.include_patterns = patterns;
        } else if (std.mem.eql(u8, arg, "--exclude-pattern")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }

            var patterns = try allocator.alloc([]const u8, 1);
            patterns[0] = args[i];
            config.exclude_patterns = patterns;
        } else if (std.mem.eql(u8, arg, "--no-threads")) {
            config.include_threads = false;
        } else if (std.mem.eql(u8, arg, "--no-fd")) {
            config.collect_fd = false;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printUsage();
            return;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            try printVersion();
            return;
        } else {
            std.log.err("Unknown argument: {s}", .{arg});
            try printUsage();
            return;
        }
    }

    try darwin_exporter.init();

    std.log.info("Metrics available at http://{s}:{d}{s}", .{ config.bind_address, config.port, config.metrics_path });

    const exporter = try darwin_exporter.createExporter(allocator, config);
    defer exporter.deinit();

    try setupSignalHandlers();

    try exporter.run();
}

fn printUsage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print(
        \\Usage: darwin-exporter [OPTIONS]
        \\
        \\ macOS/darwin process exporter for Prometheus
        \\
        \\OPTIONS:
        \\  -p, --port PORT              Port to listen on (default: 1053)
        \\  -b, --bind ADDRESS           Address to bind to (default: 0.0.0.0)
        \\      --path PATH              Metrics endpoint path (default: /metrics)
        \\  -i, --interval SECONDS       Collection interval (default: 15)
        \\      --include-pattern REGEX  Include processes matching pattern
        \\      --exclude-pattern REGEX  Exclude processes matching pattern
        \\      --no-threads             Don't include thread counts
        \\      --no-fd                  Don't collect file descriptor counts
        \\  -h, --help                   Show this help message
        \\  -v, --version                Show version information
        \\
        \\EXAMPLES:
        \\  # Run with default settings
        \\  darwin-exporter
        \\
        \\  # Custom port and include only nginx processes
        \\  darwin-exporter --port 9257 --include-pattern nginx
        \\
        \\  # Exclude kernel processes and use custom interval
        \\  darwin-exporter --exclude-pattern "^kernel" --interval 30
        \\
    , .{});
}

fn printVersion() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("darwin-exporter version {s}\n", .{build_options.version});
}

fn setupSignalHandlers() !void {
    var sa = posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = posix.empty_sigset,
        .flags = 0,
    };

    posix.sigaction(posix.SIG.INT, &sa, null);
    posix.sigaction(posix.SIG.TERM, &sa, null);
}

fn handleSignal(sig: c_int) callconv(.C) void {
    _ = sig;
    std.log.info("Received shutdown signal, exiting...", .{});
    std.process.exit(0);
}
