const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("libproc.h");
    @cInclude("sys/proc_info.h");
    @cInclude("sys/sysctl.h");
    @cInclude("errno.h");
});

pub const SysctlError = error{
    SystemResources,
    PermissionDenied,
    InvalidArgument,
    UnknownError,
};

pub fn getAllPids(allocator: std.mem.Allocator) ![]i32 {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_PROC, c.KERN_PROC_ALL, 0 };
    var size: usize = 0;

    if (c.sysctl(&mib, mib.len, null, &size, null, 0) != 0) {
        return errno_to_error();
    }

    const buffer = try allocator.alloc(u8, size);
    defer allocator.free(buffer);

    if (c.sysctl(&mib, mib.len, buffer.ptr, &size, null, 0) != 0) {
        return errno_to_error();
    }

    const proc_size = @sizeOf(c.struct_kinfo_proc);
    const proc_count = size / proc_size;

    var pids = try allocator.alloc(i32, proc_count);
    errdefer allocator.free(pids);

    var valid_count: usize = 0;
    var i: usize = 0;

    while (i < proc_count) : (i += 1) {
        const proc = @as(*c.struct_kinfo_proc, @ptrCast(@alignCast(&buffer[i * proc_size])));
        if (proc.kp_proc.p_pid > 0) {
            pids[valid_count] = proc.kp_proc.p_pid;
            valid_count += 1;
        }
    }

    if (valid_count < proc_count) {
        pids = try allocator.realloc(pids, valid_count);
    }

    return pids;
}

pub fn getProcessInfo(pid: i32) !c.struct_kinfo_proc {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_PROC, c.KERN_PROC_PID, pid };
    var info: c.struct_kinfo_proc = undefined;
    var size: usize = @sizeOf(c.struct_kinfo_proc);

    if (c.sysctl(&mib, mib.len, &info, &size, null, 0) != 0) {
        return errno_to_error();
    }

    return info;
}

pub fn getCpuCount() !u32 {
    var mib = [_]c_int{ c.CTL_HW, c.HW_NCPU };
    var cpu_count: c_int = 0;
    var size: usize = @sizeOf(c_int);

    if (c.sysctl(&mib, mib.len, &cpu_count, &size, null, 0) != 0) {
        return errno_to_error();
    }

    return @intCast(cpu_count);
}

pub fn getMemorySize() !u64 {
    var mib = [_]c_int{ c.CTL_HW, c.HW_MEMSIZE };
    var mem_size: u64 = 0;
    var size: usize = @sizeOf(u64);

    if (c.sysctl(&mib, mib.len, &mem_size, &size, null, 0) != 0) {
        return errno_to_error();
    }

    return mem_size;
}

pub fn getBootTime() !i64 {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_BOOTTIME };
    var boot_time: c.struct_timeval = undefined;
    var size: usize = @sizeOf(c.struct_timeval);

    if (c.sysctl(&mib, mib.len, &boot_time, &size, null, 0) != 0) {
        return errno_to_error();
    }

    return boot_time.tv_sec;
}

fn errno_to_error() SysctlError {
    return switch (c.__error()) {
        c.ENOMEM => SysctlError.SystemResources,
        c.EPERM => SysctlError.PermissionDenied,
        c.EINVAL => SysctlError.InvalidArgument,
        else => SysctlError.UnknownError,
    };
}

test "get all PIDs" {
    const allocator = std.testing.allocator;
    const pids = try getAllPids(allocator);
    defer allocator.free(pids);

    // Should have at least one process (ourselves)
    try std.testing.expect(pids.len >= 1);

    // Should contain our own PID
    const our_pid = std.c.getpid();
    var found = false;
    for (pids) |pid| {
        if (pid == our_pid) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "get CPU count" {
    const cpu_count = try getCpuCount();
    try std.testing.expect(cpu_count > 0);
}

test "get memory size" {
    const mem_size = try getMemorySize();
    try std.testing.expect(mem_size > 0);
}
