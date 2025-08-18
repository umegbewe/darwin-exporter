const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("libproc.h");
    @cInclude("sys/proc_info.h");
    @cInclude("sys/sysctl.h");
    @cInclude("mach/mach.h");
});

// Thin wrappers over libproc/sysctl for per-process inspection.
// These calls are inherently racy, the target process may exit or change
// between queries.
pub const ProcError = error{ InvalidPid, BufferTooSmall, SystemError, AccessDenied };

pub const MaxProcNameLen: usize = @intCast(c.PROC_PIDPATHINFO_MAXSIZE);

pub fn getProcessName(pid: i32, buf: *[MaxProcNameLen]u8) ![]const u8 {
    const ret = c.proc_name(pid, buf, buf.len);
    if (ret <= 0) {
        return ProcError.InvalidPid;
    }

    const name_len = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    return buf[0..name_len];
}

pub fn getProcessPath(allocator: std.mem.Allocator, pid: i32) ![]u8 {
    var path_buf: [c.PROC_PIDPATHINFO_MAXSIZE]u8 = undefined;

    const ret = c.proc_pidpath(pid, &path_buf, path_buf.len);
    if (ret <= 0) {
        return ProcError.InvalidPid;
    }

    return try allocator.dupe(u8, path_buf[0..@intCast(ret)]);
}

pub fn getTaskInfo(pid: i32) !c.struct_proc_taskinfo {
    var info: c.struct_proc_taskinfo = undefined;

    const ret = c.proc_pidinfo(pid, c.PROC_PIDTASKINFO, 0, &info, @sizeOf(c.struct_proc_taskinfo));

    if (ret <= 0) {
        return ProcError.InvalidPid;
    }

    return info;
}

pub fn getTaskInfoWithFallback(pid: i32) !struct { info: ?c.struct_proc_taskinfo, has_full_info: bool } {
    var info: c.struct_proc_taskinfo = undefined;

    const ret = c.proc_pidinfo(pid, c.PROC_PIDTASKINFO, 0, &info, @sizeOf(c.struct_proc_taskinfo));

    if (ret > 0) {
        return .{ .info = info, .has_full_info = true };
    }

    return .{ .info = null, .has_full_info = false };
}

pub fn getBasicInfo(pid: c.pid_t) !c.struct_proc_bsdinfo {
    var info: c.struct_proc_bsdinfo = undefined;
    const ret = c.proc_pidinfo(pid, c.PROC_PIDTBSDINFO, 0, &info, @sizeOf(c.struct_proc_bsdinfo));

    if (ret <= 0) {
        return ProcError.InvalidPid;
    }

    return info;
}

pub fn getRusageInfo(pid: i32) !c.struct_rusage_info_v2 {
    var info: c.struct_rusage_info_v2 = undefined;

    const ret = c.proc_pid_rusage(pid, c.RUSAGE_INFO_V2, @ptrCast(&info));
    if (ret != 0) {
        return ProcError.SystemError;
    }

    return info;
}

pub fn getFdCount(pid: i32) !u32 {
    const size = c.proc_pidinfo(pid, c.PROC_PIDLISTFDS, 0, null, 0);

    if (size <= 0) {
        return ProcError.InvalidPid;
    }

    const count: u32 = @intCast(@as(usize, @intCast(size)) / @sizeOf(c.struct_proc_fdinfo));

    return count;
}

// Reads KERN_PROCARGS2 and reconstructs a space-joined argv string.
// The kernel buffer contains multiple NUL runs we (1) skip the exec path,
// (2) skip NULs until argv[0], then (3) copy argc strings separated by spaces
// 
// This is an expensive call
// Hopefully doesn't make an appearance in getargv hall of shame https://getargv.narzt.cam/hallofshame.html
pub fn getProcessCmdline(allocator: std.mem.Allocator, pid: i32) ![]u8 {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_PROCARGS2, pid };
    var arg_size: usize = 0;
    if (c.sysctl(&mib, mib.len, null, &arg_size, null, 0) != 0 or arg_size < 4) {
        return ProcError.SystemError;
    }

    const buffer = try allocator.alloc(u8, arg_size);
    defer allocator.free(buffer);

    if (c.sysctl(&mib, mib.len, buffer.ptr, &arg_size, null, 0) != 0) {
        return ProcError.SystemError;
    }

    const argc = std.mem.bytesAsValue(u32, buffer[0..4]).*;
    if (argc == 0) return allocator.dupe(u8, "");

    // Some genius thought it was a good idea to dump random NULL's
    // skip ALL nulls between exec path and argv[0]
    // there can be multiple nulls here
    var idx: usize = 4;
    while (idx < arg_size and buffer[idx] != 0) : (idx += 1) {}
    while (idx < arg_size and buffer[idx] == 0) : (idx += 1) {}

    var scan = idx;
    var count: u32 = 0;
    var total: usize = 0;
    while (scan < arg_size and count < argc) {
        const start = scan;
        while (scan < arg_size and buffer[scan] != 0) : (scan += 1) {}
        if (scan > start) {
            total += scan - start;
            count += 1;
        }
        while (scan < arg_size and buffer[scan] == 0) : (scan += 1) {}
    }
    if (count > 1) total += (count - 1);

    var result = try allocator.alloc(u8, total);
    var write_idx: usize = 0;

    scan = idx;
    count = 0;

    while (scan < arg_size and count < argc) {
        const start = scan;
        while (scan < arg_size and buffer[scan] != 0) : (scan += 1) {}
        if (scan > start) {
            if (count > 0) { result[write_idx] = ' '; write_idx += 1; }
            const len = scan - start;
            @memcpy(result[write_idx .. write_idx + len], buffer[start .. scan]);
            write_idx += len;
            count += 1;
        }
        while (scan < arg_size and buffer[scan] == 0) : (scan += 1) {}
    }
    return result;
}

pub fn getThreadCount(pid: i32) !u32 {
    var task: c.mach_port_t = undefined;

    const kr = c.task_for_pid(c.mach_task_self(), pid, &task);
    if (kr != c.KERN_SUCCESS) {
        return ProcError.AccessDenied;
    }

    defer _ = c.mach_port_deallocate(c.mach_task_self(), task);

    var thread_list: c.thread_act_array_t = undefined;
    var thread_count: c.mach_msg_type_number_t = undefined;

    const result = c.task_threads(task, &thread_list, &thread_count);
    if (result != c.KERN_SUCCESS) {
        return ProcError.SystemError;
    }

    defer _ = c.vm_deallocate(
        c.mach_task_self(),
        @intFromPtr(thread_list),
        @sizeOf(c.thread_act_t) * thread_count,
    );

    return thread_count;
}

test "get process name" {
    const allocator = std.testing.allocator;
    const pid = std.c.getpid();

    const name = try getProcessName(allocator, pid);
    defer allocator.free(name);

    // Should get some name
    try std.testing.expect(name.len > 0);
}

test "get process path" {
    const allocator = std.testing.allocator;
    const pid = std.c.getpid();

    const path = try getProcessPath(allocator, pid);
    defer allocator.free(path);

    // Should get a valid path
    try std.testing.expect(path.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, path, "/"));
}

test "get task info" {
    const pid = std.c.getpid();
    const info = try getTaskInfo(pid);

    // Should have some memory usage
    try std.testing.expect(info.pti_resident_size > 0);
    try std.testing.expect(info.pti_virtual_size > 0);
}

test "get fd count" {
    const pid = std.c.getpid();
    const fd_count = try getFdCount(pid);

    // Should have at least stdin, stdout, stderr
    try std.testing.expect(fd_count >= 3);
}

test "get rusage info" {
    const pid = std.c.getpid();
    const rusage = try getRusageInfo(pid);

    try std.testing.expect(rusage.ri_user_time > 0 or rusage.ri_system_time > 0);
}
test "getProcessCmdline returns current process args" {
    const alloc = std.testing.allocator;

    const pid = std.c.getpid();
    const got = try getProcessCmdline(alloc, pid);
    defer alloc.free(got);

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    const expected = try std.mem.join(alloc, " ", args);
    defer alloc.free(expected);

    try std.testing.expect(got.len > 0);
    try std.testing.expectEqualStrings(expected, got);
}
