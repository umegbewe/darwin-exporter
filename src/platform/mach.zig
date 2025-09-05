const std = @import("std");
const c = @cImport({
    @cInclude("mach/mach.h");
    @cInclude("mach/mach_time.h");
    @cInclude("mach/task_info.h");
    @cInclude("mach/thread_info.h");
    @cInclude("mach/thread_act.h");
});

// Minimal helpers over Mach APIs
// Notes:
// task_for_pid commonly fails with KERN_FAILURE/KERN_PROTECTION_FAILURE
// for other PIDs without entitlements we surface that as AccessDenied
//
// The CPU "percent" calculation below is a coarse heuristic derived from cumulative
// thread times (not wall-clock-normalized). The production collector uses the
// proc_info path for rate calculations, this Mach path is kept for testing
// and experimentation.

pub const MachError = error{
    InvalidTask,
    InvalidThread,
    KernelError,
    AccessDenied,
};

pub const CpuUsage = struct { user_time: u64, system_time: u64, percent: f64 };

pub fn getTaskCpuInfo(pid: i32) !CpuUsage {
    var task: c.mach_port_t = undefined;

    const kr = c.task_for_pid(c.mach_task_self(), pid, &task);
    if (kr != c.KERN_SUCCESS) {
        return MachError.AccessDenied;
    }

    defer _ = c.mach_port_deallocate(c.mach_task_self(), task);

    // Basic task info (resident/virtual not needed here, but this call verifies access)
    var task_info_data: c.mach_task_basic_info_data_t = undefined;
    var task_info_count: c.mach_msg_type_number_t = c.MACH_TASK_BASIC_INFO_COUNT;

    const result = c.task_info(
        task,
        c.MACH_TASK_BASIC_INFO,
        @ptrCast(&task_info_data),
        &task_info_count,
    );

    if (result != c.KERN_SUCCESS) {
        return MachError.KernelError;
    }

    var total_user: u64 = 0;
    var total_system: u64 = 0;

    var thread_list: c.thread_act_array_t = undefined;
    var thread_count: c.mach_msg_type_number_t = undefined;

    const thread_result = c.task_threads(task, &thread_list, &thread_count);
    if (thread_result != c.KERN_SUCCESS) {
        return MachError.KernelError;
    }

    defer _ = c.vm_deallocate(
        c.mach_task_self(),
        @intFromPtr(thread_list),
        @sizeOf(c.thread_act_t) * thread_count,
    );

    var i: usize = 0;
    while (i < thread_count) : (i += 1) {
        var thread_info_data: c.thread_basic_info_data_t = undefined;
        var thread_info_count: c.mach_msg_type_number_t = c.THREAD_BASIC_INFO_COUNT;

        const thread_result2 = c.thread_info(
            thread_list[i],
            c.THREAD_BASIC_INFO,
            @ptrCast(&thread_info_data),
            &thread_info_count,
        );

        if (thread_result2 == c.KERN_SUCCESS) {
            total_user += @as(u64, @intCast(thread_info_data.user_time.seconds)) * 1_000_000 +
                @as(u64, @intCast(thread_info_data.user_time.microseconds));
            total_system += @as(u64, @intCast(thread_info_data.system_time.seconds)) * 1_000_000 +
                @as(u64, @intCast(thread_info_data.system_time.microseconds));
        }
    }

    const total_time = total_user + total_system;
    // Heuristic "percentage" from cumulative microseconds; bounded to [0,100].
    // This is not comparable to the exporter’s rate-based value.
    const cpu_percent = if (total_time > 0)
        @as(f64, @floatFromInt(total_time)) / 10_000.0
    else
        0.0;

    return CpuUsage{
        .user_time = total_user,
        .system_time = total_system,
        .percent = @min(100.0, cpu_percent),
    };
}

pub const MemoryInfo = struct { resident_size: u64, virtual_size: u64 };

pub fn getTaskMemoryInfo(pid: i32) !MemoryInfo {
    var task: c.mach_port_t = undefined;

    const kr = c.task_for_pid(c.mach_task_self(), pid, &task);
    if (kr != c.KERN_SUCCESS) {
        return MachError.AccessDenied;
    }

    defer _ = c.mach_port_deallocate(c.mach_task_self(), task);

    var task_info_data: c.mach_task_basic_info_data_t = undefined;
    var task_info_count: c.mach_msg_type_number_t = c.MACH_TASK_BASIC_INFO_COUNT;

    const result = c.task_info(
        task,
        c.MACH_TASK_BASIC_INFO,
        @ptrCast(&task_info_data),
        &task_info_count,
    );

    if (result != c.KERN_SUCCESS) {
        return MachError.KernelError;
    }

    return MemoryInfo{
        .resident_size = task_info_data.resident_size,
        .virtual_size = task_info_data.virtual_size,
    };
}

/// Converts a Mach absolute time tick count to nanoseconds.
/// this function eturns a monotonically increasing tick value whose
/// units are hardware/OS dependent. `mach_timebase_info()` supplies a rational
/// conversion factor:
///
///     real_nanoseconds = mach_time * numer / denom
///
/// where `numer`/`denom` describe how many nanoseconds each tick represents.
/// This function queries that factor and applies it.
/// Notes:
/// * `mach_timebase_info()` always succeeds and is cheap
pub fn machTimeToNs(mach_time: u64) u64 {
    var timebase_info: c.mach_timebase_info_data_t = undefined;
    _ = c.mach_timebase_info(&timebase_info);

    return (mach_time * timebase_info.numer) / timebase_info.denom;
}

pub fn getMachTime() u64 {
    return c.mach_absolute_time();
}

test "get CPU info for current process" {
    const pid = std.c.getpid();
    const cpu_info = try getTaskCpuInfo(pid);

    // Should have some CPU time
    try std.testing.expect(cpu_info.user_time > 0 or cpu_info.system_time > 0);
    try std.testing.expect(cpu_info.percent >= 0.0);
    try std.testing.expect(cpu_info.percent <= 100.0);
}

test "get memory info for current process" {
    const pid = std.c.getpid();
    const mem_info = try getTaskMemoryInfo(pid);

    std.debug.print("Memory Info:\n", .{});
    std.debug.print("  resident_size: {}\n", .{mem_info.resident_size});
    std.debug.print("  virtual_size: {}\n", .{mem_info.virtual_size});

    // Should have some memory usage
    try std.testing.expect(mem_info.resident_size > 0);
    try std.testing.expect(mem_info.virtual_size > 0);
    try std.testing.expect(mem_info.virtual_size >= mem_info.resident_size);
}
