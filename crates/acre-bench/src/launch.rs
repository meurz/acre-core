//! Run a child process on a hidden desktop and measure elapsed time, peak memory, and CPU time.
//!
//! Child windows are created on a separate WinSta0\acre-bench desktop.
//! On timeout, terminate only the process launched by this module.

use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX};
use windows::Win32::System::StationsAndDesktops::{CloseDesktop, CreateDesktopW, DESKTOP_CONTROL_FLAGS};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess, GetProcessTimes,
    PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

/// Measurements from one process launch.
#[derive(Serialize, Default, Clone, Debug)]
pub struct Measured {
    pub command: String,
    pub exit_code: Option<u32>,
    pub timed_out: bool,
    pub wall_ms: f64,
    pub cpu_user_ms: f64,
    pub cpu_kernel_ms: f64,
    pub peak_working_set: u64,
    pub peak_private: u64,
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    // Escape according to CommandLineToArgvW rules.
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

fn ft_ms(ft: FILETIME) -> f64 {
    ((ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64) as f64 / 10_000.0
}

/// Run `exe args` until completion or timeout. Append `raw_tail` verbatim for options such
/// as WizTree exports that require the opening quote immediately after an equals sign.
pub fn run_hidden(exe: &str, args: &[String], raw_tail: &str, timeout: Duration) -> Result<Measured, String> {
    let mut cmdline = quote(exe);
    for a in args {
        cmdline.push(' ');
        cmdline.push_str(&quote(a));
    }
    if !raw_tail.is_empty() {
        cmdline.push(' ');
        cmdline.push_str(raw_tail);
    }
    let desk_name = format!("acre-bench-{}", std::process::id());
    let desk_w = wide(&desk_name);
    let mut station_desk = wide(&format!("WinSta0\\{desk_name}"));
    let exe_w = wide(exe);
    let mut cmd_w = wide(&cmdline);

    // SAFETY: Standard Win32 calls with live NUL-terminated strings; all owned handles are closed.
    unsafe {
        // GENERIC_ALL allows this process and its child to create windows on the new desktop.
        let desk = CreateDesktopW(PCWSTR(desk_w.as_ptr()), PCWSTR::null(), None, DESKTOP_CONTROL_FLAGS(0), 0x1000_0000, None)
            .map_err(|e| format!("CreateDesktopW: {e}"))?;
        let si = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(station_desk.as_mut_ptr()),
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: 0, // SW_HIDE
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let t0 = Instant::now();
        let created = CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            Some(PWSTR(cmd_w.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        );
        if let Err(e) = created {
            let _ = CloseDesktop(desk);
            return Err(format!("CreateProcessW {cmdline}: {e}"));
        }
        let ms = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
        let wait = WaitForSingleObject(pi.hProcess, ms);
        let mut timed_out = false;
        if wait == WAIT_TIMEOUT {
            timed_out = true;
            let _ = TerminateProcess(pi.hProcess, 0xDEAD);
            let _ = WaitForSingleObject(pi.hProcess, 10_000);
        } else if wait != WAIT_OBJECT_0 {
            let _ = TerminateProcess(pi.hProcess, 0xDEAD);
        }
        let wall = t0.elapsed();

        let mut code = 0u32;
        let exit_code = GetExitCodeProcess(pi.hProcess, &mut code).ok().map(|_| code);
        let mut mem = PROCESS_MEMORY_COUNTERS_EX {
            cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..Default::default()
        };
        let _ = GetProcessMemoryInfo(
            pi.hProcess,
            &mut mem as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
            mem.cb,
        );
        let (mut c, mut x, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        let _ = GetProcessTimes(pi.hProcess, &mut c, &mut x, &mut k, &mut u);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseDesktop(desk);
        Ok(Measured {
            command: cmdline,
            exit_code,
            timed_out,
            wall_ms: wall.as_secs_f64() * 1000.0,
            cpu_user_ms: ft_ms(u),
            cpu_kernel_ms: ft_ms(k),
            peak_working_set: mem.PeakWorkingSetSize as u64,
            peak_private: mem.PeakPagefileUsage as u64,
        })
    }
}

/// Peak process memory: `(working set, private commit)`.
pub fn self_peak_memory() -> (u64, u64) {
    use windows::Win32::System::Threading::GetCurrentProcess;
    let mut mem = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    // SAFETY: Uses the current-process pseudo-handle and a correctly sized output structure.
    unsafe {
        let _ = GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut mem as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
            mem.cb,
        );
    }
    (mem.PeakWorkingSetSize as u64, mem.PeakPagefileUsage as u64)
}

/// Current private committed bytes.
pub fn self_private_bytes() -> u64 {
    use windows::Win32::System::Threading::GetCurrentProcess;
    let mut mem = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    // SAFETY: Uses the current-process pseudo-handle and a correctly sized output structure.
    unsafe {
        let _ = GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut mem as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
            mem.cb,
        );
    }
    mem.PrivateUsage as u64
}
