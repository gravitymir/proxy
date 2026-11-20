//! Немного WinAPI:
//!   * Job Object — убить детей при смерти родителя;
//!   * обработчик консольных сигналов (Ctrl+C, закрытие окна, выключение);
//!   * включение ANSI-цветов в консоли.

use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{BOOL, CloseHandle, HANDLE};
use windows_sys::Win32::System::Console::{
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE,
    SetConsoleCtrlHandler, SetConsoleMode, SetConsoleTitleW,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};

/// Job Object с флагом KILL_ON_JOB_CLOSE. Дескриптор намеренно не закрываем:
/// он живёт до конца процесса, а при выходе (любом) Windows закроет его
/// и завершит все процессы в Job.
pub struct Job(HANDLE);

// HANDLE — просто номер объекта ядра, передавать между потоками безопасно.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    pub fn new() -> Option<Job> {
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of_val(&info) as u32,
            );
            if ok == 0 {
                CloseHandle(h);
                return None;
            }
            Some(Job(h))
        }
    }

    pub fn assign(&self, child: &tokio::process::Child) -> bool {
        match child.raw_handle() {
            Some(p) => unsafe { AssignProcessToJobObject(self.0, p as HANDLE) != 0 },
            None => false,
        }
    }

    /// Немедленно завершает все процессы в Job.
    pub fn terminate(&self) {
        unsafe {
            TerminateJobObject(self.0, 0);
        }
    }
}

static CTRL_FN: OnceLock<fn(u32)> = OnceLock::new();

unsafe extern "system" fn ctrl_handler(kind: u32) -> BOOL {
    if let Some(f) = CTRL_FN.get() {
        f(kind); // выполняется синхронно — Windows ждёт, пока мы не закончим
    }
    1
}

/// Ставит обработчик Ctrl+C / закрытия окна / выхода / выключения.
pub fn set_ctrl_handler(f: fn(u32)) {
    let _ = CTRL_FN.set(f);
    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

/// Заголовок окна консоли.
pub fn set_title(title: &str) {
    let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        SetConsoleTitleW(wide.as_ptr());
    }
}

/// Включает обработку ANSI-цветов в консоли (для старого conhost).
pub fn enable_ansi() {
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(h, &mut mode) != 0 {
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}
