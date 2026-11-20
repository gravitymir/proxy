//! DNS-синкхол как дочерний процесс — это ЭТОТ ЖЕ exe с флагом --sinkhole.
//!
//! * ребёнок стартует без своего окна, его вывод печатается здесь
//!   голубым цветом с отступом;
//! * привязан к Job Object: умирает главный процесс (как угодно, хоть через
//!   диспетчер задач) — Windows убивает и ребёнка, порт 53 не остаётся занятым;
//! * упал сам — перезапуск через 3 секунды.

use std::process::Stdio;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};

use crate::control;

/// Флаг, с которым exe работает в режиме синкхола.
pub const CHILD_FLAG: &str = "--sinkhole";
/// Слушать :53, вышестоящий DNS — роутер бара.
pub const SINKHOLE_LISTEN: &str = "0.0.0.0:53";
pub const SINKHOLE_UPSTREAM: &str = "192.168.1.1:53";

const CHILD_COLOR: &str = "\x1b[36m"; // голубой
const MAIN_COLOR: &str = "\x1b[33m"; // жёлтый
const RESET: &str = "\x1b[0m";
const CHILD_PREFIX: &str = "    │ ";

/// Без консольного окна: ребёнок не получает Ctrl+C сам,
/// его жизнью управляет только главный процесс.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Сообщение главной программы (жёлтым).
pub fn log_main(msg: &str) {
    println!("{MAIN_COLOR}[main] {msg}{RESET}");
}

/// Запускает и сторожит дочерний синкхол.
pub async fn supervise() {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            log_main(&format!("не знаю путь к своему exe ({e}) — работаю без синкхола"));
            return;
        }
    };
    let job = control::job();
    if job.is_none() {
        log_main("не удалось создать Job Object (страховка выключена)");
    }

    loop {
        log_main(&format!(
            "запускаю дочерний процесс: {} {CHILD_FLAG} {SINKHOLE_LISTEN} {SINKHOLE_UPSTREAM}",
            exe.file_name().unwrap_or_default().to_string_lossy()
        ));
        let mut child = match spawn(&exe) {
            Ok(c) => c,
            Err(e) => {
                log_main(&format!("не удалось запустить синкхол: {e}"));
                return;
            }
        };
        let pid = child.id().unwrap_or(0);
        if let Some(j) = job {
            if !j.assign(&child) {
                log_main("не удалось привязать синкхол к Job Object");
            }
        }
        log_main(&format!("синкхол запущен, PID {pid}"));

        let status = child.wait().await;
        if control::SHUTTING_DOWN.load(SeqCst) {
            return; // это мы его остановили
        }
        log_main(&format!(
            "синкхол завершился сам ({}) — перезапуск через 3 с",
            match status {
                Ok(s) => s.to_string(),
                Err(e) => e.to_string(),
            }
        ));
        tokio::time::sleep(Duration::from_secs(3)).await;
        if control::SHUTTING_DOWN.load(SeqCst) {
            return;
        }
    }
}

fn spawn(exe: &std::path::Path) -> std::io::Result<Child> {
    // Рабочая папка наследуется — там должен лежать blocklist_hosts.txt.
    let mut child = Command::new(exe)
        .args([CHILD_FLAG, SINKHOLE_LISTEN, SINKHOLE_UPSTREAM])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(true)
        .spawn()?;
    if let Some(out) = child.stdout.take() {
        tokio::spawn(relay(out));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(relay(err));
    }
    Ok(child)
}

/// Печатает вывод ребёнка построчно: цветом и с отступом.
async fn relay<R: AsyncRead + Unpin>(r: R) {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf);
                println!("{CHILD_COLOR}{CHILD_PREFIX}{}{RESET}", line.trim_end());
            }
        }
    }
}
