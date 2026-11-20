//! Жизненный цикл программы: что настраиваем при старте и откатываем при выходе.
//!
//! Старт:  синкхол ответил на :53  ->  DNS ПК (Wi-Fi) = 127.0.0.1 и ::1
//! Выход:  DNS ПК -> автоматически (DHCP)  ->  убить синкхол  ->  exit
//!
//! Выход ловим системным обработчиком консоли (Ctrl+C, закрытие окна, выход
//! из системы, выключение ПК) и делаем откат синхронно — при закрытии окна
//! Windows даёт всего ~5 секунд.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use crate::sinkhole::log_main;
use crate::win::{self, Job};

/// Интерфейс, через который ПК ходит в интернет (Wi-Fi бара).
const WIFI_IF: &str = "Wi-Fi";

/// «Чёрный ящик»: файл есть, пока DNS переключён на синкхол.
/// Остался после старта -> прошлый запуск завершился аварийно.
const MARKER: &str = "socks5.dns_switched";

/// Выставляется в начале остановки: супервизор не перезапускает синкхол.
pub static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
/// Меняли ли мы DNS (откатываем только то, что меняли сами).
static DNS_SET: AtomicBool = AtomicBool::new(false);
static JOB: OnceLock<Option<Job>> = OnceLock::new();

/// Job Object для дочерних процессов (создаётся при первом обращении).
pub fn job() -> Option<&'static Job> {
    JOB.get_or_init(Job::new).as_ref()
}

pub fn install_handler() {
    win::set_ctrl_handler(on_ctrl);
}

fn on_ctrl(kind: u32) {
    let reason = match kind {
        0 => "Ctrl+C",
        1 => "Ctrl+Break",
        2 => "закрытие окна",
        5 => "выход из системы",
        6 => "выключение ПК",
        _ => "сигнал остановки",
    };
    shutdown(reason);
}

/// Аккуратная остановка: откат настроек, остановка детей, выход.
pub fn shutdown(reason: &str) -> ! {
    if SHUTTING_DOWN.swap(true, SeqCst) {
        // Повторный сигнал во время остановки — первый поток сам завершит процесс.
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    println!();
    log_main(&format!("получен сигнал: {reason} — завершаю работу"));
    restore_dns();
    if let Some(j) = job() {
        log_main("останавливаю дочерний процесс (синкхол)...");
        j.terminate();
        log_main("синкхол остановлен");
    }
    // При Ctrl+C окно остаётся открытым — дадим прочитать лог.
    // (При закрытии окна крестиком ждать бессмысленно.)
    if reason.starts_with("Ctrl") {
        log_main("выход через 3 секунды...");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_secs(3));
    } else {
        log_main("выход");
    }
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

/// Ждём, пока синкхол начнёт отвечать на 127.0.0.1:53.
pub async fn wait_sinkhole(timeout: Duration) -> bool {
    // Минимальный DNS-запрос: example.com, тип A.
    let mut q = vec![0x51, 0x7a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(s) = UdpSocket::bind("127.0.0.1:0").await {
            if s.send_to(&q, "127.0.0.1:53").await.is_ok() {
                let mut buf = [0u8; 512];
                // Ошибка (порт закрыт) или таймаут — значит, ещё не готов.
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(500), s.recv(&mut buf)).await
                {
                    if n >= 12 && buf[0] == 0x51 && buf[1] == 0x7a {
                        return true;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    false
}

/// Переходим в папку со списками доменов. Программу могут запустить откуда
/// угодно (панель задач -> рабочая папка target\release), поэтому ищем:
/// текущая папка, папка exe, корень проекта (exe лежит в target\release).
/// Дочерний синкхол наследует эту папку.
pub fn choose_workdir() {
    let mut cands = Vec::new();
    if let Ok(c) = std::env::current_dir() {
        cands.push(c);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            cands.push(dir.to_path_buf());
            if let Some(root) = dir.parent().and_then(|p| p.parent()) {
                cands.push(root.to_path_buf());
            }
        }
    }
    match cands
        .iter()
        .find(|d| d.join(dns_sinkhole::HOSTS_FILE).exists())
    {
        Some(d) => {
            let _ = std::env::set_current_dir(d);
            log_main(&format!("рабочая папка: {}", d.display()));
        }
        None => log_main(&format!(
            "{} рядом нет — синкхол возьмёт список, вшитый в exe",
            dns_sinkhole::HOSTS_FILE
        )),
    }
}

/// Проверяет, как завершился прошлый запуск. Возвращает true, если DNS ПК
/// до сих пор указывает на синкхол (остался после аварийного выхода).
pub fn check_previous_run() -> bool {
    let marker = marker_path().exists();
    let dns = current_dns();
    let ours = dns
        .as_ref()
        .is_some_and(|d| d.iter().any(|s| s == "127.0.0.1" || s == "::1"));
    let shown = dns
        .map(|d| d.join(", "))
        .unwrap_or_else(|| "не удалось узнать".into());

    if ours {
        log_main(&format!(
            "⚠ DNS ПК уже указывает на синкхол ({shown}) — прошлый запуск \
             завершился аварийно и не вернул DNS"
        ));
        log_main("для нас это и есть нужная настройка — продолжаю; при нормальном выходе верну DNS");
        // Откатим при выходе, даже если переключить заново не получится.
        DNS_SET.store(true, SeqCst);
    } else if marker {
        log_main(&format!(
            "прошлый запуск завершился аварийно, но DNS уже возвращён ({shown})"
        ));
        let _ = std::fs::remove_file(marker_path());
    } else {
        log_main(&format!("DNS ПК в порядке: {shown}"));
    }
    ours
}

/// Синкхол не поднялся, а DNS остался от прошлого аварийного запуска —
/// ПК сейчас без DNS. Возвращаем автоматический режим немедленно.
pub fn recover_dns() {
    log_main("синкхола нет, а DNS ПК указывает на него — возвращаю DNS сейчас, чтобы ПК не остался без интернета");
    restore_dns();
}

/// DNS ПК -> синкхол. Нужны права администратора.
pub fn setup_dns() {
    let name = format!("name={WIFI_IF}");
    let v4 = netsh(&[
        "interface", "ipv4", "set", "dnsservers", &name, "source=static",
        "address=127.0.0.1", "register=none", "validate=no",
    ]);
    let v6 = netsh(&[
        "interface", "ipv6", "set", "dnsservers", &name, "source=static",
        "address=::1", "register=none", "validate=no",
    ]);
    if v4 || v6 {
        DNS_SET.store(true, SeqCst);
        let _ = std::fs::write(
            marker_path(),
            format!("DNS {WIFI_IF} переключён на синкхол процессом PID {}\n", std::process::id()),
        );
    }
    flush_dns();
    if v4 && v6 {
        log_main(&format!("DNS ПК ({WIFI_IF}) -> 127.0.0.1 и ::1 (синкхол)"));
    } else {
        log_main(
            "не смог переключить DNS ПК (нужен запуск от администратора) — \
             реклама будет фильтроваться только встроенным списком прокси",
        );
    }
}

/// DNS ПК -> автоматически (как было до нас).
fn restore_dns() {
    if !DNS_SET.load(SeqCst) {
        return;
    }
    let name = format!("name={WIFI_IF}");
    let v4 = netsh(&["interface", "ipv4", "set", "dnsservers", &name, "source=dhcp"]);
    let v6 = netsh(&["interface", "ipv6", "set", "dnsservers", &name, "source=dhcp"]);
    flush_dns();
    if v4 && v6 {
        DNS_SET.store(false, SeqCst);
        let _ = std::fs::remove_file(marker_path());
        log_main(&format!("DNS ПК ({WIFI_IF}) возвращён в автоматический режим"));
    } else {
        log_main(&format!(
            "НЕ удалось вернуть DNS! Вручную (от админа): \
             Set-DnsClientServerAddress -InterfaceAlias '{WIFI_IF}' -ResetServerAddresses"
        ));
    }
}

/// Метка лежит рядом с exe (не зависит от рабочей папки).
fn marker_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.join(MARKER)))
        .unwrap_or_else(|| PathBuf::from(MARKER))
}

/// Текущие DNS-серверы Wi-Fi (IPv4 и IPv6).
fn current_dns() -> Option<Vec<String>> {
    let cmd = format!(
        "(Get-DnsClientServerAddress -InterfaceAlias '{WIFI_IF}').ServerAddresses -join ','"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
    )
}

fn netsh(args: &[&str]) -> bool {
    Command::new("netsh")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn flush_dns() {
    let _ = Command::new("ipconfig")
        .arg("/flushdns")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
