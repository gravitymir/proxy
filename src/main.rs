//! Мини-прокси на tokio: SOCKS5 (RFC 1928) + HTTP-прокси (CONNECT и обычный HTTP).
//! Понимает оба протокола по первому байту (0x05 => SOCKS5, иначе HTTP).
//!
//! Возможности:
//!   * туннель HTTPS через CONNECT (TLS-байты не трогаем, сертификаты не нужны);
//!   * блокировка доменов (реклама/трекеры) — встроенный список + файл blocklist.txt;
//!   * статистика в реальном времени: скорость в заголовке окна, сводка в логе
//!     (traffic.rs).
//!
//! Идея: прокси сам, от имени этого ПК, ходит в интернет — для внешней сети это
//! обычный трафик компьютера, «подписи раздачи» не остаётся.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod control;
mod dhcp;
mod sinkhole;
mod traffic;
mod update;
mod win;

use sinkhole::log_main;

const LISTEN: &str = "0.0.0.0:1080";

/// Встроенный список доменов для блокировки (подстрока в имени хоста).
/// Консервативный: реклама и трекеры. Телеметрию ОС сюда не кладём, чтобы не
/// ломать функции устройств — но вы можете добавить что угодно в blocklist.txt.
const DEFAULT_BLOCK: &[&str] = &[
    "doubleclick.net",
    "googleads",
    "googlesyndication.com",
    "google-analytics.com",
    "googleadservices.com",
    "adservice.google",
    "app-measurement.com",
    "scorecardresearch.com",
    "adnxs.com",
];

/// Общее состояние, разделяемое между всеми задачами.
struct State {
    block: Vec<String>,
    active: AtomicU64,
    total: AtomicU64,
    blocked: AtomicU64,
    /// ↓ скачано (сайт -> клиент), байт.
    down: AtomicU64,
    /// ↑ отправлено (клиент -> сайт), байт.
    up: AtomicU64,
}

/// Уменьшает счётчик активных соединений, когда задача завершается (любым путём).
struct ActiveGuard(Arc<State>);
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Relaxed);
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Режим дочернего процесса: этот же exe работает как DNS-синкхол.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(sinkhole::CHILD_FLAG) {
        let listen = args.get(2).map_or(sinkhole::SINKHOLE_LISTEN, String::as_str);
        let upstream = args
            .get(3)
            .map_or(sinkhole::SINKHOLE_UPSTREAM, String::as_str)
            .parse()
            .map_err(|_| err("плохой адрес upstream"))?;
        return dns_sinkhole::run(listen, upstream).await;
    }

    // Главный процесс.
    win::enable_ansi();
    win::set_title("socks5 — прокси + DHCP + DNS-синкхол  (Ctrl+C — выход)");
    control::choose_workdir();

    // Порт прокси занят — значит, программа уже запущена. Второй экземпляр
    // ничего не трогает (ни DNS, ни синкхол) и просто закрывается.
    let listener = match TcpListener::bind(LISTEN).await {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == io::ErrorKind::AddrInUse {
                log_main("порт 1080 занят — программа уже запущена. Ничего не трогаю.");
            } else {
                log_main(&format!("не могу занять {LISTEN}: {e}"));
            }
            log_main("окно закроется через 10 секунд");
            tokio::time::sleep(Duration::from_secs(10)).await;
            return Ok(());
        }
    };

    control::install_handler(); // Ctrl+C / закрытие окна -> откат и выход

    let state = Arc::new(State {
        block: load_blocklist(),
        active: AtomicU64::new(0),
        total: AtomicU64::new(0),
        blocked: AtomicU64::new(0),
        down: AtomicU64::new(0),
        up: AtomicU64::new(0),
    });

    println!(
        "[proxy] слушаю на {LISTEN} (SOCKS5 + HTTP). Блок-лист: {} доменов. Ctrl+C для выхода.",
        state.block.len()
    );

    // DHCP для WAN-порта роутера (выдаёт ему 192.168.137.2).
    tokio::spawn(dhcp::run());

    // Как завершился прошлый запуск? (остался ли DNS переключённым)
    let stale_dns = control::check_previous_run();

    // DNS-синкхол — дочерний процесс; когда ответит, переключаем на него DNS ПК.
    tokio::spawn(sinkhole::supervise());
    if control::wait_sinkhole(Duration::from_secs(8)).await {
        control::setup_dns();
    } else if stale_dns {
        control::recover_dns();
    } else {
        log_main("синкхол не ответил на :53 — DNS ПК не трогаю");
    }

    // Автообновление списка доменов (после DNS — чтобы было чем резолвить).
    tokio::spawn(update::run());

    // Скорость в заголовке окна (раз в секунду) + сводка в логе (раз в 10 с).
    tokio::spawn(traffic::report(state.clone()));

    // Принимаем клиентов вечно; выход — только через control::shutdown
    // (он откатит DNS и остановит синкхол).
    loop {
        match listener.accept().await {
            Ok((client, _peer)) => {
                let st = state.clone();
                tokio::spawn(async move {
                    // Обрывы соединений — норма, ошибки не шумим в консоль.
                    let _ = handle(client, st).await;
                });
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

/// Загружает блок-лист: встроенные значения + строки из blocklist.txt (если есть).
fn load_blocklist() -> Vec<String> {
    let mut list: Vec<String> = DEFAULT_BLOCK.iter().map(|s| s.to_string()).collect();
    if let Ok(txt) = std::fs::read_to_string("blocklist.txt") {
        for line in txt.lines() {
            let l = line.trim();
            if !l.is_empty() && !l.starts_with('#') {
                list.push(l.to_lowercase());
            }
        }
    }
    list
}

/// Проверяет, попадает ли "host:port" под блок-лист (по подстроке в хосте).
fn is_blocked(block: &[String], hostport: &str) -> bool {
    let host = hostport
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(hostport)
        .trim_matches(|c| c == '[' || c == ']')
        .to_lowercase();
    block.iter().any(|b| host.contains(b.as_str()))
}

/// Определяем протокол по первому байту.
async fn handle(mut client: TcpStream, st: Arc<State>) -> io::Result<()> {
    st.total.fetch_add(1, Relaxed);
    st.active.fetch_add(1, Relaxed);
    let _guard = ActiveGuard(st.clone());

    let mut first = [0u8; 1];
    if client.read(&mut first).await? == 0 {
        return Ok(());
    }
    if first[0] == 0x05 {
        socks5(client, &st).await
    } else {
        http(client, first[0], &st).await
    }
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------
async fn socks5(mut client: TcpStream, st: &State) -> io::Result<()> {
    let mut nb = [0u8; 1];
    client.read_exact(&mut nb).await?;
    let mut methods = vec![0u8; nb[0] as usize];
    client.read_exact(&mut methods).await?;
    client.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(err("bad ver"));
    }
    if req[1] != 0x01 {
        socks_reply(&mut client, 0x07).await?;
        return Err(err("только CONNECT"));
    }
    let target = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            format!("{}:{}", Ipv4Addr::from(a), read_port(&mut client).await?)
        }
        0x04 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            format!("[{}]:{}", Ipv6Addr::from(a), read_port(&mut client).await?)
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            client.read_exact(&mut host).await?;
            format!(
                "{}:{}",
                String::from_utf8_lossy(&host),
                read_port(&mut client).await?
            )
        }
        _ => {
            socks_reply(&mut client, 0x08).await?;
            return Err(err("ATYP"));
        }
    };

    if is_blocked(&st.block, &target) {
        st.blocked.fetch_add(1, Relaxed);
        println!("[block] {target}");
        socks_reply(&mut client, 0x02).await?; // not allowed by ruleset
        return Ok(());
    }

    match TcpStream::connect(&target).await {
        Ok(mut up) => {
            socks_reply(&mut client, 0x00).await?;
            println!("[socks5] -> {target}");
            let _ = traffic::relay(&mut client, &mut up, st).await;
            Ok(())
        }
        Err(e) => {
            socks_reply(&mut client, 0x05).await?;
            Err(e)
        }
    }
}

async fn read_port(s: &mut TcpStream) -> io::Result<u16> {
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    Ok(u16::from_be_bytes(p))
}

async fn socks_reply(client: &mut TcpStream, rep: u8) -> io::Result<()> {
    client
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

// ---------------------------------------------------------------------------
// HTTP-прокси
// ---------------------------------------------------------------------------
async fn http(mut client: TcpStream, first: u8, st: &State) -> io::Result<()> {
    let mut buf = vec![first];
    let mut tmp = [0u8; 2048];
    loop {
        if find(&buf, b"\r\n\r\n").is_some() {
            break;
        }
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            return Err(err("большой заголовок"));
        }
    }

    let line_end = find(&buf, b"\r\n").unwrap();
    let line = String::from_utf8_lossy(&buf[..line_end]).into_owned();
    let mut it = line.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        if is_blocked(&st.block, &target) {
            st.blocked.fetch_add(1, Relaxed);
            println!("[block] {target}");
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            return Ok(());
        }
        match TcpStream::connect(&target).await {
            Ok(mut up) => {
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                println!("[http] CONNECT {target}");
                let _ = traffic::relay(&mut client, &mut up, st).await;
                Ok(())
            }
            Err(e) => {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                Err(e)
            }
        }
    } else {
        let (host, port, path) = parse_http_url(&target)?;
        let hostport = format!("{host}:{port}");
        if is_blocked(&st.block, &hostport) {
            st.blocked.fetch_add(1, Relaxed);
            println!("[block] {host}");
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            return Ok(());
        }
        let mut up = TcpStream::connect((host.as_str(), port)).await?;
        println!("[http] {method} {host}:{port}{path}");
        let first_line = format!("{method} {path} HTTP/1.1\r\n");
        up.write_all(first_line.as_bytes()).await?;
        up.write_all(&buf[line_end + 2..]).await?;
        st.up
            .fetch_add((first_line.len() + buf.len() - line_end - 2) as u64, Relaxed);
        let _ = traffic::relay(&mut client, &mut up, st).await;
        Ok(())
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_http_url(url: &str) -> io::Result<(String, u16, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| err("не http URL"))?;
    let slash = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash];
    let path = if slash < rest.len() { &rest[slash..] } else { "/" };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

fn err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}
