//! Простой DNS-синкхол (ad-blocker на уровне DNS) на tokio.
//!
//! Что делает:
//!   * слушает UDP-запросы DNS;
//!   * имя домена из блок-листа -> отвечает NXDOMAIN (домен «не существует»),
//!     поэтому реклама/трекер просто не резолвится и не грузится;
//!   * всё остальное — форвардит вышестоящему DNS (по умолчанию 1.1.1.1) и
//!     возвращает ответ клиенту.
//!
//! Блок-лист грузится из файла в hosts-формате (строки «0.0.0.0 domain» или
//! просто «domain»), плюс небольшой встроенный список. Легко тянет сотни тысяч
//! доменов (хранятся в HashSet, поиск O(1)).
//!
//! Это библиотека: её используют и отдельный exe (src/main.rs),
//! и прокси socks5 (запускает сам себя с флагом --sinkhole).
//! Блок-лист ищется в текущей папке: blocklist_hosts.txt.
//! Файл проверяется раз в RELOAD_CHECK: изменился — список перезагружается
//! на лету, без перезапуска и без перерыва в работе DNS.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;

pub mod update;

/// Как часто проверять, не изменился ли файл со списком.
const RELOAD_CHECK: Duration = Duration::from_secs(30);

/// Встроенный минимум (на случай отсутствия файла). Основное — в hosts-файле.
/// Только чистая реклама/аналитика. НЕ добавлять сюда API-домены приложений:
/// например, graph.facebook.com — это основной API Facebook (лента,
/// Marketplace, сохранённое), его блокировка ломает приложение.
const DEFAULT_BLOCK: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "google-analytics.com",
    "googleadservices.com",
    "app-measurement.com",
];

pub const HOSTS_FILE: &str = "blocklist_hosts.txt";

struct State {
    /// Список под RwLock: читают все запросы, пишет только перезагрузка.
    block: RwLock<HashSet<String>>,
    upstream: SocketAddr,
    total: AtomicU64,
    blocked: AtomicU64,
    /// Домены, уже показанные как «напрямую» (чтобы печатать каждый один раз).
    direct_seen: Mutex<HashSet<String>>,
}

/// Сколько разных «прямых» доменов помнить, прежде чем начать заново.
const DIRECT_SEEN_MAX: usize = 5000;

/// Запускает синкхол: слушает `listen` (+ [::1] на том же порту),
/// незаблокированные запросы форвардит на `upstream`. Работает бесконечно.
pub async fn run(listen: &str, upstream: SocketAddr) -> std::io::Result<()> {
    let block = load_blocklist();
    let state = Arc::new(State {
        upstream,
        block: RwLock::new(block),
        total: AtomicU64::new(0),
        blocked: AtomicU64::new(0),
        direct_seen: Mutex::new(HashSet::new()),
    });

    let sock = Arc::new(UdpSocket::bind(&listen).await?);
    println!(
        "[dns] слушаю {listen}, upstream {upstream}, блок-лист: {} доменов. Ctrl+C.",
        state.block.read().unwrap().len()
    );

    tokio::spawn(watch_file(state.clone()));

    // Статистика каждые 15 секунд.
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(15));
            loop {
                t.tick().await;
                println!(
                    "[stat] запросов: {}, заблокировано: {}",
                    st.total.load(Relaxed),
                    st.blocked.load(Relaxed)
                );
            }
        });
    }

    // Ещё и IPv6-loopback [::1]:порт — иначе Windows спрашивает IPv6-DNS
    // роутера параллельно и обходит синкхол. Только локально, снаружи недоступен.
    if let Ok(addr) = listen.parse::<SocketAddr>() {
        let v6 = format!("[::1]:{}", addr.port());
        match UdpSocket::bind(&v6).await {
            Ok(s6) => {
                println!("[dns] слушаю также {v6}");
                tokio::spawn(serve(Arc::new(s6), state.clone()));
            }
            Err(e) => println!("[dns] не смог занять {v6}: {e}"),
        }
    }

    serve(sock, state).await;
    Ok(())
}

/// Следит за файлом списка; изменился (или появился) — перезагружает.
async fn watch_file(state: Arc<State>) {
    let mut last = file_mtime();
    loop {
        tokio::time::sleep(RELOAD_CHECK).await;
        let now = file_mtime();
        if now.is_none() || now == last {
            continue;
        }
        last = now;
        // Разбор ~2 МБ текста — в отдельном потоке, чтобы не тормозить DNS.
        let Ok(Ok(txt)) = tokio::task::spawn_blocking(|| std::fs::read_to_string(HOSTS_FILE)).await
        else {
            println!("[dns] {HOSTS_FILE} изменился, но не читается — оставляю старый список");
            continue;
        };
        let new = tokio::task::spawn_blocking(move || {
            let mut set: HashSet<String> = DEFAULT_BLOCK.iter().map(|s| s.to_string()).collect();
            parse_hosts(&txt, &mut set);
            set
        })
        .await
        .unwrap_or_default();
        if new.len() <= DEFAULT_BLOCK.len() {
            println!("[dns] в новом {HOSTS_FILE} нет доменов — оставляю старый список");
            continue;
        }
        let old_len = {
            let mut guard = state.block.write().unwrap();
            let old = guard.len();
            *guard = new;
            old
        };
        println!(
            "[dns] список перезагружен: было {old_len}, стало {} доменов",
            state.block.read().unwrap().len()
        );
    }
}

fn file_mtime() -> Option<SystemTime> {
    std::fs::metadata(HOSTS_FILE).and_then(|m| m.modified()).ok()
}

/// Цикл приёма запросов на одном сокете.
async fn serve(sock: Arc<UdpSocket>, state: Arc<State>) {
    let mut buf = [0u8; 4096];
    loop {
        // На Windows UDP recv иногда возвращает ConnectionReset — не падаем.
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let query = buf[..n].to_vec();
        let st = state.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            let _ = handle(sock, st, query, from).await;
        });
    }
}

async fn handle(
    sock: Arc<UdpSocket>,
    st: Arc<State>,
    query: Vec<u8>,
    from: SocketAddr,
) -> std::io::Result<()> {
    st.total.fetch_add(1, Relaxed);

    if let Some(name) = parse_qname(&query) {
        // Блокировку держим только на время проверки (не через await).
        let blocked = is_blocked(&st.block.read().unwrap(), &name);
        if blocked {
            st.blocked.fetch_add(1, Relaxed);
            println!("[block] {name}");
            let resp = make_nxdomain(&query);
            sock.send_to(&resp, from).await?;
            return Ok(());
        }
        // Запрос не с самого ПК (а, например, с роутера) — значит, какое-то
        // приложение пытается выйти в интернет мимо прокси. Показываем домен
        // один раз: так видно, кому прокси не подходит (голос, игры, UDP...).
        if !from.ip().is_loopback() {
            let first = {
                let mut seen = st.direct_seen.lock().unwrap();
                if seen.len() >= DIRECT_SEEN_MAX {
                    seen.clear();
                }
                seen.insert(name.clone())
            };
            if first {
                println!("[мимо прокси] {name}  (запрос от {})", from.ip());
            }
        }
    }

    // Форвардим вышестоящему DNS.
    let up = UdpSocket::bind("0.0.0.0:0").await?;
    up.send_to(&query, st.upstream).await?;
    let mut rbuf = [0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(5), up.recv(&mut rbuf)).await {
        Ok(Ok(n)) => {
            sock.send_to(&rbuf[..n], from).await?;
        }
        _ => { /* таймаут/ошибка — молча роняем, клиент повторит */ }
    }
    Ok(())
}

/// Достаёт доменное имя (QNAME) из DNS-запроса. Начинается с offset 12.
fn parse_qname(q: &[u8]) -> Option<String> {
    if q.len() < 13 {
        return None;
    }
    let mut i = 12;
    let mut labels: Vec<String> = Vec::new();
    while i < q.len() {
        let len = q[i] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None; // сжатие в вопросе не ожидается
        }
        i += 1;
        if i + len > q.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&q[i..i + len]).into_owned());
        i += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Блокируем, если домен или любой его родитель есть в списке.
fn is_blocked(set: &HashSet<String>, qname: &str) -> bool {
    let q = qname.to_lowercase();
    if set.contains(&q) {
        return true;
    }
    let mut rest = q.as_str();
    while let Some(pos) = rest.find('.') {
        rest = &rest[pos + 1..];
        if rest.contains('.') && set.contains(rest) {
            return true;
        }
    }
    false
}

/// Делает из запроса ответ NXDOMAIN (домен не существует).
fn make_nxdomain(query: &[u8]) -> Vec<u8> {
    let mut r = query.to_vec();
    if r.len() >= 12 {
        r[2] |= 0x80; // QR = 1 (это ответ)
        r[3] = 0x80 | 0x03; // RA = 1, RCODE = 3 (NXDOMAIN)
        // ANCOUNT / NSCOUNT / ARCOUNT = 0
        for b in &mut r[6..12] {
            *b = 0;
        }
    }
    r
}

/// Список, вшитый в exe при сборке (копия blocklist_hosts.txt на тот момент).
/// Работает, даже если рядом с программой нет никаких файлов.
const EMBEDDED_HOSTS: &str = include_str!("../blocklist_hosts.txt");

/// Загружает блок-лист: встроенный минимум + hosts-список.
/// Если рядом лежит blocklist_hosts.txt — берём его (можно обновить без
/// пересборки), иначе — версию, вшитую в exe.
fn load_blocklist() -> HashSet<String> {
    let mut set: HashSet<String> = DEFAULT_BLOCK.iter().map(|s| s.to_string()).collect();
    match std::fs::read_to_string(HOSTS_FILE) {
        Ok(txt) => {
            parse_hosts(&txt, &mut set);
            println!("[dns] список из файла {HOSTS_FILE}");
        }
        Err(_) => {
            parse_hosts(EMBEDDED_HOSTS, &mut set);
            println!("[dns] файла {HOSTS_FILE} нет — список, вшитый в exe");
        }
    }
    set
}

/// Строки «0.0.0.0 domain.com» | «127.0.0.1 domain.com» | «domain.com».
pub fn parse_hosts(txt: &str, set: &mut HashSet<String>) {
    for line in txt.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(dom) = l.split_whitespace().last() {
            if dom.contains('.') && !dom.starts_with('#') {
                set.insert(dom.to_lowercase());
            }
        }
    }
}
