//! Мини-DHCP-сервер для WAN-порта роутера.
//!
//! Зачем: без ICS на кабеле некому выдать роутеру адрес, а Asus упорно работает
//! как DHCP-клиент. Этот сервер всегда выдаёт ему CLIENT_IP.
//!
//! Безопасность (ПК одновременно в чужой Wi-Fi сети бара!):
//!   * отвечаем ТОЛЬКО устройствам из ALLOWED_MACS — чужим никогда;
//!   * ответы шлём только широковещательно в сеть кабеля (192.168.137.255).

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 137, 1);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 137, 2);
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const BROADCAST: Ipv4Addr = Ipv4Addr::new(192, 168, 137, 255);
/// DNS для роутера — этот ПК (здесь будет работать DNS-синкхол).
const DNS: Ipv4Addr = SERVER_IP;
const LEASE_SECS: u32 = 24 * 3600;

/// MAC WAN-порта Asus. Если роутер сменится — лог покажет его MAC, впишите сюда.
const ALLOWED_MACS: &[[u8; 6]] = &[[0x40, 0xB0, 0x76, 0xC3, 0xBB, 0xC0]];

const MAGIC: [u8; 4] = [99, 130, 83, 99];

// Типы DHCP-сообщений (опция 53).
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;

struct Req {
    msg_type: u8,
    mac: [u8; 6],
    ciaddr: Ipv4Addr,
    requested: Option<Ipv4Addr>,
}

pub async fn run() {
    let sock = match UdpSocket::bind("0.0.0.0:67").await {
        Ok(s) => s,
        Err(e) => {
            println!("[dhcp] не могу занять порт 67 ({e}) — DHCP выключен, прокси работает");
            return;
        }
    };
    if let Err(e) = sock.set_broadcast(true) {
        println!("[dhcp] set_broadcast: {e} — DHCP выключен");
        return;
    }
    println!(
        "[dhcp] слушаю :67, выдаю {CLIENT_IP} только для MAC {}",
        ALLOWED_MACS.iter().map(fmt_mac).collect::<Vec<_>>().join(", ")
    );

    let mut ignored: HashSet<[u8; 6]> = HashSet::new();
    let mut buf = [0u8; 1500];
    loop {
        // На Windows UDP recv иногда возвращает ConnectionReset — просто продолжаем.
        let Ok((n, _from)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let pkt = &buf[..n];
        let Some(req) = parse(pkt) else { continue };

        if !ALLOWED_MACS.contains(&req.mac) {
            // Чужое устройство — молчим. В лог пишем только первый раз.
            if ignored.insert(req.mac) {
                println!("[dhcp] игнорирую запрос от чужого MAC {}", fmt_mac(&req.mac));
            }
            continue;
        }

        let reply = match req.msg_type {
            DISCOVER => OFFER,
            REQUEST => {
                let wanted = req
                    .requested
                    .or((!req.ciaddr.is_unspecified()).then_some(req.ciaddr));
                match wanted {
                    Some(ip) if ip != CLIENT_IP => NAK, // просит старый адрес — пусть начнёт заново
                    _ => ACK,
                }
            }
            _ => continue, // RELEASE / DECLINE / INFORM — ничего не делаем
        };

        let resp = build(pkt, reply);
        match sock.send_to(&resp, SocketAddr::from((BROADCAST, 68))).await {
            Ok(_) => println!(
                "[dhcp] {} -> {} {}",
                fmt_mac(&req.mac),
                match reply {
                    OFFER => "OFFER",
                    ACK => "ACK",
                    _ => "NAK",
                },
                if reply == NAK { String::new() } else { CLIENT_IP.to_string() }
            ),
            Err(e) => println!("[dhcp] ошибка отправки: {e}"),
        }
    }
}

/// Разбор запроса клиента. Формат BOOTP: фиксированные 236 байт + magic + опции.
fn parse(p: &[u8]) -> Option<Req> {
    // op=1 (запрос), htype=1 (Ethernet), hlen=6
    if p.len() < 240 || p[0] != 1 || p[1] != 1 || p[2] != 6 || p[236..240] != MAGIC {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&p[28..34]);
    let ciaddr = Ipv4Addr::new(p[12], p[13], p[14], p[15]);

    let mut msg_type = 0;
    let mut requested = None;
    let mut i = 240;
    while i < p.len() {
        let code = p[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = *p.get(i + 1)? as usize;
        let v = p.get(i + 2..i + 2 + len)?;
        match code {
            53 if len == 1 => msg_type = v[0],
            50 if len == 4 => requested = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            _ => {}
        }
        i += 2 + len;
    }
    (msg_type != 0).then_some(Req { msg_type, mac, ciaddr, requested })
}

/// Собирает ответ (OFFER / ACK / NAK) на основе запроса.
fn build(req: &[u8], msg_type: u8) -> Vec<u8> {
    let mut r = vec![0u8; 240];
    r[0] = 2; // op = ответ
    r[1] = 1;
    r[2] = 6;
    r[4..8].copy_from_slice(&req[4..8]); // xid — номер «разговора»
    r[10..12].copy_from_slice(&req[10..12]); // flags
    if msg_type != NAK {
        r[16..20].copy_from_slice(&CLIENT_IP.octets()); // yiaddr — «твой адрес»
    }
    r[24..28].copy_from_slice(&req[24..28]); // giaddr
    r[28..44].copy_from_slice(&req[28..44]); // chaddr (MAC клиента)
    r[236..240].copy_from_slice(&MAGIC);

    opt(&mut r, 53, &[msg_type]);
    opt(&mut r, 54, &SERVER_IP.octets()); // кто сервер
    if msg_type != NAK {
        opt(&mut r, 51, &LEASE_SECS.to_be_bytes()); // срок аренды
        opt(&mut r, 1, &NETMASK.octets());
        opt(&mut r, 3, &SERVER_IP.octets()); // шлюз
        opt(&mut r, 6, &DNS.octets());
    }
    r.push(255); // конец опций
    r.resize(r.len().max(300), 0); // минимальный размер BOOTP-пакета
    r
}

fn opt(r: &mut Vec<u8>, code: u8, v: &[u8]) {
    r.push(code);
    r.push(v.len() as u8);
    r.extend_from_slice(v);
}

fn fmt_mac(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-")
}
