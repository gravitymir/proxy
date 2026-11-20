//! Учёт трафика в реальном времени.
//!
//! * relay — перекачивает данные между клиентом и сайтом в обе стороны и
//!   засчитывает каждый кусок сразу (раньше трафик соединения учитывался
//!   только после его закрытия — долгое видео висело на 0 MB);
//! * report — раз в секунду пишет скорость в заголовок окна, раз в 10 секунд —
//!   строку [stat] в лог (если что-то происходило).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{State, win};

const BUF: usize = 16 * 1024;

/// Перекачка в обе стороны с подсчётом: ↑ клиент -> сайт, ↓ сайт -> клиент.
pub async fn relay(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    st: &State,
) -> std::io::Result<()> {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();
    // try_join: ошибка в одном направлении (обрыв) — закрываем оба.
    tokio::try_join!(
        copy_counted(&mut cr, &mut uw, &st.up),
        copy_counted(&mut ur, &mut cw, &st.down),
    )?;
    Ok(())
}

async fn copy_counted<R, W>(r: &mut R, w: &mut W, counter: &AtomicU64) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            // Одна сторона закончила передачу — сообщаем другой («конец
            // данных»), а обратное направление пусть доработает.
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Relaxed);
    }
}

/// Скорость — в заголовок окна раз в секунду; сводка — в лог раз в 10 секунд.
pub async fn report(st: Arc<State>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut sec = (0u64, 0u64, Instant::now()); // ↓, ↑, когда замерили
    let mut ten = (0u64, 0u64, Instant::now());
    let mut last_total = 0u64;
    let mut n = 0u64;
    loop {
        tick.tick().await;
        let (down, up) = (st.down.load(Relaxed), st.up.load(Relaxed));
        let active = st.active.load(Relaxed);

        let dt = sec.2.elapsed().as_secs_f64().max(0.001);
        win::set_title(&format!(
            "socks5 — ↓ {} ↑ {} | всего {} | активных {}  (Ctrl+C — выход)",
            rate(down - sec.0, dt),
            rate(up - sec.1, dt),
            bytes(down + up),
            active
        ));
        sec = (down, up, Instant::now());

        n += 1;
        if n % 10 != 0 {
            continue;
        }
        let total = st.total.load(Relaxed);
        let moved = down != ten.0 || up != ten.1;
        // В простое не засоряем лог одинаковыми строками.
        if moved || active > 0 || total != last_total {
            let dt10 = ten.2.elapsed().as_secs_f64().max(0.001);
            println!(
                "[stat] активных: {active}, всего: {total}, заблокировано: {} | ↓ {} ↑ {} | за 10 с: ↓ {} ↑ {}",
                st.blocked.load(Relaxed),
                bytes(down),
                bytes(up),
                rate(down - ten.0, dt10),
                rate(up - ten.1, dt10),
            );
        }
        ten = (down, up, Instant::now());
        last_total = total;
    }
}

fn bytes(b: u64) -> String {
    let b = b as f64;
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} GB", b / (1024.0 * 1024.0 * 1024.0))
    } else if b >= 1024.0 * 1024.0 {
        format!("{:.1} MB", b / (1024.0 * 1024.0))
    } else if b >= 1024.0 {
        format!("{:.0} KB", b / 1024.0)
    } else {
        format!("{b:.0} B")
    }
}

fn rate(b: u64, secs: f64) -> String {
    let r = b as f64 / secs;
    if r >= 1024.0 * 1024.0 {
        format!("{:.1} MB/s", r / (1024.0 * 1024.0))
    } else if r >= 1024.0 {
        format!("{:.0} KB/s", r / 1024.0)
    } else {
        format!("{r:.0} B/s")
    }
}
