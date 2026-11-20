//! Отдельный запуск DNS-синкхола (вся логика — в lib.rs).
//!
//!   dns_sinkhole [listen_addr] [upstream]
//!   по умолчанию: 0.0.0.0:53  1.1.1.1:53
//!   для теста:    dns_sinkhole 127.0.0.1:5300 1.1.1.1:53
//!   обновить список в текущей папке и выйти:  dns_sinkhole --update

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--update") {
        println!("[update] скачиваю {}", dns_sinkhole::update::LIST_URL);
        match dns_sinkhole::update::download_list() {
            Ok(u) => println!(
                "[update] готово: {:.1} МБ, было {} -> стало {} доменов",
                u.bytes as f64 / 1_048_576.0,
                u.old,
                u.new
            ),
            Err(e) => println!("[update] не удалось: {e}"),
        }
        return Ok(());
    }

    let mut args = std::env::args().skip(1);
    let listen = args.next().unwrap_or_else(|| "0.0.0.0:53".into());
    let upstream: SocketAddr = args
        .next()
        .unwrap_or_else(|| "1.1.1.1:53".into())
        .parse()
        .expect("плохой адрес upstream");
    dns_sinkhole::run(&listen, upstream).await
}
