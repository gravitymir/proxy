//! Автообновление списка доменов.
//!
//! Файл старше MAX_AGE (или его нет) -> скачиваем свежий. Дальше проверяем
//! возраст каждые CHECK_EVERY. Не получилось — повтор через RETRY.
//! Сам файл заменяет dns_sinkhole::update (с проверкой и атомарно),
//! а дочерний синкхол замечает новый файл и перезагружает список на лету.

use std::time::Duration;

use dns_sinkhole::update::{download_list, list_age};

use crate::sinkhole::log_main;

const DAY: u64 = 24 * 3600;
const MAX_AGE: Duration = Duration::from_secs(7 * DAY);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
const RETRY: Duration = Duration::from_secs(3600);

pub async fn run() {
    let mut first = true;
    loop {
        let wait = match list_age() {
            Some(age) if age < MAX_AGE => {
                if first {
                    log_main(&format!(
                        "список доменов свежий ({}), обновлю, когда ему будет 7 дней",
                        fmt_age(age)
                    ));
                }
                (MAX_AGE - age).min(CHECK_EVERY)
            }
            age => {
                log_main(&match age {
                    Some(a) => format!("списку доменов {} — скачиваю свежий...", fmt_age(a)),
                    None => "файла со списком доменов нет — скачиваю...".to_string(),
                });
                match tokio::task::spawn_blocking(download_list).await {
                    Ok(Ok(u)) => {
                        log_main(&format!(
                            "список обновлён: {:.1} МБ, было {} -> стало {} доменов \
                             (синкхол подхватит в течение 30 с)",
                            u.bytes as f64 / 1_048_576.0,
                            u.old,
                            u.new
                        ));
                        CHECK_EVERY
                    }
                    Ok(Err(e)) => {
                        log_main(&format!("обновить список не удалось: {e}. Повтор через час"));
                        RETRY
                    }
                    Err(_) => RETRY,
                }
            }
        };
        first = false;
        tokio::time::sleep(wait).await;
    }
}

fn fmt_age(age: Duration) -> String {
    let s = age.as_secs();
    if s >= DAY {
        format!("{} дн.", s / DAY)
    } else {
        format!("{} ч.", s / 3600)
    }
}
