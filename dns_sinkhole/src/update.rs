//! Скачивание свежего списка доменов (StevenBlack hosts).
//!
//! Защита от мусора: публичный Wi-Fi может вместо файла отдать HTML-страницу
//! входа. Если в скачанном меньше MIN_DOMAINS доменов — файл не трогаем.
//! Замена атомарная: пишем .tmp и переименовываем — синкхол никогда не
//! прочитает полуфайл.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use crate::{HOSTS_FILE, parse_hosts};

pub const LIST_URL: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
const MIN_DOMAINS: usize = 10_000;
const TIMEOUT: Duration = Duration::from_secs(60);

/// Результат успешного обновления.
pub struct Updated {
    pub bytes: usize,
    pub old: usize,
    pub new: usize,
}

/// Возраст файла списка в текущей папке (None — файла нет).
pub fn list_age() -> Option<Duration> {
    let m = std::fs::metadata(HOSTS_FILE).and_then(|m| m.modified()).ok()?;
    Some(SystemTime::now().duration_since(m).unwrap_or(Duration::ZERO))
}

/// Скачать, проверить, атомарно заменить файл. Блокирующая функция.
pub fn download_list() -> Result<Updated, String> {
    let txt = ureq::get(LIST_URL)
        .timeout(TIMEOUT)
        .call()
        .map_err(|e| format!("скачивание: {e}"))?
        .into_string()
        .map_err(|e| format!("чтение ответа: {e}"))?;

    let mut set = HashSet::new();
    parse_hosts(&txt, &mut set);
    if set.len() < MIN_DOMAINS {
        return Err(format!(
            "в скачанном всего {} доменов — это не список (страница входа Wi-Fi?), старый оставлен",
            set.len()
        ));
    }

    let old = std::fs::read_to_string(HOSTS_FILE)
        .map(|t| {
            let mut s = HashSet::new();
            parse_hosts(&t, &mut s);
            s.len()
        })
        .unwrap_or(0);

    let tmp = format!("{HOSTS_FILE}.tmp");
    std::fs::write(&tmp, &txt).map_err(|e| format!("запись {tmp}: {e}"))?;
    std::fs::rename(&tmp, HOSTS_FILE).map_err(|e| format!("замена {HOSTS_FILE}: {e}"))?;

    Ok(Updated {
        bytes: txt.len(),
        old,
        new: set.len(),
    })
}
