//! Вшивает в exe значок и манифест (запуск только с правами администратора —
//! без них программа не может переключать DNS).

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=assets/socks5.ico");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/socks5.ico");
        res.set("FileDescription", "socks5: прокси + DHCP + DNS-синкхол");
        res.set("ProductName", "socks5");
        res.set_manifest(MANIFEST);
        res.compile().expect("не удалось вшить значок/манифест");
    }
}
