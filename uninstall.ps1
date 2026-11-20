# Удаляет автозапуск и боевую копию из C:\Program Files\socks5.
# В админ-терминале, из папки проекта:
#   powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
$name = 'socks5 proxy'
$dst  = Join-Path $env:ProgramFiles 'socks5'

if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
    Write-Output "автозапуск '$name' удалён"
} else {
    Write-Output "автозапуска '$name' нет"
}

$live = Get-Process socks5 -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$dst\*" }
if ($live) {
    Write-Output 'Программа запущена из Program Files — остановите её (Ctrl+C, она вернёт DNS) и повторите.'
    exit 1
}
if (Test-Path $dst) {
    Remove-Item $dst -Recurse -Force
    Write-Output "папка $dst удалена"
}
