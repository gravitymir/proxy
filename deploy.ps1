# Разворачивает «боевую» копию в C:\Program Files\socks5 и (пере)создаёт автозапуск.
#
# Порядок обновления:
#   1. обычный терминал:  cargo build --release
#   2. админ-терминал, из папки проекта:  powershell -ExecutionPolicy Bypass -File .\deploy.ps1
#   3. если программа была запущена — Ctrl+C в её окне и запустить снова
#
# Почему Program Files: автозапуск идёт с правами администратора без вопросов,
# а писать в Program Files может только администратор — exe не подменить тихо.

$ErrorActionPreference = 'Stop'
$src  = $PSScriptRoot
$dst  = Join-Path $env:ProgramFiles 'socks5'
$exe  = Join-Path $src 'target\release\socks5.exe'
$name = 'socks5 proxy'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Запустите в терминале от администратора.'
}
if (-not (Test-Path $exe)) { throw "Нет $exe — сначала соберите: cargo build --release" }

New-Item -ItemType Directory -Force $dst | Out-Null

# Хвосты прошлых обновлений.
Get-ChildItem $dst -Filter 'socks5.old*.exe' -ErrorAction SilentlyContinue |
    ForEach-Object { try { Remove-Item $_.FullName -Force -ErrorAction Stop } catch {} }

# Работающий exe удалить нельзя, но можно переименовать.
$target  = Join-Path $dst 'socks5.exe'
$running = $false
if (Test-Path $target) {
    try {
        Remove-Item $target -Force -ErrorAction Stop
    } catch {
        $n = 1; while (Test-Path (Join-Path $dst "socks5.old$n.exe")) { $n++ }
        Rename-Item $target "socks5.old$n.exe"
        $running = $true
    }
}
Copy-Item $exe $target
Write-Output "exe скопирован: $target"

# Списки — только если их ещё нет (правки в боевой папке не затираем).
$lists = @{
    'blocklist.txt'       = Join-Path $src 'blocklist.txt'
    'blocklist_hosts.txt' = Join-Path $src 'dns_sinkhole\blocklist_hosts.txt'
}
foreach ($f in $lists.Keys) {
    $from = $lists[$f]
    $to   = Join-Path $dst $f
    if ((Test-Path $from) -and -not (Test-Path $to)) {
        Copy-Item $from $to
        Write-Output "скопирован список: $f"
    }
}

# Автозапуск: при входе в Windows, через 10 с, видимое окно, права администратора
# без UAC, без ограничения времени работы (по умолчанию было бы 3 дня).
$user      = "$env:USERDOMAIN\$env:USERNAME"
$action    = New-ScheduledTaskAction -Execute $target -WorkingDirectory $dst
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $user
$trigger.Delay = 'PT10S'
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force `
    -Description "Прокси + DHCP + DNS-синкхол ($dst)" | Out-Null
Write-Output "автозапуск '$name' -> $target"

Write-Output ''
if ($running) {
    Write-Output 'Программа сейчас работает (старая версия). Чтобы перейти на новую:'
    Write-Output "  Ctrl+C в её окне, затем:  schtasks /run /tn `"$name`""
} else {
    Write-Output "Запустить сейчас:  schtasks /run /tn `"$name`""
}
