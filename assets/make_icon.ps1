# Рисует значок программы: синий фон, белый щит, зелёная галочка.
# Сохраняет assets\socks5.ico (размеры 16..256, PNG внутри ICO).
#   powershell -ExecutionPolicy Bypass -File assets\make_icon.ps1
Add-Type -AssemblyName System.Drawing

function New-RoundRect([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    $p
}

function Get-IconPng([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)

    # Фон: скруглённый квадрат с градиентом.
    $bg = New-RoundRect 0 0 ($s - 1) ($s - 1) ($s * 0.22)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush (
        (New-Object System.Drawing.PointF 0, 0),
        (New-Object System.Drawing.PointF $s, $s),
        [System.Drawing.Color]::FromArgb(255, 30, 58, 138),
        [System.Drawing.Color]::FromArgb(255, 37, 99, 235))
    $g.FillPath($grad, $bg)

    # Щит.
    $f = { param($v) [float]($v * $s) }
    $sh = New-Object System.Drawing.Drawing2D.GraphicsPath
    $sh.AddLine((& $f 0.50), (& $f 0.10), (& $f 0.84), (& $f 0.22))
    $sh.AddLine((& $f 0.84), (& $f 0.22), (& $f 0.84), (& $f 0.48))
    $sh.AddBezier((& $f 0.84), (& $f 0.48), (& $f 0.84), (& $f 0.72), (& $f 0.66), (& $f 0.84), (& $f 0.50), (& $f 0.92))
    $sh.AddBezier((& $f 0.50), (& $f 0.92), (& $f 0.34), (& $f 0.84), (& $f 0.16), (& $f 0.72), (& $f 0.16), (& $f 0.48))
    $sh.AddLine((& $f 0.16), (& $f 0.48), (& $f 0.16), (& $f 0.22))
    $sh.CloseFigure()
    $g.FillPath([System.Drawing.Brushes]::White, $sh)

    # Галочка.
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 22, 163, 74)), ([float]([Math]::Max(1.6, $s * 0.10)))
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $pts = [System.Drawing.PointF[]]@(
        (New-Object System.Drawing.PointF (& $f 0.33), (& $f 0.52)),
        (New-Object System.Drawing.PointF (& $f 0.46), (& $f 0.65)),
        (New-Object System.Drawing.PointF (& $f 0.68), (& $f 0.38)))
    $g.DrawLines($pen, $pts)

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    , $ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$images = foreach ($s in $sizes) { , (Get-IconPng $s) }

# Формат ICO: заголовок 6 байт + по 16 байт на картинку + сами PNG.
$out = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter $out
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $len = $images[$i].Length
    $b = if ($s -ge 256) { 0 } else { $s }
    $w.Write([byte]$b); $w.Write([byte]$b); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32)
    $w.Write([UInt32]$len); $w.Write([UInt32]$offset)
    $offset += $len
}
foreach ($img in $images) { $w.Write($img) }
$w.Flush()

$dest = Join-Path $PSScriptRoot 'socks5.ico'
[System.IO.File]::WriteAllBytes($dest, $out.ToArray())
# Превью 256px — посмотреть глазами.
[System.IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'socks5_preview.png'), $images[-1])
"Готово: $dest"
