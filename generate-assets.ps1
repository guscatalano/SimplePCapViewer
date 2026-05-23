# Generates every image asset for SimplePCapViewer from one drawing routine:
# the app icon (multi-size AppIcon.ico + AppIcon.png) and the MSIX tile/logo PNGs.
# The icon is a magnifying glass over packet rows (capture + search).

Add-Type -AssemblyName System.Drawing

$outDir = Join-Path $PSScriptRoot 'src\PcapViewer.App\Assets'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Draws the icon centred in a width x height canvas (square art, transparent margins).
function New-IconBitmap([int]$w, [int]$h) {
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    $s  = [Math]::Min($w, $h)
    $ox = ($w - $s) / 2.0
    $oy = ($h - $s) / 2.0

    # background: rounded rect with a diagonal gradient
    $rect = New-Object System.Drawing.Rectangle([int]$ox, [int]$oy, $s, $s)
    $bg = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $rect,
        [System.Drawing.Color]::FromArgb(255, 38, 50, 120),
        [System.Drawing.Color]::FromArgb(255, 32, 162, 198),
        50)
    $r = [Math]::Max(2, [int]($s * 0.16))
    $bgPath = New-Object System.Drawing.Drawing2D.GraphicsPath
    $bgPath.AddArc($ox, $oy, $r*2, $r*2, 180, 90)
    $bgPath.AddArc($ox + $s - $r*2, $oy, $r*2, $r*2, 270, 90)
    $bgPath.AddArc($ox + $s - $r*2, $oy + $s - $r*2, $r*2, $r*2, 0, 90)
    $bgPath.AddArc($ox, $oy + $s - $r*2, $r*2, $r*2, 90, 90)
    $bgPath.CloseFigure()
    $g.FillPath($bg, $bgPath)

    # magnifying glass
    $cx = $ox + $s * 0.44
    $cy = $oy + $s * 0.42
    $lr = $s * 0.30
    $ringT = [Math]::Max(1.0, $s * 0.09)
    $clipR = $lr - $ringT / 2.0

    $lensFill = New-Object System.Drawing.SolidBrush(
        [System.Drawing.Color]::FromArgb(175, 12, 20, 55))
    $g.FillEllipse($lensFill, [float]($cx-$clipR), [float]($cy-$clipR),
        [float]($clipR*2), [float]($clipR*2))

    # packet rows clipped to the lens
    $clip = New-Object System.Drawing.Drawing2D.GraphicsPath
    $clip.AddEllipse([float]($cx-$clipR), [float]($cy-$clipR),
        [float]($clipR*2), [float]($clipR*2))
    $g.SetClip($clip)
    $barH = [Math]::Max(1.0, $s * 0.085)
    $gap  = $clipR * 0.66
    $white = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $amber = New-Object System.Drawing.SolidBrush(
        [System.Drawing.Color]::FromArgb(255, 250, 196, 82))
    $g.FillRectangle($amber, [float]($cx-$clipR), [float]($cy-$gap-$barH/2), [float]($clipR*2), [float]$barH)
    $g.FillRectangle($white, [float]($cx-$clipR), [float]($cy-$barH/2),       [float]($clipR*2), [float]$barH)
    $g.FillRectangle($white, [float]($cx-$clipR), [float]($cy+$gap-$barH/2), [float]($clipR*2), [float]$barH)
    $g.ResetClip()

    # handle then ring
    $hp = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [float]($ringT * 1.3))
    $hp.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $hp.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $d = 0.7071
    $hx = $cx + $lr * $d
    $hy = $cy + $lr * $d
    $L = $s * 0.27
    $g.DrawLine($hp, [float]$hx, [float]$hy, [float]($hx + $L), [float]($hy + $L))

    $rp = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [float]$ringT)
    $g.DrawEllipse($rp, [float]($cx-$lr), [float]($cy-$lr), [float]($lr*2), [float]($lr*2))

    $g.Dispose()
    return $bmp
}

function Save-Png([int]$w, [int]$h, [string]$name) {
    $b = New-IconBitmap $w $h
    $b.Save((Join-Path $outDir $name), [System.Drawing.Imaging.ImageFormat]::Png)
    $b.Dispose()
}

# ---- MSIX tile / logo assets ----
Save-Png 50   50   'StoreLogo.png'
Save-Png 88   88   'Square44x44Logo.scale-200.png'
Save-Png 24   24   'Square44x44Logo.targetsize-24_altform-unplated.png'
Save-Png 48   48   'Square44x44Logo.targetsize-48_altform-lightunplated.png'
Save-Png 300  300  'Square150x150Logo.scale-200.png'
Save-Png 620  300  'Wide310x150Logo.scale-200.png'
Save-Png 1240 600  'SplashScreen.scale-200.png'
Save-Png 256  256  'AppIcon.png'

# ---- multi-size .ico ----
$sizes = @(16, 32, 48, 64, 128, 256)
$bitmaps = $sizes | ForEach-Object { New-IconBitmap $_ $_ }
$pngData = foreach ($b in $bitmaps) {
    $ms = New-Object System.IO.MemoryStream
    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    , $ms.ToArray()
}
$icoPath = Join-Path $outDir 'AppIcon.ico'
$stream = [System.IO.File]::Create($icoPath)
$wtr = New-Object System.IO.BinaryWriter($stream)
$wtr.Write([UInt16]0); $wtr.Write([UInt16]1); $wtr.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]
    $wtr.Write([Byte]($sz % 256)); $wtr.Write([Byte]($sz % 256))
    $wtr.Write([Byte]0); $wtr.Write([Byte]0)
    $wtr.Write([UInt16]1); $wtr.Write([UInt16]32)
    $wtr.Write([UInt32]$pngData[$i].Length); $wtr.Write([UInt32]$offset)
    $offset += $pngData[$i].Length
}
foreach ($d in $pngData) { $wtr.Write($d) }
$wtr.Close(); $stream.Close()
foreach ($b in $bitmaps) { $b.Dispose() }

Write-Host "Assets generated in $outDir"
