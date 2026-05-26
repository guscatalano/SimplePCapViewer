# Captures the SimplePCapViewer main window to docs/screenshots/<name>.png.
# Usage:  .\take-shot.ps1 01-packet-list
#         .\take-shot.ps1 02-dissection -Size 1920x1080
#
# -Size resizes the window (client + chrome) before capture. Microsoft Store
# accepts desktop screenshots between 1366x768 and 3840x2160.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Name,
    [string] $Size = '',          # e.g. '1920x1080' to resize before capture
    [string] $TitleMatch = 'SimplePCapViewer',
    [switch] $NoActivate
)

$ErrorActionPreference = 'Stop'

Add-Type @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public static class Win {
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h,int x,int y,int w,int h2,bool repaint);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
}
"@ -ReferencedAssemblies System.Drawing,System.Drawing.Common,System.Runtime.InteropServices -ErrorAction SilentlyContinue

# Find the SimplePCapViewer window
$proc = Get-Process | Where-Object { $_.MainWindowTitle -like "*$TitleMatch*" -and $_.MainWindowHandle -ne 0 } |
        Sort-Object StartTime -Descending | Select-Object -First 1
if (-not $proc) { throw "No window matching '*$TitleMatch*' found. Is the app running?" }
$hwnd = $proc.MainWindowHandle
Write-Host "Target: PID $($proc.Id)  HWND 0x$($hwnd.ToString('X'))  '$($proc.MainWindowTitle)'"

# Optional resize
if ($Size) {
    if ($Size -notmatch '^(\d+)x(\d+)$') { throw "Size must look like 1920x1080" }
    $w = [int]$matches[1]; $h = [int]$matches[2]
    $r = New-Object Win+RECT
    [Win]::GetWindowRect($hwnd, [ref]$r) | Out-Null
    [Win]::MoveWindow($hwnd, $r.L, $r.T, $w, $h, $true) | Out-Null
    Start-Sleep -Milliseconds 250
}

if (-not $NoActivate) {
    [Win]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE
    [Win]::SetForegroundWindow($hwnd) | Out-Null
    Start-Sleep -Milliseconds 200
}

$rect = New-Object Win+RECT
[Win]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = $rect.R - $rect.L
$h = $rect.B - $rect.T
Write-Host "Window: ${w}x${h} at ($($rect.L),$($rect.T))"

# PrintWindow with PW_RENDERFULLCONTENT=2 — needed for DWM-rendered WinUI windows.
$bmp = New-Object System.Drawing.Bitmap $w, $h, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $gfx.GetHdc()
$ok  = [Win]::PrintWindow($hwnd, $hdc, 2)
$gfx.ReleaseHdc($hdc)

if (-not $ok) {
    # Fall back to grabbing the screen region (loses if window is partially off-screen / occluded)
    Write-Warning "PrintWindow failed; falling back to CopyFromScreen"
    $gfx.CopyFromScreen($rect.L, $rect.T, 0, 0, (New-Object System.Drawing.Size $w, $h))
}
$gfx.Dispose()

$outDir = $PSScriptRoot
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory $outDir | Out-Null }
$path = Join-Path $outDir ("$Name.png")
$bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host "saved $path"
