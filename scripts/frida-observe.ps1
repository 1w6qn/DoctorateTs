# scripts/frida-observe.ps1 - Windows Frida observer for game Lua bundle reads
#
# Flow:
#   1) Stop ACE(AntiCheatExpert) service (anti-cheat off during observe; needs admin).
#   2) Spawn Arknights.exe under frida with hook/observe-assetbundle.js, logging
#      anon/Bundles file opens into tmp/frida-observe.log.
#   3) After timeout (default 120s) or Ctrl+C, restore ACE service.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\frida-observe.ps1 -Seconds 180 -Log tmp\frida-observe.log
param(
  [int]$Seconds = 150,
  [string]$Log = "tmp\frida-observe.log",
  [string]$GameExe = "E:\Games\Hypergryph Launcher\games\Arknights Game\Arknights.exe"
)
$ErrorActionPreference = "Continue"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$script = Join-Path $root "hook\observe-assetbundle.js"
$logAbs = Join-Path $root $Log

# --- 1) handle ACE anti-cheat ---
$aceService = "AntiCheatExpert Protection"
Write-Host "[frida-observe] stopping ACE service: $aceService"
$wasRunning = (Get-Service -Name $aceService -ErrorAction SilentlyContinue).Status -eq "Running"
if ($wasRunning) {
  try { Stop-Service -Name $aceService -Force -ErrorAction Stop; Write-Host "[frida-observe] ACE stopped" }
  catch { Write-Host "[frida-observe][WARN] stop ACE failed: $($_.Exception.Message)" }
} else {
  Write-Host "[frida-observe] ACE already stopped"
}
Get-Process -Name "ACE-Service*","AntiCheatExpert*","Arknights*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# --- 2) launch observe ---
Write-Host "[frida-observe] observing up to $Seconds s (Ctrl+C to cut short); log: $logAbs"
$proc = $null
try {
  if (-not (Test-Path $GameExe)) { throw "game not found: $GameExe" }
  $fridaArgs = @("-f", ('"'+$GameExe+'"'), "-l", ('"'+$script+'"'), "-o", ('"'+$logAbs+'"'), "--realm=native")
  $proc = Start-Process -FilePath "frida" -ArgumentList $fridaArgs -PassThru -NoNewWindow
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $Seconds -and -not $proc.HasExited) {
    Start-Sleep -Milliseconds 500
  }
  if (-not $proc.HasExited) {
    Write-Host "[frida-observe] timeout reached, stopping"
    $proc | Stop-Process -Force -ErrorAction SilentlyContinue
  }
  Get-Process -Name "Arknights*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
} catch {
  Write-Host "[frida-observe][ERR] $($_.Exception.Message)"
}

# --- 3) restore ACE ---
if ($wasRunning) {
  try { Start-Service -Name $aceService -ErrorAction Stop; Write-Host "[frida-observe] ACE restored" }
  catch { Write-Host "[frida-observe][WARN] restore ACE failed: $($_.Exception.Message)" }
}
Write-Host "[frida-observe] done. log: $logAbs"

if (Test-Path $logAbs) {
  Write-Host "==== anon/Bundles reads observed ===="
  Select-String -Path $logAbs -Pattern "\[open\].*anon|\[assetbundle\]|hooked|started" | ForEach-Object { $_.Line }
}