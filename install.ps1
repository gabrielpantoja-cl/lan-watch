# Install lan-watch on Windows 10/11 for the current user (no admin rights needed).
#   .\install.ps1              scan every minute through Task Scheduler
#   .\install.ps1 -Voice       also speak alerts out loud while you are logged in
#   .\install.ps1 -Dashboard   also open the live dashboard in a window at logon
#       -Position "x,y"        ...maximized on the monitor that holds that point (e.g. "-1800,50")
#       -Fullscreen            ...full screen instead of a window
#   .\install.ps1 -Uninstall   remove tasks, shortcut and program (keeps config and state)
param([switch]$Voice, [switch]$Dashboard, [string]$Position = "", [switch]$Fullscreen, [switch]$Uninstall)
$ErrorActionPreference = "Stop"
$Src = $PSScriptRoot
$App = Join-Path $env:LOCALAPPDATA "Programs\lan-watch"
$Data = Join-Path $env:LOCALAPPDATA "lan-watch"
$Lnk = Join-Path ([Environment]::GetFolderPath("Startup")) "lan-watch dashboard.lnk"

function Remove-Tasks { Get-ScheduledTask -TaskName "lan-watch*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false }

if ($Uninstall) {
    Remove-Tasks
    Remove-Item -Force -ErrorAction SilentlyContinue $Lnk
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $App
    $path = [Environment]::GetEnvironmentVariable("Path", "User")
    [Environment]::SetEnvironmentVariable("Path", (($path -split ";") | Where-Object { $_ -and $_ -ne $App }) -join ";", "User")
    Write-Host "Uninstalled. Config and state kept in $Data"
    exit 0
}

# Resolve the real interpreter (not the Microsoft Store alias) and check the version.
$Py = & python -c "import sys; print(sys.executable) if sys.version_info >= (3, 11) else sys.exit(1)"
if ($LASTEXITCODE -ne 0 -or -not $Py) { throw "Python >= 3.11 is required (https://www.python.org/downloads/)" }
$PyW = Join-Path (Split-Path $Py) "pythonw.exe"  # no console window flashing every minute

New-Item -ItemType Directory -Force -Path $App, (Join-Path $App "sounds"), $Data | Out-Null
Copy-Item (Join-Path $Src "lan_watch.py") $App -Force
Copy-Item (Join-Path $Src "sounds\*.wav") (Join-Path $App "sounds") -Force
Set-Content -Encoding ascii (Join-Path $App "lan-watch.cmd") "@`"$Py`" `"%~dp0lan_watch.py`" %*"

$cfg = Join-Path $Data "config.toml"
if (-not (Test-Path $cfg)) { Copy-Item (Join-Path $Src "examples\config.example.toml") $cfg }
$dev = Join-Path $Data "devices.toml"
if (-not (Test-Path $dev)) { Copy-Item (Join-Path $Src "examples\devices.example.toml") $dev }
$topic = Join-Path $Data "ntfy-topic"
if (-not (Test-Path $topic)) {
    # The topic acts as the password of your ntfy channel: long and random.
    & $Py -c "import secrets; print('lanwatch-' + secrets.token_urlsafe(18))" | Set-Content -Encoding ascii $topic
}
$oui = Join-Path $Data "ieee-oui.txt"
if (-not (Test-Path $oui)) {
    # Vendor names for alerts; the same file arp-scan ships on Linux.
    try { Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/royhills/arp-scan/master/ieee-oui.txt" -OutFile $oui }
    catch { Write-Warning "Could not download ieee-oui.txt: alerts will say 'Vendor: unknown'" }
}

$path = [Environment]::GetEnvironmentVariable("Path", "User")
if (($path -split ";") -notcontains $App) { [Environment]::SetEnvironmentVariable("Path", "$path;$App".TrimStart(";"), "User") }

Remove-Tasks
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable
$every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "lan-watch scan" -Description "lan-watch: scan the LAN every minute" `
    -Action (New-ScheduledTaskAction -Execute $PyW -Argument "`"$App\lan_watch.py`" scan") `
    -Trigger $every -Settings $settings | Out-Null
if ($Voice) {
    $forever = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 999
    Register-ScheduledTask -TaskName "lan-watch voice" -Description "lan-watch: speak alerts out loud" `
        -Action (New-ScheduledTaskAction -Execute $PyW -Argument "`"$App\lan_watch.py`" voice") `
        -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME) -Settings $forever | Out-Null
    Start-ScheduledTask -TaskName "lan-watch voice"
}
if ($Dashboard) {
    $sh = (New-Object -ComObject WScript.Shell).CreateShortcut($Lnk)
    $sh.TargetPath = "wt.exe"
    $win = if ($Fullscreen) { "--fullscreen" } elseif ($Position) { "--pos $Position --maximized" } else { "" }
    $sh.Arguments = "$win --title lan-watch `"$Py`" `"$App\lan_watch.py`" dashboard".Trim()
    $sh.Save()
}

Write-Host "Installed in $App (config and state in $Data)."
Write-Host "Next: open a new terminal, then"
Write-Host "  lan-watch list                  # what answered; label your devices in $dev"
Write-Host "  Get-Content $topic   # subscribe your phone to this ntfy topic"
Write-Host "  lan-watch test-alert ; lan-watch arm"
