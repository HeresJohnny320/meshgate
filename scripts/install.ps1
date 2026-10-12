# meshgate installer for Windows. Run in PowerShell as Administrator:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.ps1))) join <token>
#   & ([scriptblock]::Create((irm .../install.ps1))) join <token> --kind client
#   & ([scriptblock]::Create((irm .../install.ps1))) uninstall
#
# Environment: MESHGATE_ZIP = path to a local meshgate-windows-<arch>.zip
param(
    [Parameter(Position = 0)][string]$Action = "join",
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)][string[]]$Rest
)
$ErrorActionPreference = "Stop"
$Repo = "heresjohnny320/meshgate"
$Dir = Join-Path $env:ProgramFiles "meshgate"
$Exe = Join-Path $Dir "meshgate.exe"

function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

if ($Action -eq "uninstall") {
    if (Test-Path $Exe) { & $Exe leave -y; & $Exe service uninstall 2>$null }
    Get-NetFirewallRule -DisplayName "meshgate*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item -Recurse -Force $Dir -ErrorAction SilentlyContinue
    $p = [Environment]::GetEnvironmentVariable("Path", "Machine")
    [Environment]::SetEnvironmentVariable("Path", (($p -split ';') | Where-Object { $_ -and $_ -ne $Dir }) -join ';', "Machine")
    Say "meshgate removed. Remove this node in the web UI/TUI of another node if it is still listed."
    return
}

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
Say "Installing meshgate ($arch) to $Dir"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$zip = $env:MESHGATE_ZIP
if (-not $zip) {
    $zip = Join-Path $env:TEMP "meshgate-windows-$arch.zip"
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$Repo/releases/latest/download/meshgate-windows-$arch.zip" -OutFile $zip
}
if (Get-Service meshgate -ErrorAction SilentlyContinue) { Stop-Service meshgate -ErrorAction SilentlyContinue }
Expand-Archive -Force -Path $zip -DestinationPath $Dir

$p = [Environment]::GetEnvironmentVariable("Path", "Machine")
if (($p -split ';') -notcontains $Dir) {
    [Environment]::SetEnvironmentVariable("Path", "$p;$Dir", "Machine")
}

# WireGuard and probes arrive on UDP 51820/51822; allow meshgate.exe in.
if (-not (Get-NetFirewallRule -DisplayName "meshgate" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "meshgate" -Direction Inbound -Program $Exe -Action Allow | Out-Null
}

$conf = Join-Path $env:ProgramData "meshgate\node.json"
if (Test-Path $conf) {
    Say "Already configured; restarting"
    Restart-Service meshgate
} else {
    if ($Action -eq "join") { & $Exe join @Rest } else { & $Exe init @Rest }
    if ($LASTEXITCODE -ne 0) { throw "setup failed" }
    & $Exe service install
}

# The tunnel adapter appears as an unidentified (Public) network; make it
# Private so Windows Firewall rules for your game server apply to it.
for ($i = 0; $i -lt 20; $i++) {
    $prof = Get-NetConnectionProfile -InterfaceAlias mg0 -ErrorAction SilentlyContinue
    if ($prof) { Set-NetConnectionProfile -InterfaceAlias mg0 -NetworkCategory Private; break }
    Start-Sleep -Seconds 1
}
& $Exe status
Say "Done. Open a new PowerShell (as Administrator) and try: meshgate status | meshgate tui"
Say "Hosting a game for a VPS forward? Allow its port in Windows Defender Firewall."
