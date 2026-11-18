# A Windows node for real: Wintun adapter, the service, the local API pipe.
# Usage (as Administrator): smoke.ps1 <folder with meshgate.exe> <amd64|arm64>
param([string]$Dir, [string]$Arch)
$ErrorActionPreference = "Stop"
Invoke-WebRequest https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile "$env:RUNNER_TEMP/wintun.zip"
Expand-Archive "$env:RUNNER_TEMP/wintun.zip" -DestinationPath "$env:RUNNER_TEMP/wt" -Force
Copy-Item "$env:RUNNER_TEMP/wt/wintun/bin/$Arch/wintun.dll" $Dir
$mg = Join-Path $Dir "meshgate.exe"
& $mg version
& $mg init --role controller -y --name win --admin-pass labpassword
if ($LASTEXITCODE -ne 0) { exit 1 }
& $mg service install
if ($LASTEXITCODE -ne 0) { exit 1 }
for ($i = 0; $i -lt 30; $i++) { & $mg status *> $null; if ($LASTEXITCODE -eq 0) { break }; Start-Sleep 1 }
& $mg status
if ($LASTEXITCODE -ne 0) { Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10 | Format-List; exit 1 }
Get-NetIPAddress -InterfaceAlias mg0 -AddressFamily IPv4
& $mg service uninstall
if ($LASTEXITCODE -ne 0) { exit 1 }
