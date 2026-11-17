#Requires -Version 5.1
# SPDX-License-Identifier: MIT
param([switch]$DryRun)
. (Join-Path $PSScriptRoot 'environment-common.ps1')
if (-not (Test-Path -LiteralPath $backupPath)) {
    throw 'No environment-backup.json found. No settings were changed; do not guess the original values.'
}
$backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
Assert-BackupOwner $backup
Write-Host "Restore timezone $($backup.timezone), culture $($backup.culture), and original user proxy settings."
if ($DryRun) { Write-Host 'Preview only; nothing changed.'; return }
if ((Get-TimeZone).Id -ne $backup.timezone -and -not (Test-Administrator)) {
    throw 'Reopen PowerShell as administrator using the SAME Windows account to restore the timezone.'
}
if ((Get-TimeZone).Id -ne $backup.timezone) { Set-TimeZone -Id $backup.timezone }
Set-Culture -CultureInfo $backup.culture
foreach ($property in $backup.environment.PSObject.Properties) {
    [Environment]::SetEnvironmentVariable($property.Name, $property.Value, 'User')
    if ($property.Value) { Set-Item -Path "Env:$($property.Name)" -Value $property.Value }
    else { Remove-Item -LiteralPath "Env:$($property.Name)" -ErrorAction SilentlyContinue }
}
foreach ($property in $backup.registry.PSObject.Properties) {
    if ($property.Value.present) {
        $kind = if ($property.Name -eq 'ProxyEnable') { 'DWord' } else { 'String' }
        Set-ItemProperty -LiteralPath $inetKey -Name $property.Name -Value $property.Value.value -Type $kind
    } else {
        Remove-ItemProperty -LiteralPath $inetKey -Name $property.Name -ErrorAction SilentlyContinue
    }
}
Send-SettingsChanged
if (Test-Path -LiteralPath $relayFile) {
    $relay = Get-Content -LiteralPath $relayFile -Raw | ConvertFrom-Json
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$relay.pid)" -ErrorAction SilentlyContinue
    if ($process) {
        $expectedScript = Join-Path $root 'claude_clean.py'
        $started = [DateTimeOffset]::FromUnixTimeSeconds([long]$relay.started).UtcDateTime
        $sameStart = [Math]::Abs(($process.CreationDate.ToUniversalTime() - $started).TotalSeconds) -lt 30
        if ($sameStart -and $process.CommandLine -like "*$expectedScript*" -and $process.CommandLine -like '*--relay-only*') {
            Stop-Process -Id ([int]$relay.pid) -ErrorAction Stop
        } else {
            Write-Warning 'PID no longer matches this relay. It was not terminated.'
        }
    }
    Remove-Item -LiteralPath $relayFile
}
Write-Host 'Restored. Reopen applications. The original backup is retained; do not share it.'
