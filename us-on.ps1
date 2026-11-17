#Requires -Version 5.1
# SPDX-License-Identifier: MIT
param(
    [switch]$DryRun,
    [string]$Timezone = '',
    [ValidateRange(1,65535)][int]$Port = 10800
)
. (Join-Path $PSScriptRoot 'environment-common.ps1')
Set-Location -LiteralPath $root
$python = Get-Python
if (-not (Test-Path -LiteralPath (Join-Path $root 'config.json'))) {
    throw 'Run setup.bat and configure your proxy in config.json first.'
}
# Probe does not modify Windows settings. Do not silently select a US timezone on failure.
$raw = & $python -B (Join-Path $root 'claude_clean.py') --probe
if ($LASTEXITCODE -ne 0) { throw 'Proxy probe failed; no Windows settings were changed.' }
$probe = ($raw -join "`n") | ConvertFrom-Json
if (-not $probe.ip) { throw 'Could not detect a working exit. Check your proxy before changing Windows settings.' }
$target = if ($Timezone) { $Timezone } else { $probe.timezone }
if (-not $target) { throw 'Could not determine timezone; supply -Timezone explicitly.' }
$winTimezone = Resolve-WindowsTimezone $target
$relayUrl = "http://127.0.0.1:$Port"
Write-Host "Timezone: $winTimezone; culture: en-US; user proxy: $relayUrl"
Write-Host 'This affects Windows and newly opened applications. Display language, keyboard and IPv6 are unchanged.'
if ($DryRun) { Write-Host 'Preview complete. No Windows settings or backup were changed.'; return }
if ((Get-TimeZone).Id -ne $winTimezone -and -not (Test-Administrator)) {
    throw 'Timezone change needs elevation. Reopen PowerShell as administrator using the SAME Windows account, then rerun this script.'
}
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
if (Test-Path -LiteralPath $backupPath) {
    $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
    Assert-BackupOwner $backup
} else {
    $registry = Get-ItemProperty -LiteralPath $inetKey -ErrorAction SilentlyContinue
    $registryBackup = @{}
    foreach ($name in @('ProxyEnable','ProxyServer','ProxyOverride')) {
        $property = if ($registry) { $registry.PSObject.Properties[$name] } else { $null }
        $registryBackup[$name] = @{ present=($null -ne $property); value=if($property){$property.Value}else{$null} }
    }
    $environment = @{}
    foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')) {
        $environment[$name] = [Environment]::GetEnvironmentVariable($name, 'User')
    }
    $backup = @{
        version=1; sid=$identity.User.Value; machine=$env:COMPUTERNAME
        created=(Get-Date).ToString('o'); timezone=(Get-TimeZone).Id
        culture=(Get-Culture).Name; registry=$registryBackup; environment=$environment
    }
    $backup | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $backupPath -Encoding UTF8
}
# Always expose an HTTP relay to WinINET, including for SOCKS5 upstreams.
& $python -B (Join-Path $root 'claude_clean.py') --status *> $null
if ($LASTEXITCODE -ne 0) {
    if (Test-Path -LiteralPath $relayFile) {
        throw 'A stale or mismatched relay state exists. Run environment-off.bat before retrying.'
    }
    $arguments = '-B "' + (Join-Path $root 'claude_clean.py') + '" --relay-only --port ' + $Port
    $relayProcess = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $stateDir 'relay.log') -RedirectStandardError (Join-Path $stateDir 'relay.log.err')
    for ($i=0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 250
        if ($relayProcess.HasExited) { throw 'Relay exited. Check state/relay.log.err; Windows settings have not been applied.' }
        if (Test-Path -LiteralPath $relayFile) { break }
    }
}
& $python -B (Join-Path $root 'claude_clean.py') --status *> $null
if ($LASTEXITCODE -ne 0) { throw 'Relay is not ready; Windows settings have not been applied.' }
$relayState = Get-Content -LiteralPath $relayFile -Raw | ConvertFrom-Json
$relayUrl = "http://127.0.0.1:$($relayState.port)"
try {
    if ((Get-TimeZone).Id -ne $winTimezone) { Set-TimeZone -Id $winTimezone }
    Set-Culture -CultureInfo 'en-US'
    foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')) {
        [Environment]::SetEnvironmentVariable($name, $relayUrl, 'User')
        Set-Item -Path "Env:$name" -Value $relayUrl
    }
    [Environment]::SetEnvironmentVariable('NO_PROXY','localhost,127.0.0.1','User')
    New-Item -Path $inetKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $inetKey -Name ProxyEnable -Value 1 -Type DWord
    Set-ItemProperty -LiteralPath $inetKey -Name ProxyServer -Value "127.0.0.1:$($relayState.port)" -Type String
    Set-ItemProperty -LiteralPath $inetKey -Name ProxyOverride -Value '<local>' -Type String
    Send-SettingsChanged
} catch {
    Write-Warning 'Some settings may have changed. Run environment-off.bat to restore the saved backup.'
    throw
}
Write-Host 'Applied. Reopen applications to pick up changes. Run environment-off.bat when finished.'
