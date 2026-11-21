#Requires -Version 5.1
# SPDX-License-Identifier: MIT
# Offline. All launch, dialog and firewall actions are recorded in memory.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'sakuracat-web.ps1'
$tempDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid().ToString()))
try {
    Copy-Item -LiteralPath $source -Destination $tempDir.FullName
    Set-Content -LiteralPath (Join-Path $tempDir 'config.json') -Value '{"proxy":"http://127.0.0.1:7890"}'
    . (Join-Path $tempDir 'sakuracat-web.ps1')

    function Test-ListenerOwnership {
        $listener = [Net.Sockets.TcpListener]::new([ipaddress]::Loopback,0)
        $listener.Start()
        try {
            $testPort = $listener.LocalEndpoint.Port
            function Get-NetTCPConnection { [pscustomobject]@{LocalAddress='127.0.0.1'; OwningProcess=98} }
            function Get-CimInstance($className) {
                if ($className -eq 'Win32_Service') { return [pscustomobject]@{State='Running'; ProcessId=97} }
                return [pscustomobject]@{Name=$worker; ProcessId=98; ParentProcessId=$parent}
            }
            $worker = 'com.vortex.helper.exe'
            $parent = 97
            if (-not (Test-SakuraListener $testPort)) { throw 'Expected local SakuraCat worker to pass.' }
            $parent = 99
            if (Test-SakuraListener $testPort) { throw 'Accepted a worker from another service.' }
            $parent = 97
            $worker = 'other.exe'
            if (Test-SakuraListener $testPort) { throw 'Accepted another executable listening on the proxy port.' }
        } finally { $listener.Stop() }
    }
    Test-ListenerOwnership

    function Test-ExistingBrowser {
        . (Join-Path (Split-Path -Parent $source) 'web-guard.ps1')
        $target = 'C:\Fixture\chrome.exe'
        function Get-Process { return $true }
        function Get-CimInstance { return [pscustomobject]@{ExecutablePath=$target; CommandLine=$line} }
        function Check-Proxy([int]$expectedPort) {
            if ($expectedPort -ne 7890 -or -not $systemProxyMatches) { throw 'System proxy differs.' }
        }
        foreach ($item in @(
            @{Tail=''; System=$true; Allowed=$true},
            @{Tail=''; System=$false; Allowed=$false},
            @{Tail=' --proxy-server=http://127.0.0.1:7890'; Allowed=$true},
            @{Tail=' "--proxy-server=http://127.0.0.1:7890"'; Allowed=$true},
            @{Tail=' --proxy-server="http://127.0.0.1:7890"'; Allowed=$true},
            @{Tail=' --proxy-server="http://127.0.0.1:7891"'; System=$true; Allowed=$false},
            @{Tail=' --proxy-server=http://127.0.0.1:7890 --no-proxy-server'; Allowed=$false},
            @{Tail=' --proxy-server=http://127.0.0.1:7890 --proxy-server=direct://'; Allowed=$false}
        )) {
            $line = $target + $item.Tail
            $systemProxyMatches = $item.System
            $allowed = $true
            try { Assert-RunningChromeProxy $target 7890 } catch { $allowed = $false }
            if ($allowed -ne $item.Allowed) { throw "Existing Chrome proxy check failed for $line" }
        }
        Write-Host 'Existing native Chrome proxy settings OK'
    }
    Test-ExistingBrowser

    function Assert-OrdinarySession {}
    function Test-ClientRunning { return $script:running }
    function Test-ClientReady([int]$port) {
        if ($port -ne 7890) { throw 'Unexpected proxy port.' }
        if ($script:readiness.Count) { $script:ready = $script:readiness.Dequeue() }
        return $script:ready
    }
    function Get-ExistingGuard { return $script:installed }
    function Get-ClientPath { return 'C:\Fixture\SakuraCat.exe' }
    function Start-Process { $script:events.Add('start-client'); $script:running = $true }
    function Confirm-WebAction($message) {
        if (-not $script:answers.Count) { throw 'Unexpected dialog.' }
        $script:events.Add('ask')
        return $script:answers.Dequeue()
    }
    $guard = {
        param($Mode,$LocalProxyPort)
        $script:events.Add("guard-$Mode$LocalProxyPort")
        if ($Mode -eq 'Status' -and $script:badRule) { throw 'Invalid firewall rule.' }
    }

    function Test-LaunchCase($label,$runningAtStart,$guardAtStart,[bool[]]$responses,
            [bool[]]$samples,$badRule,$errorPattern,$expected,$launchMode = 'Open') {
        $Mode = $launchMode
        $script:running = $runningAtStart
        $script:installed = $guardAtStart
        $script:badRule = $badRule
        $script:ready = $false
        $script:answers = [Collections.Generic.Queue[bool]]::new()
        foreach ($value in $responses) { $script:answers.Enqueue($value) }
        $script:readiness = [Collections.Generic.Queue[bool]]::new()
        foreach ($value in $samples) { $script:readiness.Enqueue($value) }
        $script:events = [Collections.Generic.List[string]]::new()
        $failure = $null
        try { Invoke-CheckedLaunch } catch { $failure = $_.Exception.Message }
        if (($errorPattern -and $failure -notlike $errorPattern) -or (-not $errorPattern -and $failure) -or
            $script:answers.Count -or ($script:events -join ',') -ne $expected) {
            throw "$label failed. Events: $($script:events -join ','). Error: $failure"
        }
        Write-Host "$label OK"
    }
    Test-LaunchCase 'Decline client' $false $false @($false) @() $false '*SakuraCat*' 'ask'
    Test-LaunchCase 'Start missing client and install guard' $false $false @($true,$true,$true) @($false,$true,$true) $false '' 'ask,start-client,ask,guard-On,guard-Status,ask,guard-Open7890'
    Test-LaunchCase 'Decline guard' $true $false @($false) @($true) $false '' 'ask'
    Test-LaunchCase 'Altered guard' $true $true @() @($true) $true '*Invalid firewall*' 'guard-Status'
    Test-LaunchCase 'Decline Chrome' $true $true @($false) @($true) $false '' 'guard-Status,ask'
    Test-LaunchCase 'Proxy drops during confirmation' $true $true @($true) @($true,$false) $false '*SakuraCat*' 'guard-Status,ask'
    Test-LaunchCase 'Existing client and guard' $true $true @($true) @($true) $false '' 'guard-Status,ask,guard-Open7890'
    Test-LaunchCase 'Client check before elevation' $true $false @() @($true) $false '' '' 'ClientOnly'
    Test-LaunchCase 'Local proxy stays unavailable' $true $true @() @($false) $false '*7890*' ''
} finally {
    foreach ($name in 'config.json','sakuracat-web.ps1') {
        $file = Join-Path $tempDir $name
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
    Remove-Item -LiteralPath $tempDir.FullName
}
