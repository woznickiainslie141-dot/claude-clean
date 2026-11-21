#Requires -Version 5.1
# SPDX-License-Identifier: MIT
[CmdletBinding()]
param(
    [ValidateSet('On','Off','Status','Open','CheckEgress')][string]$Mode = 'Status',
    [string]$CallerSid,
    [ValidateRange(0,65535)][int]$LocalProxyPort = 0,
    [switch]$WaitForGuardedChrome
)
$ErrorActionPreference = 'Stop'
$ruleName = 'ClaudeClean.NativeChrome.LoopbackOnly.v1'
$ruleGroup = 'Claude Clean native Chrome privacy'
# All IPv4 except 127/8 and all routable IPv6 except ::1. Split by family
# to avoid the Windows dynamic "Internet" keyword (it can omit LAN/VPN).
$ranges = @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')

function Find-Chrome {
    $paths = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    $installed = @($paths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -Unique)
    if ($installed.Count -ne 1) { throw 'Expected exactly one standard Google Chrome installation. Protection could not be verified for your browser.' }
    return (Get-Item -LiteralPath $installed[0]).FullName
}

function Find-Rule([string]$store) {
    try {
        return Get-NetFirewallRule -PolicyStore $store -Name $ruleName -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound_*,Get-NetFirewallRule') { return }
        throw
    }
}

function Assert-Owned($rule) {
    if ($rule.Group -ne $ruleGroup) { throw 'A firewall rule name is already in use. It has been left untouched.' }
}

function Assert-Firewall {
    if ((Get-Service MpsSvc).Status -ne 'Running') { throw 'Windows Defender Firewall service is not running.' }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3 -or @($profiles | Where-Object {
        "$($_.Enabled)" -ne 'True' -or "$($_.AllowLocalFirewallRules)" -eq 'False' -or "$($_.DisabledInterfaceAliases)" -notin @('','NotConfigured')
    }).Count) { throw 'Windows Firewall has a disabled profile/interface or disallows local rules. Protection is unverified.' }
}

function Address-Key([string]$range) {
    # ActiveStore may format the high IPv4 half as a /1 subnet.
    if ($range -eq '128.0.0.0/1') { return '128.0.0.0-255.255.255.255' }
    $ends = $range.Split('-')
    if ($ends.Count -ne 2) { return $range }
    return ([ipaddress]::Parse($ends[0])).ToString() + '-' + ([ipaddress]::Parse($ends[1])).ToString()
}

function Assert-Effective([string]$chrome) {
    Assert-Firewall
    $rule = Find-Rule 'ActiveStore'
    if (-not $rule) { throw 'No active guard rule. Use On before opening Chrome.' }
    Assert-Owned $rule
    if ("$($rule.Enabled)" -ne 'True' -or $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block' -or "$($rule.Profile)" -ne 'Any' -or $rule.PrimaryStatus -ne 'OK') {
        throw 'Active firewall rule differs from the required outbound block.'
    }
    $app = $rule | Get-NetFirewallApplicationFilter
    $address = $rule | Get-NetFirewallAddressFilter
    $port = $rule | Get-NetFirewallPortFilter
    $observed = @($address.RemoteAddress | ForEach-Object { Address-Key $_ })
    if ([Environment]::ExpandEnvironmentVariables($app.Program) -ne $chrome -or
        "$($port.Protocol)" -ne 'Any' -or "$($port.RemotePort)" -ne 'Any' -or "$($port.LocalPort)" -ne 'Any' -or
        "$($address.LocalAddress)" -ne 'Any' -or (Compare-Object $ranges $observed)) {
        throw 'Active firewall program, addresses or ports could not be verified.'
    }
}

function Assert-ChromeClosed {
    if (Get-Process -Name chrome -ErrorAction SilentlyContinue) {
        throw 'Save your work and fully quit Chrome (including background processes), then retry. No process was terminated.'
    }
}

function Check-Proxy([int]$expectedPort = 0) {
    $settings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($settings.ProxyEnable -ne 1 -or $settings.AutoConfigURL -or
        $settings.ProxyServer -notmatch '^(127\.0\.0\.1|\[::1\]):([0-9]{1,5})$') {
        throw 'Set Windows to a manual local HTTP proxy such as 127.0.0.1:7890. The firewall guard continues blocking direct connections.'
    }
    $ip = [ipaddress]::Parse($Matches[1].Trim('[',']'))
    $port = [int]$Matches[2]
    if ($expectedPort -and ($port -ne $expectedPort -or -not $ip.Equals([ipaddress]::Loopback))) {
        throw 'Chrome is already open. Fully quit it to start with the checked SakuraCat proxy.'
    }
    $socket = New-Object Net.Sockets.TcpClient $ip.AddressFamily
    try {
        if (-not $socket.ConnectAsync($ip, $port).Wait(1500)) { throw 'Local proxy timeout.' }
    } finally { $socket.Dispose() }
}

function Assert-RunningChromeProxy([string]$chrome, [int]$port) {
    # A running Chrome instance can ignore a second process's proxy switch.
    if (-not (Get-Process -Name chrome -ErrorAction SilentlyContinue)) { return }
    $running = @(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" |
        Where-Object { $_.CommandLine -notmatch '(?:^|\s)"?--type=' })
    if (-not $running.Count) { throw 'Chrome is starting. Wait for it or quit it before retrying.' }
    foreach ($instance in $running) {
        if ($instance.ExecutablePath -ne $chrome -or -not $instance.CommandLine -or
            $instance.CommandLine -match '(?:^|\s)"?--(?:no-proxy-server|proxy-pac-url|proxy-auto-detect|proxy-bypass-list)\b') {
            throw 'Could not confirm the running Chrome proxy. Fully quit Chrome, then retry.'
        }
        $switches = [regex]::Matches($instance.CommandLine,'(?i)(?:^|\s)"?--proxy-server\b')
        if ($switches.Count -eq 0) { Check-Proxy $port; continue }
        if ($switches.Count -ne 1 -or $instance.CommandLine -notmatch "(?:^|\s)\x22?--proxy-server=\x22?http://127\.0\.0\.1:$port\x22?(?:\s|$)") {
            throw 'Running Chrome uses another proxy. Quit it before retrying.'
        }
    }
}

if ($MyInvocation.InvocationName -eq '.') { return }
if ($Mode -in @('Open','CheckEgress')) {
    . (Join-Path $PSScriptRoot 'web-egress.ps1')
    Assert-WebEgressPolicy -ShowWarning
    if ($Mode -eq 'CheckEgress') { return }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($CallerSid -and $CallerSid -ne $identity.User.Value) { throw 'Run as the same Windows account.' }
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Mode -in @('On','Off') -and -not $isAdmin) {
    if ($CallerSid) { throw 'Elevation did not produce an administrator token.' }
    $argsLine = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode {1} -CallerSid {2}' -f $PSCommandPath,$Mode,$identity.User.Value)
    $child = Start-Process powershell.exe -Verb RunAs -ArgumentList $argsLine -Wait -PassThru
    if ($child.ExitCode -ne 0) { throw 'Guard change did not complete. Read the elevated error and check Status.' }
    return
}
if ($Mode -eq 'Off') {
    $existing = Find-Rule 'PersistentStore'
    if ($existing) {
        Assert-Owned $existing
        Assert-ChromeClosed
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName
    }
    if (Find-Rule 'ActiveStore') { throw 'The rule is still active.' }
    Write-Host 'Chrome web guard: OFF.'
    return
}
$chrome = Find-Chrome
if ($Mode -eq 'On') {
    Assert-Firewall
    $existing = Find-Rule 'PersistentStore'
    if ($existing) { Assert-Owned $existing } else {
        Assert-ChromeClosed
        New-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -Group $ruleGroup -DisplayName 'Claude Clean - restrict native Chrome to loopback' -Program $chrome -Action Block -Direction Outbound -Enabled True -Profile Any -Protocol Any -RemoteAddress $ranges | Out-Null
    }
}
Assert-Effective $chrome
Write-Host "Chrome web guard: ACTIVE for $chrome (all windows)."
if ($Mode -eq 'Open') {
    if ($WaitForGuardedChrome) {
        if (-not $LocalProxyPort) { throw 'The guarded session requires its local monitor port.' }
        Assert-ChromeClosed
        foreach ($key in 'HKCU:\Software\Policies\Google\Chrome','HKLM:\Software\Policies\Google\Chrome','HKLM:\Software\WOW6432Node\Policies\Google\Chrome') {
            if ((Test-Path -LiteralPath $key) -and
                (((Get-Item -LiteralPath $key).GetValueNames() -match '^Proxy') -or (Test-Path -LiteralPath (Join-Path $key 'ProxySettings')))) {
                throw 'A Windows Chrome proxy policy may override the session proxy. Launch stopped.'
            }
        }
        $arguments = @("--proxy-server=http://127.0.0.1:$LocalProxyPort",'--disable-quic',
            '--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--new-window','about:blank')
        $browser = Start-Process -FilePath $chrome -ArgumentList $arguments -PassThru
        $browser.WaitForExit()
        return
    }
    if ($LocalProxyPort) {
        Assert-RunningChromeProxy $chrome $LocalProxyPort
        $arguments = @("--proxy-server=http://127.0.0.1:$LocalProxyPort",'--new-window','about:blank')
        Start-Process -FilePath $chrome -ArgumentList $arguments
    } else {
        Check-Proxy
        Start-Process -FilePath $chrome -ArgumentList '--new-window about:blank'
    }
}
