#Requires -Version 5.1
# SPDX-License-Identifier: MIT
# This fixture has its own provider and sublayer and only targets its generated socket probe.
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Windows administrator rights needed for the disposable fixture.' }
$root = Split-Path -Parent $PSScriptRoot
$base = Join-Path $env:TEMP ('desktop-wfp-test-' + [guid]::NewGuid().ToString('N'))
$target = Join-Path $base 'target'
New-Item -ItemType Directory -Path $target -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'build-desktop-guard.bat'),(Join-Path $root 'desktop-wfp.cpp') -Destination $base
$oldCl = $env:CL
try {
    $env:CL = '/DDESKTOP_GUARD_FIXTURE'
    & (Join-Path $base 'build-desktop-guard.bat')
    if ($LASTEXITCODE -ne 0) { throw 'Fixture build failed.' }
} finally { $env:CL = $oldCl }
$helper = Join-Path $base 'desktop-wfp.exe'
$probe = Join-Path $target 'socket-probe.exe'
$control = Join-Path $base 'control.exe'
Add-Type -OutputAssembly $probe -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
public static class Probe {
    public static int Main(string[] a) {
        var ip = IPAddress.Parse(a[1]);
        var port = int.Parse(a[2]);
        try {
            if (a[0] == "tcp") {
                using (var c = new TcpClient(ip.AddressFamily)) {
                    return c.ConnectAsync(ip,port).Wait(2000) ? 0 : 1;
                }
            }
            using (var c = new UdpClient(ip.AddressFamily)) {
                c.Connect(ip, port);
                byte[] query = {0x19,0x21,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,7,105,110,118,97,108,105,100,0,0,1,0,1};
                c.Send(query,query.Length);
                return 0;
            }
        } catch (SocketException) { return 1; }
          catch (AggregateException) { return 1; }
    }
}
'@
Copy-Item -LiteralPath $probe -Destination $control
function Test-Tcp($exe,$address,$port,[bool]$allowed) {
    & $exe tcp $address $port
    if (($LASTEXITCODE -eq 0) -ne $allowed) { throw "Unexpected TCP result for $address port $port." }
}
function Test-Udp($exe,$socket,[bool]$allowed) {
    $ep = $socket.Client.LocalEndPoint
    & $exe udp $ep.Address.ToString() $ep.Port
    $received = $socket.Client.Poll(300000,'SelectRead')
    if ($received) { $sender = [Net.IPEndPoint]::new([ipaddress]::Any,0); [void]$socket.Receive([ref]$sender) }
    if ($received -ne $allowed) { throw 'Unexpected DNS datagram delivery.' }
}
function Test-RuleCommand($verb) {
    if ($verb -eq 'remove') { & $helper remove } else { & $helper $verb $target }
    if ($LASTEXITCODE -ne 0) { throw "Policy $verb failed." }
}
$loop = [ipaddress]::Loopback
$proxy = [Net.Sockets.TcpListener]::new($loop,0)
$other = [Net.Sockets.TcpListener]::new($loop,0)
$v6 = [Net.Sockets.TcpListener]::new([ipaddress]::IPv6Loopback,0)
$dnsAddress = [ipaddress]::Parse('127.77.0.53')
$dns = $null
try {
    $dns = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new($dnsAddress,53))
    $dnsTcp = [Net.Sockets.TcpListener]::new($dnsAddress,53)
    $dnsTcp.Start()
} catch [Net.Sockets.SocketException] {
    if ($dns) { $dns.Dispose() }
    $dns = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new($dnsAddress,0))
    $dnsTcp = [Net.Sockets.TcpListener]::new($dnsAddress,0)
    $dnsTcp.Start()
    Write-Host 'Port 53 is occupied; using private ephemeral ports for the DNS fixture.'
}
$token = [guid]::NewGuid().ToString('N')
$prefix = 'Local\ClaudeCleanDesktop-' + $token
$ready = [Threading.EventWaitHandle]::new($false,'ManualReset',$prefix+'-ready')
$stop = [Threading.EventWaitHandle]::new($false,'ManualReset',$prefix+'-stop')
$installed = $false
$broker = $null
try {
    foreach ($listener in $proxy,$other,$v6) { $listener.Start() }
    $port = $proxy.LocalEndpoint.Port
    Test-Tcp $probe '127.0.0.1' $port $true
    Test-Tcp $probe '::1' $v6.LocalEndpoint.Port $true
    Test-Tcp $probe $dnsAddress.ToString() $dnsTcp.LocalEndpoint.Port $true
    Test-Udp $probe $dns $true
    Test-RuleCommand install
    $installed = $true
    Test-RuleCommand install
    Test-RuleCommand status
    Test-Tcp $probe '127.0.0.1' $port $false
    $broker = Start-Process $helper -WindowStyle Hidden -ArgumentList ('lease "{0}" {1} {2} {3}' -f $target,$port,$PID,$token) -PassThru
    if (-not $ready.WaitOne(10000)) { throw 'No temporary WFP permit.' }
    $duplicate = Start-Process $helper -WindowStyle Hidden -ArgumentList ('lease "{0}" {1} {2} {3}' -f $target,$other.LocalEndpoint.Port,$PID,$token) -PassThru
    if (-not $duplicate.WaitForExit(5000)) { $duplicate.Kill(); throw 'Two desktop relay leases were granted.' }
    if ($duplicate.ExitCode -eq 0) { throw 'Concurrent relay lease should fail.' }
    Test-Tcp $probe '127.0.0.1' $port $true
    Test-Tcp $probe '127.0.0.1' $other.LocalEndpoint.Port $false
    Test-Tcp $probe '::1' $v6.LocalEndpoint.Port $false
    Test-Tcp $probe $dnsAddress.ToString() $dnsTcp.LocalEndpoint.Port $false
    Test-Udp $probe $dns $false
    Test-Tcp $control '127.0.0.1' $other.LocalEndpoint.Port $true
    Test-Udp $control $dns $true
    # Force a crash of the disposable permit owner. The kernel must revoke its exception.
    $broker.Kill()
    $broker.WaitForExit()
    Test-Tcp $probe '127.0.0.1' $port $false
    Test-RuleCommand remove
    $installed = $false
    Test-RuleCommand remove
    Test-Tcp $probe '127.0.0.1' $other.LocalEndpoint.Port $true
    Write-Host 'Verified default deny, dedicated relay only, IPv6/alternate proxy/TCP and UDP DNS blocked, control unaffected, lease loss and removal.'
} finally {
    [void]$stop.Set()
    if ($broker -and -not $broker.HasExited) { [void]$broker.WaitForExit(5000) }
    if ($installed) { Test-RuleCommand remove }
    $ready.Dispose(); $stop.Dispose(); $dns.Dispose()
    foreach ($listener in $proxy,$other,$v6,$dnsTcp) { $listener.Stop() }
}
