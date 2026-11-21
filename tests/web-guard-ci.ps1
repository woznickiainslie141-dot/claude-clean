# Disposable GitHub Windows runner only. No installed browser or account is used.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Integration test requires a disposable GitHub-hosted runner.'
}
$originalPF = $env:ProgramFiles
$originalPF86 = ${env:ProgramFiles(x86)}
$originalLocal = $env:LOCALAPPDATA
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The disposable test runner needs administrator privileges for this integration test.'
}
$guard = Join-Path (Split-Path -Parent $PSScriptRoot) 'web-guard.ps1'
$base = Join-Path $env:RUNNER_TEMP ([guid]::NewGuid().ToString())
$path = Join-Path $base 'Google\Chrome\Application'
New-Item -Path $path -ItemType Directory -Force | Out-Null
$exe = Join-Path $path 'chrome.exe'
# Probe a TCP endpoint only; never send HTTP, TLS, credentials or page contents.
Add-Type -OutputAssembly $exe -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
public class SocketProbe {
    public static int Main(string[] args) {
        try {
            if (args.Length == 4 && args[0].StartsWith("--proxy-server=") &&
                args[1] == "--disable-quic" && args[2] == "--new-window" && args[3] == "about:blank") {
                var proxy = new Uri(args[0].Substring("--proxy-server=".Length));
                using (var client = new TcpClient()) {
                    client.Connect(IPAddress.Loopback, proxy.Port);
                    client.GetStream().WriteByte(42);
                    return 0;
                }
            }
            var ip = IPAddress.Parse(args[0]);
            using (var client = new TcpClient(ip.AddressFamily)) {
                return client.ConnectAsync(ip, int.Parse(args[1])).Wait(3500) ? 0 : 1;
            }
        } catch (Exception) { return 1; }
    }
}
'@
$publicIP = ([Net.Dns]::GetHostAddresses('github.com') | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).ToString()
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
$listener.Start()
try {
    $env:ProgramFiles = $base
    ${env:ProgramFiles(x86)} = Join-Path $base 'unused'
    $env:LOCALAPPDATA = Join-Path $base 'unused-local'
    Write-Host 'Testing unprotected TCP baseline'
    & $exe $publicIP 443
    if ($LASTEXITCODE -ne 0) { throw 'Unprotected TCP baseline unavailable.' }
    Write-Host 'Installing and verifying temporary rule'
    & $guard -Mode On
    & $guard -Mode On
    & $guard -Mode Status
    & $guard -Mode Open -LocalProxyPort $listener.LocalEndpoint.Port -WaitForGuardedChrome
    if (-not $listener.Pending()) { throw 'The stand-in browser did not reach its specified guard port.' }
    $probeClient = $listener.AcceptTcpClient()
    try {
        if ($probeClient.GetStream().ReadByte() -ne 42) { throw 'Wrong test browser launch arguments.' }
    } finally { $probeClient.Close() }
    & $exe '127.0.0.1' $listener.LocalEndpoint.Port
    if ($LASTEXITCODE -ne 0) { throw 'Guard unexpectedly blocked the local proxy.' }
    & $exe $publicIP 443
    if ($LASTEXITCODE -eq 0) { throw 'Guard allowed direct outbound TCP.' }
    $listener.Stop()
    & $exe $publicIP 443
    if ($LASTEXITCODE -eq 0) { throw 'Guard allowed direct traffic after proxy loss.' }
    & $guard -Mode Off
    & $exe $publicIP 443
    if ($LASTEXITCODE -ne 0) { throw 'Direct TCP was not restored after removing guard.' }
    Write-Host 'Verified direct TCP before, loopback only during, direct TCP after.'
} finally {
    $listener.Stop()
    $env:ProgramFiles = $originalPF
    ${env:ProgramFiles(x86)} = $originalPF86
    $env:LOCALAPPDATA = $originalLocal
}
