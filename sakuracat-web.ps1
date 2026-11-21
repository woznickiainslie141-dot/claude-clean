#Requires -Version 5.1
# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([ValidateSet('Open','ClientOnly','Check','ResetExit')][string]$Mode = 'Open')

$ErrorActionPreference = 'Stop'
$guard = Join-Path $PSScriptRoot 'web-guard.ps1'

function Confirm-WebAction([string]$message) {
    Add-Type -AssemblyName System.Windows.Forms
    $answer = [Windows.Forms.MessageBox]::Show($message, 'Chrome 启动前检查', 'YesNo', 'Question', 'Button2')
    return $answer -eq [Windows.Forms.DialogResult]::Yes
}

function Get-ClientPath($cfg) {
    if ($cfg.sakuracat_path) {
        $path = [string]$cfg.sakuracat_path
    } else {
        $shell = New-Object -ComObject WScript.Shell
        $path = $null
        foreach ($folder in 'DesktopDirectory','CommonDesktopDirectory','Programs','CommonPrograms') {
            $base = [Environment]::GetFolderPath($folder)
            foreach ($relative in 'SakuraCat.lnk','SakuraCat\SakuraCat.lnk') {
                $link = Join-Path $base $relative
                if (Test-Path -LiteralPath $link -PathType Leaf) {
                    $candidate = $shell.CreateShortcut($link).TargetPath
                    if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf) -and
                        [IO.Path]::GetFileName($candidate) -ieq 'SakuraCat.exe') { return $candidate }
                }
            }
        }
    }
    if (-not $path -or -not [IO.Path]::IsPathRooted($path) -or
        [IO.Path]::GetFileName($path) -ine 'SakuraCat.exe' -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw '找不到 SakuraCat.exe。请手动打开客户端，或在本机 config.json 中填写 sakuracat_path。'
    }
    return $path
}

function Test-ClientRunning {
    $session = (Get-Process -Id $PID).SessionId
    return [bool](Get-Process -Name 'SakuraCat' -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session)
}

function Assert-OrdinarySession {
    $user = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($user.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '请从普通桌面双击启动入口。只有设置防火墙时需要管理员权限。'
    }
}

function Test-SakuraListener([int]$port) {
    # Test only the local listener. No DNS or website request is needed.
    $socket = [Net.Sockets.TcpClient]::new()
    try {
        if (-not $socket.ConnectAsync([ipaddress]::Loopback,$port).Wait(500)) { return $false }
    } catch { return $false }
    finally { $socket.Dispose() }
    $service = Get-CimInstance Win32_Service -Filter "Name='com.vortex.helper'"
    if (-not $service -or $service.State -ne 'Running') { return $false }
    $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in @('127.0.0.1','0.0.0.0','::','::ffff:127.0.0.1') })
    if (-not $listeners.Count) { return $false }
    foreach ($listener in $listeners) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$listener.OwningProcess)"
        if (-not $process -or $process.Name -ine 'com.vortex.helper.exe' -or
            $service.ProcessId -notin @($process.ProcessId,$process.ParentProcessId)) { return $false }
    }
    return $true
}

function Test-ClientReady([int]$port) {
    return ((Test-ClientRunning) -and (Test-SakuraListener $port))
}

function Get-ExistingGuard {
    try { return Get-NetFirewallRule -Name 'ClaudeClean.NativeChrome.LoopbackOnly.v1' -PolicyStore ActiveStore -ErrorAction Stop }
    catch {
        if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound_*,Get-NetFirewallRule') { return }
        throw
    }
}

function Start-ExitGuard([int]$port) {
    if (Get-Process -Name chrome -ErrorAction SilentlyContinue) {
        throw '请保存工作、完全退出 Chrome（包括后台进程），再启动受出口保护的会话。'
    }
    $listener = @(Get-NetTCPConnection -LocalPort $port -State Listen | Where-Object { $_.LocalAddress -in @('127.0.0.1','0.0.0.0','::','::ffff:127.0.0.1') })
    $owners = @($listener.OwningProcess | Select-Object -Unique)
    if ($owners.Count -ne 1 -or -not (Test-SakuraListener $port)) { throw '无法核验 SakuraCat 代理进程。' }
    $local = @(Get-NetTCPConnection -State Listen -OwningProcess $owners[0] |
        Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.LocalPort -ne $port })
    if ($local.Count -ne 1) { throw '无法唯一识别 SakuraCat 的本机控制端口，已停止启动。' }
    $python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python)) { $python = (Get-Command python.exe -ErrorAction Stop).Source }
    Write-Host '本窗口负责持续核验代理和出口。关闭窗口会中断受保护会话的代理连接。'
    & $python -B (Join-Path $PSScriptRoot 'exit_guard.py') --upstream $port --controller $local[0].LocalPort
    if ($LASTEXITCODE -ne 0) { throw '出口保护会话已停止。' }
}

function Invoke-CheckedLaunch {
    if ($Mode -eq 'ResetExit') {
        if (Get-Process -Name chrome -ErrorAction SilentlyContinue) { throw '请先完全退出 Chrome。' }
        $pin = Join-Path $PSScriptRoot 'state\web-exit.json'
        if ((Test-Path -LiteralPath $pin) -and (Confirm-WebAction '忘记已确认的 Chrome 出口？下次启动时须重新核对并确认新地址。')) {
            Remove-Item -LiteralPath $pin
        }
        return
    }
    $cfg = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'config.json') | ConvertFrom-Json
    if ([string]$cfg.proxy -notmatch '^http://127\.0\.0\.1:([0-9]{1,5})/?$') { throw '此入口需要在 config.json 设置本机 HTTP 代理，例如 http://127.0.0.1:7890。' }
    $port = [int]$Matches[1]
    if ($port -lt 1 -or $port -gt 65535) { throw 'config.json 的代理端口无效。' }
    if ($Mode -eq 'Check') {
        $running = Test-ClientRunning
        $ready = Test-SakuraListener $port
        $guardState = '未启用'
        if (Get-ExistingGuard) { & $guard -Mode Status; $guardState = '已核验' }
        Write-Host "SakuraCat 运行=$running，本机代理端口 $port 就绪=$ready，Chrome 断线保护=$guardState"
        return
    }

    if (-not (Test-ClientRunning)) {
        if (-not (Confirm-WebAction 'SakuraCat 尚未运行。现在启动它，并等待本机代理就绪吗？')) {
            throw '已取消启动 SakuraCat。'
        }
        Assert-OrdinarySession
        $client = Get-ClientPath $cfg
        Start-Process -FilePath $client -WorkingDirectory (Split-Path -Parent $client)
    }
    if (-not (Test-ClientReady $port)) {
        Write-Host "正在等待 SakuraCat 的本机代理端口 $port，请确认客户端已经连接……"
        $timer = [Diagnostics.Stopwatch]::StartNew()
        do {
            Start-Sleep -Milliseconds 600
            $ready = Test-ClientReady $port
        } until ($ready -or $timer.Elapsed.TotalSeconds -ge 30)
        if (-not $ready) { throw "SakuraCat 或其本机 HTTP 代理端口 $port 尚未就绪，已停止启动。" }
    }
    if ($Mode -eq 'ClientOnly') { return }
    Assert-OrdinarySession

    if (-not (Get-ExistingGuard)) {
        if (-not (Confirm-WebAction 'Chrome 断线保护尚未启用。现在启用吗？首次启用前请保存工作并完全退出 Chrome。Windows 随后会请求管理员权限。')) { return }
        & $guard -Mode On
    }
    & $guard -Mode Status
    if (-not (Confirm-WebAction '启用持续出口保护并打开 Chrome 空白窗口吗？程序会仅经代理定期向 ipify 核对出口。首次需确认可信 IP。')) { return }
    if (-not (Test-ClientReady $port)) { throw '确认期间 SakuraCat 或本机代理已停止，已取消打开 Chrome。' }
    Start-ExitGuard $port
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-CheckedLaunch }
