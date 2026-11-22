#Requires -Version 5.1
# SPDX-License-Identifier: MIT
[CmdletBinding()]
param(
    [ValidateSet('Open','Status','CheckExit','TestRelay','Install','Remove','Lease')][string]$Mode = 'Open',
    [ValidateRange(0,65535)][int]$Port = 0, [int]$RelayPid = 0,
    [string]$Token, [string]$ExpectedApp
)
$operation = $Mode
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'sakuracat-web.ps1') -Mode Check

function Get-DesktopDirectory {
    $p = @(Get-AppxPackage -Name Claude | Where-Object PackageFamilyName -eq 'Claude_pzs8sxrjxfjjc')
    if ($p.Count -ne 1 -or "$($p[0].Status)" -ne 'Ok') { throw '未能确认此用户安装的 Windows MSIX 桌面版。' }
    $dir = Join-Path $p[0].InstallLocation 'app'
    if (-not (Test-Path -LiteralPath (Join-Path $dir 'Claude.exe') -PathType Leaf)) { throw '桌面版安装路径已变。' }
    return $dir
}
function Invoke-DesktopRules([string]$action, [string]$dir) {
    $argsLine = '{0} "{1}"' -f $action,$dir
    if ($action -eq 'remove') { $argsLine = 'remove' }
    if ($action -eq 'lease') {
        if (-not $Port -or $RelayPid -le 0 -or $Token -cnotmatch '^[0-9a-f]{32}$' -or $ExpectedApp -ne $dir) {
            throw '桌面会话或安装位置已变。'
        }
        $sockets = @(Get-NetTCPConnection -State Listen -LocalPort $Port)
        if ($sockets.Count -ne 1 -or $sockets[0].LocalAddress -ne '127.0.0.1' -or $sockets[0].OwningProcess -ne $RelayPid) {
            throw '本次桌面版的专用转发端口未就绪。'
        }
        $argsLine += ' {0} {1} {2}' -f $Port,$RelayPid,$Token
    }
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $options = @{FilePath=$helper; ArgumentList=$argsLine; Wait=$true; PassThru=$true; WindowStyle='Hidden'}
    if (-not $admin) { $options.Verb = 'RunAs' }
    $child = Start-Process @options
    if ($child.ExitCode -ne 0) { throw "Windows 网络规则操作失败（$($child.ExitCode)）。桌面入口已停止。" }
}
try {
    $helper = Join-Path $PSScriptRoot 'desktop-wfp.exe'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw '缺少 Windows 网络保护组件，请先运行 build-desktop-guard.bat。' }
    if ($operation -eq 'Remove') {
        if (Get-Process -Name Claude -ErrorAction SilentlyContinue) { throw '请先保存工作并完全退出桌面版。' }
        Invoke-DesktopRules 'remove' ''
        return
    }
    $app = Get-DesktopDirectory
    if ($operation -eq 'Lease') { Invoke-DesktopRules 'lease' $app; return }
    if ($operation -eq 'Status') {
        & $helper status $app
        if ($LASTEXITCODE -ne 0) { throw '未核验桌面版独立断线保护，请运行 Install。' }
        return
    }
    if ($operation -ne 'CheckExit' -and (Get-Process -Name Claude -ErrorAction SilentlyContinue)) {
        throw '请先保存工作并完全退出桌面版（包括通知区），再使用此入口。'
    }
    if ($operation -eq 'Install') { Invoke-DesktopRules 'install' $app; return }
    if ($operation -in @('Open','TestRelay')) { Assert-OrdinarySession }
    $cfg = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'config.json') | ConvertFrom-Json
    if ([string]$cfg.proxy -notmatch '^http://127\.0\.0\.1:([0-9]{1,5})/?$') { throw '需要 SakuraCat 的本机 HTTP 代理。' }
    $upstream = [int]$Matches[1]
    if ($upstream -lt 1 -or $upstream -gt 65535 -or -not (Test-ClientReady $upstream)) {
        throw 'SakuraCat 未就绪，请先打开它并选好全局固定节点。'
    }
    $sessionId = (Get-Process -Id $PID).SessionId
    $clients = @(Get-Process -Name SakuraCat | Where-Object SessionId -eq $sessionId | Sort-Object StartTime)
    $workers = @(Get-NetTCPConnection -LocalPort $upstream -State Listen |
        Where-Object LocalAddress -in @('127.0.0.1','0.0.0.0','::','::ffff:127.0.0.1') | Select-Object -ExpandProperty OwningProcess -Unique)
    if (-not $clients.Count -or $workers.Count -ne 1) { throw 'SakuraCat 进程身份不明确。' }
    $controller = @(Get-NetTCPConnection -State Listen -OwningProcess $workers[0] |
        Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.LocalPort -ne $upstream })
    if ($controller.Count -ne 1) { throw '无法唯一识别 SakuraCat 的控制端口。' }
    $python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python)) { $python = (Get-Command python.exe -ErrorAction Stop).Source }
    $options = @('--upstream', $upstream, '--controller', $controller[0].LocalPort, '--desktop', $app,
                 '--client-pid', $clients[0].Id, '--worker-pid', $workers[0])
    if ($cfg.PSObject.Properties['web_require_ipv6'] -and $cfg.web_require_ipv6 -isnot [bool]) { throw 'IPv6 配置无效。' }
    if ($cfg.web_require_ipv6) { $options += '--require-ipv6' }
    if ($operation -eq 'CheckExit') { $options += '--check' }
    elseif ($operation -eq 'TestRelay') { $options += '--test-desktop-relay' }
    else {
        Write-Host '请保持此窗口开启。Windows 会询问是否临时放行本次桌面版专用端口。'
        Write-Host '保护覆盖桌面安装包。独立虚拟机、外部工具和系统代发的 DNS 请求不在这套规则内。'
    }
    & $python -B (Join-Path $PSScriptRoot 'exit_guard.py') @options
    if ($LASTEXITCODE -eq 20) { throw [System.OperationCanceledException]::new('桌面守护已提示原因。') }
    if ($LASTEXITCODE -ne 0) { throw '桌面版未通过出口检查。' }
} catch {
    if ($operation -eq 'Open' -and $_.Exception -isnot [System.OperationCanceledException]) {
        Add-Type -AssemblyName System.Windows.Forms
        [void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'Claude 桌面版断线保护','OK','Warning')
    }
    throw
}
