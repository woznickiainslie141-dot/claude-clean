#Requires -Version 5.1
# SPDX-License-Identifier: MIT
function Get-WebEgressBlockReason {
    try {
        $raw = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'config.json') -ErrorAction Stop
        if ($raw -notmatch '^\s*\{') { throw 'Expected an object.' }
        $cfg = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    } catch {
        return '无法读取 Chrome 保护设置（config.json）。为避免直连，已停止启动。'
    }
    $setting = $cfg.PSObject.Properties['web_require_verified_ipv4']
    if ($setting -and $setting.Value -isnot [bool]) {
        return 'Chrome 保护设置 web_require_verified_ipv4 必须为 true 或 false。已停止启动。'
    }
    if (-not $setting -or $setting.Value) {
        return '受保护的 Chrome 已停止启动。检测站只能确认它自己看到的 IPv4。当前代理无法保证所有网站都看到已核验的那个 IPv4，因此不会放行。'
    }
}

function Assert-WebEgressPolicy([switch]$ShowWarning) {
    $reason = Get-WebEgressBlockReason
    if ($reason) {
        if ($ShowWarning) {
            Add-Type -AssemblyName System.Windows.Forms
            [void][Windows.Forms.MessageBox]::Show($reason, 'Chrome 出口保护', 'OK', 'Warning')
        }
        throw $reason
    }
}
