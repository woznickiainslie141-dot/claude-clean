#Requires -Version 5.1
# SPDX-License-Identifier: MIT
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$stateDir = Join-Path $root 'state'
$backupPath = Join-Path $stateDir 'environment-backup.json'
$relayFile = Join-Path $root 'relay.json'
$inetKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()

function Get-Python {
    $localPython = Join-Path $root '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $localPython) { return $localPython }
    $command = Get-Command python -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'Run setup.bat first (Python 3.10+ is required).'
}

function Test-Administrator {
    return (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-BackupOwner($backup) {
    if ($backup.sid -ne $identity.User.Value -or $backup.machine -ne $env:COMPUTERNAME) {
        throw 'This backup belongs to another Windows user or computer. Do not apply it.'
    }
}

function Resolve-WindowsTimezone([string]$name) {
    $map = @{
        'America/Los_Angeles'='Pacific Standard Time'; 'America/Vancouver'='Pacific Standard Time'
        'America/Denver'='Mountain Standard Time'; 'America/Phoenix'='US Mountain Standard Time'
        'America/Chicago'='Central Standard Time'; 'America/New_York'='Eastern Standard Time'
        'America/Toronto'='Eastern Standard Time'; 'America/Sao_Paulo'='E. South America Standard Time'
        'Europe/London'='GMT Standard Time'; 'Europe/Dublin'='GMT Standard Time'
        'Europe/Berlin'='W. Europe Standard Time'; 'Europe/Amsterdam'='W. Europe Standard Time'
        'Europe/Paris'='Romance Standard Time'; 'Europe/Madrid'='Romance Standard Time'
        'Europe/Rome'='W. Europe Standard Time'; 'Europe/Zurich'='W. Europe Standard Time'
        'Europe/Stockholm'='W. Europe Standard Time'; 'Europe/Oslo'='W. Europe Standard Time'
        'Europe/Copenhagen'='Romance Standard Time'; 'Europe/Helsinki'='FLE Standard Time'
        'Europe/Warsaw'='Central European Standard Time'
        'Asia/Tokyo'='Tokyo Standard Time'; 'Asia/Seoul'='Korea Standard Time'
        'Asia/Singapore'='Singapore Standard Time'; 'Asia/Taipei'='Taipei Standard Time'
        'Asia/Hong_Kong'='China Standard Time'; 'Asia/Shanghai'='China Standard Time'
        'Asia/Kolkata'='India Standard Time'; 'Asia/Calcutta'='India Standard Time'
        'Australia/Sydney'='AUS Eastern Standard Time'; 'Pacific/Auckland'='New Zealand Standard Time'
        'UTC'='UTC'; 'Etc/UTC'='UTC'
    }
    if ($map.ContainsKey($name)) { return $map[$name] }
    if (Get-TimeZone -Id $name -ErrorAction SilentlyContinue) { return $name }
    throw 'Unknown timezone. Supply -Timezone with a valid Windows timezone ID from Get-TimeZone -ListAvailable.'
}

function Send-SettingsChanged {
    if (-not ('ClaudeClean.Native' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace ClaudeClean {
 public static class Native {
  [DllImport("wininet.dll", SetLastError=true)]
  public static extern bool InternetSetOption(IntPtr h, int option, IntPtr buffer, int length);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, UIntPtr w, string l, uint f, uint t, out UIntPtr r);
 }
}
'@
    }
    [ClaudeClean.Native]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
    [ClaudeClean.Native]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
    $result = [UIntPtr]::Zero
    [ClaudeClean.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 3000, [ref]$result) | Out-Null
}
