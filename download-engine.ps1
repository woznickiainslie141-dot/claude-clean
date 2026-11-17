#Requires -Version 5.1
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+(\.[0-9]+){3}$')][string]$Version,
    [ValidatePattern('^([a-fA-F0-9]{64})?$')][string]$Sha256 = ''
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$repository = 'adryfish/fingerprint-chromium'
$headers = @{ 'User-Agent'='claude-clean'; 'Accept'='application/vnd.github+json' }
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repository/releases/tags/$Version" -Headers $headers
$assets = @($release.assets | Where-Object { $_.name -match '_windows_x64\.zip$' })
if ($assets.Count -ne 1) { throw 'Expected exactly one Windows x64 ZIP. Choose an asset manually from the upstream Releases page.' }
$asset = $assets[0]
$url = [uri]$asset.browser_download_url
if ($url.Scheme -ne 'https' -or $url.Host -ne 'github.com' -or -not $url.AbsolutePath.StartsWith("/$repository/releases/download/")) {
    throw 'Unexpected download location.'
}
$expected = $Sha256.ToLowerInvariant()
if (-not $expected -and $asset.digest -match '^sha256:([a-fA-F0-9]{64})$') { $expected = $Matches[1].ToLowerInvariant() }
if (-not $expected) {
    throw 'Upstream did not supply a SHA256 digest. Obtain a trusted hash and pass -Sha256, or download manually after reviewing the release.'
}
$destination = Join-Path $PSScriptRoot "engines\$Version"
if (Test-Path -LiteralPath $destination) { throw 'This version already has an installation directory; no files were overwritten.' }
$archive = Join-Path ([IO.Path]::GetTempPath()) (([guid]::NewGuid().ToString()) + '.zip')
try {
    Write-Host "Downloading $($asset.name) from the upstream project..."
    Invoke-WebRequest -Uri $url.AbsoluteUri -OutFile $archive -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw 'SHA256 mismatch. Archive was not extracted.' }
    # Check archive paths before extraction; avoid absolute paths and traversal.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $boundary = [IO.Path]::GetFullPath($destination) + [IO.Path]::DirectorySeparatorChar
        foreach ($entry in $zip.Entries) {
            $candidate = [IO.Path]::GetFullPath((Join-Path $destination $entry.FullName))
            if (-not $candidate.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe path in archive.' }
        }
    } finally { $zip.Dispose() }
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Expand-Archive -LiteralPath $archive -DestinationPath $destination
    $binary = Get-ChildItem -LiteralPath $destination -Filter chrome.exe -Recurse -File | Select-Object -First 1
    if (-not $binary) { throw 'No chrome.exe found in the release.' }
    Write-Host 'Download verified and extracted. Nothing was executed.'
    Write-Host 'Set engine to fpchrome and engine_path to the executable path in config.json.'
    Write-Host $binary.FullName
    Write-Host 'Read THIRD_PARTY_NOTICES.md and retain upstream notices if redistributing binaries.'
} finally {
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive }
}
