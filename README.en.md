# Claude Clean

A Windows isolated-browser launcher and local HTTP/SOCKS5 relay, with optional reversible Windows environment settings.

[中文文档](README.md) · [MIT license](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)

**Bring your own proxy.** This project does not provide US IP addresses, accounts or subscriptions. It does not guarantee anonymity or protection from account restrictions, and is not affiliated with Anthropic.

## Quick start

For an existing native Google Chrome login, enable a manual loopback HTTP proxy in Windows, fully quit Chrome and run `protect-web.bat`. It installs and verifies a persistent outbound Windows Firewall rule for the installed Chrome executable, then opens a blank window with its normal profile. This entry point does not probe any website. It affects all windows of that Chrome installation. If the proxy disappears or Chrome tries to connect directly, non-loopback connections are blocked. Quit Chrome and run `unprotect-web.bat` to remove this rule. Check the effective policy with `web-guard.ps1 -Mode Status`. This requires a single standard Chrome installation and an enabled Windows firewall. The proxy client's own routing and changes to its exit IP, OS services and desktop applications are outside this rule's scope.

1. Install Python 3.10+ and Chrome or Edge on Windows 10/11.
2. Download and extract this repository. Run `setup.bat` to create `.venv`, install dependencies, and create `config.json` if absent.
3. Edit `proxy` in `config.json`. The example `http://127.0.0.1:7890` requires your own local proxy client listening there.
4. Run `start.bat`. Keep its terminal running while using the isolated browser.

Supported upstreams: `http://`, `socks5://`, `socks5h://`, optionally with URL-encoded username/password credentials. Both SOCKS schemes resolve destination hostnames at the proxy. The proxy server's own hostname may still be resolved locally. SOCKS4 and TLS connections to HTTPS proxy servers are not implemented. HTTP CONNECT still carries HTTPS website traffic.

In `relay: "auto"` mode, SOCKS5 and authenticated upstreams use a loopback HTTP relay. Unauthenticated HTTP upstreams can be used directly. `always` forces the relay; `never` is allowed only for unauthenticated HTTP. HTTP Basic and SOCKS5 password authentication do not themselves encrypt the proxy connection; protect remote links appropriately.

```powershell
.\.venv\Scripts\python.exe claude_clean.py --probe
.\.venv\Scripts\python.exe claude_clean.py --dry-run
.\.venv\Scripts\python.exe claude_clean.py --verify
.\.venv\Scripts\python.exe claude_clean.py --direct
```

`--dry-run` makes network probes and writes local configuration/state/report files, but does not launch a browser. `--direct` explicitly uses the existing direct connection and does not change your IP. An empty or invalid proxy configuration must not silently fall back to direct browsing.

The default example uses system Chrome/Edge (`engine: "chrome"`). Set `engine_path` if automatic discovery fails. Use a separate `profile` name for incompatible browser versions. Browser profiles isolate login data, not malicious software. Browser flags and CDP overrides may not cover workers, every frame or all traffic.

## Optional Windows settings

Run `environment-on.bat`, or preview with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\us-on.ps1 -DryRun
```

The script probes the exit, saves the initial settings to `state/environment-backup.json`, starts a loopback HTTP relay, and changes the system timezone, user culture to `en-US`, user proxy and proxy environment variables. It does not change display language, keyboard layouts or IPv6 bindings. An unknown exit/timezone stops the operation instead of guessing. `-Timezone` accepts a supported IANA name or a Windows timezone ID; `-Port` selects the relay port.

Timezone changes may require administrator PowerShell **under the same Windows account**. Restart applications to pick up settings. Restore with `environment-off.bat`. Backups are specific to the originating machine/account and are never shipped. The relay does not auto-start after reboot: rerun the on script or restore the settings. Some applications ignore user proxy settings entirely.

## Optional fingerprint-chromium

Review the upstream [releases](https://github.com/adryfish/fingerprint-chromium/releases), choose a Windows x64 version and run `download-engine.ps1 -Version <version>`. The downloader verifies a SHA256 digest from release metadata or the explicit `-Sha256` argument, checks archive paths, and extracts without executing the software. If upstream supplies no digest, obtain a trusted hash or install manually after verification. Set `engine: "fpchrome"` and the installed `engine_path`. Browser binaries are not bundled and are not covered by this project's MIT license; upstream and Chromium component notices apply.

## Privacy and limitations

Never publish `config.json`, `profiles/`, `state/`, `state.json`, `relay.json`, or `last_report.txt`. `.gitignore` excludes them from Git, but does not sanitize manually created archives. Local applications can still access loopback relay/debugging ports.

Probes contact Claude/Anthropic trace endpoints and `ip-api.com`, `ipwho.is`, `ipapi.co`; those services receive the exit IP. The free ip-api endpoint is plain HTTP. Browser verification attempts Google STUN; optional `--check` opens CleanIP. There is no project-operated telemetry endpoint. These checks cannot establish account safety or eligibility; use the service's official rules. Same-country IP addresses do not prove a shared route.

## Testing

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe claude_clean.py --selftest
.\.venv\Scripts\python.exe claude_clean.py --selftest-cdp
```

Protocol tests use loopback only. The CDP smoke test starts a temporary headless browser on a local page. See [VALIDATION.md](VALIDATION.md) for tested scope. Only share redacted diagnostics when reporting problems.
