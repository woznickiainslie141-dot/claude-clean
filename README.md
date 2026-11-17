# Claude Clean

Windows 上的独立浏览器启动器、HTTP / SOCKS5 代理中继，以及可还原的系统环境设置工具。

[English](README.en.md) · [来源与第三方许可](THIRD_PARTY_NOTICES.md) · [MIT 许可证](LICENSE)

**你需要自己准备可用的代理。** 本项目不提供美国 IP、代理节点、账号或订阅。它可以按代理出口设置浏览器的时区和语言，但不能保证匿名、所有网络流量都经过代理，或账号不被限制。它与 Anthropic 没有隶属或合作关系。

## 功能

- 以独立的浏览器资料目录启动 Chrome / Edge，保留自己的登录状态。
- 检测服务域名和 IP 查询服务看到的出口，提示地址或时区差异。
- 用浏览器调试协议设置页面时区和 locale；尝试限制非代理 WebRTC 流量。
- 将 HTTP 或 SOCKS5 上游转换为本机 HTTP 代理，支持用户名密码认证和远程目标域名解析。
- 可选修改 Windows 时区、区域格式、用户代理和代理环境变量，并从本机备份还原。
- 可选使用独立下载的 [fingerprint-chromium](https://github.com/adryfish/fingerprint-chromium)。指纹内核不是本项目开发的。

## 安装：第一次使用

需要 **Windows 10/11、Python 3.10+、Chrome 或 Edge**。Python 从 [python.org](https://www.python.org/downloads/windows/) 安装；请启用命令行访问。

1. 在本仓库选择 **Code → Download ZIP** 并解压，或使用 Git 克隆仓库。
2. 双击 `setup.bat`。它创建 `.venv` 并安装 `requirements.txt` 中的依赖，只在配置不存在时复制配置模板。
3. 用文本编辑器打开生成的 `config.json`，把 `proxy` 改成自己的代理地址。
4. 双击 `start.bat`。终端需要保持开启；关闭该独立浏览器后会结束本次会话。

默认配置 `http://127.0.0.1:7890` 只是常见的本地代理示例，该端口必须确实有你的代理客户端监听。下载包不含任何人的浏览器资料、代理订阅或已安装内核。

手动安装与运行：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item config.example.json config.json  # 仅首次；已有配置不要覆盖
.\.venv\Scripts\python.exe claude_clean.py
```

### 代理配置

`config.json` 必须是合法 JSON，不能写注释。可使用以下任一种 `proxy` 值：

```json
"http://127.0.0.1:7890"
"socks5://127.0.0.1:1080"
"socks5h://127.0.0.1:1080"
"http://username:password@proxy.example.com:8080"
"socks5://username:password@proxy.example.com:1080"
```

上面是单独的值示例，不是完整配置文件。用户名和密码中的 `@`、`:`、`/` 等字符需进行 URL 编码，例如 `@` 写成 `%40`。不要把真实配置贴到公开 Issue。

本项目的 `socks5://` 和 `socks5h://` 都通过中继把目标域名交给 SOCKS5 服务器解析。代理服务器自身如果用域名表示，仍需本机解析。不支持 `socks4://` 和连接代理服务器本身使用 TLS 的 `https://` 上游；`http://` 上游仍可通过 CONNECT 访问 HTTPS 网站。HTTP Basic 和 SOCKS5 密码认证自身不提供传输加密，远程使用需有可信的受保护网络链路。

### 常用配置项

| 字段 | 默认 / 含义 |
|---|---|
| `proxy` | 自备上游代理；空值仅在明确传入 `--direct` 时用于直连 |
| `relay` | `auto`：无认证 HTTP 可以直连上游；SOCKS5 和有认证的上游使用中继。也可用 `always`；`never` 仅允许无认证 HTTP |
| `engine` | 示例默认 `chrome`，自动寻找系统 Chrome / Edge；`fpchrome` 用于可选内核；`auto` 优先搜索 `engines/` |
| `engine_path` | 可选，明确指定浏览器可执行文件完整路径。Windows 路径在 JSON 中用双反斜杠或正斜杠 |
| `locale` / `timezone` | 留空按查询结果选择；可显式设置，例如 `en-US` / `America/Los_Angeles` |
| `profile` | 默认 `claude`；仅支持英文字母、数字、下划线和连字符 |
| `fingerprint_seed` | `0` 表示首次生成并存入本机配置；仅可选指纹内核使用此值 |
| `start_urls` | 启动时打开的页面；示例为 Claude 新对话页 |
| `open_check_page` | 默认 `false`；启用后额外打开 CleanIP 网站 |

## 日常操作与检测

```powershell
.\.venv\Scripts\python.exe claude_clean.py --probe        # 出口 JSON；会访问外网
.\.venv\Scripts\python.exe claude_clean.py --dry-run      # 预检，不启动浏览器；会写本机配置/报告
.\.venv\Scripts\python.exe claude_clean.py --verify       # 临时无头浏览器检测；会访问外网
.\.venv\Scripts\python.exe claude_clean.py --engine chrome
.\.venv\Scripts\python.exe claude_clean.py --direct       # 明确直连：不更换 IP
```

`--verify` 只是在当次临时浏览器中的有限检查，不代表所有站点、iframe、worker 或后续浏览器版本都不会泄露信息。独立资料目录也是登录隔离，不是虚拟机或恶意软件隔离环境。

## 可选：同时调整 Windows 环境

只使用独立浏览器时不必做这一步。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\us-on.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\us-on.ps1
```

也可以双击 `environment-on.bat`。若需要改系统时区，脚本会提示用**同一 Windows 账号**打开管理员 PowerShell 再运行。不要使用另一个管理员账号，否则会修改错误用户的代理设置。

此操作会：

1. 检查代理出口；检测失败时停止，不自动猜测美国时区。
2. 首次保存 `state/environment-backup.json`，后续执行不覆盖原始备份。
3. 启动仅监听 `127.0.0.1` 的 HTTP 中继，默认端口 `10800`。
4. 修改系统时区、当前用户区域格式为 `en-US`、Windows 用户代理，以及 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`。

显示语言、键盘和 IPv6 绑定不修改。已有程序可能需要重开，部分程序也可能不遵循用户代理或环境变量。重启 Windows 后中继不会自动启动；如果仍要使用，重新执行切换脚本；否则及时还原代理设置。

还原：双击 `environment-off.bat`，或运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\us-off.ps1
```

备份仅适用于生成它的电脑和账号，请勿删除、共享或从旧版本直接复制。原始备份会保留；若要建立新基线，应先成功还原，再把旧备份移到安全位置。`-Timezone` 可指定 Windows 时区 ID；用 `Get-TimeZone -ListAvailable` 查询。可用 `-Port 10801` 更改中继端口。

## 可选：指纹内核

系统 Chrome / Edge 是默认选择。若确有需要，自行查看上游 [Releases](https://github.com/adryfish/fingerprint-chromium/releases)，选择 Windows x64 版本后执行：

```powershell
.\download-engine.ps1 -Version <上游版本号>
```

脚本从上游获取压缩包，校验 SHA256 后解压到 `engines/`，不会执行下载文件。上游没有提供校验值时必须传入从可信来源得到的 `-Sha256`，或自行核验后手动安装。下载不代表自动更新，版本选择和后续更新由使用者负责。

把 `engine` 设置为 `fpchrome`，`engine_path` 设置为脚本输出的 `chrome.exe` 路径。不同大版本建议使用不同的 `profile` 名称，避免资料格式不兼容。再分发该内核须保留它及 Chromium 第三方组件的许可；本仓库不分发内核二进制。

## 数据、来源和限制

- 本地敏感数据：`config.json`、`profiles/`、`state/`、`state.json`、`relay.json` 和 `last_report.txt`。已被 `.gitignore` 排除；手动 ZIP 打包仍需自行排除它们。
- 预检会访问 `claude.ai`、`api.anthropic.com`、`platform.claude.com`、`ip-api.com`、`ipwho.is`、`ipapi.co`。IP 查询服务会收到出口 IP；`ip-api.com` 的免费端点为 HTTP 明文。`--verify` 还会尝试 Google STUN，`--check` 会打开 CleanIP。无自建遥测服务器。
- 本机中继和浏览器调试端口只供本机使用。本机其他程序仍可能连接这些端口；不应将它们暴露到局域网或公网。
- IP 地理库、运营商关键词和内置地区列表只是粗略提示，不是服务商的官方判断。同一国家的两个 IP 不能证明同一节点。请以 [Anthropic 官方地区说明](https://www.anthropic.com/supported-countries) 和服务条款为准。
- 本项目从 DSH 辅助生成的个人脚本整理，来源与参考关系见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。公开版专注 Windows 核心流程；私人诊断工具和手机支付相关笔记未纳入。

## 测试与故障排查

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe claude_clean.py --selftest
.\.venv\Scripts\python.exe claude_clean.py --selftest-cdp
```

前两项只用本机回环网络；第三项启动临时无头浏览器并在本地页面验证时区和 locale，不读取个人浏览器资料。发布验证记录见 [VALIDATION.md](VALIDATION.md)。

| 问题 | 处理 |
|---|---|
| 缺少 Python / 模块 | 安装 Python 后重跑 `setup.bat`；使用 `.venv` 中的 Python |
| 代理连接失败 | 确认客户端已启动、端口及协议正确，检查 `--probe` 结果 |
| SOCKS5 认证失败 | 检查账号密码、URL 编码及服务器允许的认证方式 |
| 不同域名出口不同 | 检查客户端分流；`clash-snippet.yaml` 是需合并的规则示例 |
| 找不到浏览器 | 在 `engine_path` 指定真实可执行文件路径 |
| 浏览器马上退出 | 关闭使用同一个 `profile` 的旧窗口，或为新版本设置新资料目录 |
| 中继状态过期 / 端口占用 | 先还原，确认端口空闲后重新切换；不要停止不明进程 |
| 切换后系统网络异常 | 执行 `environment-off.bat`，重开相关程序 |

提交问题时只提供脱敏后的错误信息；不要上传 Cookies、完整配置、浏览记录或系统备份。
