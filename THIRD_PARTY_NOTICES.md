# 来源与第三方许可 / Provenance and third-party notices

核查日期：2026-11-18。

Claude Clean 是从 DSH 辅助生成的个人 Python / PowerShell 脚本整理出来的集成工具。初始交付没有 Git 历史，因此不能完整重建每一段代码的生成过程；不宣称本项目实现了浏览器内核，也不宣称它是下面任何项目的官方版本。此次公开整理重新实现了 SOCKS5 协商和 Windows 切换/还原脚本，移除了个人资料与针对单台电脑的说明，并补充了测试。

项目自身的脚本、测试和新编写文档按根目录 [MIT LICENSE](LICENSE) 发布。第三方组件保持其原有许可；本项目的 MIT 许可不覆盖 Chromium、可选浏览器二进制或下面仅供参考的第三方作品。项目名称及商标仍归各自权利人所有，列出来源不表示上游背书。

## 实际使用的可选组件

| 项目 | 使用方式 | 许可及处理 |
|---|---|---|
| [adryfish/fingerprint-chromium](https://github.com/adryfish/fingerprint-chromium) | 可选外部浏览器进程；下载器从它的 Releases 下载 Windows x64 ZIP。本仓库没有浏览器源码或二进制 | 上游仓库标注 BSD-3-Clause；[上游许可证](https://github.com/adryfish/fingerprint-chromium/blob/main/LICENSE) 的原文存于 [LICENSES/fingerprint-chromium-BSD-3-Clause.txt](LICENSES/fingerprint-chromium-BSD-3-Clause.txt) |

上游 LICENSE 的版权署名为 `The ungoogled-chromium Authors`，原样保留。核查时该 LICENSE 文件的 Git blob SHA 为 `fedda042293952c0e6fd2863e82f081d53a96300`。BSD-3-Clause 要求按分发形式保留版权、条件和免责声明，并禁止未经许可用作者名称背书。若自行重新分发完整浏览器，还必须检查并保留 Chromium 及捆绑第三方组件自己的许可、版权和其他适用要求；这一份 BSD 文件不是完整浏览器所有组件的统一授权。

## 原始说明记录的参考项目

下表描述原始说明中的参考关系，不表示本仓库打包了这些项目。此次整理未从这些项目导入源文件。仅参考检测维度、使用思路或把外部网站用作交叉检查，与复制具体源码、文档或美术素材是不同的关系。

| 项目 | 原始说明中的关系 | 已核查的许可信息 |
|---|---|---|
| [newtv-ai/CLAUDE-SHIELD](https://github.com/newtv-ai/CLAUDE-SHIELD) | IP、DNS、WebRTC、时区/语言等检测维度和代理环境配置思路 | [package.json](https://github.com/newtv-ai/CLAUDE-SHIELD/blob/main/package.json) 标注 `MIT`；核查时未找到独立根目录 LICENSE。没有擅自补写作者版权声明或把该声明当成完整的来源证明 |
| [yacuo/check-cc](https://github.com/yacuo/check-cc) | 环境信号的交叉验证参考 | MIT；原始许可保存在 [LICENSES/check-cc-MIT.txt](LICENSES/check-cc-MIT.txt)，作为来源记录，不代表打包了其实现 |
| [sunreview/anti-claude](https://github.com/sunreview/anti-claude) | 出口变化等社区经验参考 | 未将其文档作为本项目内容再分发 |
| [proxyShard/ShardBrowser](https://github.com/proxyshard/shardbrowser) | 按代理出口选择时区/语言的思路参考 | 未引入闭源二进制或代码 |
| [Wtcity22/Open-Anti-Browser](https://github.com/Wtcity22/Open-Anti-Browser) | 根据 IP 选择语言与时区的思路参考 | 不凭“公开仓库”推定授权；未引入其源文件 |
| [daijro/camoufox](https://github.com/daijro/camoufox) | 原始笔记讨论过的替代内核 | 本项目未集成或分发 |
| [Lee-xeo/Claude-Cage](https://github.com/Lee-xeo/Claude-Cage)、[sylvinus/agent-vm](https://github.com/sylvinus/agent-vm) | 原始笔记中的虚拟机路线比较 | 本项目未集成或分发 |

`CLAUDE-SHIELD` 的 package.json 核查 blob SHA：`9164572a4dcd515637ee4028053689d5992ce040`。CheckCC LICENSE 核查 blob SHA：`02927b254b55fb7899a7f2aeecdd25880afa5436`。未来若引入上述项目的实际代码或资源，须重新核查对应版本许可，保留必要通知；不能只靠此表完成再分发义务。

## 安装时下载的 Python 依赖

本仓库不打包这些依赖的源码或 wheel；安装器通过 pip 安装它们及其依赖，原包许可仍然适用。

| 依赖 | 用途 | 上游 |
|---|---|---|
| Requests | 出口 HTTP 查询 | [项目与许可](https://github.com/psf/requests)，Apache-2.0 |
| websocket-client | 本机浏览器 CDP WebSocket | [项目与许可](https://github.com/websocket-client/websocket-client)，Apache-2.0 |
| tzdata | Windows 上的 IANA 时区数据库 | [项目与许可](https://github.com/python/tzdata)；Python 包 Apache-2.0，IANA 时区数据有独立来源声明 |

SOCKS5 协议实现依据 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)；用户名密码协商依据 [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)。本项目采用本地套接字测试验证报文格式，没有复制 RFC 全文。
