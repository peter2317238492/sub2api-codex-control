<p align="center">
  <img src="apps/pwa/public/icon.svg" width="88" height="88" alt="Sub2API Codex Control 图标">
</p>

<h1 align="center">Sub2API Codex Control</h1>

<p align="center">
  无需在设备上开放入站端口，通过浏览器安全使用自己的 Codex。
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="#普通用户快速开始">快速开始</a> ·
  <a href="https://github.com/peter2317238492/sub2api-codex-control/releases">发布下载</a> ·
  <a href="docs/installation.zh-CN.md">安装指南</a> ·
  <a href="docs/usage.zh-CN.md">使用手册</a> ·
  <a href="docs/visual-guide.zh-CN.md">图形化指南</a> ·
  <a href="docs/operations.zh-CN.md">运维指南</a> ·
  <a href="SECURITY.md">安全策略</a>
</p>

<p align="center">
  <a href="https://github.com/peter2317238492/sub2api-codex-control/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/peter2317238492/sub2api-codex-control/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="发布状态" src="https://img.shields.io/badge/status-release%20candidate-E6A23C">
  <img alt="Codex 版本" src="https://img.shields.io/badge/Codex-0.147.0-111827">
  <img alt="Sub2API 版本" src="https://img.shields.io/badge/Sub2API-0.2.0-2563EB">
  <a href="LICENSE"><img alt="许可证" src="https://img.shields.io/badge/license-Apache--2.0-22C55E"></a>
</p>

> [!IMPORTANT]
> 当前仓库发布的是**源码候选版**，尚未发布正式签名的 GitHub Release 和受支持安装包。
> 不要把可变工作区、自行构建的二进制或未签名镜像当作生产版本。只有 GitHub 出现不可变
> 标签 Release 后，才应按对应发布说明安装。

## 发布下载

所有受支持的下载都会发布在仓库的
[GitHub Releases 页面](https://github.com/peter2317238492/sub2api-codex-control/releases)。
源码候选版仍在审查期间，该页面保持为空是正常现象。

| 使用者 | Release 标签 | 受支持的下载路径 |
| --- | --- | --- |
| 普通用户 | `connector-v*` | 优先使用 Control PWA 显示的安装包与 SHA-256；同一签名 `.deb` 或 `.rpm` 必须存在于对应 GitHub Release |
| 服务器管理员 | `control-v*` | 下载 online/offline 服务器包及其证据，再按[正式部署流程](docs/runbooks/deployment.md)操作 |

不要把 GitHub 自动生成的 **Source code** 压缩包当作生产安装包。如果 PWA 元数据、Release
标签、文件名或 SHA-256 任一不完全一致，应立即停止，不要改用其他文件。

## 一眼看懂

| | 说明 |
| --- | --- |
| **解决什么问题** | 在手机或另一台电脑的浏览器中，查看并控制自己设备上的 Codex |
| **如何连接** | 用户设备只主动建立出站 WSS，不开放入站端口 |
| **谁可以使用** | 每个已登录的 Sub2API 普通用户，只能看到并管理自己的设备和线程 |
| **谁负责配置** | Sub2API 管理员一次性启用站点；原生包安装后，配置、配对、使用和撤销均由用户自助完成 |
| **安全边界** | 固定八类 RPC、工作区白名单、沙箱上限、限时审批，不提供原始远程 shell |
| **支持平台** | Connector 支持 Linux `amd64` / `arm64`；本次发布不支持 macOS 与 Windows |

## 项目介绍

Sub2API Codex Control 是与 Sub2API 同源部署的自托管 Codex 控制平面，由三个小型组件组成：

| 组件 | 运行位置 | 职责 |
| --- | --- | --- |
| **Control PWA** | 浏览器 | 设备、线程、流式对话、审批与撤销 |
| **Control API** | Sub2API 服务器 | 短期会话、用户隔离、可靠派发与审计状态 |
| **Connector** | 用户的 Codex 设备 | 仅出站 WSS，并通过 stdio 启动固定版本的 `codex app-server` |

Connector 不开放设备入站端口，也不会修改 Codex 配置、登录凭据、工作区、插件或 shell
配置。每个普通 Sub2API 用户都拥有并管理自己的设备；配置、配对、使用和撤销不需要
Sub2API 管理员协助。安装系统包仍可能需要本机 `sudo`。

```mermaid
flowchart LR
    B["浏览器 /codex/"] -->|"同源 HTTPS + WSS"| E["Nginx 边缘"]
    E --> A["Control API"]
    A --> D[("PostgreSQL + Redis")]
    A --> S["Sub2API 身份"]
    C["用户设备上的 Connector"] -->|"仅出站 WSS"| E
    C -->|"stdio"| X["Codex app-server 0.147.0"]
```

## 核心能力

- **普通用户自助管理。** 登录后可选择匹配的安装包；完成本机安装授权后，可复制初始化命令、
  配对并撤销自己的设备，无需 Sub2API 管理员介入。
- **只允许八类操作。** 远程仅开放 `model/list`、`thread/start`、`thread/list`、
  `thread/read`、`thread/resume`、`turn/start`、`turn/steer` 和 `turn/interrupt`。
- **审批默认拒绝。** 命令、文件变更和权限审批均为单次、限时、绑定连接世代；超时或失联即拒绝。
- **设备本地决定边界。** 当前正式管理命令只准入一个设备本地工作区，并将沙箱上限固定为
  `workspace-write`；直接扩大边界会被拒绝。
- **没有原始远程 shell。** shell/exec、任意文件或进程访问、配置修改、账号登录、插件安装和
  原始 RPC 透传都会在进入 Codex 前被拒绝。
- **正式发布与恢复门禁。** 仓库内置签名源码、不可变镜像、备份恢复、数据隔离、回滚和监控工具。

## 普通用户快速开始

以下流程适用于正式 `connector-v*` Release 发布，并且你的 Sub2API 站点已启用 Control 之后。

开始前准备好：已登录的 Sub2API 账号、安装了准确版本 Codex CLI 的 Linux 设备、
至少一个允许远程使用的绝对工作区路径，以及到站点 TCP 443 的出站网络。你不需要 Sub2API
管理员创建设备、下发配对码或代为修改 Connector 配置。原生包安装可能要求本机 `sudo` 或
这与 Sub2API 管理权限无关。

### 1. 登录

先在正常站点根路径登录 Sub2API，再打开同一域名下的 Control PWA：

```text
https://control.example.com/codex/
```

Control 会将当前 Sub2API access 会话换成短期 HttpOnly 会话。Sub2API refresh 凭据不会进入
Control API。

### 2. 下载、校验并安装

在左侧设备栏点击下载图标，或在空状态点击**安装 Connector**。选择与你的系统和架构一致的
安装包，下载后执行 PWA 给出的校验与安装命令。只有 SHA-256 完全一致时才继续安装。

| 平台 | 支持的安装包 | 安装命令 |
| --- | --- | --- |
| Debian / Ubuntu `amd64`、`arm64` | `.deb` | `sudo apt install ./sub2api-codex-connector_*.deb` |
| Fedora / RHEL `amd64`、`arm64` | `.rpm` | `sudo dnf install ./sub2api-codex-connector_*.rpm` |

PWA 会给出精确文件名和校验命令。Linux 安装使用本机 `sudo`。
本机管理员凭据；Sub2API 管理员不需要代为创建设备或完成配对。

后续 Connector 命令必须由拥有 Codex 和工作区的普通用户执行，不要以 `root` 运行。

### 3. 创建私密配置

正式向导一次初始化一个工作区。在 PWA 填写设备名称和绝对工作区路径后，以拥有 Codex 的
普通用户执行页面给出的命令，创建 mode `0600` 私密配置：

```sh
sub2api-codex-connector-ctl init \
  --origin https://control.example.com \
  --workspace /absolute/path/to/workspace \
  --display-name "我的工作站"
```

配置路径固定为 `$HOME/.config/sub2api-codex-connector/connector.json`，确保交互命令与用户
后台服务读取同一个文件；非空的 `XDG_CONFIG_HOME` override 会被拒绝。

管理命令会用配置 SHA-256 将该文件绑定到私密 v2 布局，请勿直接编辑。当前正式命令只支持
每个 Connector 一个工作区。需要更换时，先在 PWA 撤销设备，再停止并清除受管状态，最后
重新执行 `init`、`pair` 和 `start`；多工作区和沙箱上限变更尚未提供受控命令。

### 4. 配对并认领设备

```sh
sub2api-codex-connector-ctl pair
```

`pair` 会提示一个 mode `0600` 文件路径，文件内是一组一次性配对码。保持命令运行，在 PWA
点击**配对已有 Connector**并输入 16 位配对码，直到命令确认认领并退出。不要把配对码粘贴
到聊天、日志或公开 Issue。

### 5. 启动服务

只有 `pair` 已确认网页认领后，才以同一普通用户启动后台服务：

```sh
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

Linux 包安装用户级 `systemd` 服务。安装和升级不会修改现有
Codex 文件。

### 6. 使用 Codex

1. 在 PWA 选择在线设备。
2. 在该设备允许的工作区根目录内新建线程。
3. 选择模型并发送文本输入。
4. 仔细确认每个审批；过期或未处理的审批会自动拒绝。
5. 可在 PWA 中引导或中断当前 turn、恢复托管线程，或归档空闲线程。

## 界面速览

| 区域 | 用途 |
| --- | --- |
| 顶栏 | 查看实时连接状态、打开待审批列表、刷新会话或安全退出 |
| 设备栏 | 安装或配对 Connector、切换设备、查看在线状态及撤销设备 |
| 线程栏 | 搜索、新建、选择和归档当前设备的托管线程 |
| 对话区 | 发送消息；运行中继续输入会引导当前 turn；停止按钮会中断当前 turn |
| 审批抽屉 | 查看来源、类型、详情和到期时间，再明确批准或拒绝一次性请求 |

## 常用命令

```sh
# 显示私密配置文件路径
sub2api-codex-connector-ctl config-path

# 服务生命周期
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl stop
sub2api-codex-connector-ctl restart
sub2api-codex-connector-ctl status

# 查看最近的用户服务日志
sub2api-codex-connector-ctl logs
```

设备退役时，应先在 PWA 撤销设备。卸载原生包只删除安装包拥有的文件，保留用户的私密
Connector 状态；确认不再需要后，用户可以显式清除自己的状态：

```sh
sub2api-codex-connector-ctl purge-user-state --yes
```

对于 v2 受管配置，该命令拒绝以 root 执行；删除两个 Connector 自有目录前，会重新校验配置
SHA-256、所有者、权限、symlink，以及记录的配置、状态、工作区和 `CODEX_HOME` 是否存在
任意重叠。没有可信布局的旧配置会被拒绝清除，不会猜测删除范围。

## 常见问题

| 现象 | 检查项 |
| --- | --- |
| PWA 自动返回 Sub2API | 先在 `/` 登录，再打开同一域名的 `/codex/`。 |
| 配对一直不完成 | 保持 `connector-ctl pair` 运行，检查系统时间、HTTPS origin、出站 WSS 和配对码是否过期。 |
| Codex 版本被拒绝 | 安装准确的 `codex-cli 0.147.0`；Connector 会主动阻止协议漂移。 |
| 受管配置被修改 | 不要直接编辑 `connector.json`；先在 PWA 撤销设备，再停止、清除并重新初始化。 |
| 旧配置缺少后台绑定 | 以当前普通 Codex 用户运行一次 `sub2api-codex-connector-ctl start`，将未改变的旧配置与当前 Codex 绝对路径绑定。 |
| `XDG_CONFIG_HOME` 被拒绝 | 先备份旧配置及其引用的状态，在不覆盖目标文件的前提下复制到固定路径，目录设为 `0700`、文件设为 `0600`，再取消 override；按安装指南的迁移步骤操作。 |
| 工作区被拒绝 | 使用已存在的绝对路径，且不要与 Connector 状态目录或 `CODEX_HOME` 重叠。 |
| 设备离线 | 运行 `connector-ctl status` 和 `connector-ctl logs`，检查出站 TLS。 |
| 审批突然消失 | 审批可能已过期、已处理、属于其他用户，或在重连后失效。 |

首次配置、日常对话、审批、恢复、归档、撤销、注销和数据边界见完整
[使用手册](docs/usage.zh-CN.md)。

## 用户与管理员边界

| 普通用户自行完成 | 仅服务器管理员负责 |
| --- | --- |
| 下载匹配的 Connector、创建私密配置 | 部署并升级 Control 服务 |
| 初始化唯一允许的工作区（当前沙箱上限固定为 `workspace-write`） | 配置 TLS、Nginx、数据库和 Redis 隔离 |
| 配对、启动、诊断和撤销自己的设备 | 发布并签名可信安装包和镜像 |
| 新建线程、对话、审批、中断和归档 | 执行备份、恢复演练、回滚和监控 |

正常使用不需要 Sub2API 管理员接触用户的设备、Codex 登录信息、工作区内容或配对码。平台
要求时，原生包安装仍属于本机操作系统授权步骤。

## 服务器管理员

生产部署不是一条简单的 Compose 命令。管理员必须从已验证的服务器安装包部署同一精确版本，
并满足以下准入条件：

1. Sub2API 和 Control 使用不可变镜像身份；
2. 具备新鲜、仅 root 可读的完整备份，并完成隔离恢复演练；
3. PostgreSQL 使用专用所有权，Redis 使用认证且限制前缀的 ACL；
4. Nginx/TLS 保持同源路由，内部服务只绑定回环地址；
5. 源码、镜像锁、SBOM、来源证明和回滚证据均已签名验证；
6. 完成认证后的浏览器/设备验收与告警送达验证。

先从 [Releases 页面](https://github.com/peter2317238492/sub2api-codex-control/releases)
取得同一签名 `control-v*` 版本，按[部署手册](docs/runbooks/deployment.md)认证、解包和安装，
并结合[备份与回滚](docs/runbooks/backups-and-rollback.md)
和[可观测性](docs/runbooks/observability.md)。直接执行迁移、直接 `docker compose up` 或从工作区
部署都会绕过必要门禁，不属于受支持的生产路径。

## 本地开发

需要 Node.js 22+、pnpm 11+、Python 3.12+、Go 1.24+、Docker Compose v2、
PostgreSQL 16+、Redis 7+ 和 Codex CLI `0.147.0`。

```sh
git clone https://github.com/peter2317238492/sub2api-codex-control.git
cd sub2api-codex-control
pnpm install
pnpm dev
```

一次性全栈验收会构建真实 Connector，但使用模拟 Sub2API 权限服务和遵循协议的假 Codex
app-server。它只能作为开发证据，不能替代生产验收：

```sh
install -d -m 0700 "$HOME/.local/state/sub2api-codex-control/e2e-reports"
CONTROL_E2E_REPORT_DIR="$HOME/.local/state/sub2api-codex-control/e2e-reports" \
  ./tests/e2e/run-local.sh
```

## 仓库结构

```text
apps/control-api/          FastAPI 控制平面
apps/pwa/                  Vue 3 同源 PWA
connector/                 Go 编写的仅出站 Connector
connector/packaging/       原生安装包和服务定义
packages/control-protocol/ 共享协议类型和策略
packages/appserver-schema/ 固定的 Codex 0.147.0 schema
migrations/                Alembic 数据库迁移
deploy/                    发布、部署、备份和监控工具
tests/e2e/                 一次性系统验收环境
docs/                      用户、管理员、合约与安全文档
```

## 文档导航

| 读者 | 文档 |
| --- | --- |
| 普通用户 | [安装指南](docs/installation.zh-CN.md) · [使用手册](docs/usage.zh-CN.md) |
| 服务器管理员 | [运维指南](docs/operations.zh-CN.md) · [生产运行手册](docs/runbooks/README.md) |
| 发布管理员 | [Connector 发布策略](connector/release/README.md) · [Control 发布策略](deploy/release/README.md) |
| 安全审查者 | [威胁模型与 ADR](docs/adr/) · [版本矩阵](docs/runbooks/version-matrix.md) |
| 贡献者 | [贡献指南](CONTRIBUTING.md) · [安全策略](SECURITY.md) |

## 安全与许可

请按照 [SECURITY.md](SECURITY.md) 通过 GitHub 私密漏洞报告功能提交安全问题。不要在公开 Issue
中包含凭据、配对码、私密路径、生产日志或用户数据。

项目使用 [Apache License 2.0](LICENSE)。第三方署名见 [NOTICE](NOTICE) 和
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。这是独立社区项目，不隶属于 OpenAI 或
Sub2API 项目，也未获得其背书或赞助。
