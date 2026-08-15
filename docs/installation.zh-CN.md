# 安装

[English](installation.md) | [文档索引](../README.zh-CN.md#文档导航)

## 先选择正确的安装路径

当前有三条完全不同的路径：

1. 隔离 E2E 路径现在可用，用一次性基础设施验证源码。
2. 正式签名的 `connector-v*` Release 发布后，普通用户选择对应原生包，并在安装后通过 PWA
   自助完成配置。原生包安装可能需要本机操作系统管理员授权。
3. 首个公开源码版本不能直接安装到生产。它尚未发布生产安装所需的完整签名证据。

Connector 目前可从源码构建用于开发与评估。在上述签名 Release 出现之前，不提供受支持的
预编译 Connector。

受支持的发布资产只会出现在仓库的
[GitHub Releases 页面](https://github.com/peter2317238492/sub2api-codex-control/releases)。
不要把 GitHub 自动生成的源码压缩包当作安装包。

本文命令假设使用 Linux 或 macOS 的 POSIX shell。当前源码支持这两个 Connector 运行目标，
不支持 Windows Connector。

## 隔离全栈验证

开发机需要：

- Git；
- Docker Engine 和 Docker Compose v2；
- Go 1.24 或更高版本；
- Go race detector 支持的 C 工具链；
- Python 3 和 OpenSSL；
- `amd64` 或 `arm64` Docker daemon；
- 足够的本地资源，用于构建和运行 PostgreSQL、Redis、Control API、PWA、Nginx 及测试夹具。

克隆公开仓库，并把生成的验收证据放在工作区之外：

```sh
git clone https://github.com/peter2317238492/sub2api-codex-control.git
cd sub2api-codex-control
install -d -m 0700 "$HOME/.local/state/sub2api-codex-control/e2e-reports"
CONTROL_E2E_REPORT_DIR="$HOME/.local/state/sub2api-codex-control/e2e-reports" \
  ./tests/e2e/run-local.sh
```

测试会自行生成凭据和临时 Docker 资源，并使用模拟 Sub2API 权限服务和遵循协议的假
Codex app-server；它不会使用真实账号或真实供应商密钥。除非为了调试设置 `KEEP_E2E=1`，
测试结束后会自动清理。

测试通过会覆盖同源路由、配对、允许的 RPC、审批、重连、撤销、数据存储隔离和秘密处理，
但不能证明真实账号登录、真实 Codex canary、公网 TLS、生产 WSS 或发布真实性。

## 安装签名 Connector 包

仅在仓库发布不可变、已签名的 `connector-v*` GitHub Release，并且 Control PWA 显示同一
精确版本后使用此流程。打开
[Releases 页面](https://github.com/peter2317238492/sub2api-codex-control/releases)，选择该
精确 `connector-v*` 标签，并确认 PWA 指向完全相同的标签、文件名和 SHA-256。Release
说明会列出六个受支持的原生包，不要混用其他标签的文件。

在 PWA 的设备栏点击下载图标，或在空状态点击**安装 Connector**，
选择操作系统和架构，下载安装包，再执行页面给出的校验与安装命令。只有下载文件的 SHA-256
完全一致时才继续安装。

| 平台 | 安装包 | 安装命令 |
| --- | --- | --- |
| Debian / Ubuntu `amd64`、`arm64` | `.deb` | `sudo apt install ./sub2api-codex-connector_*.deb` |
| Fedora / RHEL `amd64`、`arm64` | `.rpm` | `sudo dnf install ./sub2api-codex-connector_*.rpm` |
| macOS Intel、Apple 芯片 | 已签名并公证的 `.pkg` | `open ./sub2api-codex-connector_*.pkg` |

此安装步骤不需要 Sub2API 管理员，但 Linux 会使用本机 `sudo`，macOS Installer 也可能要求
本机管理员凭据。

安装包只安装 Connector、用户级服务定义和管理命令，不会安装或升级 Codex。安装完成后，
其余命令均由拥有 Codex 和目标工作区的普通用户执行。

## 创建私密配置

正式向导一次初始化一个工作区。在 PWA 填写设备名称和已存在的绝对工作区路径后，以拥有
Codex 的普通用户执行页面给出的管理命令。等价命令形式如下：

```sh
sub2api-codex-connector-ctl init \
  --origin https://control.example.com \
  --workspace /absolute/path/to/workspace \
  --display-name "我的工作站"
```

命令会把配置写入以下路径，并自动使用 mode `0600`：

```text
$HOME/.config/sub2api-codex-connector/connector.json
```

这是正式版本的固定配置路径。非空的 `XDG_CONFIG_HOME` override 会被拒绝，避免交互命令与
安装包提供的用户服务读取不同文件。

确认实际路径：

```sh
sub2api-codex-connector-ctl config-path
```

私密配置只在设备本地创建并保存，不要将其提交到 Git、发送到聊天或交给管理员。新初始化会
把当前 `codex` 命令解析为绝对可执行路径，并把最终文件 SHA-256 绑定到私密 v2 受管布局。
不要直接编辑 `connector.json`；摘要变化后，配对、启动和后台服务入口都会默认拒绝。当前
正式命令一次只初始化一个工作区，尚未提供多工作区或沙箱上限的受控修改命令。需要更换
工作区时，先在 PWA 撤销设备，再停止并清除 v2 受管状态，最后重新执行 `init`、`pair` 和
`start`。

### 无损迁移旧配置

固定路径上已有的 mode `0600` 旧配置如果没有受管布局，仍可使用 `pair`、`start` 和
`run-service`；Connector 会继续校验配置结构，并使用当前有效的 `CODEX_HOME`。由于没有可信
删除边界，`purge-user-state` 会拒绝清除此类旧配置。请先以当前普通用户交互运行一次
`sub2api-codex-connector-ctl start`：它会把未改变的配置摘要与当前 Codex 绝对路径写入私有
绑定。绑定缺失或不再匹配时，后台启动会直接拒绝，不会静默使用错误程序。

如果旧安装使用了非空 `XDG_CONFIG_HOME`，先停止 Connector，并以 mode `0600` 分别备份其
`connector.json` 和 `state_dir` 指向的状态目录。确认
`$HOME/.config/sub2api-codex-connector` 尚不存在后，把旧配置复制而不是移动到固定路径，将
目标目录设为 `0700`、`connector.json` 设为 `0600`，取消设置 `XDG_CONFIG_HOME`，再运行
`pair` 和 `start`。设备重新在线且确认状态保留前，不要删除旧文件或备份。如果固定路径已经
存在，保持两份文件不动并人工处理冲突，绝不能覆盖。

## 配对并启动

配置完成后开始配对：

```sh
sub2api-codex-connector-ctl pair
```

保持 `pair` 运行。它会提示一个 mode `0600` 文件路径，文件内是一组一次性配对码；在已登录
的 PWA 点击**配对已有 Connector**并输入该配对码。保持命令运行，直到它确认网页认领并
退出；只有此后才以同一普通用户启动用户服务并确认状态：

```sh
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

Linux 包安装用户级 `systemd` 服务，macOS 包安装 `launchd` agent。升级和卸载会保留用户的
私密 Connector 状态。对于 v2 受管配置，需要彻底清除时，先在 PWA 撤销设备，再运行
`sub2api-codex-connector-ctl purge-user-state --yes`；没有可信布局的旧配置应按上述无损迁移
指引处理。

## 从源码构建 Connector 用于开发

此路径仅用于开发与评估，不属于生产安装。安装 Go 1.24 或更高版本及
`codex-cli 0.147.0`。Connector 应以拥有目标 Codex 和工作区的同一个普通用户运行，
不要用 root 运行。

```sh
cd connector
go test ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o sub2api-codex-connector ./cmd/connector
```

创建私密配置目录并复制示例：

```sh
install -d -m 0700 "$HOME/.config/sub2api-codex-connector"
install -m 0600 connector.example.json \
  "$HOME/.config/sub2api-codex-connector/connector.json"
```

只编辑私密副本。替换 `control.example.com`、`display_name`、`state_dir` 和
`workspace_roots`。所有路径必须是绝对路径，工作区根目录必须已经存在。状态目录不能与工作区
根目录或 `CODEX_HOME` 重叠。

三个 URL 必须使用同一个主机：

```json
{
  "control_url": "wss://control.example.com/codex-ws/device",
  "pairing_url": "https://control.example.com/codex-api/v1/device-pairings/start",
  "token_url": "https://control.example.com/codex-api/v1/device/connect-token"
}
```

除非源码协议也同步升级，不要修改 `codex_version` 和 `schema_digest`。Codex 版本变化或不符合
预期时，Connector 会在启动 app-server 前拒绝运行。

Control 平面已经可用时，开始配对：

```sh
./sub2api-codex-connector \
  -config "$HOME/.config/sub2api-codex-connector/connector.json" \
  -pair-only
```

保持进程运行，在已登录的 PWA 中认领 stderr 提示的私密 `pairing-code.json` 文件内配对码。
命令确认认领并退出后，去掉 `-pair-only` 启动长期运行的 Connector。

## 安装 Control 服务器包

服务器管理员应从 [GitHub Releases 页面](https://github.com/peter2317238492/sub2api-codex-control/releases)
取得匹配的签名 `control-v*` 版本，不能使用仓库工作区或 GitHub 自动生成的源码压缩包。下载
online 或 offline 服务器包时，必须同时取得 manifest、独立 verifier 与签名证据；先认证
verifier，再校验完整 Release 目录，并且只安装校验后解出的包。

完整命令与信任参数见正式[部署手册](runbooks/deployment.md)，该手册只接受经过验证的包
生命周期 wrapper 作为入口。

## 生产前置条件

不要从可变工作区或临时本地镜像安装生产。只有同一个源码版本满足以下全部条件，生产安装
才可以继续：

- 签名并固定 digest 的 `linux/amd64` Control API、PWA 和 PostgreSQL-tools 镜像；
- 已验证的源码身份、Sigstore 身份、来源证明和 SBOM；
- 平台签名与证据通过消费端验证器的 Connector 发布；
- 不可变且符合协议锁定的 Sub2API 运行时；
- 隔离的 PostgreSQL 账号/数据库和 Redis ACL 用户/前缀；
- `https://control.example.com` 这类单一来源的有效 TLS 证书；
- 经审查的 Nginx 集成、一次已验证的变更前恢复快照，以及仓库外私密部署记录；
- 针对目标来源完成真实登录 HTTP、浏览器 WSS、设备 WSS、Connector、审批、重连、撤销和
  注销验收。

仓库包含部署工具和策略文档，但文件存在本身不代表已经发布。准入边界见
[部署手册](runbooks/deployment.md)。

## 网络边界

宿主 Nginx 是唯一公网入口。公网允许 TCP `443`；TCP `80` 只在 HTTP 跳转或 ACME 校验
需要时开放；SSH 限制到管理员来源网段。回环端口 `18090`、`18091`、`18092`、`18093`
不得对公网开放，也不要开放 PostgreSQL 或 Redis。Connector 只需要出站 HTTPS/WSS。
