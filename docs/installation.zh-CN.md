# 安装

[English](installation.md) | [文档索引](../README.zh-CN.md#文档)

## 先选择正确的安装路径

当前有两条完全不同的路径：

1. 隔离 E2E 路径现在可用，用一次性基础设施验证源码。
2. 首个公开源码版本不能直接安装到生产。它尚未发布生产安装所需的完整签名证据。

Connector 可从源码构建用于开发与评估，但目前不提供受支持的预编译二进制。

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

## 以普通用户构建 Connector

安装 Go 1.24 或更高版本及 `codex-cli 0.147.0`。Connector 应以拥有目标 Codex 和工作区
的同一个普通用户运行，不要用 root 运行。

```sh
cd connector
go test ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o sub2api-codex-connector ./cmd/connector
```

创建私密配置目录并复制示例：

```sh
install -d -m 0700 "$HOME/.config/sub2api-codex-control"
install -m 0600 connector.example.json \
  "$HOME/.config/sub2api-codex-control/connector.json"
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
  -config "$HOME/.config/sub2api-codex-control/connector.json" \
  -pair-only
```

保持进程运行，在已登录的 PWA 中认领 stderr 提示的私密 `pairing-code.json` 文件内配对码。
命令确认认领并退出后，去掉 `-pair-only` 启动长期运行的 Connector。

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
