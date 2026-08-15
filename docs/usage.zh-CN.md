# 使用手册

[English](usage.md) | [返回中文 README](../README.zh-CN.md)

> [!IMPORTANT]
> 本手册描述正式签名 Connector 发布后的用户流程。当前公开仓库仍是源码候选版；在 GitHub
> 出现不可变的 `connector-v*` Release 之前，不要把临时构建当作受支持的安装包。

## 使用前准备

普通用户需要准备以下内容，不需要管理员代为创建设备或生成配对码：

- 一个可以正常登录的 Sub2API 账号；
- 已启用 Control 的同一 HTTPS 站点地址；
- 一台 Linux 或 macOS 设备，以及准确版本的 `codex-cli 0.147.0`；
- 至少一个已存在的绝对工作区路径；
- 设备到 Control 站点 TCP 443 的出站网络。

管理员只负责一次性部署站点、发布可信安装包和维护服务。用户自行完成 Connector 安装后的
配置、配对、启动、日常操作、诊断和撤销。

## 界面布局

| 区域 | 可以做什么 |
| --- | --- |
| 顶栏 | 查看“实时 / 连接中 / 离线”状态，打开审批、续期刷新或退出 |
| 左侧设备栏 | 安装 Connector、配对设备、切换设备、查看在线状态和撤销 |
| 中间线程栏 | 搜索、新建、选择和归档所选设备的线程 |
| 右侧对话区 | 发送消息、引导或中断当前 turn、恢复失败线程 |
| 审批抽屉 | 查看一次性请求的类型、来源、详情和到期时间，并批准或拒绝 |

在窄屏设备上，顶栏的设备与线程图标用于打开对应侧栏。

## 首次设置

### 1. 登录并打开 Control

PWA 不是独立登录页。先在站点根路径登录 Sub2API，例如：

```text
https://control.example.com/
```

然后打开同一域名的 Control PWA：

```text
https://control.example.com/codex/
```

浏览器会用当前 Sub2API access 会话换取短期 HttpOnly Control 会话。Sub2API refresh 凭据只
留在原有浏览器登录流程，不会发送到 Control API。

### 2. 安装 Connector

点击设备栏顶部的下载图标，或在“暂无设备”状态点击**安装 Connector**。选择操作系统、架构
和包格式，下载安装包，再执行 PWA 给出的校验与安装命令。只有 SHA-256 完全一致时才继续。

完整安装命令和源码评估路径见[安装指南](installation.zh-CN.md)。安装包不会安装或升级 Codex，
也不会修改 Codex 配置、登录文件、工作区、插件、shell 配置或防火墙。

### 3. 创建配置

正式向导一次初始化一个工作区。填写已存在的绝对工作区路径和设备名称后，以拥有 Codex 和
该工作区的普通用户执行页面给出的命令：

```sh
sub2api-codex-connector-ctl init \
  --origin https://control.example.com \
  --workspace /absolute/path/to/workspace \
  --display-name "我的工作站"
```

命令会在设备本地创建 mode `0600` 的私密配置，默认路径是：

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sub2api-codex-connector/connector.json
```

可用以下命令确认实际路径：

```sh
sub2api-codex-connector-ctl config-path
```

状态目录、工作区与 `CODEX_HOME` 不能互相包含。浏览器不需要取得该文件；不要把
`connector.json` 提交到 Git、发到聊天或交给管理员。

### 4. 配对设备

运行并保持命令等待：

```sh
sub2api-codex-connector-ctl pair
```

Connector 会在 stderr 提示一个 mode `0600` 的 `pairing-code.json` 路径。只从该私密文件读取
16 位一次性配对码，然后在 PWA 点击**配对已有 Connector**并输入。保持 `pair` 运行，直到
网页认领完成且命令自行退出。

配对码是临时凭据。不要截图、复制到聊天或写入日志；过期、被拒绝或已使用的配对码必须重新
生成。

### 5. 启动并确认在线

只有 `pair` 已完成，才以同一普通用户启动后台服务：

```sh
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

返回 PWA，确认设备状态为**在线**。Connector 只建立出站 WSS，不监听设备入站端口。

## 日常使用

### 选择设备并新建线程

1. 在设备栏选择一台在线设备。
2. 在线程栏点击“新建线程”图标。
3. 从设备本地允许的工作区中选择工作目录。
4. 选择模型，或保留“使用设备默认模型”。
5. 点击**创建**。

服务端无法选择本地白名单之外的路径，也不能把沙箱提升到 Connector 配置的上限以上。

### 对话、引导与中断

- 线程空闲时，输入内容并发送会开始新的 turn。
- turn 正在运行时，输入框变为**引导当前 turn**；此时发送会引导正在运行的 turn，而不是
  新建另一个并发 turn。
- 需要停止时，点击对话区右上角的停止图标中断当前 turn。
- 设备离线时仍可查看最近同步内容，但不能发送、引导、中断或恢复。

### 处理审批

待审批数量显示在顶栏铃铛上。打开审批抽屉后，先检查设备、请求类型、摘要、投影后的详情和
到期时间，再选择**批准**或**拒绝**。

审批是一次性、限时并绑定当前连接世代的。超时、断线、重复处理、设备撤销或连接世代变化
都会使其失效；失效时默认拒绝。看不懂或无法确认影响时应选择拒绝。

### 恢复与归档

- 失败线程会显示恢复图标；设备在线时可尝试恢复托管线程。
- 只有空闲或失败的线程可以归档，运行中或等待审批的线程不能归档。
- 从 Control 归档只移除远程托管视图，不会删除设备上的原始 Codex 线程。

## 修改工作区或沙箱

工作区和沙箱边界由设备本地配置拥有，不能从浏览器静默扩大。多工作区属于高级本地操作：
先运行 `sub2api-codex-connector-ctl config-path`，再编辑该 mode `0600` 私密
`connector.json`，将 `workspace_roots` 设为 1 到 32 个已存在的绝对目录。修改后重启用户服务：

```sh
sub2api-codex-connector-ctl restart
sub2api-codex-connector-ctl status
```

新增工作区必须已经存在且使用绝对路径。`sandbox_cap` 只能是 `read-only` 或
`workspace-write`。Connector 启动校验失败时会拒绝连接，可通过日志查看不含秘密的错误信息。

## 常用命令

```sh
# 配置位置
sub2api-codex-connector-ctl config-path

# 服务生命周期
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl stop
sub2api-codex-connector-ctl restart
sub2api-codex-connector-ctl status

# 最近的用户服务日志
sub2api-codex-connector-ctl logs
```

所有命令都应由拥有 Codex 的普通用户执行。`connector-ctl` 会拒绝 root。

## 撤销、注销与卸载

### 撤销设备

设备丢失、转让或不再使用时，打开该设备的操作菜单并选择**撤销设备**。撤销会阻止后续 token
交换并关闭有效远程访问路径。撤销后需要再次使用该设备时，必须重新配对。

### 安全退出

使用顶栏的退出图标结束 Control 会话并协调 Sub2API 注销。只关闭浏览器标签页不等于显式
注销；共用设备上应始终使用退出操作。

### 卸载与清除状态

原生包卸载默认保留用户的私密 Connector 状态，便于调查或重新安装。先在 PWA 撤销设备，
确认不再需要后，再由同一普通用户显式清除：

```sh
sub2api-codex-connector-ctl purge-user-state --yes
```

该命令拒绝 root，并拒绝删除任何与 `CODEX_HOME` 重叠的路径。它不会删除 Codex 配置、登录
信息或工作区。

## 故障排查

| 现象 | 处理顺序 |
| --- | --- |
| PWA 显示“需要登录 Sub2API” | 先在同一域名 `/` 登录，再重新打开 `/codex/`；不要混用不同域名 |
| 正式安装包暂不可用 | 站点尚未提供通过校验的 Release 元数据；不要改用来源不明的二进制 |
| `init` 拒绝路径 | 确认路径存在且为绝对路径，并且不与状态目录或 `CODEX_HOME` 重叠 |
| 配对一直不完成 | 保持 `pair` 运行，检查系统时间、HTTPS origin、出站 TCP 443/WSS 和配对码有效期 |
| Codex 版本被拒绝 | 安装准确的 `codex-cli 0.147.0`；不要手改 `codex_version` 或 `schema_digest` 绕过校验 |
| 服务启动失败 | 运行 `connector-ctl status` 和 `connector-ctl logs`，检查配置路径与 JSON |
| 设备显示离线 | 检查用户服务、系统时间和出站 TLS；旧 metrics 文件不能证明进程仍在运行 |
| 线程不能创建 | 选择在线设备，并确认工作目录在该设备的 `workspace_roots` 中 |
| 线程不能归档 | 先等待 turn 和审批结束，或中断当前 turn |
| 审批突然消失 | 它可能已过期、已处理、属于另一用户，或在重连后失效 |
| ready 正常但仍不能控制 | readiness 只证明依赖可用，不证明登录、浏览器 WSS、设备 WSS 或 Connector 策略正常 |

需要向管理员报告时，只提供发生时间、页面现象、HTTP 状态和经过脱敏的错误类别。不要发送
access/refresh token、Cookie、配对码、设备凭据、私密路径、命令输出或工作区内容。

## 远程可见范围

Control 只允许 `model/list`、`thread/start`、`thread/list`、`thread/read`、`thread/resume`、
`turn/start`、`turn/steer` 和 `turn/interrupt`。浏览器不会获得原始 RPC 通道、任意 shell、
任意文件或进程访问、Codex 配置、账号登录、插件管理、环境变量、完整命令输出或未投影的
本地数据。未明确允许的操作一律拒绝。

服务端事件处理见[运维指南](operations.zh-CN.md)，完整安全决策见[威胁模型](adr/)。
