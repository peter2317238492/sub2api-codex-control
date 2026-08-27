# 图形化使用指南

[English](visual-guide.md) · 详细文字版：[使用手册](usage.zh-CN.md) · [安装指南](installation.zh-CN.md)

本指南用图辅助你从零开始安装、配对并日常使用 Sub2API Codex Control。每张图之后给出可直接复制的命令。所有命令都由拥有 Codex 的普通用户执行，`connector-ctl` 会拒绝 root。

## 1. 架构总览

Connector 只建立**出站** WSS 连接，设备不开放任何入站端口；浏览器永远不直连你的设备。

```mermaid
flowchart LR
    subgraph browser["你的浏览器（电脑或手机）"]
        PWA["Control PWA<br/>https://控制站点/codex/"]
    end
    subgraph server["Sub2API 服务器（运营方部署）"]
        S2A["Sub2API 站点登录"]
        API["Control API"]
        DB[("PostgreSQL / Redis")]
    end
    subgraph device["你的设备（Linux amd64 / arm64）"]
        CONN["Connector<br/>sub2api-codex-connector"]
        CODEX["你自己的 Codex 安装"]
    end
    PWA -- "HTTPS（短期 HttpOnly 会话）" --> API
    PWA -. "同域登录" .-> S2A
    API --- DB
    CONN == "出站 WSS（设备无入站端口）" ==> API
    CONN -- "本机调用" --> CODEX
```

远程能力被固定为**八类 RPC**，没有原始远程 shell：

| 类别 | RPC |
| --- | --- |
| 模型 | `model/list` |
| 线程 | `thread/start` · `thread/list` · `thread/read` · `thread/resume` |
| 回合 | `turn/start` · `turn/steer` · `turn/interrupt` |

## 2. 首次设置之旅（5 步）

```mermaid
flowchart TD
    A["① 登录并打开 Control<br/>先登录 Sub2API 站点根路径<br/>再打开同域 /codex/"] --> B
    B["② 安装 Connector<br/>在 PWA 下载 .deb / .rpm<br/>核对 SHA-256 与 GitHub Release 完全一致"] --> C
    C["③ 创建配置<br/>connector-ctl init<br/>生成 0600 私密 connector.json"] --> D
    D["④ 配对设备<br/>connector-ctl pair 保持运行<br/>从私密文件读 16 位配对码填入 PWA"] --> E
    E["⑤ 启动并确认在线<br/>connector-ctl start<br/>PWA 中设备显示为在线"]
```

各步命令（把 `https://control.example.com` 换成你的站点，路径换成真实工作区）：

```sh
# ③ 创建配置
sub2api-codex-connector-ctl init \
  --origin https://control.example.com \
  --workspace /absolute/path/to/workspace \
  --display-name "我的工作站"

# ④ 配对（保持运行直到网页认领完成后自行退出）
sub2api-codex-connector-ctl pair

# ⑤ 启动并确认
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

> 安全要点：只有 PWA 显示的标签、文件名和 SHA-256 与 [GitHub Releases](https://github.com/peter2317238492/sub2api-codex-control/releases) 完全一致才安装；配对码只从 mode `0600` 的 `pairing-code.json` 读取，不截图、不复制到聊天；`connector.json` 不提交 Git、不外发。

## 3. 配对如何完成（时序）

```mermaid
sequenceDiagram
    autonumber
    participant T as 设备终端
    participant F as pairing-code.json（0600）
    participant U as 你
    participant P as Control PWA
    participant A as Control API
    T->>T: sub2api-codex-connector-ctl pair
    T->>F: 写入一次性 16 位配对码
    T-->>A: 等待认领（保持运行）
    U->>F: 只从私密文件读取配对码
    U->>P: 点击「配对已有 Connector」并输入
    P->>A: 提交配对码
    A-->>T: 认领成功
    T->>T: pair 自行退出
    Note over U,A: 配对码一次性、限时；过期 / 被拒 / 已用需重新生成
```

## 4. 日常使用：线程与 turn

```mermaid
flowchart TD
    S["选择在线设备"] --> N["新建线程：选工作区（仅本地白名单）+ 选模型"]
    N --> I["线程空闲"]
    I -- "输入并发送" --> R["turn 运行中"]
    R -- "再次发送 = 引导当前 turn" --> R
    R -- "点停止图标" --> X["中断"]
    R --> DN["完成"]
    R --> FL["失败"]
    FL -- "设备在线时点恢复图标" --> R
    X --> I
    DN --> I
    I -- "空闲或失败时可归档" --> AR["归档（只移除远程视图，不删设备上的 Codex 线程）"]
    FL --> AR
```

- 服务端无法选择本地白名单之外的路径，也不能把沙箱提升到 Connector 配置上限之上。
- 设备离线时仍可查看最近同步内容，但不能发送、引导、中断或恢复。

## 5. 审批如何流转（时序）

```mermaid
sequenceDiagram
    autonumber
    participant C as Codex（你的设备）
    participant K as Connector
    participant A as Control API
    participant P as PWA（顶栏铃铛）
    participant U as 你
    C->>K: 请求需要授权的操作
    K->>A: 上报待审批项
    A->>P: 铃铛显示待审批数量
    U->>P: 打开审批抽屉
    P->>U: 展示设备、类型、摘要、投影详情、到期时间
    alt 看得懂且确认影响
        U->>P: 批准
    else 看不懂或无法确认
        U->>P: 拒绝
    end
    P->>A: 提交决定
    A->>K: 下发（一次性、限时、绑定连接世代）
    Note over C,U: 超时 / 断线 / 重复处理 / 撤销 / 世代变化 ⇒ 失效并默认拒绝
```

## 6. 出问题时怎么查（决策树）

```mermaid
flowchart TD
    Q["PWA 里设备不在线？"] --> S1["sub2api-codex-connector-ctl status"]
    S1 -- "服务没在跑" --> S2["sub2api-codex-connector-ctl start"]
    S1 -- "在跑但离线" --> S3["sub2api-codex-connector-ctl logs<br/>查看最近用户服务日志"]
    S3 --> S4{"日志提示配对或凭据问题？"}
    S4 -- "是" --> S5["在 PWA 撤销设备后重新 pair + start"]
    S4 -- "否" --> S6["检查设备出站网络与站点地址<br/>再看使用手册故障排查一节"]
    S2 --> OK["回到 PWA 确认在线"]
    S5 --> OK
    S6 --> OK
```

常用命令备查：

```sh
sub2api-codex-connector-ctl config-path   # 配置位置
sub2api-codex-connector-ctl restart       # 重启服务
sub2api-codex-connector-ctl logs          # 最近日志
```

## 7. 更换工作区、撤销与卸载

当前正式命令一次只支持一个工作区；更换 = 撤销后重建：

```mermaid
flowchart LR
    R1["PWA：撤销现有设备"] --> R2["stop"] --> R3["purge-user-state --yes"] --> R4["init（新工作区）"] --> R5["pair"] --> R6["start + status"]
```

```sh
sub2api-codex-connector-ctl stop
sub2api-codex-connector-ctl purge-user-state --yes
sub2api-codex-connector-ctl init --origin https://control.example.com \
  --workspace /new/absolute/workspace --display-name "我的工作站"
sub2api-codex-connector-ctl pair
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

彻底移除：先在 PWA **撤销设备**，包管理器卸载后（默认保留私密状态），确认不再需要时由同一普通用户执行 `purge-user-state --yes` 清除 Connector 自有目录。它不会删除 Codex 配置、登录信息或工作区。

共用设备上，请始终用顶栏退出图标显式注销，而不是只关标签页。

---

更多细节（XDG 迁移、审批语义、安全边界、完整故障排查）见[使用手册](usage.zh-CN.md)与[安装指南](installation.zh-CN.md)。
