# 使用

[English](usage.md) | [文档索引](../README.zh-CN.md#文档)

本教程假设已有通过准入的 Control 部署。仓库首个公开版本不包含受支持的生产镜像或预编译
Connector。

## 先登录，再打开 PWA

PWA 不是独立登录页。先在同一来源根路径登录 Sub2API，例如
`https://control.example.com/`，再打开 `https://control.example.com/codex/`。浏览器会用当前
Sub2API access 会话换取短期 HttpOnly Control 会话；refresh 凭据只留在 Sub2API 浏览器流程，
不会进入 Control API。

## 配对设备

1. 按[安装文档](installation.zh-CN.md#以普通用户构建-connector)构建并配置 Connector。
2. 使用 `-pair-only` 启动，保持进程运行。
3. 只从 stderr 提示的 mode `0600` `pairing-code.json` 文件读取配对码，并把它当作临时凭据。
4. 在 PWA 中选择“配对设备”，输入 16 位配对码，确认设备和工作区信息。
5. 等待 Connector 确认认领并退出。配对码过期或被拒绝后应重新配对，不要通过不可信渠道分享。

以普通 Codex 用户启动长期 Connector：

```sh
/absolute/path/to/sub2api-codex-connector \
  -config "$HOME/.config/sub2api-codex-control/connector.json"
```

Connector 只建立出站连接。若需在用户退出桌面会话后继续运行，请使用用户自己的服务管理器，
并确保状态目录始终仅该用户可读。

## 使用 Codex

1. 在 PWA 中选择在线设备。
2. 从该设备已配置的工作区根目录中选择路径并新建线程；服务端不能选择本地白名单之外的路径。
3. 选择允许的模型，创建线程并发送文本输入。
4. 仔细审查审批弹窗。审批缺失、过期、失联或超时时默认拒绝；只读 Connector 不能批准写操作。
5. 不再需要时，可以归档空闲或失败的托管线程。

远程视图会主动省略原始命令输出、diff、本地图片、skills、任意配置、环境变量和不相关的本地
Codex 线程。未明确允许的方法一律拒绝。

## 撤销与注销

设备丢失或退役时，在设备菜单撤销 Connector。撤销会阻止后续 token 交换并关闭有效的远程
访问路径。只有确认不再需要事件调查证据后，才删除设备上的私密 Connector 状态目录。

使用 PWA 的注销操作结束会话，它会协调 Control 会话与 Sub2API 注销。只关闭浏览器标签页
不等于显式注销。

## 故障排查

- **PWA 返回 Sub2API：** 先在 `/` 登录，再打开 `/codex/`。
- **配对一直不完成：** 确认三个 Connector URL 使用同一公网主机、系统时钟准确、出站 WSS
  没有被阻止。
- **Codex 版本被拒绝：** 安装准确的 `codex-cli 0.147.0`；Connector 会主动拒绝协议漂移。
- **工作区被拒绝：** 使用已存在的绝对目录，并确保它不与 Connector 状态目录或
  `CODEX_HOME` 重叠。
- **设备离线：** 检查用户 Connector 进程、出站 TLS 和 `state_dir/connector.prom` 的更新时间。
  旧 metrics 文件不能证明进程仍在运行。
- **ready 正常但控制失败：** readiness 只覆盖依赖，不证明登录、浏览器 WSS、设备 WSS 或
  Connector 策略正常。

服务端排查和事件处理见[运维](operations.zh-CN.md)。
